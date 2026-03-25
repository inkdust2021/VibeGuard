package proxy

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/andybalholm/brotli"
	"github.com/elazarl/goproxy"
	"github.com/inkdust2021/vibeguard/internal/admin"
	"github.com/inkdust2021/vibeguard/internal/cert"
	"github.com/inkdust2021/vibeguard/internal/config"
	"github.com/inkdust2021/vibeguard/internal/pii_next/keywords"
	"github.com/inkdust2021/vibeguard/internal/pii_next/ner"
	"github.com/inkdust2021/vibeguard/internal/pii_next/pipeline"
	piirec "github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
	"github.com/inkdust2021/vibeguard/internal/pii_next/rulelist"
	"github.com/inkdust2021/vibeguard/internal/redact"
	"github.com/inkdust2021/vibeguard/internal/restore"
	"github.com/inkdust2021/vibeguard/internal/rulelists"
	"github.com/inkdust2021/vibeguard/internal/secretsources"
	"github.com/inkdust2021/vibeguard/internal/session"
	"github.com/inkdust2021/vibeguard/internal/stream"
	"github.com/inkdust2021/vibeguard/internal/wsproxy"
	"github.com/inkdust2021/vibeguard/internal/zstd"
)

const (
	maxTextBodyBytes          = 10 * 1024 * 1024 // 10MB
	defaultPlaceholderPrefix  = "__VG_"
	defaultProxyInterceptMode = "global"
)

var errUnsupportedContentEncoding = errors.New("unsupported content-encoding")

type runtimeConfig struct {
	interceptMode          string
	targets                map[string]bool
	redactEng              redact.Redactor
	restoreEng             *restore.Engine
	websocketRedactionBeta bool
}

// Server represents the MITM proxy server
type Server struct {
	proxy      *goproxy.ProxyHttpServer
	config     *config.Manager
	ca         *cert.CA
	session    *session.Manager
	listenAddr string
	runtime    atomic.Value // runtimeConfig
	admin      *admin.Admin
	certPath   string
	keyPath    string
	subMgr     *rulelists.SubscriptionManager
}

type auditCtx struct {
	id       int64
	redacted bool
}

type readWriteCloserAdapter struct {
	io.ReadCloser
	writer io.Writer
}

func (a *readWriteCloserAdapter) Write(p []byte) (int, error) {
	if a == nil || a.writer == nil {
		return 0, io.ErrClosedPipe
	}
	return a.writer.Write(p)
}

// NewServer creates a new proxy server
func NewServer(cfg *config.Manager, ca *cert.CA, certPath, keyPath string) (*Server, error) {
	c := cfg.Get()

	// Create session manager
	sessTTL, err := time.ParseDuration(c.Session.TTL)
	if err != nil {
		sessTTL = time.Hour
	}
	sess := session.NewManager(sessTTL, c.Session.MaxMappings)
	if c.Session.WALEnabled {
		key, err := ca.DeriveStorageKey()
		if err != nil {
			return nil, fmt.Errorf("failed to derive WAL key: %w", err)
		}

		walPath := resolveSessionWALPath(c.Session.WALPath)
		wal, err := session.NewWAL(walPath, key)
		if err != nil {
			return nil, fmt.Errorf("failed to init session WAL: %w", err)
		}
		if err := wal.RestoreInto(sess); err != nil {
			slog.Warn("Failed to restore session WAL; continuing with empty in-memory mappings", "error", err, "path", walPath)
		}
		sess.AttachWAL(wal)
	}

	// Create goproxy
	proxy := goproxy.NewProxyHttpServer()

	// Configure transport
	proxy.Tr = &http.Transport{
		DisableCompression: true,
		ForceAttemptHTTP2:  false,
		TLSNextProto:       make(map[string]func(string, *tls.Conn) http.RoundTripper),
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
	}

	// Create admin handler
	adm := admin.New(cfg, sess, ca, certPath, keyPath)

	server := &Server{
		proxy:      proxy,
		config:     cfg,
		ca:         ca,
		session:    sess,
		listenAddr: c.Proxy.Listen,
		admin:      adm,
		certPath:   certPath,
		keyPath:    keyPath,
	}
	server.applyConfig(c)
	// Enable background rule subscription updates: remote rule lists are fetched, validated, cached locally, and hot-reloaded.
	server.subMgr = rulelists.NewSubscriptionManager(cfg, server.ReloadFromConfig)
	server.subMgr.Start()

	// Set up handlers
	server.setupHandlers()

	return server, nil
}

// Start starts the proxy server
func (s *Server) Start() error {
	// Record start time
	s.admin.SetStartTime(time.Now().Unix())

	// Do not use http.ServeMux for CONNECT (authority-form) requests:
	// CONNECT request-target is like "host:port", so URL.Path may be empty or not start with "/".
	// ServeMux may return a 301 redirect, breaking HTTPS proxy traffic (clients keep reconnecting).
	// Use a custom router here: only /manager/ goes to the admin UI; everything else goes to the proxy (including CONNECT).
	adminHandler := s.admin.Handler()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r != nil {
			if r.URL.Path == "/manager" {
				http.Redirect(w, r, "/manager/", http.StatusMovedPermanently)
				return
			}
			if strings.HasPrefix(r.URL.Path, "/manager/") {
				adminHandler.ServeHTTP(w, r)
				return
			}
		}
		s.proxy.ServeHTTP(w, r)
	})

	slog.Info("Starting VibeGuard proxy", "address", s.listenAddr, "manager", "http://"+s.listenAddr+"/manager/")
	return http.ListenAndServe(s.listenAddr, handler)
}

// Stop stops the proxy server
func (s *Server) Stop() {
	if s.subMgr != nil {
		s.subMgr.Stop()
	}
	s.session.Close()
	if s.admin != nil {
		s.admin.Close()
	}
	slog.Info("VibeGuard proxy stopped")
}

func (s *Server) runtimeSnapshot() runtimeConfig {
	v := s.runtime.Load()
	if v == nil {
		return runtimeConfig{}
	}
	return v.(runtimeConfig)
}

func (s *Server) shouldIntercept(host string) bool {
	rt := s.runtimeSnapshot()
	if rt.interceptMode == "global" {
		return true
	}
	_, ok := rt.targets[canonicalHost(host)]
	return ok
}

func canonicalHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	// Prefer robust parsing for host:port / [ipv6]:port.
	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.ToLower(h)
	}
	// If host is like "[::1]" (no port) or plain hostname, normalize brackets/case.
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	return strings.ToLower(host)
}

func requestHost(req *http.Request) string {
	if req == nil {
		return ""
	}
	if req.URL != nil {
		if h := canonicalHost(req.URL.Hostname()); h != "" {
			return h
		}
		if h := canonicalHost(req.URL.Host); h != "" {
			return h
		}
	}
	return canonicalHost(req.Host)
}

func isWebSocketUpgradeRequest(req *http.Request) bool {
	if req == nil {
		return false
	}
	if !headerContainsToken(req.Header, "Connection", "upgrade") {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(req.Header.Get("Upgrade")), "websocket")
}

func headerContainsToken(h http.Header, key, want string) bool {
	if h == nil {
		return false
	}
	value := h.Get(key)
	if strings.TrimSpace(value) == "" {
		return false
	}
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), want) {
			return true
		}
	}
	return false
}

func safeRequestPath(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	// Only show the Path to avoid exposing sensitive query parameters in the admin UI.
	return req.URL.Path
}

func buildAuditMatches(redactLog bool, matches []redact.Match) []admin.AuditMatch {
	const (
		maxMatches     = 50
		maxValueRunes  = 256
		maxPreviewTail = 2
		maxPreviewHead = 2
	)

	if len(matches) == 0 {
		return nil
	}

	n := len(matches)
	if n > maxMatches {
		n = maxMatches
	}

	out := make([]admin.AuditMatch, 0, n)
	for i := 0; i < n; i++ {
		m := matches[i]

		origLen := utf8.RuneCountInString(m.Original)
		value, truncated := truncateRunes(m.Original, maxValueRunes)

		isPreview := redactLog
		if redactLog {
			value = previewValue(value, maxPreviewHead, maxPreviewTail)
		}

		out = append(out, admin.AuditMatch{
			Category:    m.Category,
			Placeholder: m.Placeholder,
			Value:       value,
			IsPreview:   isPreview,
			Length:      origLen,
			Truncated:   truncated,
		})
	}

	return out
}

func truncateRunes(s string, max int) (string, bool) {
	if max <= 0 {
		return "", true
	}
	r := []rune(s)
	if len(r) <= max {
		return s, false
	}
	if max == 1 {
		return "…", true
	}
	return string(r[:max-1]) + "…", true
}

func previewValue(s string, head, tail int) string {
	r := []rune(s)
	n := len(r)
	if n == 0 {
		return ""
	}
	if n <= 4 {
		return strings.Repeat("*", n)
	}
	if head <= 0 {
		head = 1
	}
	if tail <= 0 {
		tail = 1
	}
	if head+tail >= n {
		return strings.Repeat("*", n)
	}
	return string(r[:head]) + "…" + string(r[n-tail:])
}

func redactJSONBody(redactEng redact.Redactor, body []byte) (out []byte, matches []redact.Match, changed bool, err error) {
	// Only attempt structured redaction if the body is valid JSON; otherwise fall back to whole-text redaction upstream.
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()

	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, nil, false, err
	}
	// Defensive: reject "valid JSON + trailing extra content" to avoid semantic changes after re-encoding.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, nil, false, fmt.Errorf("trailing JSON data")
	}

	// Important: do not redact all string fields across the whole JSON object.
	// That can break fields like model/metadata/schema (and generic recognizers may misclassify timestamps/versions),
	// causing upstream API errors or unexpected behavior. By default, only redact "prompt-like" fields:
	// - messages[].content / messages[].content[].text
	// - input / input[].content / input[].content[].text
	// Note: to minimize interference with upstream protocol fields, do not process system/metadata by default.
	redacted, matches, changed, err := redactJSONValuePromptOnly(redactEng, v)
	if err != nil {
		return nil, nil, false, err
	}
	if !changed {
		return body, nil, false, nil
	}

	out, err = json.Marshal(redacted)
	if err != nil {
		return nil, nil, false, err
	}
	return out, matches, true, nil
}

func redactPromptJSONStringValue(redactEng redact.Redactor, s string) (out any, matches []redact.Match, changed bool, err error) {
	// For JSON string fields: redact the raw value first, then apply JSON escaping once.
	// This avoids treating escape sequences like `\n` as plain text and harming NER/entity recognition.
	redactedRaw, ms := redactEng.RedactWithMatches([]byte(s))
	if len(ms) == 0 {
		return s, nil, false, nil
	}

	b, err := json.Marshal(string(redactedRaw))
	if err != nil {
		return s, nil, false, err
	}

	// Inject the already-encoded JSON string (including quotes) via RawMessage to avoid double-escaping and structural corruption.
	raw := json.RawMessage(b)
	if !json.Valid(raw) {
		// Edge case: user regex/keywords may hit and break escape sequences, producing invalid JSON strings.
		// To avoid forwarding invalid JSON upstream, fall back to "do not rewrite this field".
		return s, nil, false, nil
	}

	return raw, ms, true, nil
}

func redactJSONValuePromptOnly(redactEng redact.Redactor, v any) (out any, matches []redact.Match, changed bool, err error) {
	switch vv := v.(type) {
	case []any:
		anyChanged := false
		var all []redact.Match
		for i := range vv {
			nv, ms, ch, err := redactJSONValuePromptOnly(redactEng, vv[i])
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv[i] = nv
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}
		return vv, all, anyChanged, nil

	case map[string]any:
		anyChanged := false
		var all []redact.Match
		for k, val := range vv {
			var (
				nv any
				ms []redact.Match
				ch bool
			)

			switch k {
			case "messages", "input", "contents":
				nv, ms, ch, err = redactJSONMessagesLike(redactEng, val)
			default:
				nv, ms, ch, err = redactJSONValuePromptOnly(redactEng, val)
			}
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv[k] = nv
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}
		return vv, all, anyChanged, nil

	default:
		return v, nil, false, nil
	}
}

func redactJSONStringLike(redactEng redact.Redactor, v any) (out any, matches []redact.Match, changed bool, err error) {
	s, ok := v.(string)
	if !ok {
		return v, nil, false, nil
	}
	return redactPromptJSONStringValue(redactEng, s)
}

func redactJSONSystemLike(redactEng redact.Redactor, v any) (out any, matches []redact.Match, changed bool, err error) {
	switch vv := v.(type) {
	case string:
		return redactPromptJSONStringValue(redactEng, vv)
	case []any:
		anyChanged := false
		var all []redact.Match
		for i := range vv {
			nv, ms, ch, err := redactJSONTextPart(redactEng, vv[i])
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv[i] = nv
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}
		return vv, all, anyChanged, nil
	case map[string]any:
		// system may also be {type,text} or other structures.
		return redactJSONTextPart(redactEng, vv)
	default:
		return v, nil, false, nil
	}
}

func redactJSONMessagesLike(redactEng redact.Redactor, v any) (out any, matches []redact.Match, changed bool, err error) {
	switch vv := v.(type) {
	case string:
		// Some APIs use a plain string directly as input/prompt.
		return redactPromptJSONStringValue(redactEng, vv)
	case []any:
		anyChanged := false
		var all []redact.Match
		for i := range vv {
			nv, ms, ch, err := redactJSONMessageItem(redactEng, vv[i])
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv[i] = nv
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}
		return vv, all, anyChanged, nil
	case map[string]any:
		// A few implementations wrap messages/input in an object.
		return redactJSONValuePromptOnly(redactEng, vv)
	default:
		return v, nil, false, nil
	}
}

func redactJSONMessageItem(redactEng redact.Redactor, v any) (out any, matches []redact.Match, changed bool, err error) {
	switch vv := v.(type) {
	case string:
		return redactPromptJSONStringValue(redactEng, vv)
	case map[string]any:
		anyChanged := false
		var all []redact.Match

		// Common shape: role + content.
		if c, ok := vv["content"]; ok {
			nc, ms, ch, err := redactJSONMessageContent(redactEng, c)
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv["content"] = nc
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}

		// Gemini：parts
		if p, ok := vv["parts"]; ok {
			np, ms, ch, err := redactJSONTextParts(redactEng, p)
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv["parts"] = np
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}

		// OpenAI Responses: sometimes it is directly {type:"input_text", text:"..."}.
		if t, ok := vv["text"]; ok {
			nt, ms, ch, err := redactJSONStringLike(redactEng, t)
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv["text"] = nt
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}

		return vv, all, anyChanged, nil
	default:
		return v, nil, false, nil
	}
}

func redactJSONMessageContent(redactEng redact.Redactor, v any) (out any, matches []redact.Match, changed bool, err error) {
	switch vv := v.(type) {
	case string:
		return redactPromptJSONStringValue(redactEng, vv)
	case []any:
		return redactJSONTextParts(redactEng, vv)
	case map[string]any:
		// Compatibility: content may also be {text:"..."}.
		return redactJSONTextPart(redactEng, vv)
	default:
		return v, nil, false, nil
	}
}

func redactJSONTextParts(redactEng redact.Redactor, v any) (out any, matches []redact.Match, changed bool, err error) {
	parts, ok := v.([]any)
	if !ok {
		return v, nil, false, nil
	}

	anyChanged := false
	var all []redact.Match
	for i := range parts {
		nv, ms, ch, err := redactJSONTextPart(redactEng, parts[i])
		if err != nil {
			return v, nil, false, err
		}
		if ch {
			parts[i] = nv
			anyChanged = true
		}
		if len(ms) > 0 {
			all = append(all, ms...)
		}
	}
	return parts, all, anyChanged, nil
}

func redactJSONTextPart(redactEng redact.Redactor, v any) (out any, matches []redact.Match, changed bool, err error) {
	switch vv := v.(type) {
	case string:
		return redactPromptJSONStringValue(redactEng, vv)
	case map[string]any:
		// Common shape: {type:"text", text:"..."}.
		if t, ok := vv["text"]; ok {
			if ts, ok := t.(string); ok && isSystemReminderText(ts) {
				// Clients like Claude Code may inject <system-reminder> into messages[].content[].
				// These are protocol/runtime hints and should not be affected by redaction rules (do not rewrite even if matched),
				// otherwise upstream behavior or client parsing may break.
				return vv, nil, false, nil
			}
			nt, ms, ch, err := redactJSONStringLike(redactEng, t)
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv["text"] = nt
			}
			return vv, ms, ch, err
		}
		return v, nil, false, nil
	default:
		return v, nil, false, nil
	}
}

func isSystemReminderText(s string) bool {
	t := strings.TrimSpace(s)
	if t == "" {
		return false
	}
	// Example:
	// <system-reminder>
	// ...
	// </system-reminder>
	//
	// Also allow extended forms like <system-reminder ...>.
	if !strings.HasPrefix(t, "<system-reminder") {
		return false
	}
	return strings.Contains(t, "</system-reminder>")
}

func jsonEscapeStringValue(s string) (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	if len(b) >= 2 && b[0] == '"' && b[len(b)-1] == '"' {
		return string(b[1 : len(b)-1]), nil
	}
	return string(b), nil
}

// setupHandlers configures request/response handlers
func (s *Server) setupHandlers() {
	stats := s.admin.GetStats()

	// Request handler
	s.proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		if req != nil && req.Method != http.MethodConnect {
			stats.TotalRequests.Add(1)
		}

		rt := s.runtimeSnapshot()
		host := requestHost(req)
		method := ""
		contentType := ""
		contentEncoding := ""
		if req != nil {
			method = req.Method
			contentType = req.Header.Get("Content-Type")
			contentEncoding = strings.TrimSpace(req.Header.Get("Content-Encoding"))
		}
		auditEv := admin.AuditEvent{
			Host:            host,
			Method:          method,
			Path:            safeRequestPath(req),
			ContentType:     contentType,
			ContentEncoding: contentEncoding,
		}
		var savedAudit admin.AuditEvent
		recordAudit := func() admin.AuditEvent {
			saved := s.admin.RecordAudit(auditEv)
			savedAudit = saved
			if ctx != nil {
				ctx.UserData = auditCtx{
					id:       saved.ID,
					redacted: auditEv.RedactedCount > 0,
				}
			}
			return saved
		}
		if !s.shouldIntercept(host) {
			auditEv.Attempted = false
			auditEv.Note = "pass_through"
			recordAudit()
			return req, nil // Pass through
		}

		// WebSocket 握手对协议头和连接升级流程更敏感，这里保持透传，
		// 避免通用 HTTP 文本处理逻辑误改握手请求。
		if isWebSocketUpgradeRequest(req) {
			auditEv.Attempted = false
			auditEv.Note = "websocket_upgrade"
			recordAudit()
			return req, nil
		}

		dbg := s.admin.Debug()
		dbgOn := dbg != nil && dbg.Enabled()
		dbgMaxBody := 0
		dbgMaskHeaders := true
		if dbgOn {
			dbgMaxBody = dbg.MaxBodyBytes()
			dbgMaskHeaders = dbg.MaskHeaders()
		}
		var dbgReqHdrOrig http.Header
		var dbgReqURL string
		if dbgOn && req != nil {
			dbgReqHdrOrig = req.Header.Clone()
			if dbgMaskHeaders {
				dbgReqHdrOrig = admin.MaskSensitiveHeaders(dbgReqHdrOrig)
			}
			if req.URL != nil {
				dbgReqURL = strings.TrimSpace(req.URL.String())
			}
			if dbgReqURL == "" {
				dbgReqURL = strings.TrimSpace(req.RequestURI)
			}
		}

		slog.Debug("Intercepting request", "host", host, "method", req.Method, "path", req.URL.Path)

		// Set Accept-Encoding: identity to prevent compression
		req.Header.Set("Accept-Encoding", "identity")

		// Handle request body redaction
		if req.Body != nil && req.Body != http.NoBody && isTextContent(contentType) {
			auditEv.Attempted = true
			contentEncodingHeader := req.Header.Get("Content-Encoding")
			if !isSupportedContentEncodingHeader(contentEncodingHeader) {
				// Unknown/unsupported encoding: skip redaction to avoid corrupting binary bodies by false matches.
				auditEv.Attempted = false
				auditEv.Note = "encoded"
				recordAudit()
				return req, nil
			}

			if req.ContentLength > int64(maxTextBodyBytes) {
				slog.Debug("Skip redaction (request too large)", "host", host, "content_length", req.ContentLength)
				auditEv.Attempted = false
				auditEv.Note = "too_large"
				recordAudit()
				return req, nil
			}

			originalBody := req.Body
			limited := io.LimitReader(originalBody, int64(maxTextBodyBytes)+1)
			rawBody, err := io.ReadAll(limited)
			if err != nil {
				// Best-effort: put back already-read bytes to avoid breaking request forwarding.
				req.Body = &readerWithClose{
					r: io.MultiReader(bytes.NewReader(rawBody), originalBody),
					c: originalBody,
				}
				req.ContentLength = -1
				req.Header.Del("Content-Length")
				slog.Error("Failed to read request body", "error", err, "host", host)
				stats.Errors.Add(1)
				auditEv.Attempted = false
				auditEv.Note = "read_error"
				recordAudit()
				return req, nil
			}

			if len(rawBody) > maxTextBodyBytes {
				// Body too large: skip redaction, but put back the already-read prefix and continue forwarding.
				req.Body = &readerWithClose{
					r: io.MultiReader(bytes.NewReader(rawBody), originalBody),
					c: originalBody,
				}
				req.ContentLength = -1
				req.Header.Del("Content-Length")
				slog.Debug("Skip redaction (request too large)", "host", host, "limit_bytes", maxTextBodyBytes)
				auditEv.Attempted = false
				auditEv.Note = "too_large"
				recordAudit()
				return req, nil
			}

			_ = originalBody.Close()

			body := rawBody
			// If the request body is encoded, decode it before redaction and forward it unencoded (remove Content-Encoding).
			if strings.TrimSpace(contentEncodingHeader) != "" {
				decoded, derr := decompressBytes(rawBody, contentEncodingHeader, maxTextBodyBytes)
				if derr != nil {
					// Decode failed: forward the original encoded body to avoid breaking the request.
					req.Body = io.NopCloser(bytes.NewReader(rawBody))
					req.ContentLength = int64(len(rawBody))
					req.Header.Set("Content-Length", fmt.Sprintf("%d", len(rawBody)))
					req.TransferEncoding = nil
					req.Header.Del("Transfer-Encoding")
					stats.Errors.Add(1)
					auditEv.Attempted = false
					auditEv.Note = "decode_error"
					recordAudit()
					return req, nil
				}
				body = decoded
				req.Header.Del("Content-Encoding")
			}

			// Extra defense: do not redact non-UTF-8 text to avoid corrupting binary/garbled bodies.
			if !utf8.Valid(body) {
				req.Body = io.NopCloser(bytes.NewReader(rawBody))
				req.ContentLength = int64(len(rawBody))
				req.Header.Set("Content-Length", fmt.Sprintf("%d", len(rawBody)))
				req.TransferEncoding = nil
				req.Header.Del("Transfer-Encoding")
				auditEv.Attempted = false
				auditEv.Note = "not_utf8"
				recordAudit()
				return req, nil
			}

			var (
				redacted []byte
				matches  []redact.Match
			)
			if strings.Contains(contentType, "application/json") {
				if out, ms, changed, jerr := redactJSONBody(rt.redactEng, body); jerr == nil && changed {
					redacted = out
					matches = ms
				} else if jerr == nil && !changed {
					redacted = body
					matches = nil
				} else {
					redacted, matches = rt.redactEng.RedactWithMatches(body)
				}
			} else {
				redacted, matches = rt.redactEng.RedactWithMatches(body)
			}

			count := len(matches)
			auditEv.RedactedCount = count
			if count > 0 {
				auditEv.Matches = buildAuditMatches(s.config.Get().Log.RedactLog, matches)
			}

			outBody := body
			usedRedacted := false
			if count > 0 {
				outBody = redacted
				usedRedacted = true
			}
			// Compatibility fallback: if whole-text redaction broke valid JSON, revert to the original body to avoid upstream parse failures.
			if usedRedacted && strings.Contains(contentType, "application/json") && json.Valid(body) && !json.Valid(outBody) {
				outBody = body
				usedRedacted = false
				auditEv.Note = "invalid_json"
			}

			recordAudit()

			if usedRedacted {
				stats.RedactedRequests.Add(1)
				slog.Info("Redacted sensitive data in request", "count", count, "host", host)
			}

			req.Body = io.NopCloser(bytes.NewReader(outBody))
			req.ContentLength = int64(len(outBody))
			req.Header.Set("Content-Length", fmt.Sprintf("%d", len(outBody)))
			req.TransferEncoding = nil
			req.Header.Del("Transfer-Encoding")

			if dbgOn && savedAudit.ID > 0 {
				hdrFwd := req.Header.Clone()
				if dbgMaskHeaders {
					hdrFwd = admin.MaskSensitiveHeaders(hdrFwd)
				}

				origText, origBytes, origTrunc := clipBodyForDebug(body, dbgMaxBody)
				fwdText, fwdBytes, fwdTrunc := clipBodyForDebug(outBody, dbgMaxBody)
				dbg.UpsertRequest(savedAudit.ID, admin.DebugRequestCapture{
					Time: savedAudit.Time,
					Host: host, Method: method, Path: safeRequestPath(req), URL: dbgReqURL,
					ContentType: contentType, ContentEncoding: contentEncodingHeader,
					HeadersOriginal: dbgReqHdrOrig, HeadersForwarded: hdrFwd,
					BodyOriginalText: origText, BodyOriginalBytes: origBytes, BodyOriginalTrunc: origTrunc,
					BodyForwardedText: fwdText, BodyForwardedBytes: fwdBytes, BodyForwardedTrunc: fwdTrunc,
				})
			}
		} else {
			if req.Body == nil || req.Body == http.NoBody {
				auditEv.Attempted = false
				auditEv.Note = "no_body"
			} else if !isTextContent(contentType) {
				auditEv.Attempted = false
				auditEv.Note = "not_text"
			}
			recordAudit()
			if dbgOn && savedAudit.ID > 0 {
				hdrFwd := req.Header.Clone()
				if dbgMaskHeaders {
					hdrFwd = admin.MaskSensitiveHeaders(hdrFwd)
				}
				dbg.UpsertRequest(savedAudit.ID, admin.DebugRequestCapture{
					Time: savedAudit.Time,
					Host: host, Method: method, Path: safeRequestPath(req), URL: dbgReqURL,
					ContentType: contentType, ContentEncoding: contentEncoding,
					HeadersOriginal: dbgReqHdrOrig, HeadersForwarded: hdrFwd,
				})
			}
		}

		return req, nil
	})

	// Response handler
	s.proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp == nil || ctx.Req == nil {
			return resp
		}

		rt := s.runtimeSnapshot()
		host := requestHost(ctx.Req)
		if !s.shouldIntercept(host) {
			return resp // Pass through
		}

		contentType := resp.Header.Get("Content-Type")
		var (
			auditID         int64
			requestRedacted bool
		)
		if ctx != nil {
			if v, ok := ctx.UserData.(auditCtx); ok {
				auditID = v.id
				requestRedacted = v.redacted
			} else if v, ok := ctx.UserData.(int64); ok {
				auditID = v
			}
		}

		dbg := s.admin.Debug()
		dbgOn := dbg != nil && dbg.Enabled() && auditID > 0
		dbgMaxBody := 0
		dbgMaskHeaders := true
		var dbgRespHdrOrig http.Header
		if dbgOn {
			dbgMaxBody = dbg.MaxBodyBytes()
			dbgMaskHeaders = dbg.MaskHeaders()
			dbgRespHdrOrig = resp.Header.Clone()
			if dbgMaskHeaders {
				dbgRespHdrOrig = admin.MaskSensitiveHeaders(dbgRespHdrOrig)
			}
		}

		if auditID > 0 {
			s.admin.UpdateAudit(auditID, func(ev *admin.AuditEvent) {
				ev.ResponseStatus = resp.StatusCode
				ev.ResponseContentType = contentType
			})
		}

		if isWebSocketUpgradeRequest(ctx.Req) && resp.StatusCode == http.StatusSwitchingProtocols {
			if rt.websocketRedactionBeta {
				switch rwc := any(resp.Body).(type) {
				case io.ReadWriteCloser:
					resp.Body = wsproxy.NewTransformConn(rwc, rt.redactEng, rt.restoreEng)
				case interface {
					io.ReadCloser
					io.Writer
				}:
					resp.Body = wsproxy.NewTransformConn(&readWriteCloserAdapter{
						ReadCloser: rwc,
						writer:     rwc,
					}, rt.redactEng, rt.restoreEng)
				default:
					slog.Warn("WebSocket redaction beta requested, but upgraded connection is not writable; falling back to pass-through", "host", host)
				}
			}
			return resp
		}

		// Check for compression (defensive)
		contentEncoding := resp.Header.Get("Content-Encoding")
		decompressed := false
		if contentEncoding != "" {
			if decoded, ok := decompressBody(resp.Body, contentEncoding); ok {
				resp.Body = decoded
				resp.Header.Del("Content-Encoding")
				decompressed = true
			}
		}

		// Handle SSE streaming
		isSSE := strings.Contains(contentType, "text/event-stream")
		if !isSSE && requestRedacted && strings.TrimSpace(contentType) == "" && (contentEncoding == "" || decompressed) && resp.Body != nil {
			// Some upstreams omit Content-Type even when the body is SSE; then placeholders cannot be restored across delta events.
			// Do a lightweight sniff without leaking content: peek a small prefix and do not change downstream-consumed bytes.
			origBody := resp.Body
			br := bufio.NewReaderSize(origBody, 4096)
			peek, _ := br.Peek(256)
			resp.Body = &readerWithClose{r: br, c: origBody}
			if looksLikeSSEPrefix(peek) {
				isSSE = true
				if auditID > 0 {
					s.admin.UpdateAudit(auditID, func(ev *admin.AuditEvent) {
						if strings.TrimSpace(ev.ResponseContentType) == "" {
							ev.ResponseContentType = "text/event-stream (sniffed)"
						}
					})
				}
			}
		}
		if isSSE {
			slog.Debug("SSE response detected", "host", host)
			if auditID > 0 {
				s.admin.UpdateAudit(auditID, func(ev *admin.AuditEvent) { ev.RestoreApplied = true })
			}
			stats.RestoredRequests.Add(1)
			if dbgOn {
				up := newCaptureBuffer(dbgMaxBody)
				down := newCaptureBuffer(dbgMaxBody)
				upstream := &captureReadCloser{rc: resp.Body, w: up}
				restoring := stream.NewSSERestoringReader(upstream, rt.restoreEng)
				// Persist on downstream close to avoid frequent locking during long SSE streams.
				downstream := &captureReadCloser{
					rc: restoring,
					w:  down,
					onClose: func() {
						hdrFwd := resp.Header.Clone()
						if dbgMaskHeaders {
							hdrFwd = admin.MaskSensitiveHeaders(hdrFwd)
						}
						dbg.UpsertResponse(auditID, admin.DebugResponseCapture{
							ContentType:       contentType,
							Status:            resp.StatusCode,
							HeadersOriginal:   dbgRespHdrOrig,
							HeadersForwarded:  hdrFwd,
							BodyUpstreamText:  up.Text(),
							BodyUpstreamBytes: up.TotalBytes(),
							BodyUpstreamTrunc: up.Truncated(),
							BodyClientText:    down.Text(),
							BodyClientBytes:   down.TotalBytes(),
							BodyClientTrunc:   down.Truncated(),
						})
					},
				}
				resp.Body = downstream
			} else {
				resp.Body = stream.NewSSERestoringReader(resp.Body, rt.restoreEng)
			}
			resp.ContentLength = -1
			resp.Header.Del("Content-Length")
			return resp
		}

		// Handle JSON response
		if isJSONContentType(contentType) {
			if resp.ContentLength > int64(maxTextBodyBytes) {
				slog.Debug("Skip restore (response too large)", "host", host, "content_length", resp.ContentLength)
				return resp
			}

			// Streaming JSON (common in some compatible gateways/proxies): Content-Length may be -1.
			// If we ReadAll here before restoring, downstream sees no output for a long time (CLI appears "stuck").
			// When length is unknown, restore in a streaming way (supports placeholders across chunk boundaries).
			if resp.ContentLength < 0 {
				if auditID > 0 {
					s.admin.UpdateAudit(auditID, func(ev *admin.AuditEvent) { ev.RestoreApplied = true })
				}
				stats.RestoredRequests.Add(1)
				if dbgOn {
					up := newCaptureBuffer(dbgMaxBody)
					down := newCaptureBuffer(dbgMaxBody)
					upstream := &captureReadCloser{rc: resp.Body, w: up}
					restoring := stream.NewRestoringReader(upstream, rt.restoreEng)
					downstream := &captureReadCloser{
						rc: restoring,
						w:  down,
						onClose: func() {
							hdrFwd := resp.Header.Clone()
							if dbgMaskHeaders {
								hdrFwd = admin.MaskSensitiveHeaders(hdrFwd)
							}
							dbg.UpsertResponse(auditID, admin.DebugResponseCapture{
								ContentType:       contentType,
								Status:            resp.StatusCode,
								HeadersOriginal:   dbgRespHdrOrig,
								HeadersForwarded:  hdrFwd,
								BodyUpstreamText:  up.Text(),
								BodyUpstreamBytes: up.TotalBytes(),
								BodyUpstreamTrunc: up.Truncated(),
								BodyClientText:    down.Text(),
								BodyClientBytes:   down.TotalBytes(),
								BodyClientTrunc:   down.Truncated(),
							})
						},
					}
					resp.Body = downstream
				} else {
					resp.Body = stream.NewRestoringReader(resp.Body, rt.restoreEng)
				}
				resp.ContentLength = -1
				resp.Header.Del("Content-Length")
				return resp
			}

			originalBody := resp.Body
			limited := io.LimitReader(originalBody, int64(maxTextBodyBytes)+1)
			body, err := io.ReadAll(limited)
			if err != nil {
				// Best-effort: put back already-read bytes to avoid breaking response forwarding.
				resp.Body = &readerWithClose{
					r: io.MultiReader(bytes.NewReader(body), originalBody),
					c: originalBody,
				}
				resp.ContentLength = -1
				resp.Header.Del("Content-Length")
				slog.Error("Failed to read response body", "error", err, "host", host)
				stats.Errors.Add(1)
				return resp
			}
			if len(body) > maxTextBodyBytes {
				resp.Body = &readerWithClose{
					r: io.MultiReader(bytes.NewReader(body), originalBody),
					c: originalBody,
				}
				resp.ContentLength = -1
				resp.Header.Del("Content-Length")
				slog.Debug("Skip restore (response too large)", "host", host, "limit_bytes", maxTextBodyBytes)
				return resp
			}

			_ = originalBody.Close()

			if auditID > 0 {
				s.admin.UpdateAudit(auditID, func(ev *admin.AuditEvent) { ev.RestoreApplied = true })
			}
			stats.RestoredRequests.Add(1)
			restored := rt.restoreEng.Restore(body)
			resp.Body = io.NopCloser(bytes.NewReader(restored))
			resp.ContentLength = int64(len(restored))
			resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(restored)))
			resp.TransferEncoding = nil
			resp.Header.Del("Transfer-Encoding")

			if dbgOn {
				hdrFwd := resp.Header.Clone()
				if dbgMaskHeaders {
					hdrFwd = admin.MaskSensitiveHeaders(hdrFwd)
				}
				upText, upBytes, upTrunc := clipBodyForDebug(body, dbgMaxBody)
				downText, downBytes, downTrunc := clipBodyForDebug(restored, dbgMaxBody)
				dbg.UpsertResponse(auditID, admin.DebugResponseCapture{
					ContentType:       contentType,
					Status:            resp.StatusCode,
					HeadersOriginal:   dbgRespHdrOrig,
					HeadersForwarded:  hdrFwd,
					BodyUpstreamText:  upText,
					BodyUpstreamBytes: upBytes,
					BodyUpstreamTrunc: upTrunc,
					BodyClientText:    downText,
					BodyClientBytes:   downBytes,
					BodyClientTrunc:   downTrunc,
				})
			}
			return resp
		}

		// Handle other text responses (plain text / markdown / html, etc.)
		if isTextMediaType(contentType) {
			if auditID > 0 {
				s.admin.UpdateAudit(auditID, func(ev *admin.AuditEvent) { ev.RestoreApplied = true })
			}
			stats.RestoredRequests.Add(1)
			if dbgOn {
				up := newCaptureBuffer(dbgMaxBody)
				down := newCaptureBuffer(dbgMaxBody)
				upstream := &captureReadCloser{rc: resp.Body, w: up}
				restoring := stream.NewRestoringReader(upstream, rt.restoreEng)
				downstream := &captureReadCloser{
					rc: restoring,
					w:  down,
					onClose: func() {
						hdrFwd := resp.Header.Clone()
						if dbgMaskHeaders {
							hdrFwd = admin.MaskSensitiveHeaders(hdrFwd)
						}
						dbg.UpsertResponse(auditID, admin.DebugResponseCapture{
							ContentType:       contentType,
							Status:            resp.StatusCode,
							HeadersOriginal:   dbgRespHdrOrig,
							HeadersForwarded:  hdrFwd,
							BodyUpstreamText:  up.Text(),
							BodyUpstreamBytes: up.TotalBytes(),
							BodyUpstreamTrunc: up.Truncated(),
							BodyClientText:    down.Text(),
							BodyClientBytes:   down.TotalBytes(),
							BodyClientTrunc:   down.Truncated(),
						})
					},
				}
				resp.Body = downstream
			} else {
				resp.Body = stream.NewRestoringReader(resp.Body, rt.restoreEng)
			}
			resp.ContentLength = -1
			resp.Header.Del("Content-Length")
			return resp
		}

		// Fallback: some upstreams omit Content-Type even for text responses.
		// If the request had redactions, try restoring the response body anyway (only if it's not still encoded).
		if requestRedacted && (contentEncoding == "" || decompressed) {
			if auditID > 0 {
				s.admin.UpdateAudit(auditID, func(ev *admin.AuditEvent) { ev.RestoreApplied = true })
			}
			stats.RestoredRequests.Add(1)
			if dbgOn {
				up := newCaptureBuffer(dbgMaxBody)
				down := newCaptureBuffer(dbgMaxBody)
				upstream := &captureReadCloser{rc: resp.Body, w: up}
				restoring := stream.NewRestoringReader(upstream, rt.restoreEng)
				downstream := &captureReadCloser{
					rc: restoring,
					w:  down,
					onClose: func() {
						hdrFwd := resp.Header.Clone()
						if dbgMaskHeaders {
							hdrFwd = admin.MaskSensitiveHeaders(hdrFwd)
						}
						dbg.UpsertResponse(auditID, admin.DebugResponseCapture{
							ContentType:       contentType,
							Status:            resp.StatusCode,
							HeadersOriginal:   dbgRespHdrOrig,
							HeadersForwarded:  hdrFwd,
							BodyUpstreamText:  up.Text(),
							BodyUpstreamBytes: up.TotalBytes(),
							BodyUpstreamTrunc: up.Truncated(),
							BodyClientText:    down.Text(),
							BodyClientBytes:   down.TotalBytes(),
							BodyClientTrunc:   down.Truncated(),
						})
					},
				}
				resp.Body = downstream
			} else {
				resp.Body = stream.NewRestoringReader(resp.Body, rt.restoreEng)
			}
			resp.ContentLength = -1
			resp.Header.Del("Content-Length")
			return resp
		}

		return resp
	})

	// HTTPS CONNECT:
	// - intercept_mode=global: enable MITM for all hosts
	// - intercept_mode=targets: enable MITM only for hosts in targets
	s.proxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		if !s.shouldIntercept(host) {
			slog.Debug("HTTPS tunnel pass-through", "host", host)
			return goproxy.OkConnect, host
		}

		slog.Debug("MITM for HTTPS", "host", host)

		caCert, err := s.ca.GetTLSCertificate()
		if err != nil {
			slog.Error("Failed to get CA certificate", "error", err)
			return goproxy.RejectConnect, host
		}

		return &goproxy.ConnectAction{
			Action:    goproxy.ConnectMitm,
			TLSConfig: goproxy.TLSConfigFromCA(&caCert),
		}, host
	}))
}

// isTextContent checks if content type is text-like
func isTextContent(contentType string) bool {
	textTypes := []string{
		"application/json",
		"text/",
		"application/x-www-form-urlencoded",
	}
	for _, t := range textTypes {
		if strings.Contains(contentType, t) {
			return true
		}
	}
	return false
}

func isJSONContentType(contentType string) bool {
	if strings.TrimSpace(contentType) == "" {
		return false
	}
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mt = contentType
	}
	mt = strings.ToLower(strings.TrimSpace(mt))
	if mt == "" {
		return false
	}
	if mt == "application/json" || mt == "text/json" {
		return true
	}
	if strings.HasSuffix(mt, "+json") {
		return true
	}
	// Some uncommon vendors use types like application/x-ndjson or application/json-seq.
	return strings.Contains(mt, "json")
}

func isTextMediaType(contentType string) bool {
	if strings.TrimSpace(contentType) == "" {
		return false
	}
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mt = contentType
	}
	mt = strings.ToLower(strings.TrimSpace(mt))
	return strings.HasPrefix(mt, "text/")
}

func normalizeInterceptMode(mode string) string {
	m := strings.ToLower(strings.TrimSpace(mode))
	if m == "" {
		return defaultProxyInterceptMode
	}
	switch m {
	case "global", "targets":
		return m
	default:
		return defaultProxyInterceptMode
	}
}

func looksLikeSSEPrefix(prefix []byte) bool {
	// SSE (Server-Sent Events) usually starts with fields like "data:" / "event:".
	// Some upstreams/gateways may omit Content-Type, so we do a lightweight sniff via body prefix.
	b := bytes.TrimLeft(prefix, "\r\n\t ")
	if len(b) == 0 {
		return false
	}
	return bytes.HasPrefix(b, []byte("data:")) ||
		bytes.HasPrefix(b, []byte("event:")) ||
		bytes.HasPrefix(b, []byte("id:")) ||
		bytes.HasPrefix(b, []byte("retry:")) ||
		bytes.HasPrefix(b, []byte(":"))
}

func (s *Server) applyConfig(c config.Config) {
	// Session placeholder key mode:
	// - default: process-random key (stable only within the process)
	// - deterministic_placeholders: derive key from CA (stable across processes)
	if c.Session.DeterministicPlaceholders {
		if key, err := s.ca.DerivePlaceholderKey(); err != nil {
			slog.Warn("Failed to derive deterministic placeholder key; falling back to random placeholders", "error", err)
			_ = s.session.SetDeterministicPlaceholders(false, nil)
		} else if err := s.session.SetDeterministicPlaceholders(true, key); err != nil {
			slog.Warn("Failed to enable deterministic placeholders; falling back to random placeholders", "error", err)
			_ = s.session.SetDeterministicPlaceholders(false, nil)
		}
	} else {
		_ = s.session.SetDeterministicPlaceholders(false, nil)
	}

	prefix := strings.TrimSpace(c.Proxy.PlaceholderPrefix)
	if prefix == "" {
		prefix = defaultPlaceholderPrefix
	}

	var (
		kws     []keywords.Keyword
		exclude []string
	)
	for _, kw := range c.Patterns.Keywords {
		val := config.SanitizePatternValue(kw.Value)
		if val == "" {
			continue
		}
		cat := config.SanitizeCategory(kw.Category)
		if cat == "" {
			cat = "TEXT"
		}
		kws = append(kws, keywords.Keyword{Text: val, Category: cat})
	}
	for _, ex := range c.Patterns.Exclude {
		ex = config.SanitizePatternValue(ex)
		if ex == "" {
			continue
		}
		exclude = append(exclude, ex)
	}

	if len(c.Patterns.SecretFiles) > 0 {
		extra, warns := secretsources.LoadKeywords(c.Patterns.SecretFiles)
		for _, w := range warns {
			slog.Warn("Secret file source warning", "error", w)
		}
		if len(extra) > 0 {
			seen := make(map[string]struct{}, len(kws)+len(extra))
			for _, kw := range kws {
				if kw.Text == "" {
					continue
				}
				seen[kw.Text] = struct{}{}
			}
			for _, kw := range extra {
				if kw.Text == "" {
					continue
				}
				if _, ok := seen[kw.Text]; ok {
					continue
				}
				seen[kw.Text] = struct{}{}
				kws = append(kws, kw)
			}
		}
	}

	// The admin UI does not edit regex/builtin directly: use rule lists (.vgrules) for reusable regex/keyword rules.
	// If the user still configured regex/builtin in config, warn and ignore them here
	// to avoid "over-broad regexes corrupting the whole text".
	if len(c.Patterns.Regex) > 0 || len(c.Patterns.Builtin) > 0 {
		slog.Warn("Ignoring regex/builtin patterns; use rule lists for reusable regex/keywords",
			"regex", len(c.Patterns.Regex),
			"builtin", len(c.Patterns.Builtin),
		)
	}

	var ruleRecs []piirec.Recognizer
	for _, rl := range c.Patterns.RuleLists {
		if !rl.Enabled {
			continue
		}
		path := ""
		if strings.TrimSpace(rl.URL) != "" {
			if p, ok := rulelists.SubscriptionRulesPath(rl); ok {
				path = p
			}
		} else {
			path = resolveRuleListPath(rl.Path)
		}
		if strings.TrimSpace(path) == "" {
			continue
		}
		name := strings.TrimSpace(rl.Name)
		if name == "" {
			name = strings.TrimSpace(rl.ID)
		}
		if name == "" {
			name = filepath.Base(path)
		}
		if _, err := os.Stat(path); err != nil {
			if strings.TrimSpace(rl.URL) != "" {
				slog.Warn("Rule list subscription not available yet; continuing without it", "url", rl.URL)
			} else {
				slog.Warn("Rule list file not found; continuing without it", "path", rl.Path)
			}
			continue
		}
		rec, err := rulelist.ParseFile(path, rulelist.ParseOptions{
			Name:     name,
			Priority: rl.Priority,
		})
		if err != nil {
			if strings.TrimSpace(rl.URL) != "" {
				slog.Warn("Failed to load rule list subscription; continuing without it", "error", err, "url", rl.URL)
			} else {
				slog.Warn("Failed to load rule list; continuing without it", "error", err, "path", rl.Path)
			}
			continue
		}
		ruleRecs = append(ruleRecs, rec)
	}

	var redactor redact.Redactor
	if len(ruleRecs) > 0 || c.Patterns.NER.Enabled {
		var merged []piirec.Recognizer
		// Keywords: merge into one recognizer to avoid duplicate scans.
		if len(kws) > 0 {
			merged = append(merged, keywords.New(kws))
		}

		merged = append(merged, ruleRecs...)

		if c.Patterns.NER.Enabled {
			rec, err := ner.New(ner.Options{
				PresidioURL: c.Patterns.NER.PresidioURL,
				Language:    c.Patterns.NER.Language,
				Entities:    c.Patterns.NER.Entities,
				MinScore:    c.Patterns.NER.MinScore,
			})
			if err != nil {
				slog.Warn("Failed to init NER recognizer; continuing without NER", "error", err)
			} else if rec != nil {
				merged = append(merged, rec)
			}
		}

		p := pipeline.New(s.session, prefix, merged...)
		p.SetExclude(exclude)
		redactor = p
	} else {
		redactEng := redact.NewEngine(s.session, prefix)
		for _, kw := range kws {
			redactEng.AddKeyword(kw.Text, kw.Category)
		}
		for _, ex := range exclude {
			redactEng.AddExclude(ex)
		}
		redactor = redactEng
	}

	targets := make(map[string]bool)
	for _, t := range c.Targets {
		if t.Enabled {
			targets[canonicalHost(t.Host)] = true
		}
	}

	interceptMode := normalizeInterceptMode(c.Proxy.InterceptMode)
	rawMode := strings.ToLower(strings.TrimSpace(c.Proxy.InterceptMode))
	if rawMode != "" && rawMode != "global" && rawMode != "targets" {
		slog.Warn("Invalid proxy intercept_mode, defaulting to global", "intercept_mode", c.Proxy.InterceptMode)
	}

	s.runtime.Store(runtimeConfig{
		interceptMode:          interceptMode,
		targets:                targets,
		redactEng:              redactor,
		restoreEng:             restore.NewEngine(s.session, prefix),
		websocketRedactionBeta: c.Proxy.WebSocketRedactionBeta,
	})
}

// ReloadFromConfig reloads configuration without restarting the proxy (mainly for rules/targets changes).
// Note: it does not hot-update listen address, session TTL, or other parameters that require rebuilding components.
func (s *Server) ReloadFromConfig() {
	c := s.config.Get()
	if strings.TrimSpace(c.Proxy.Listen) != "" && strings.TrimSpace(c.Proxy.Listen) != strings.TrimSpace(s.listenAddr) {
		slog.Warn("Config reloaded but listen address cannot be hot-updated; restart required",
			"current", s.listenAddr, "configured", c.Proxy.Listen)
	}

	s.applyConfig(c)
	rt := s.runtimeSnapshot()
	slog.Info("Config reloaded",
		"intercept_mode", rt.interceptMode,
		"targets", len(rt.targets),
		"websocket_redaction_beta", rt.websocketRedactionBeta,
		"deterministic_placeholders", c.Session.DeterministicPlaceholders,
		"keywords", len(c.Patterns.Keywords),
		"secret_files", len(c.Patterns.SecretFiles),
		"rule_lists", len(c.Patterns.RuleLists),
		"ner_enabled", c.Patterns.NER.Enabled,
		"exclude", len(c.Patterns.Exclude),
	)
}

// decompressBody decompresses response body based on Content-Encoding
func decompressBody(body io.ReadCloser, encoding string) (io.ReadCloser, bool) {
	encodings := parseContentEncodings(encoding)
	if len(encodings) == 0 {
		return body, false
	}

	r := io.Reader(body)
	closers := []io.Closer{body}

	// Decode in reverse order.
	for i := len(encodings) - 1; i >= 0; i-- {
		enc := encodings[i]
		switch enc {
		case "", "identity":
			continue
		case "gzip":
			gr, err := gzip.NewReader(r)
			if err != nil {
				return body, false
			}
			r = gr
			closers = append(closers, gr)
		case "br", "brotli":
			r = brotli.NewReader(r)
		case "deflate":
			zr, err := zlib.NewReader(r)
			if err == nil {
				r = zr
				closers = append(closers, zr)
			} else {
				fr := flate.NewReader(r)
				r = fr
				closers = append(closers, fr)
			}
		case "zstd":
			r = zstd.NewReader(r)
		default:
			return body, false
		}
	}

	return &readerWithClose{
		r: r,
		c: multiCloser(closers),
	}, true
}

func decompressBytes(raw []byte, encoding string, limit int) ([]byte, error) {
	encodings := parseContentEncodings(encoding)
	if len(encodings) == 0 {
		return raw, nil
	}

	out := raw
	// Content-Encoding applies in order; to decode we must reverse the list.
	for i := len(encodings) - 1; i >= 0; i-- {
		enc := encodings[i]
		if enc == "" || enc == "identity" {
			continue
		}

		var (
			reader io.Reader
			closer io.Closer
		)
		switch enc {
		case "gzip":
			gr, err := gzip.NewReader(bytes.NewReader(out))
			if err != nil {
				return nil, err
			}
			reader = gr
			closer = gr
		case "br", "brotli":
			reader = brotli.NewReader(bytes.NewReader(out))
		case "deflate":
			// HTTP "deflate" is historically ambiguous: try zlib wrapper first, then raw DEFLATE.
			zr, err := zlib.NewReader(bytes.NewReader(out))
			if err == nil {
				reader = zr
				closer = zr
			} else {
				fr := flate.NewReader(bytes.NewReader(out))
				reader = fr
				closer = fr
			}
		case "zstd":
			reader = zstd.NewReader(bytes.NewReader(out))
		default:
			return nil, fmt.Errorf("%w: %s", errUnsupportedContentEncoding, enc)
		}

		decoded, err := readAllLimited(reader, limit)
		if closer != nil {
			_ = closer.Close()
		}
		if err != nil {
			return nil, err
		}
		out = decoded
	}

	return out, nil
}

func readAllLimited(r io.Reader, limit int) ([]byte, error) {
	limited := io.LimitReader(r, int64(limit)+1)
	out, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(out) > limit {
		return nil, fmt.Errorf("decompressed body too large")
	}
	return out, nil
}

func isSupportedContentEncodingHeader(headerVal string) bool {
	for _, enc := range parseContentEncodings(headerVal) {
		switch enc {
		case "", "identity", "gzip", "br", "brotli", "deflate", "zstd":
			continue
		default:
			return false
		}
	}
	return true
}

func parseContentEncodings(headerVal string) []string {
	if strings.TrimSpace(headerVal) == "" {
		return nil
	}
	parts := strings.Split(headerVal, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		e := strings.ToLower(strings.TrimSpace(p))
		if e == "" {
			continue
		}
		if semi := strings.IndexByte(e, ';'); semi >= 0 {
			e = strings.TrimSpace(e[:semi])
		}
		if e == "" {
			continue
		}
		out = append(out, e)
	}
	return out
}

func resolveSessionWALPath(path string) string {
	p := strings.TrimSpace(path)
	if p == "" {
		return filepath.Join(config.GetConfigDir(), "session.wal")
	}
	if p == "~" {
		if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
			return home
		}
		return p
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "~"+string(os.PathSeparator)) {
		if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

func resolveRuleListPath(path string) string {
	p := strings.TrimSpace(path)
	if p == "" {
		return p
	}
	if p == "~" {
		if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
			return home
		}
		return p
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "~"+string(os.PathSeparator)) {
		if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

type readerWithClose struct {
	r io.Reader
	c io.Closer
}

func (rc *readerWithClose) Read(p []byte) (int, error) { return rc.r.Read(p) }
func (rc *readerWithClose) Close() error {
	if rc.c == nil {
		return nil
	}
	return rc.c.Close()
}

type multiCloser []io.Closer

func (mc multiCloser) Close() error {
	var firstErr error
	for _, c := range mc {
		if c == nil {
			continue
		}
		if err := c.Close(); firstErr == nil && err != nil {
			firstErr = err
		}
	}
	return firstErr
}
