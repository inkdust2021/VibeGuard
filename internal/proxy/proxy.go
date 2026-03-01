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
	"github.com/inkdust2021/vibeguard/internal/redact"
	"github.com/inkdust2021/vibeguard/internal/restore"
	"github.com/inkdust2021/vibeguard/internal/session"
	"github.com/inkdust2021/vibeguard/internal/stream"
	"github.com/inkdust2021/vibeguard/internal/zstd"
)

const (
	maxTextBodyBytes          = 10 * 1024 * 1024 // 10MB
	defaultPlaceholderPrefix  = "__VG_"
	defaultProxyInterceptMode = "global"
)

var errUnsupportedContentEncoding = errors.New("unsupported content-encoding")

type runtimeConfig struct {
	interceptMode string
	targets       map[string]bool
	redactEng     *redact.Engine
	restoreEng    *restore.Engine
}

// Server represents the MITM proxy server
type Server struct {
	proxy       *goproxy.ProxyHttpServer
	config      *config.Manager
	ca          *cert.CA
	session     *session.Manager
	listenAddr  string
	runtime     atomic.Value // runtimeConfig
	admin       *admin.Admin
	certPath    string
	keyPath     string
}

type auditCtx struct {
	id       int64
	redacted bool
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
		proxy:       proxy,
		config:      cfg,
		ca:          ca,
		session:     sess,
		listenAddr:  c.Proxy.Listen,
		admin:       adm,
		certPath:    certPath,
		keyPath:     keyPath,
	}
	server.applyConfig(c)

	// Set up handlers
	server.setupHandlers()

	return server, nil
}

// Start starts the proxy server
func (s *Server) Start() error {
	// Record start time
	s.admin.SetStartTime(time.Now().Unix())

	// 不能直接用 http.ServeMux 去处理 CONNECT（authority-form）请求：
	// CONNECT 的 request-target 形如 "host:port"，URL.Path 可能为空/不以 "/" 开头，
	// ServeMux 会返回 301 重定向，导致所有 HTTPS 代理流量失败（表现为客户端反复重连/断流）。
	// 因此这里用自定义路由：仅 /manager/ 走管理端，其余全部交给代理（包括 CONNECT）。
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
	s.session.Close()
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

func safeRequestPath(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	// 只展示 Path，避免把 query 中的敏感信息暴露到管理端。
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

func redactJSONBody(redactEng *redact.Engine, body []byte) (out []byte, matches []redact.Match, changed bool, err error) {
	// 仅在 body 为合法 JSON 时尝试结构化脱敏；否则由上层回退到“整段文本脱敏”逻辑。
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()

	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, nil, false, err
	}
	// 防御：拒绝 “合法 JSON + 额外尾随内容” 的情况，避免重编码后语义变化。
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, nil, false, fmt.Errorf("trailing JSON data")
	}

	redacted, matches, changed, err := redactJSONValue(redactEng, v)
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

func redactJSONValue(redactEng *redact.Engine, v any) (out any, matches []redact.Match, changed bool, err error) {
	switch vv := v.(type) {
	case string:
		escaped, err := jsonEscapeStringValue(vv)
		if err != nil {
			return v, nil, false, err
		}

		redactedEscaped, ms := redactEng.RedactWithMatches([]byte(escaped))
		if len(ms) == 0 {
			return v, nil, false, nil
		}

		// 用 RawMessage 直接注入“已转义后的 JSON 字符串”，避免二次转义与结构破坏。
		raw := make(json.RawMessage, 0, len(redactedEscaped)+2)
		raw = append(raw, '"')
		raw = append(raw, redactedEscaped...)
		raw = append(raw, '"')
		if !json.Valid(raw) {
			// 极端情况：用户配置的正则/关键词可能命中并破坏转义序列，导致无效 JSON 字符串。
			// 为避免把无效 JSON 转发到上游，这里回退为“不改写该字段”。
			return v, nil, false, nil
		}

		return raw, ms, true, nil

	case []any:
		anyChanged := false
		var all []redact.Match
		for i := range vv {
			nv, ms, ch, err := redactJSONValue(redactEng, vv[i])
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
			nv, ms, ch, err := redactJSONValue(redactEng, val)
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
		recordAudit := func() {
			saved := s.admin.RecordAudit(auditEv)
			if ctx != nil {
				ctx.UserData = auditCtx{
					id:       saved.ID,
					redacted: auditEv.RedactedCount > 0,
				}
			}
		}
		if !s.shouldIntercept(host) {
			auditEv.Attempted = false
			auditEv.Note = "pass_through"
			recordAudit()
			return req, nil // Pass through
		}

		slog.Debug("Intercepting request", "host", host, "method", req.Method, "path", req.URL.Path)

		// Set Accept-Encoding: identity to prevent compression
		req.Header.Set("Accept-Encoding", "identity")

		// Handle request body redaction
		if req.Body != nil && req.Body != http.NoBody && isTextContent(contentType) {
			auditEv.Attempted = true
			contentEncodingHeader := req.Header.Get("Content-Encoding")
			if !isSupportedContentEncodingHeader(contentEncodingHeader) {
				// 未知/不支持的压缩：不做脱敏，避免在二进制数据上误命中并破坏请求。
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
				// 尽量把已经读取的内容放回去，避免破坏请求转发。
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
				// 体积超限：不做脱敏，但需要把已读取的前缀放回去继续转发。
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
			// 若请求体带压缩编码，先解压后再做脱敏，并把请求改为“无压缩”转发（移除 Content-Encoding）。
			if strings.TrimSpace(contentEncodingHeader) != "" {
				decoded, derr := decompressBytes(rawBody, contentEncodingHeader, maxTextBodyBytes)
				if derr != nil {
					// 解压失败：转发原始压缩体，避免中断业务请求。
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

			// 额外防御：非 UTF-8 文本不做脱敏，避免误伤二进制/乱码体。
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
			// 兼容兜底：若走了“整段文本脱敏”且把合法 JSON 改坏了，则回退发送原始 body，避免上游解析失败。
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
		} else {
			if req.Body == nil || req.Body == http.NoBody {
				auditEv.Attempted = false
				auditEv.Note = "no_body"
			} else if !isTextContent(contentType) {
				auditEv.Attempted = false
				auditEv.Note = "not_text"
			}
			recordAudit()
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
		if auditID > 0 {
			s.admin.UpdateAudit(auditID, func(ev *admin.AuditEvent) {
				ev.ResponseStatus = resp.StatusCode
				ev.ResponseContentType = contentType
			})
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
			// 有些上游会漏掉 Content-Type，但 body 实际仍是 SSE；这会导致无法跨 delta event 还原占位符。
			// 这里在不泄露内容的前提下做轻量嗅探：只 peek 少量前缀，且不改变下游读取的数据。
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
			resp.Body = stream.NewSSERestoringReader(resp.Body, rt.restoreEng)
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

			// 流式 JSON（常见于某些兼容网关/代理）：Content-Length 可能为 -1。
			// 若在这里 ReadAll 再还原，会导致下游“长时间无输出”（表现为 CLI 卡住）。
			// 因此当长度未知时，改为流式还原（跨 chunk 边界支持占位符拼接）。
			if resp.ContentLength < 0 {
				if auditID > 0 {
					s.admin.UpdateAudit(auditID, func(ev *admin.AuditEvent) { ev.RestoreApplied = true })
				}
				stats.RestoredRequests.Add(1)
				resp.Body = stream.NewRestoringReader(resp.Body, rt.restoreEng)
				resp.ContentLength = -1
				resp.Header.Del("Content-Length")
				return resp
			}

			originalBody := resp.Body
			limited := io.LimitReader(originalBody, int64(maxTextBodyBytes)+1)
			body, err := io.ReadAll(limited)
			if err != nil {
				// 尽量把已经读取的内容放回去，避免破坏响应转发。
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
			return resp
		}

		// Handle other text responses (plain text / markdown / html, etc.)
		if isTextMediaType(contentType) {
			if auditID > 0 {
				s.admin.UpdateAudit(auditID, func(ev *admin.AuditEvent) { ev.RestoreApplied = true })
			}
			stats.RestoredRequests.Add(1)
			resp.Body = stream.NewRestoringReader(resp.Body, rt.restoreEng)
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
			resp.Body = stream.NewRestoringReader(resp.Body, rt.restoreEng)
			resp.ContentLength = -1
			resp.Header.Del("Content-Length")
			return resp
		}

		return resp
	})

	// HTTPS CONNECT:
	// - intercept_mode=global：对所有域名启用 MITM
	// - intercept_mode=targets：仅对 targets 中启用的域名启用 MITM
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
	// SSE（Server-Sent Events）通常以 "data:" / "event:" 等字段开头。
	// 一些上游/网关可能遗漏 Content-Type，此时可通过 body 前缀进行轻量嗅探。
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
	prefix := strings.TrimSpace(c.Proxy.PlaceholderPrefix)
	if prefix == "" {
		prefix = defaultPlaceholderPrefix
	}

	redactEng := redact.NewEngine(s.session, prefix)
	for _, kw := range c.Patterns.Keywords {
		val := config.SanitizePatternValue(kw.Value)
		if val == "" {
			continue
		}
		cat := config.SanitizeCategory(kw.Category)
		if cat == "" {
			cat = "TEXT"
		}
		redactEng.AddKeyword(val, cat)
	}
	for _, ex := range c.Patterns.Exclude {
		ex = config.SanitizePatternValue(ex)
		if ex == "" {
			continue
		}
		redactEng.AddExclude(ex)
	}

	// 当前版本管理页仅支持关键词匹配；若用户配置了 regex/builtin，提示但不启用，
	// 避免“过宽正则误伤整段文本”的情况。
	if len(c.Patterns.Regex) > 0 || len(c.Patterns.Builtin) > 0 {
		slog.Warn("Ignoring regex/builtin patterns; only keywords are enabled",
			"regex", len(c.Patterns.Regex),
			"builtin", len(c.Patterns.Builtin),
		)
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
		interceptMode: interceptMode,
		targets:       targets,
		redactEng:     redactEng,
		restoreEng:    restore.NewEngine(s.session, prefix),
	})
}

// ReloadFromConfig 在不重启代理的情况下重载配置（主要用于匹配规则/目标域名变更）。
// 注意：不会热更新 listen 地址、Session TTL 等需要重建组件的参数。
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
		"keywords", len(c.Patterns.Keywords),
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
