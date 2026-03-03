package admin

import (
	"net/http"
	"net/textproto"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DebugStore 用于“抓包调试”：保存完整请求/响应（含前后对比）。
//
// 重要安全约束：
// - 仅保存在内存中，不落盘
// - 默认关闭，需在管理面板中显式开启
// - 仅用于本机调试；仍会对敏感 header 做打码（可配置关闭）
type DebugStore struct {
	mu sync.RWMutex

	max    int
	order  []int64
	events map[int64]*DebugEvent

	enabled      atomic.Bool
	maxBodyBytes atomic.Int64
	maskHeaders  atomic.Bool
}

type DebugStatus struct {
	Enabled      bool `json:"enabled"`
	MaxBodyBytes int  `json:"max_body_bytes"`
	MaxEvents    int  `json:"max_events"`
	MaskHeaders  bool `json:"mask_headers"`
	Count        int  `json:"count"`
}

type DebugEventSummary struct {
	ID   int64     `json:"id"`
	Time time.Time `json:"time"`

	Host   string `json:"host"`
	Method string `json:"method"`
	Path   string `json:"path"`
	URL    string `json:"url,omitempty"`

	HasRequest  bool `json:"has_request"`
	HasResponse bool `json:"has_response"`

	RequestTruncated  bool `json:"request_truncated,omitempty"`
	ResponseTruncated bool `json:"response_truncated,omitempty"`

	ResponseStatus      int    `json:"response_status,omitempty"`
	ResponseContentType string `json:"response_content_type,omitempty"`
}

type DebugBody struct {
	Text      string `json:"text"`
	Bytes     int    `json:"bytes"`
	Truncated bool   `json:"truncated"`
}

type DebugHTTP struct {
	HeadersOriginal  http.Header `json:"headers_original,omitempty"`
	HeadersForwarded http.Header `json:"headers_forwarded,omitempty"`
	BodyOriginal     DebugBody   `json:"body_original,omitempty"`
	BodyForwarded    DebugBody   `json:"body_forwarded,omitempty"`
	ContentType      string      `json:"content_type,omitempty"`
	ContentEncoding  string      `json:"content_encoding,omitempty"`
	ResponseStatus   int         `json:"response_status,omitempty"`
}

type DebugEvent struct {
	ID   int64     `json:"id"`
	Time time.Time `json:"time"`

	Host   string `json:"host"`
	Method string `json:"method"`
	Path   string `json:"path"`
	URL    string `json:"url,omitempty"`

	Request  DebugHTTP `json:"request"`
	Response DebugHTTP `json:"response"`
}

func NewDebugStore(maxEvents int) *DebugStore {
	if maxEvents <= 0 {
		maxEvents = 50
	}
	s := &DebugStore{
		max:    maxEvents,
		events: make(map[int64]*DebugEvent),
	}
	s.enabled.Store(false)
	s.maxBodyBytes.Store(int64(1024 * 1024)) // 1MB
	s.maskHeaders.Store(true)
	return s
}

func (s *DebugStore) Status() DebugStatus {
	if s == nil {
		return DebugStatus{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return DebugStatus{
		Enabled:      s.enabled.Load(),
		MaxBodyBytes: int(s.maxBodyBytes.Load()),
		MaxEvents:    s.max,
		MaskHeaders:  s.maskHeaders.Load(),
		Count:        len(s.events),
	}
}

func (s *DebugStore) Enabled() bool {
	if s == nil {
		return false
	}
	return s.enabled.Load()
}

func (s *DebugStore) MaxBodyBytes() int {
	if s == nil {
		return 0
	}
	return int(s.maxBodyBytes.Load())
}

func (s *DebugStore) MaskHeaders() bool {
	if s == nil {
		return true
	}
	return s.maskHeaders.Load()
}

func (s *DebugStore) Update(enabled *bool, maxBodyBytes *int, maxEvents *int, maskHeaders *bool) DebugStatus {
	if s == nil {
		return DebugStatus{}
	}

	if enabled != nil {
		s.enabled.Store(*enabled)
	}
	if maskHeaders != nil {
		s.maskHeaders.Store(*maskHeaders)
	}
	if maxBodyBytes != nil {
		// 过小会导致“看不到关键信息”；过大容易撑爆内存。
		v := clampInt(*maxBodyBytes, 4*1024, 20*1024*1024) // 4KB ~ 20MB
		s.maxBodyBytes.Store(int64(v))
	}

	if maxEvents != nil {
		v := clampInt(*maxEvents, 1, 500)
		s.mu.Lock()
		s.max = v
		s.trimLocked()
		s.mu.Unlock()
	}

	return s.Status()
}

func (s *DebugStore) Clear() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.order = nil
	s.events = make(map[int64]*DebugEvent)
}

func (s *DebugStore) List(limit int) []DebugEventSummary {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > len(s.order) {
		limit = len(s.order)
	}
	if limit == 0 {
		return nil
	}

	ids := s.order[len(s.order)-limit:]
	out := make([]DebugEventSummary, 0, len(ids))
	for _, id := range ids {
		ev := s.events[id]
		if ev == nil {
			continue
		}
		sum := DebugEventSummary{
			ID:   ev.ID,
			Time: ev.Time,
			Host: ev.Host, Method: ev.Method, Path: ev.Path, URL: ev.URL,
			HasRequest:          len(ev.Request.BodyForwarded.Text) > 0 || len(ev.Request.HeadersForwarded) > 0 || ev.Request.ContentType != "" || ev.Request.ContentEncoding != "",
			HasResponse:         ev.Response.ResponseStatus != 0 || len(ev.Response.BodyForwarded.Text) > 0 || len(ev.Response.HeadersForwarded) > 0 || ev.Response.ContentType != "",
			RequestTruncated:    ev.Request.BodyOriginal.Truncated || ev.Request.BodyForwarded.Truncated,
			ResponseTruncated:   ev.Response.BodyOriginal.Truncated || ev.Response.BodyForwarded.Truncated,
			ResponseStatus:      ev.Response.ResponseStatus,
			ResponseContentType: ev.Response.ContentType,
		}
		out = append(out, sum)
	}
	return out
}

func (s *DebugStore) Get(id int64) (DebugEvent, bool) {
	if s == nil || id <= 0 {
		return DebugEvent{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	ev := s.events[id]
	if ev == nil {
		return DebugEvent{}, false
	}
	cp := *ev
	cp.Request.HeadersOriginal = cloneHeader(ev.Request.HeadersOriginal)
	cp.Request.HeadersForwarded = cloneHeader(ev.Request.HeadersForwarded)
	cp.Response.HeadersOriginal = cloneHeader(ev.Response.HeadersOriginal)
	cp.Response.HeadersForwarded = cloneHeader(ev.Response.HeadersForwarded)
	return cp, true
}

type DebugRequestCapture struct {
	Time   time.Time
	Host   string
	Method string
	Path   string
	URL    string

	ContentType     string
	ContentEncoding string

	HeadersOriginal  http.Header
	HeadersForwarded http.Header

	BodyOriginalText  string
	BodyOriginalBytes int
	BodyOriginalTrunc bool

	BodyForwardedText  string
	BodyForwardedBytes int
	BodyForwardedTrunc bool
}

func (s *DebugStore) UpsertRequest(id int64, c DebugRequestCapture) {
	if s == nil || id <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	ev := s.ensureLocked(id)
	if !c.Time.IsZero() {
		ev.Time = c.Time
	}
	if c.Host != "" {
		ev.Host = c.Host
	}
	if c.Method != "" {
		ev.Method = c.Method
	}
	if c.Path != "" {
		ev.Path = c.Path
	}
	if c.URL != "" {
		ev.URL = c.URL
	}

	ev.Request.ContentType = c.ContentType
	ev.Request.ContentEncoding = c.ContentEncoding
	ev.Request.HeadersOriginal = cloneHeader(c.HeadersOriginal)
	ev.Request.HeadersForwarded = cloneHeader(c.HeadersForwarded)
	ev.Request.BodyOriginal = DebugBody{Text: c.BodyOriginalText, Bytes: c.BodyOriginalBytes, Truncated: c.BodyOriginalTrunc}
	ev.Request.BodyForwarded = DebugBody{Text: c.BodyForwardedText, Bytes: c.BodyForwardedBytes, Truncated: c.BodyForwardedTrunc}
}

type DebugResponseCapture struct {
	ContentType string

	// status/code 写在 DebugHTTP 上（ResponseStatus），避免额外结构。
	Status int

	HeadersOriginal  http.Header
	HeadersForwarded http.Header

	BodyUpstreamText  string
	BodyUpstreamBytes int
	BodyUpstreamTrunc bool

	BodyClientText  string
	BodyClientBytes int
	BodyClientTrunc bool
}

func (s *DebugStore) UpsertResponse(id int64, c DebugResponseCapture) {
	if s == nil || id <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	ev := s.ensureLocked(id)
	ev.Response.ContentType = c.ContentType
	ev.Response.ResponseStatus = c.Status
	ev.Response.HeadersOriginal = cloneHeader(c.HeadersOriginal)
	ev.Response.HeadersForwarded = cloneHeader(c.HeadersForwarded)
	ev.Response.BodyOriginal = DebugBody{Text: c.BodyUpstreamText, Bytes: c.BodyUpstreamBytes, Truncated: c.BodyUpstreamTrunc}
	ev.Response.BodyForwarded = DebugBody{Text: c.BodyClientText, Bytes: c.BodyClientBytes, Truncated: c.BodyClientTrunc}
}

func (s *DebugStore) ensureLocked(id int64) *DebugEvent {
	if s.events == nil {
		s.events = make(map[int64]*DebugEvent)
	}
	if ev := s.events[id]; ev != nil {
		return ev
	}
	ev := &DebugEvent{ID: id}
	s.events[id] = ev
	s.order = append(s.order, id)
	s.trimLocked()
	return ev
}

func (s *DebugStore) trimLocked() {
	if s.max <= 0 {
		s.max = 50
	}
	if len(s.order) <= s.max {
		return
	}
	drop := len(s.order) - s.max
	toDrop := append([]int64(nil), s.order[:drop]...)
	s.order = append([]int64(nil), s.order[drop:]...)
	for _, id := range toDrop {
		delete(s.events, id)
	}
}

func cloneHeader(h http.Header) http.Header {
	if h == nil {
		return nil
	}
	return h.Clone()
}

// MaskSensitiveHeaders 会对常见敏感 header（如 Authorization/Cookie/API Key）做打码。
// 该函数用于调试抓包展示，避免把 token 等信息直接暴露在管理面板中。
func MaskSensitiveHeaders(h http.Header) http.Header {
	if h == nil {
		return nil
	}

	// 统一 canonical key，避免因大小写差异导致 Get()/展示不一致。
	// 同时也避免同一 header 因大小写不同而出现重复项。
	out := make(http.Header, len(h))
	for k, vs := range h {
		ck := textproto.CanonicalMIMEHeaderKey(k)
		if len(vs) == 0 {
			// 保持空值语义
			if _, ok := out[ck]; !ok {
				out[ck] = nil
			}
			continue
		}
		cp := make([]string, 0, len(vs))
		for _, v := range vs {
			cp = append(cp, v)
		}
		out[ck] = append(out[ck], cp...)
	}

	for k := range out {
		lk := strings.ToLower(strings.TrimSpace(k))
		if isSensitiveHeaderKey(lk) {
			vs := out.Values(k)
			if len(vs) == 0 {
				out.Del(k)
				continue
			}
			masked := make([]string, 0, len(vs))
			for _, v := range vs {
				masked = append(masked, maskHeaderValue(v))
			}
			out[k] = masked
		}
	}
	return out
}

func isSensitiveHeaderKey(lowerKey string) bool {
	switch lowerKey {
	case "authorization",
		"proxy-authorization",
		"cookie",
		"set-cookie",
		"x-api-key",
		"api-key",
		"x-goog-api-key",
		"openai-api-key",
		"x-openai-api-key",
		"anthropic-api-key",
		"x-anthropic-api-key":
		return true
	default:
		// 避免把所有 header 都过度打码：仅在 header 名称的“分段”（用 '-' 分隔）明确包含 token/secret 时才打码。
		// 例如：
		// - My-Token ✅
		// - X-Secret-Key ✅
		// - X-NotSecret ❌（不应误伤）
		parts := strings.Split(lowerKey, "-")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			switch p {
			case "token", "tokens", "secret", "secrets":
				return true
			}
		}
		return false
	}
}

func maskHeaderValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	parts := strings.SplitN(v, " ", 2)
	if len(parts) == 2 && len(parts[0]) > 0 && len(parts[0]) <= 16 {
		return parts[0] + " ***"
	}
	return "***"
}
