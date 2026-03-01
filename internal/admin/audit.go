package admin

import (
	"sync"
	"time"
)

// AuditMatch 表示一次请求中命中的敏感片段（用于管理端展示）。
type AuditMatch struct {
	Category    string `json:"category"`
	Placeholder string `json:"placeholder"`
	// Value 是“可展示值”：当启用隐私模式时为预览（打码/截断），否则为原文（同样会截断）。
	Value string `json:"value"`
	// IsPreview 表示 Value 是否为预览（隐私模式下为 true）。
	IsPreview bool `json:"is_preview"`
	// Length 表示命中原文长度（未截断前的长度），便于判断是否命中预期内容。
	Length int `json:"length"`
	// Truncated 表示是否因过长而被截断。
	Truncated bool `json:"truncated"`
}

// AuditEvent 表示一次代理请求的审计记录（用于“是否命中脱敏规则”的可视化判断）。
type AuditEvent struct {
	ID int64 `json:"id"`
	// Time 为服务器时间（RFC3339），用于排序与排查。
	Time time.Time `json:"time"`

	Host        string `json:"host"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	ContentType string `json:"content_type"`
	// ContentEncoding 为请求体的 Content-Encoding（空表示未压缩/未知）。
	ContentEncoding string `json:"content_encoding,omitempty"`

	// Attempted 表示本次请求是否进入“可脱敏文本内容”的扫描流程。
	Attempted bool `json:"attempted"`
	// RedactedCount 表示命中并替换的次数（matches 可能会被截断显示，但 count 为真实次数）。
	RedactedCount int          `json:"redacted_count"`
	Matches       []AuditMatch `json:"matches"`

	// Note 用于解释未扫描/跳过原因（例如：no_body / not_text / too_large / read_error）。
	Note string `json:"note,omitempty"`

	// ResponseStatus 为上游响应状态码（若无响应则为 0）。
	ResponseStatus int `json:"response_status,omitempty"`
	// ResponseContentType 为上游响应的 Content-Type（空表示未知/无响应）。
	ResponseContentType string `json:"response_content_type,omitempty"`
	// RestoreApplied 表示响应侧是否尝试过占位符还原（仅对 JSON/SSE 等文本响应）。
	RestoreApplied bool `json:"restore_applied,omitempty"`
	// RestoredCount 表示响应中还原的占位符数量（粗略统计：匹配到的占位符个数）。
	RestoredCount int `json:"restored_count,omitempty"`
}

type AuditStore struct {
	mu     sync.RWMutex
	max    int
	nextID int64
	events []AuditEvent

	subNext int
	subs    map[int]chan AuditEvent
}

func NewAuditStore(max int) *AuditStore {
	if max <= 0 {
		max = 200
	}
	return &AuditStore{
		max:  max,
		subs: make(map[int]chan AuditEvent),
	}
}

func (s *AuditStore) Add(ev AuditEvent) AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.nextID++
	ev.ID = s.nextID
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}

	s.events = append(s.events, ev)
	if len(s.events) > s.max {
		// 丢弃最旧的记录
		s.events = append([]AuditEvent(nil), s.events[len(s.events)-s.max:]...)
	}

	for _, ch := range s.subs {
		select {
		case ch <- ev:
		default:
			// 慢客户端：丢弃以避免阻塞代理线程
		}
	}

	return ev
}

// Update finds an event by ID and mutates it in-place.
// If updated, the updated event will be broadcast to subscribers (as an "audit_event" again),
// allowing the UI to merge by ID.
func (s *AuditStore) Update(id int64, fn func(*AuditEvent)) (AuditEvent, bool) {
	if id <= 0 || fn == nil {
		return AuditEvent{}, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.events {
		if s.events[i].ID != id {
			continue
		}
		fn(&s.events[i])
		updated := s.events[i]

		for _, ch := range s.subs {
			select {
			case ch <- updated:
			default:
			}
		}

		return updated, true
	}
	return AuditEvent{}, false
}

func (s *AuditStore) List(limit int) []AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > len(s.events) {
		limit = len(s.events)
	}
	if limit == 0 {
		return nil
	}
	out := make([]AuditEvent, limit)
	copy(out, s.events[len(s.events)-limit:])
	return out
}

func (s *AuditStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = nil
}

func (s *AuditStore) Subscribe(buf int) (ch <-chan AuditEvent, cancel func()) {
	if buf <= 0 {
		buf = 32
	}
	c := make(chan AuditEvent, buf)

	s.mu.Lock()
	id := s.subNext
	s.subNext++
	s.subs[id] = c
	s.mu.Unlock()

	return c, func() {
		s.mu.Lock()
		if ch2, ok := s.subs[id]; ok {
			delete(s.subs, id)
			close(ch2)
		}
		s.mu.Unlock()
	}
}
