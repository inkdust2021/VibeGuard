package admin

import (
	"sync/atomic"

	"github.com/inkdust2021/vibeguard/internal/cert"
	"github.com/inkdust2021/vibeguard/internal/config"
	"github.com/inkdust2021/vibeguard/internal/session"
)

// StatsCollector tracks request statistics
type StatsCollector struct {
	TotalRequests    atomic.Int64
	RedactedRequests atomic.Int64
	RestoredRequests atomic.Int64
	Errors           atomic.Int64
}

// Admin handles the web UI HTTP endpoints
type Admin struct {
	config   *config.Manager
	session  *session.Manager
	ca       *cert.CA
	certPath string
	keyPath  string
	stats    *StatsCollector
	started  atomic.Int64 // Unix timestamp
	audit    *AuditStore
}

// New creates a new Admin handler
func New(cfg *config.Manager, sess *session.Manager, ca *cert.CA, certPath, keyPath string) *Admin {
	a := &Admin{
		config:   cfg,
		session:  sess,
		ca:       ca,
		certPath: certPath,
		keyPath:  keyPath,
		stats:    &StatsCollector{},
		audit:    NewAuditStore(200),
	}
	a.started.Store(0)
	return a
}

// GetStats returns the stats collector for external incrementing
func (a *Admin) GetStats() *StatsCollector {
	return a.stats
}

// SetStartTime records when the proxy started
func (a *Admin) SetStartTime(unix int64) {
	a.started.Store(unix)
}

// RecordAudit 记录一次“是否命中脱敏规则”的审计事件。
// 该记录仅保存在内存中，不落盘（避免敏感信息长期驻留）。
func (a *Admin) RecordAudit(ev AuditEvent) AuditEvent {
	if a == nil || a.audit == nil {
		return ev
	}
	return a.audit.Add(ev)
}

// UpdateAudit 更新一条已记录的审计事件（用于补充响应状态等信息）。
func (a *Admin) UpdateAudit(id int64, fn func(*AuditEvent)) (AuditEvent, bool) {
	if a == nil || a.audit == nil {
		return AuditEvent{}, false
	}
	return a.audit.Update(id, fn)
}
