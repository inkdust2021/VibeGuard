package admin

import (
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/inkdust2021/vibeguard/internal/auditdb"
	"github.com/inkdust2021/vibeguard/internal/cert"
	"github.com/inkdust2021/vibeguard/internal/config"
	vlog "github.com/inkdust2021/vibeguard/internal/log"
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
	auditDB  *auditdb.Store
	stopPurge func()
	debug    *DebugStore
	auth     *AuthManager
}

// New creates a new Admin handler
func New(cfg *config.Manager, sess *session.Manager, ca *cert.CA, certPath, keyPath string) *Admin {
	auth := NewAuthManager(defaultAuthFilePath())
	a := &Admin{
		config:   cfg,
		session:  sess,
		ca:       ca,
		certPath: certPath,
		keyPath:  keyPath,
		stats:    &StatsCollector{},
		audit:    NewAuditStore(200),
		debug:    NewDebugStore(50),
		auth:     auth,
	}
	a.started.Store(0)

	// Audit persistence (SQLite) is disabled by default; it is only effective in the "full" build when enabled in config.
	c := cfg.Get()
	if c.AuditDB.Enabled {
		a.openAuditDB(c.AuditDB)
	}

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

// StartedTime returns the Unix timestamp when the proxy started
func (a *Admin) StartedTime() int64 {
	if a == nil {
		return 0
	}
	return a.started.Load()
}

// RecordAudit records one audit event about whether redaction rules were hit.
func (a *Admin) RecordAudit(ev AuditEvent) AuditEvent {
	if a == nil || a.audit == nil {
		return ev
	}
	saved := a.audit.Add(ev)

	// Optional: persist to disk (full build + enabled in config).
	if a.auditDB != nil {
		if _, err := a.auditDB.Add(adminToDBEvent(saved)); err != nil {
			slog.Warn("auditdb: write failed", "error", err)
		}
	}

	return saved
}

// UpdateAudit updates a previously recorded audit event (e.g. to fill response status fields).
func (a *Admin) UpdateAudit(id int64, fn func(*AuditEvent)) (AuditEvent, bool) {
	if a == nil || a.audit == nil {
		return AuditEvent{}, false
	}
	ev, ok := a.audit.Update(id, fn)
	if ok && a.auditDB != nil {
		_ = a.auditDB.Update(id, func(dbEv *auditdb.AuditEvent) {
			dbEv.ResponseStatus = ev.ResponseStatus
			dbEv.ResponseContentType = ev.ResponseContentType
			dbEv.RestoreApplied = ev.RestoreApplied
			dbEv.RestoredCount = ev.RestoredCount
			dbEv.Attempted = ev.Attempted
			dbEv.RedactedCount = ev.RedactedCount
			dbEv.Matches = append([]auditdb.AuditMatch(nil), adminToDBMatches(ev.Matches)...)
			dbEv.Note = ev.Note
		})
	}
	return ev, ok
}

// Debug returns the debug capture store (in-memory only; not persisted).
func (a *Admin) Debug() *DebugStore {
	if a == nil {
		return nil
	}
	return a.debug
}

// Close releases resources held by the admin component (currently only the audit DB).
func (a *Admin) Close() {
	if a == nil {
		return
	}
	a.closeAuditDB()
}

func (a *Admin) openAuditDB(cfg config.AuditDBConfig) {
	if a == nil {
		return
	}
	if a.auditDB != nil {
		return
	}
	if !auditdb.Available {
		slog.Warn("AuditDB enabled in config but not available in this build (lite); ignoring")
		return
	}

	path := vlog.ExpandPath(cfg.Path)
	db, err := auditdb.Open(path)
	if err != nil {
		slog.Error("Failed to open audit database", "path", path, "error", err)
		return
	}
	a.auditDB = db

	// Advance in-memory audit IDs to the persisted max ID to avoid conflicts after restarts/toggles.
	if a.audit != nil {
		if maxID, err := db.MaxID(); err == nil {
			a.audit.BumpNextID(maxID)
		}
	}

	retention := parseDuration(cfg.Retention, 7*24*time.Hour)
	a.stopPurge = db.StartPurgeLoop(retention, 1*time.Hour)
	slog.Info("Audit database enabled", "path", path, "retention", retention)
}

func (a *Admin) closeAuditDB() {
	if a.stopPurge != nil {
		a.stopPurge()
		a.stopPurge = nil
	}
	if a.auditDB != nil {
		_ = a.auditDB.Close()
		a.auditDB = nil
	}
}

func parseDuration(s string, fallback time.Duration) time.Duration {
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback
	}
	// Support "7d" style day durations.
	if len(s) > 1 && s[len(s)-1] == 'd' {
		if days, err := time.ParseDuration(s[:len(s)-1] + "h"); err == nil {
			return days * 24
		}
	}
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	return fallback
}

func adminToDBEvent(ev AuditEvent) auditdb.AuditEvent {
	return auditdb.AuditEvent{
		ID:                  ev.ID,
		Time:                ev.Time,
		Host:                ev.Host,
		Method:              ev.Method,
		Path:                ev.Path,
		ContentType:         ev.ContentType,
		ContentEncoding:     ev.ContentEncoding,
		Attempted:           ev.Attempted,
		RedactedCount:       ev.RedactedCount,
		Matches:             append([]auditdb.AuditMatch(nil), adminToDBMatches(ev.Matches)...),
		Note:                ev.Note,
		ResponseStatus:      ev.ResponseStatus,
		ResponseContentType: ev.ResponseContentType,
		RestoreApplied:      ev.RestoreApplied,
		RestoredCount:       ev.RestoredCount,
	}
}

func adminToDBMatches(in []AuditMatch) []auditdb.AuditMatch {
	if len(in) == 0 {
		return nil
	}
	out := make([]auditdb.AuditMatch, len(in))
	for i := range in {
		out[i] = auditdb.AuditMatch{
			Category:    in[i].Category,
			Placeholder: in[i].Placeholder,
			Value:       in[i].Value,
			IsPreview:   in[i].IsPreview,
			Length:      in[i].Length,
			Truncated:   in[i].Truncated,
		}
	}
	return out
}
