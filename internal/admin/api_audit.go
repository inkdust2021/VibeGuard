package admin

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/inkdust2021/vibeguard/internal/config"
)

type AuditResponse struct {
	RedactLog bool         `json:"redact_log"`
	MaxEvents int          `json:"max_events"`
	Events    []AuditEvent `json:"events"`
}

// handleAudit handles GET/DELETE /manager/api/audit
func (a *Admin) handleAudit(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.getAudit(w, r)
	case http.MethodDelete:
		a.clearAudit(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *Admin) getAudit(w http.ResponseWriter, r *http.Request) {
	if a == nil || a.audit == nil {
		http.Error(w, "Audit store not available", http.StatusInternalServerError)
		return
	}

	limit := clampInt(queryInt(r, "limit", 200), 1, 500)
	cfg := a.config.Get()

	resp := AuditResponse{
		RedactLog: cfg.Log.RedactLog,
		MaxEvents: a.audit.max,
		Events:    a.audit.List(limit),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

func (a *Admin) clearAudit(w http.ResponseWriter, r *http.Request) {
	if a == nil || a.audit == nil {
		http.Error(w, "Audit store not available", http.StatusInternalServerError)
		return
	}
	a.audit.Clear()
	w.WriteHeader(http.StatusNoContent)
}

// handleAuditPrivacy handles POST /manager/api/audit/privacy
// 用于在管理页切换“隐私模式”（是否在审计面板展示原文）。
func (a *Admin) handleAuditPrivacy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a == nil || a.config == nil {
		http.Error(w, "Config manager not available", http.StatusInternalServerError)
		return
	}

	var req struct {
		RedactLog *bool `json:"redact_log"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.RedactLog == nil {
		http.Error(w, "redact_log is required", http.StatusBadRequest)
		return
	}

	if err := a.config.Update(func(c *config.Config) {
		c.Log.RedactLog = *req.RedactLog
	}); err != nil {
		http.Error(w, "Failed to save: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":     "ok",
		"redact_log": a.config.Get().Log.RedactLog,
	})
}

// handleAuditStream handles GET /manager/api/audit/stream?limit=200
func (a *Admin) handleAuditStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a == nil || a.audit == nil {
		http.Error(w, "Audit store not available", http.StatusInternalServerError)
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	send := func(event string, v any) {
		data, _ := json.Marshal(v)
		_, _ = w.Write([]byte("event: " + event + "\n"))
		_, _ = w.Write([]byte("data: " + string(data) + "\n\n"))
		flusher.Flush()
	}

	limit := clampInt(queryInt(r, "limit", 200), 1, 500)
	cfg := a.config.Get()
	send("audit_init", AuditResponse{
		RedactLog: cfg.Log.RedactLog,
		MaxEvents: a.audit.max,
		Events:    a.audit.List(limit),
	})

	ch, cancel := a.audit.Subscribe(64)
	defer cancel()

	// 心跳：避免中间代理/浏览器断开长连接
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			send("audit_event", ev)
		case <-ticker.C:
			// SSE comment line as heartbeat
			_, _ = w.Write([]byte(": ping " + strings.ReplaceAll(time.Now().Format(time.RFC3339), " ", "") + "\n\n"))
			flusher.Flush()
		}
	}
}
