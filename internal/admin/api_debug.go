package admin

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

type updateDebugRequest struct {
	Enabled      *bool `json:"enabled"`
	MaxBodyBytes *int  `json:"max_body_bytes"`
	MaxEvents    *int  `json:"max_events"`
	MaskHeaders  *bool `json:"mask_headers"`
}

type debugEventsResponse struct {
	Status DebugStatus         `json:"status"`
	Events []DebugEventSummary `json:"events"`
}

// handleDebug handles GET/POST /manager/api/debug
func (a *Admin) handleDebug(w http.ResponseWriter, r *http.Request) {
	if a == nil || a.debug == nil {
		http.Error(w, "Debug store not available", http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(a.debug.Status())
	case http.MethodPost:
		var req updateDebugRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		st := a.debug.Update(req.Enabled, req.MaxBodyBytes, req.MaxEvents, req.MaskHeaders)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(st)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDebugEvents handles GET/DELETE /manager/api/debug/events
func (a *Admin) handleDebugEvents(w http.ResponseWriter, r *http.Request) {
	if a == nil || a.debug == nil {
		http.Error(w, "Debug store not available", http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case http.MethodGet:
		limit := clampInt(queryInt(r, "limit", 200), 1, 500)
		resp := debugEventsResponse{
			Status: a.debug.Status(),
			Events: a.debug.List(limit),
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(resp)
	case http.MethodDelete:
		a.debug.Clear()
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDebugEventsItem handles GET /manager/api/debug/events/{id}
func (a *Admin) handleDebugEventsItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a == nil || a.debug == nil {
		http.Error(w, "Debug store not available", http.StatusInternalServerError)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/manager/api/debug/events/")
	idStr = strings.TrimSpace(idStr)
	if idStr == "" {
		http.Error(w, "Missing id", http.StatusBadRequest)
		return
	}
	// 允许尾部带斜杠
	idStr = strings.TrimSuffix(idStr, "/")

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "Invalid id", http.StatusBadRequest)
		return
	}

	ev, ok := a.debug.Get(id)
	if !ok {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(ev)
}
