package admin

import (
	"encoding/json"
	"net/http"

	"github.com/inkdust2021/vibeguard/internal/config"
)

// SessionMapping represents a single session mapping (without original value)
type SessionMapping struct {
	Placeholder string `json:"placeholder"`
	Category    string `json:"category"`
	CreatedAt   string `json:"created_at,omitempty"`
	ExpiresAt   string `json:"expires_at,omitempty"`
}

// SessionsResponse represents the sessions API response
type SessionsResponse struct {
	Total                    int              `json:"total"`
	Mappings                 []SessionMapping `json:"mappings"`
	DeterministicPlaceholders bool             `json:"deterministic_placeholders"`
}

type updateSessionsSettingsRequest struct {
	DeterministicPlaceholders *bool `json:"deterministic_placeholders"`
}

type updateSessionsSettingsResponse struct {
	DeterministicPlaceholders bool `json:"deterministic_placeholders"`
}

// handleSessions handles GET/POST/DELETE /manager/api/sessions
func (a *Admin) handleSessions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.getSessions(w, r)
	case http.MethodPost:
		a.updateSessionsSettings(w, r)
	case http.MethodDelete:
		a.clearSessions(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *Admin) getSessions(w http.ResponseWriter, r *http.Request) {
	// Get search query
	search := r.URL.Query().Get("search")

	// Get all mappings from session manager
	// Note: We only return placeholders, never original values
	mappings := a.session.ListMappings()

	result := make([]SessionMapping, 0, len(mappings))
	for _, m := range mappings {
		// Filter by search if provided
		if search != "" {
			if !containsIgnoreCase(m.Placeholder, search) && !containsIgnoreCase(m.Category, search) {
				continue
			}
		}

		result = append(result, SessionMapping{
			Placeholder: m.Placeholder,
			Category:    m.Category,
		})
	}

	resp := SessionsResponse{
		Total:                    len(result),
		Mappings:                 result,
		DeterministicPlaceholders: a.session.DeterministicPlaceholdersEnabled(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(resp)
}

func (a *Admin) updateSessionsSettings(w http.ResponseWriter, r *http.Request) {
	var req updateSessionsSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.DeterministicPlaceholders == nil {
		http.Error(w, "Missing deterministic_placeholders", http.StatusBadRequest)
		return
	}

	enabled := *req.DeterministicPlaceholders
	var key32 []byte
	if enabled {
		k, err := a.ca.DerivePlaceholderKey()
		if err != nil {
			http.Error(w, "Failed to derive CA key", http.StatusInternalServerError)
			return
		}
		key32 = k
	}

	if err := a.config.Update(func(c *config.Config) {
		c.Session.DeterministicPlaceholders = enabled
	}); err != nil {
		http.Error(w, "Failed to update config", http.StatusInternalServerError)
		return
	}
	if err := a.session.SetDeterministicPlaceholders(enabled, key32); err != nil {
		http.Error(w, "Failed to apply setting", http.StatusInternalServerError)
		return
	}

	resp := updateSessionsSettingsResponse{
		DeterministicPlaceholders: a.session.DeterministicPlaceholdersEnabled(),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

func (a *Admin) clearSessions(w http.ResponseWriter, r *http.Request) {
	a.session.Clear()
	w.WriteHeader(http.StatusNoContent)
}

func containsIgnoreCase(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && containsLower(lower(s), lower(substr))))
}

func containsLower(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func lower(s string) string {
	b := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}
