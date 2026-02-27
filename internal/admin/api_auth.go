package admin

import (
	"encoding/json"
	"net/http"
	"strings"
)

type AuthStatusResponse struct {
	Configured    bool   `json:"configured"`
	Authenticated bool   `json:"authenticated"`
	Broken        bool   `json:"broken"`
	BrokenError   string `json:"broken_error,omitempty"`
}

func (a *Admin) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a == nil || a.auth == nil {
		http.Error(w, "Admin auth not initialized", http.StatusInternalServerError)
		return
	}

	configured, authed, broken, brokenErr := a.auth.Status(r)
	resp := AuthStatusResponse{
		Configured:    configured,
		Authenticated: authed,
		Broken:        broken,
		BrokenError:   brokenErr,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

func (a *Admin) handleAuthSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a == nil || a.auth == nil {
		http.Error(w, "Admin auth not initialized", http.StatusInternalServerError)
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	req.Password = strings.TrimSpace(req.Password)

	if err := a.auth.Setup(req.Password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Setup 成功后直接创建会话，避免用户再手动登录一次。
	a.auth.mu.Lock()
	token, _, err := a.auth.CreateSessionLocked()
	a.auth.mu.Unlock()
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}
	setAdminSessionCookie(w, token)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (a *Admin) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a == nil || a.auth == nil {
		http.Error(w, "Admin auth not initialized", http.StatusInternalServerError)
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	req.Password = strings.TrimSpace(req.Password)

	if err := a.auth.Verify(req.Password); err != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	a.auth.mu.Lock()
	token, _, err := a.auth.CreateSessionLocked()
	a.auth.mu.Unlock()
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}
	setAdminSessionCookie(w, token)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (a *Admin) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a == nil || a.auth == nil {
		http.Error(w, "Admin auth not initialized", http.StatusInternalServerError)
		return
	}

	a.auth.DestroySession(r)
	clearAdminSessionCookie(w)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
