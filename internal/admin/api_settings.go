package admin

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/inkdust2021/vibeguard/internal/config"
)

type SettingsResponse struct {
	Lang  string               `json:"lang"`
	Proxy SettingsProxyPayload `json:"proxy"`
}

type SettingsProxyPayload struct {
	WebSocketRedactionBeta bool `json:"websocket_redaction_beta"`
}

type updateSettingsRequest struct {
	Proxy *updateSettingsProxyRequest `json:"proxy"`
}

type updateSettingsProxyRequest struct {
	WebSocketRedactionBeta *bool `json:"websocket_redaction_beta"`
}

func normalizeLang(lang string) string {
	v := strings.ToLower(strings.TrimSpace(lang))
	switch v {
	case "zh", "zh-cn", "zh_cn", "cn", "中文", "chinese":
		return "zh"
	case "en", "en-us", "en_us", "english":
		return "en"
	default:
		if strings.HasPrefix(v, "zh") || strings.Contains(v, "zh") {
			return "zh"
		}
		if strings.HasPrefix(v, "en") || strings.Contains(v, "en") {
			return "en"
		}
		return ""
	}
}

func (a *Admin) preferredLangFromFile() string {
	langPath := filepath.Join(config.GetConfigDir(), "lang")
	b, err := os.ReadFile(langPath)
	if err != nil {
		return ""
	}
	return normalizeLang(string(b))
}

func preferredLangFromRequest(r *http.Request) string {
	al := strings.ToLower(r.Header.Get("Accept-Language"))
	if strings.Contains(al, "zh") {
		return "zh"
	}
	if strings.Contains(al, "en") {
		return "en"
	}
	return ""
}

func (a *Admin) preferredUILang(r *http.Request) string {
	if v := a.preferredLangFromFile(); v != "" {
		return v
	}
	if v := normalizeLang(os.Getenv("VIBEGUARD_LANG")); v != "" {
		return v
	}
	if v := preferredLangFromRequest(r); v != "" {
		return v
	}
	return "zh"
}

func (a *Admin) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.getSettings(w, r)
	case http.MethodPost:
		if a == nil || a.auth == nil {
			http.Error(w, "Admin auth not initialized", http.StatusInternalServerError)
			return
		}
		if ok := a.auth.Require(w, r); !ok {
			return
		}
		a.updateSettings(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *Admin) getSettings(w http.ResponseWriter, r *http.Request) {
	c := a.config.Get()
	resp := SettingsResponse{
		Lang: a.preferredUILang(r),
		Proxy: SettingsProxyPayload{
			WebSocketRedactionBeta: c.Proxy.WebSocketRedactionBeta,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

func (a *Admin) updateSettings(w http.ResponseWriter, r *http.Request) {
	var req updateSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Proxy == nil || req.Proxy.WebSocketRedactionBeta == nil {
		http.Error(w, "Missing fields", http.StatusBadRequest)
		return
	}

	if err := a.config.Update(func(c *config.Config) {
		c.Proxy.WebSocketRedactionBeta = *req.Proxy.WebSocketRedactionBeta
	}); err != nil {
		http.Error(w, "Failed to update config", http.StatusInternalServerError)
		return
	}

	a.getSettings(w, r)
}
