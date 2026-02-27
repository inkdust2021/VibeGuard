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
	Lang string `json:"lang"`
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
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp := SettingsResponse{Lang: a.preferredUILang(r)}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}
