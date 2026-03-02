package admin

import (
	"encoding/json"
	"net/http"

	"github.com/inkdust2021/vibeguard/internal/config"
	"github.com/inkdust2021/vibeguard/internal/pii_next/presidio"
)

type PresidioSettings struct {
	Enabled     bool     `json:"enabled"`
	Recognizers []string `json:"recognizers"`
}

type updatePresidioSettingsRequest struct {
	Enabled     *bool     `json:"enabled"`
	Recognizers *[]string `json:"recognizers"`
}

// handlePresidio handles GET/POST /manager/api/presidio
func (a *Admin) handlePresidio(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.getPresidioSettings(w, r)
	case http.MethodPost:
		a.updatePresidioSettings(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *Admin) getPresidioSettings(w http.ResponseWriter, r *http.Request) {
	c := a.config.Get()
	recs := append([]string(nil), c.Patterns.Presidio.Recognizers...)
	// 保守默认：当用户未显式配置 recognizers 时，返回一组“高置信度 + 低误报”的默认集合，
	// 避免开启泛化匹配后误伤时间戳/ID 导致开发体验下降。
	if len(recs) == 0 {
		recs = presidio.SafeRecognizerNames()
	}

	resp := PresidioSettings{
		Enabled:     c.Patterns.Presidio.Enabled,
		Recognizers: recs,
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

func (a *Admin) updatePresidioSettings(w http.ResponseWriter, r *http.Request) {
	var req updatePresidioSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Enabled == nil && req.Recognizers == nil {
		http.Error(w, "Missing enabled/recognizers", http.StatusBadRequest)
		return
	}

	if err := a.config.Update(func(c *config.Config) {
		if req.Enabled != nil {
			c.Patterns.Presidio.Enabled = *req.Enabled
		}
		if req.Recognizers != nil {
			out := make([]string, 0, len(*req.Recognizers))
			for _, n := range *req.Recognizers {
				v := config.SanitizeRecognizerName(n)
				if v == "" {
					continue
				}
				out = append(out, v)
			}
			c.Patterns.Presidio.Recognizers = out
		}
	}); err != nil {
		http.Error(w, "Failed to update config", http.StatusInternalServerError)
		return
	}

	c := a.config.Get()
	resp := PresidioSettings{
		Enabled:     c.Patterns.Presidio.Enabled,
		Recognizers: append([]string(nil), c.Patterns.Presidio.Recognizers...),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}
