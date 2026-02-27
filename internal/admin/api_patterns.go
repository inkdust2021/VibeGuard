package admin

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/inkdust2021/vibeguard/internal/config"
)

// PatternsResponse represents the patterns API response
type PatternsResponse struct {
	Keywords []config.KeywordPattern `json:"keywords"`
	Exclude  []string                `json:"exclude"`
}

// handlePatterns handles GET/POST /manager/api/patterns
func (a *Admin) handlePatterns(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.getPatterns(w, r)
	case http.MethodPost:
		a.addPattern(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handlePatternsItem handles DELETE /manager/api/patterns/{type}/{index}
func (a *Admin) handlePatternsItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/manager/api/patterns/")
	parts := strings.Split(path, "/")

	if len(parts) != 2 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	patternType := parts[0]
	index, err := strconv.Atoi(parts[1])
	if err != nil {
		http.Error(w, "Invalid index", http.StatusBadRequest)
		return
	}

	if err := a.config.Update(func(c *config.Config) {
		switch patternType {
		case "keywords":
			if index >= 0 && index < len(c.Patterns.Keywords) {
				c.Patterns.Keywords = append(c.Patterns.Keywords[:index], c.Patterns.Keywords[index+1:]...)
			}
		case "exclude":
			if index >= 0 && index < len(c.Patterns.Exclude) {
				c.Patterns.Exclude = append(c.Patterns.Exclude[:index], c.Patterns.Exclude[index+1:]...)
			}
		}
	}); err != nil {
		http.Error(w, "Failed to save: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (a *Admin) getPatterns(w http.ResponseWriter, r *http.Request) {
	c := a.config.Get()

	keywords := make([]config.KeywordPattern, 0, len(c.Patterns.Keywords))
	for _, kw := range c.Patterns.Keywords {
		v := config.SanitizePatternValue(kw.Value)
		if v == "" {
			continue
		}
		cat := config.SanitizeCategory(kw.Category)
		if cat == "" {
			cat = "TEXT"
		}
		keywords = append(keywords, config.KeywordPattern{Value: v, Category: cat})
	}
	exclude := make([]string, 0, len(c.Patterns.Exclude))
	for _, ex := range c.Patterns.Exclude {
		v := config.SanitizePatternValue(ex)
		if v == "" {
			continue
		}
		exclude = append(exclude, v)
	}

	resp := PatternsResponse{
		Keywords: keywords,
		Exclude:  exclude,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(resp)
}

func (a *Admin) addPattern(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type     string `json:"type"`
		Value    string `json:"value"`
		Category string `json:"category"`
		Pattern  string `json:"pattern"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// 基本校验：尽量在写入配置前阻止无效规则，减少“添加成功但不生效”的困惑
	switch req.Type {
	case "keyword":
		if config.SanitizePatternValue(req.Value) == "" {
			http.Error(w, "Keyword value is required", http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "Invalid pattern type", http.StatusBadRequest)
		return
	}

	if err := a.config.Update(func(c *config.Config) {
		switch req.Type {
		case "keyword":
			// 清理不可见字符，避免规则“看起来已添加但实际不匹配”
			val := config.SanitizePatternValue(req.Value)
			if val == "" {
				return
			}
			cat := config.SanitizeCategory(req.Category)
			if cat == "" {
				cat = "TEXT"
			}
			c.Patterns.Keywords = append(c.Patterns.Keywords, config.KeywordPattern{
				Value:    val,
				Category: cat,
			})
		}
	}); err != nil {
		http.Error(w, "Failed to save: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "created",
		"message": "Pattern added",
	})
}
