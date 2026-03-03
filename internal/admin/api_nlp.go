package admin

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/inkdust2021/vibeguard/internal/config"
	"github.com/inkdust2021/vibeguard/internal/pii_next/nlp"
)

type NLPSettings struct {
	Enabled         bool     `json:"enabled"`
	Engine          string   `json:"engine"`
	ModelPath       string   `json:"model_path"`
	RouteByLang     bool     `json:"route_by_lang"`
	ModelPathEN     string   `json:"model_path_en"`
	ModelPathZH     string   `json:"model_path_zh"`
	MaxLoadedModels int      `json:"max_loaded_models"`
	Entities        []string `json:"entities"`
	MinScore        float64  `json:"min_score"`
	OnnxAvailable   bool     `json:"onnx_available"`
}

type updateNLPSettingsRequest struct {
	Enabled         *bool     `json:"enabled"`
	Engine          *string   `json:"engine"`
	ModelPath       *string   `json:"model_path"`
	RouteByLang     *bool     `json:"route_by_lang"`
	ModelPathEN     *string   `json:"model_path_en"`
	ModelPathZH     *string   `json:"model_path_zh"`
	MaxLoadedModels *int      `json:"max_loaded_models"`
	Entities        *[]string `json:"entities"`
	MinScore        *float64  `json:"min_score"`
}

// handleNLP handles GET/POST /manager/api/nlp
func (a *Admin) handleNLP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.getNLPSettings(w, r)
	case http.MethodPost:
		a.updateNLPSettings(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *Admin) getNLPSettings(w http.ResponseWriter, r *http.Request) {
	c := a.config.Get()
	entities := append([]string(nil), c.Patterns.NLP.Entities...)
	if len(entities) == 0 {
		entities = nlp.SafeEntityNames()
	}

	resp := NLPSettings{
		Enabled:         c.Patterns.NLP.Enabled,
		Engine:          strings.TrimSpace(c.Patterns.NLP.Engine),
		ModelPath:       strings.TrimSpace(c.Patterns.NLP.ModelPath),
		RouteByLang:     c.Patterns.NLP.RouteByLang,
		ModelPathEN:     strings.TrimSpace(c.Patterns.NLP.ModelPathEN),
		ModelPathZH:     strings.TrimSpace(c.Patterns.NLP.ModelPathZH),
		MaxLoadedModels: c.Patterns.NLP.MaxLoadedModels,
		Entities:        entities,
		MinScore:        c.Patterns.NLP.MinScore,
		OnnxAvailable:   nlp.OnnxAvailable(),
	}
	if resp.Engine == "" {
		resp.Engine = "heuristic"
	}
	if resp.Engine == "onnx" && !resp.OnnxAvailable {
		resp.Engine = "heuristic"
	}
	if resp.MaxLoadedModels <= 0 {
		resp.MaxLoadedModels = 1
	}
	if resp.MaxLoadedModels > 2 {
		resp.MaxLoadedModels = 2
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

func (a *Admin) updateNLPSettings(w http.ResponseWriter, r *http.Request) {
	var req updateNLPSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Enabled == nil && req.Engine == nil && req.ModelPath == nil && req.RouteByLang == nil && req.ModelPathEN == nil && req.ModelPathZH == nil && req.MaxLoadedModels == nil && req.Entities == nil && req.MinScore == nil {
		http.Error(w, "Missing fields", http.StatusBadRequest)
		return
	}

	if req.Engine != nil {
		eng := config.SanitizeNLPEngine(*req.Engine)
		if eng == "" {
			http.Error(w, "Invalid engine", http.StatusBadRequest)
			return
		}
		if eng == "onnx" && !nlp.OnnxAvailable() {
			http.Error(w, "ONNX not available", http.StatusBadRequest)
			return
		}
	}

	if req.Entities != nil {
		// 允许空数组：表示“回退到默认实体集合”。
		for _, e := range *req.Entities {
			if config.SanitizeCategory(e) == "" {
				http.Error(w, "Invalid entities", http.StatusBadRequest)
				return
			}
		}
	}

	if req.MinScore != nil {
		if *req.MinScore < 0 || *req.MinScore > 1 {
			http.Error(w, "Invalid min_score", http.StatusBadRequest)
			return
		}
	}

	if req.MaxLoadedModels != nil {
		if *req.MaxLoadedModels < 1 || *req.MaxLoadedModels > 2 {
			http.Error(w, "Invalid max_loaded_models", http.StatusBadRequest)
			return
		}
	}

	if err := a.config.Update(func(c *config.Config) {
		if req.Enabled != nil {
			c.Patterns.NLP.Enabled = *req.Enabled
		}
		if req.Engine != nil {
			eng := config.SanitizeNLPEngine(*req.Engine)
			if eng != "" {
				c.Patterns.NLP.Engine = eng
			}
		}
		if req.ModelPath != nil {
			c.Patterns.NLP.ModelPath = strings.TrimSpace(*req.ModelPath)
		}
		if req.RouteByLang != nil {
			c.Patterns.NLP.RouteByLang = *req.RouteByLang
		}
		if req.ModelPathEN != nil {
			c.Patterns.NLP.ModelPathEN = strings.TrimSpace(*req.ModelPathEN)
		}
		if req.ModelPathZH != nil {
			c.Patterns.NLP.ModelPathZH = strings.TrimSpace(*req.ModelPathZH)
		}
		if req.MaxLoadedModels != nil && *req.MaxLoadedModels > 0 {
			c.Patterns.NLP.MaxLoadedModels = *req.MaxLoadedModels
		}
		if req.Entities != nil {
			out := make([]string, 0, len(*req.Entities))
			for _, e := range *req.Entities {
				v := config.SanitizeCategory(e)
				if v == "" {
					continue
				}
				out = append(out, v)
			}
			c.Patterns.NLP.Entities = out
		}
		if req.MinScore != nil {
			c.Patterns.NLP.MinScore = *req.MinScore
		}
	}); err != nil {
		http.Error(w, "Failed to update config", http.StatusInternalServerError)
		return
	}

	a.getNLPSettings(w, r)
}
