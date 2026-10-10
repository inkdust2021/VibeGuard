package mcp

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/inkdust2021/vibeguard/internal/redact"

	"github.com/inkdust2021/vibeguard/internal/config"
)

// Tool 表示一个 MCP 工具定义
type Tool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema any    `json:"inputSchema"`
}

func (s *Server) registerTools() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tools["get_proxy_status"] = s.handleGetProxyStatus
	s.tools["detect_sensitive"] = s.handleDetectSensitive
	s.tools["preview_redacted"] = s.handlePreviewRedacted
	s.tools["list_keywords"] = s.handleListKeywords
	s.tools["list_rule_lists"] = s.handleListRuleLists
}

func (s *Server) listTools() []Tool {
	return []Tool{
		{
			Name:        "get_proxy_status",
			Description: "获取 VibeGuard 代理的运行状态，包括启动时间、请求统计、拦截模式等",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "detect_sensitive",
			Description: "检测文本中是否包含敏感信息，返回命中规则列表。默认不暴露原始值，设置 include_originals=true 可查看",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"text": map[string]any{
						"type":        "string",
						"description": "待检测的文本",
					},
					"include_originals": map[string]any{
						"type":        "boolean",
						"description": "是否在结果中包含原始敏感值（默认 false）",
					},
				},
				"required": []string{"text"},
			},
		},
		{
			Name:        "preview_redacted",
			Description: "预览文本脱敏效果，返回带临时占位符的文本（占位符不持久化，不会注册到 session）",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"text": map[string]any{
						"type":        "string",
						"description": "待预览脱敏的文本",
					},
				},
				"required": []string{"text"},
			},
		},
		{
			Name:        "list_keywords",
			Description: "查询当前加载的关键词规则列表，每条规则包含匹配文本、分类和来源",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "list_rule_lists",
			Description: "查询当前启用的规则列表（rule lists）及其元数据",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
	}
}

func (s *Server) handleGetProxyStatus(_ json.RawMessage) (any, error) {
	stats := s.admin.GetStats()
	cfg := s.cfg.Get()

	started := s.admin.StartedTime()
	uptime := ""
	if started > 0 {
		uptime = time.Since(time.Unix(started, 0)).Round(time.Second).String()
	}

	return map[string]any{
		"version":          s.version,
		"started_at":       time.Unix(started, 0).Format(time.RFC3339),
		"uptime":           uptime,
		"total_requests":   stats.TotalRequests.Load(),
		"redacted_count":   stats.RedactedRequests.Load(),
		"restored_count":   stats.RestoredRequests.Load(),
		"errors":           stats.Errors.Load(),
		"intercept_mode":   cfg.Proxy.InterceptMode,
		"websocket_beta":   cfg.Proxy.WebSocketRedactionBeta,
		"listen_address":   cfg.Proxy.Listen,
	}, nil
}

func (s *Server) handleDetectSensitive(params json.RawMessage) (any, error) {
	var args struct {
		Text              string `json:"text"`
		IncludeOriginals  bool   `json:"include_originals"`
	}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &JSONRPCError{Code: ErrInvalidParams, Message: "Invalid params", Data: err.Error()}
	}
	if args.Text == "" {
		return nil, &JSONRPCError{Code: ErrInvalidParams, Message: "Invalid params", Data: "text is required"}
	}

	if s.engine == nil {
		return nil, &JSONRPCError{Code: -32001, Message: "Detection unavailable", Data: "NER/pipeline mode does not support Detect"}
	}

	matches := s.engine.Detect([]byte(args.Text))
	return buildDetectResult(matches, args.IncludeOriginals), nil
}

func (s *Server) handlePreviewRedacted(params json.RawMessage) (any, error) {
	var args struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, &JSONRPCError{Code: ErrInvalidParams, Message: "Invalid params", Data: err.Error()}
	}
	if args.Text == "" {
		return nil, &JSONRPCError{Code: ErrInvalidParams, Message: "Invalid params", Data: "text is required"}
	}

	if s.engine == nil {
		return nil, &JSONRPCError{Code: -32001, Message: "Detection unavailable", Data: "NER/pipeline mode does not support Detect"}
	}

	matches := s.engine.Detect([]byte(args.Text))
	redacted := applyTemporaryPlaceholders(args.Text, matches)
	return map[string]any{
		"redacted_text": redacted,
		"match_count":   len(matches),
	}, nil
}

func buildDetectResult(matches []redact.Match, includeOriginals bool) map[string]any {
	hits := make([]map[string]any, len(matches))
	for i, m := range matches {
		hit := map[string]any{
			"category": m.Category,
			"start":    m.Start,
			"end":      m.End,
		}
		if includeOriginals {
			hit["original"] = m.Original
		}
		hits[i] = hit
	}
	return map[string]any{
		"has_sensitive": len(matches) > 0,
		"match_count":  len(matches),
		"matches":      hits,
	}
}

func applyTemporaryPlaceholders(text string, matches []redact.Match) string {
	if len(matches) == 0 {
		return text
	}

	result := []byte(text)
	// 从后往前替换，避免偏移
	for i := len(matches) - 1; i >= 0; i-- {
		m := matches[i]
		placeholder := fmt.Sprintf("__VG_%s_PREVIEW__", m.Category)
		result = append(result[:m.Start], append([]byte(placeholder), result[m.End:]...)...)
	}
	return string(result)
}

func (s *Server) handleListKeywords(_ json.RawMessage) (any, error) {
	cfg := s.cfg.Get()

	var keywords []map[string]any

	// 从 config 中读取用户定义的关键词
	for _, kw := range cfg.Patterns.Keywords {
		keywords = append(keywords, map[string]any{
			"keyword":  kw.Value,
			"category": kw.Category,
			"source":   "user",
		})
	}

	// 从 config 中读取内置规则
	for _, b := range cfg.Patterns.Builtin {
		keywords = append(keywords, map[string]any{
			"keyword":  b,
			"category": b,
			"source":   "builtin",
		})
	}

	// 从 engine 中读取已加载的关键词（含 rule list 注入的）
	if s.engine != nil {
		for kw, cat := range s.engine.ListKeywords() {
			keywords = append(keywords, map[string]any{
				"keyword":  kw,
				"category": cat,
				"source":   "engine",
			})
		}
	}

	return map[string]any{
		"count":    len(keywords),
		"keywords": keywords,
	}, nil
}

func (s *Server) handleListRuleLists(_ json.RawMessage) (any, error) {
	cfg := s.cfg.Get()

	var lists []map[string]any
	for _, rl := range cfg.Patterns.RuleLists {
		lists = append(lists, map[string]any{
			"id":       rl.ID,
			"name":     rl.Name,
			"enabled":  rl.Enabled,
			"source":   ruleListSource(rl),
		})
	}

	return map[string]any{
		"count":      len(lists),
		"rule_lists": lists,
	}, nil
}

func ruleListSource(rl config.RuleListConfig) string {
	if rl.URL != "" {
		return "subscribed"
	}
	return "local"
}
