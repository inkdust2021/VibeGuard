package mcp

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/inkdust2021/vibeguard/internal/admin"
	"github.com/inkdust2021/vibeguard/internal/config"
	"github.com/inkdust2021/vibeguard/internal/redact"
)

// JSONRPCRequest 表示 MCP JSON-RPC 请求
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      any             `json:"id,omitempty"`
}

// JSONRPCResponse 表示 MCP JSON-RPC 响应
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

// JSONRPCError 表示 JSON-RPC 错误
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *JSONRPCError) Error() string {
	return fmt.Sprintf("JSON-RPC error %d: %s", e.Code, e.Message)
}

// 标准 JSON-RPC 错误码
const (
	ErrParseError     = -32700
	ErrInvalidRequest = -32600
	ErrMethodNotFound = -32601
	ErrInvalidParams  = -32602
	ErrInternalError  = -32603
)

// Server 是 VibeGuard MCP Server
type Server struct {
	mu      sync.RWMutex
	version string
	name    string
	cfg     *config.Manager
	admin   *admin.Admin
	engine  *redact.Engine
	tools   map[string]ToolHandler
}

// ToolHandler 是一个 MCP 工具处理函数
type ToolHandler func(params json.RawMessage) (any, error)

// NewServer 创建 MCP Server
func NewServer(cfg *config.Manager, adm *admin.Admin, eng *redact.Engine, version string) *Server {
	s := &Server{
		version: version,
		name:    "vibeguard",
		cfg:     cfg,
		admin:   adm,
		engine:  eng,
		tools:   make(map[string]ToolHandler),
	}
	s.registerTools()
	return s
}

// Handler 返回 HTTP handler
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeError(w, nil, ErrParseError, "Parse error", err.Error())
			return
		}

		switch req.Method {
		case "initialize":
			s.handleInitialize(w, &req)
		case "tools/list":
			s.handleToolsList(w, &req)
		case "tools/call":
			s.handleToolsCall(w, &req)
		default:
			s.writeError(w, req.ID, ErrMethodNotFound, "Method not found", req.Method)
		}
	})
}

func (s *Server) handleInitialize(w http.ResponseWriter, req *JSONRPCRequest) {
	result := map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities": map[string]any{
			"tools": map[string]any{},
		},
		"serverInfo": map[string]any{
			"name":    s.name,
			"version": s.version,
		},
	}
	s.writeResult(w, req.ID, result)
}

func (s *Server) handleToolsList(w http.ResponseWriter, req *JSONRPCRequest) {
	tools := s.listTools()
	result := map[string]any{
		"tools": tools,
	}
	s.writeResult(w, req.ID, result)
}

func (s *Server) handleToolsCall(w http.ResponseWriter, req *JSONRPCRequest) {
	var call struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &call); err != nil {
		s.writeError(w, req.ID, ErrInvalidParams, "Invalid params", err.Error())
		return
	}
	if call.Name == "" {
		s.writeError(w, req.ID, ErrInvalidParams, "Invalid params", "missing tool name")
		return
	}

	s.mu.RLock()
	handler, ok := s.tools[call.Name]
	s.mu.RUnlock()

	if !ok {
		s.writeError(w, req.ID, ErrMethodNotFound, "Tool not found", call.Name)
		return
	}

	result, err := handler(call.Arguments)
	if err != nil {
		if jerr, ok := err.(*JSONRPCError); ok {
			s.writeError(w, req.ID, jerr.Code, jerr.Message, jerr.Data)
			return
		}
		s.writeError(w, req.ID, ErrInternalError, "Internal error", err.Error())
		return
	}

	s.writeResult(w, req.ID, map[string]any{
		"content": []map[string]any{
			{
				"type": "text",
				"text": mustJSON(result),
			},
		},
	})
}

func (s *Server) writeResult(w http.ResponseWriter, id any, result any) {
	w.Header().Set("Content-Type", "application/json")
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
	}
	data, err := json.Marshal(result)
	if err != nil {
		s.writeError(w, id, ErrInternalError, "Failed to marshal result", err.Error())
		return
	}
	resp.Result = data
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Warn("MCP response write failed", "error", err)
	}
}

func (s *Server) writeError(w http.ResponseWriter, id any, code int, message string, data any) {
	w.Header().Set("Content-Type", "application/json")
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &JSONRPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Warn("MCP error response write failed", "error", err)
	}
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf(`{"error":%q}`, err.Error())
	}
	return string(b)
}
