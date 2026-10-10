package mcp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/inkdust2021/vibeguard/internal/admin"
	"github.com/inkdust2021/vibeguard/internal/cert"
	"github.com/inkdust2021/vibeguard/internal/config"
	"github.com/inkdust2021/vibeguard/internal/redact"
	"github.com/inkdust2021/vibeguard/internal/session"
)

func TestMcpServer_Initialize(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServer(t)
	token, _ := getOrCreateMcpToken()

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "initialize",
		"id":      1,
	}
	resp := postJSON(t, srv, reqBody, token)

	if resp["jsonrpc"] != "2.0" {
		t.Errorf("expected jsonrpc=2.0, got %v", resp["jsonrpc"])
	}
	if resp["id"] != float64(1) {
		t.Errorf("expected id=1, got %v", resp["id"])
	}
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected result object, got %T", resp["result"])
	}
	if result["protocolVersion"] != "2024-11-05" {
		t.Errorf("expected protocolVersion=2024-11-05, got %v", result["protocolVersion"])
	}
	capabilities, ok := result["capabilities"].(map[string]any)
	if !ok {
		t.Fatalf("expected capabilities object")
	}
	if _, hasTools := capabilities["tools"]; !hasTools {
		t.Error("expected capabilities to include tools")
	}
	serverInfo, ok := result["serverInfo"].(map[string]any)
	if !ok {
		t.Fatalf("expected serverInfo object")
	}
	if serverInfo["name"] != "vibeguard" {
		t.Errorf("expected name=vibeguard, got %v", serverInfo["name"])
	}
	if serverInfo["version"] != "test-version" {
		t.Errorf("expected version=test-version, got %v", serverInfo["version"])
	}
}

func TestMcpServer_ToolsList(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServer(t)
	token, _ := getOrCreateMcpToken()

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/list",
		"id":      2,
	}
	resp := postJSON(t, srv, reqBody, token)

	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected result object")
	}
	tools, ok := result["tools"].([]any)
	if !ok {
		t.Fatalf("expected tools array")
	}
	if len(tools) == 0 {
		t.Error("expected at least one tool")
	}

	first := tools[0].(map[string]any)
	if first["name"] != "get_proxy_status" {
		t.Errorf("expected first tool=get_proxy_status, got %v", first["name"])
	}
}

func TestMcpServer_GetProxyStatus(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServer(t)
	token, _ := getOrCreateMcpToken()

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "get_proxy_status",
			"arguments": map[string]any{},
		},
		"id": 3,
	}
	resp := postJSON(t, srv, reqBody, token)

	if _, hasError := resp["error"]; hasError {
		t.Fatalf("unexpected error: %v", resp["error"])
	}
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected result object")
	}
	content, ok := result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("expected content array")
	}
	textItem := content[0].(map[string]any)
	if textItem["type"] != "text" {
		t.Errorf("expected type=text, got %v", textItem["type"])
	}

	// 验证 text 内容中的 JSON 结构
	var status map[string]any
	if err := json.Unmarshal([]byte(textItem["text"].(string)), &status); err != nil {
		t.Fatalf("failed to parse status JSON: %v", err)
	}
	requiredFields := []string{"version", "started_at", "uptime", "total_requests", "redacted_count", "restored_count", "errors", "intercept_mode", "listen_address"}
	for _, f := range requiredFields {
		if _, ok := status[f]; !ok {
			t.Errorf("missing field: %s", f)
		}
	}
	if status["version"] != "test-version" {
		t.Errorf("expected version=test-version, got %v", status["version"])
	}
}

func TestMcpServer_InvalidJSON(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServer(t)
	token, _ := getOrCreateMcpToken()

	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte("not json")))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	AuthMiddleware(srv.Handler()).ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	errObj, _ := resp["error"].(map[string]any)
	if errObj["code"] != float64(-32700) {
		t.Errorf("expected error code -32700, got %v", errObj["code"])
	}
}

func TestMcpServer_MethodNotAllowed(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServer(t)

	r := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", w.Code)
	}
}

func TestMcpServer_EmptyMethod(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServer(t)
	token, _ := getOrCreateMcpToken()

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
	}
	resp := postJSON(t, srv, reqBody, token)

	errObj, _ := resp["error"].(map[string]any)
	if errObj["code"] != float64(-32601) {
		t.Errorf("expected error code -32601 (method not found), got %v", errObj["code"])
	}
}

func TestMcpServer_UnknownMethod(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServer(t)
	token, _ := getOrCreateMcpToken()

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "nonexistent/method",
		"id":      1,
	}
	resp := postJSON(t, srv, reqBody, token)

	errObj, _ := resp["error"].(map[string]any)
	if errObj["code"] != float64(-32601) {
		t.Errorf("expected error code -32601, got %v", errObj["code"])
	}
}

func TestMcpServer_ToolNotFound(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServer(t)
	token, _ := getOrCreateMcpToken()

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "nonexistent_tool",
			"arguments": map[string]any{},
		},
		"id": 1,
	}
	resp := postJSON(t, srv, reqBody, token)

	errObj, _ := resp["error"].(map[string]any)
	if errObj["code"] != float64(-32601) {
		t.Errorf("expected error code -32601 (tool not found), got %v", errObj["code"])
	}
}

func TestMcpServer_ToolCallMissingName(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServer(t)
	token, _ := getOrCreateMcpToken()

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": map[string]any{
			"arguments": map[string]any{},
		},
		"id": 1,
	}
	resp := postJSON(t, srv, reqBody, token)

	errObj, _ := resp["error"].(map[string]any)
	if errObj["code"] != float64(-32602) {
		t.Errorf("expected error code -32602 (invalid params), got %v", errObj["code"])
	}
}

func TestMcpServer_DetectSensitive(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServerWithKeywords(t, map[string]string{"secret": "TEXT"})
	token, _ := getOrCreateMcpToken()

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": map[string]any{
			"name": "detect_sensitive",
			"arguments": map[string]any{
				"text": "this is a secret message",
			},
		},
		"id": 1,
	}
	resp := postJSON(t, srv, reqBody, token)

	if _, hasError := resp["error"]; hasError {
		t.Fatalf("unexpected error: %v", resp["error"])
	}
	result := resp["result"].(map[string]any)
	content := result["content"].([]any)
	textItem := content[0].(map[string]any)

	var detectResult map[string]any
	json.Unmarshal([]byte(textItem["text"].(string)), &detectResult)

	if detectResult["has_sensitive"] != true {
		t.Errorf("expected has_sensitive=true, got %v", detectResult["has_sensitive"])
	}
	matches := detectResult["matches"].([]any)
	if len(matches) == 0 {
		t.Fatal("expected at least one match")
	}
	hit := matches[0].(map[string]any)
	if hit["category"] != "TEXT" {
		t.Errorf("expected category=TEXT, got %v", hit["category"])
	}
	if _, hasOriginal := hit["original"]; hasOriginal {
		t.Error("expected no original field by default")
	}
}

func TestMcpServer_DetectSensitive_WithOriginals(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServerWithKeywords(t, map[string]string{"secret": "TEXT"})
	token, _ := getOrCreateMcpToken()

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": map[string]any{
			"name": "detect_sensitive",
			"arguments": map[string]any{
				"text":              "this is a secret message",
				"include_originals": true,
			},
		},
		"id": 1,
	}
	resp := postJSON(t, srv, reqBody, token)

	result := resp["result"].(map[string]any)
	content := result["content"].([]any)
	textItem := content[0].(map[string]any)

	var detectResult map[string]any
	json.Unmarshal([]byte(textItem["text"].(string)), &detectResult)

	matches := detectResult["matches"].([]any)
	hit := matches[0].(map[string]any)
	if hit["original"] != "secret" {
		t.Errorf("expected original=secret, got %v", hit["original"])
	}
}

func TestMcpServer_DetectSensitive_NoMatch(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServerWithKeywords(t, map[string]string{"secret": "TEXT"})
	token, _ := getOrCreateMcpToken()

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": map[string]any{
			"name": "detect_sensitive",
			"arguments": map[string]any{
				"text": "this is a clean message",
			},
		},
		"id": 1,
	}
	resp := postJSON(t, srv, reqBody, token)

	result := resp["result"].(map[string]any)
	content := result["content"].([]any)
	textItem := content[0].(map[string]any)

	var detectResult map[string]any
	json.Unmarshal([]byte(textItem["text"].(string)), &detectResult)

	if detectResult["has_sensitive"] != false {
		t.Errorf("expected has_sensitive=false, got %v", detectResult["has_sensitive"])
	}
}

func TestMcpServer_DetectSensitive_MissingText(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServerWithKeywords(t, nil)
	token, _ := getOrCreateMcpToken()

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "detect_sensitive",
			"arguments": map[string]any{},
		},
		"id": 1,
	}
	resp := postJSON(t, srv, reqBody, token)

	errObj, _ := resp["error"].(map[string]any)
	if errObj["code"] != float64(-32602) {
		t.Errorf("expected error code -32602, got %v", errObj["code"])
	}
}

func TestMcpServer_PreviewRedacted(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServerWithKeywords(t, map[string]string{"secret": "TEXT"})
	token, _ := getOrCreateMcpToken()

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": map[string]any{
			"name": "preview_redacted",
			"arguments": map[string]any{
				"text": "this is a secret message",
			},
		},
		"id": 1,
	}
	resp := postJSON(t, srv, reqBody, token)

	if _, hasError := resp["error"]; hasError {
		t.Fatalf("unexpected error: %v", resp["error"])
	}
	result := resp["result"].(map[string]any)
	content := result["content"].([]any)
	textItem := content[0].(map[string]any)

	var previewResult map[string]any
	json.Unmarshal([]byte(textItem["text"].(string)), &previewResult)

	if previewResult["match_count"] != float64(1) {
		t.Errorf("expected match_count=1, got %v", previewResult["match_count"])
	}
	redactedText := previewResult["redacted_text"].(string)
	if redactedText == "this is a secret message" {
		t.Error("expected text to be redacted, got original")
	}
	if !contains(redactedText, "__VG_TEXT_PREVIEW__") {
		t.Errorf("expected placeholder in redacted text, got %s", redactedText)
	}
}

func TestMcpServer_ListKeywords(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServer(t)
	token, _ := getOrCreateMcpToken()

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "list_keywords",
			"arguments": map[string]any{},
		},
		"id": 1,
	}
	resp := postJSON(t, srv, reqBody, token)

	if _, hasError := resp["error"]; hasError {
		t.Fatalf("unexpected error: %v", resp["error"])
	}
	result := resp["result"].(map[string]any)
	content := result["content"].([]any)
	textItem := content[0].(map[string]any)

	var listResult map[string]any
	json.Unmarshal([]byte(textItem["text"].(string)), &listResult)

	keywords := listResult["keywords"].([]any)
	if len(keywords) == 0 {
		t.Error("expected at least one keyword")
	}
	first := keywords[0].(map[string]any)
	if _, ok := first["keyword"]; !ok {
		t.Error("expected keyword field")
	}
	if _, ok := first["category"]; !ok {
		t.Error("expected category field")
	}
	if _, ok := first["source"]; !ok {
		t.Error("expected source field")
	}
}

func TestMcpServer_ListRuleLists(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServer(t)
	token, _ := getOrCreateMcpToken()

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "list_rule_lists",
			"arguments": map[string]any{},
		},
		"id": 1,
	}
	resp := postJSON(t, srv, reqBody, token)

	if _, hasError := resp["error"]; hasError {
		t.Fatalf("unexpected error: %v", resp["error"])
	}
	result := resp["result"].(map[string]any)
	content := result["content"].([]any)
	textItem := content[0].(map[string]any)

	var listResult map[string]any
	json.Unmarshal([]byte(textItem["text"].(string)), &listResult)

	// 默认配置没有 rule lists，但字段应该存在
	if _, ok := listResult["rule_lists"]; !ok {
		t.Error("expected rule_lists field")
	}
	if _, ok := listResult["count"]; !ok {
		t.Error("expected count field")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestMcpServer_ValidTokenMultipleRequests(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServer(t)
	token, _ := getOrCreateMcpToken()

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "initialize",
		"id":      1,
	}

	for i := 0; i < 3; i++ {
		resp := postJSON(t, srv, reqBody, token)
		if _, hasError := resp["error"]; hasError {
			t.Errorf("request %d: unexpected error: %v", i, resp["error"])
		}
		if resp["jsonrpc"] != "2.0" {
			t.Errorf("request %d: expected jsonrpc=2.0, got %v", i, resp["jsonrpc"])
		}
	}
}

func TestMcpServer_AuthRequired(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServer(t)

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "initialize",
		"id":      1,
	}

	body, _ := json.Marshal(reqBody)
	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	AuthMiddleware(srv.Handler()).ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", w.Code)
	}
}

func TestMcpServer_InvalidToken(t *testing.T) {
	ResetMcpTokenForTesting()
	srv := newTestServer(t)

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "initialize",
		"id":      1,
	}

	body, _ := json.Marshal(reqBody)
	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()

	AuthMiddleware(srv.Handler()).ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with invalid token, got %d", w.Code)
	}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	return newTestServerWithKeywords(t, map[string]string{"secret": "TEXT"})
}

func newTestServerWithKeywords(t *testing.T, keywords map[string]string) *Server {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	cfg := config.NewManager()
	caCertPath := dir + "/ca-cert.pem"
	caKeyPath := dir + "/ca-key.pem"
	ca, err := cert.LoadOrGenerateCA(caCertPath, caKeyPath)
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}
	sess := session.NewManager(0, 1000)
	adm := admin.New(cfg, sess, ca, "", "")

	eng := redact.NewEngine(sess, "__VG_")
	for kw, cat := range keywords {
		eng.AddKeyword(kw, cat)
	}

	return NewServer(cfg, adm, eng, "test-version")
}

func postJSON(t *testing.T, srv *Server, reqBody map[string]any, token string) map[string]any {
	t.Helper()
	body, _ := json.Marshal(reqBody)
	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()

	handler := AuthMiddleware(srv.Handler())
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
			return map[string]any{"_status": w.Code}
		}
		t.Fatalf("unexpected status: %d, body: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v, body: %s", err, w.Body.String())
	}
	return resp
}
