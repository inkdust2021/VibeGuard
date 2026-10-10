package main_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	binPathOnce sync.Once
	binPath     string
	binBuildErr error
)

// buildVibeguardOnce 编译 vibeguard 二进制（仅一次，所有 E2E 测试共享）。
func buildVibeguardOnce(t *testing.T) string {
	t.Helper()
	binPathOnce.Do(func() {
		dir, err := os.MkdirTemp("", "vibeguard-e2e-bin-*")
		if err != nil {
			binBuildErr = err
			return
		}
		bin := filepath.Join(dir, "vibeguard")
		wd, err := os.Getwd()
		if err != nil {
			binBuildErr = err
			return
		}
		build := exec.Command("go", "build", "-o", bin, ".")
		build.Dir = wd
		if out, err := build.CombinedOutput(); err != nil {
			binBuildErr = fmt.Errorf("build failed: %v\n%s", err, out)
			return
		}
		binPath = bin
	})
	if binBuildErr != nil {
		t.Fatalf("build vibeguard: %v", binBuildErr)
	}
	return binPath
}

// startVibeguard 启动一个独立的 vibeguard 进程，返回基础 URL、token 和清理函数。
//
// 使用临时目录作为 HOME，OS 分配随机端口（先抢占再写 config）。
func startVibeguard(t *testing.T) (baseURL, token string, cleanup func()) {
	return startVibeguardWithKeywords(t)
}

// startVibeguardWithKeywords 启动 vibeguard，并注入若干关键词规则（category 统一为 TEST）。
func startVibeguardWithKeywords(t *testing.T, keywords ...string) (baseURL, token string, cleanup func()) {
	t.Helper()

	bin := buildVibeguardOnce(t)

	// 1. 准备临时 HOME 和 config dir
	tmpHome := t.TempDir()
	configDir := filepath.Join(tmpHome, ".vibeguard")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}

	// 2. 抢占一个随机端口
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	// 3. 写最小 config，覆盖默认监听端口
	// 显式提供空的 patterns 配置，避免加载默认 rule_lists（会让代理走 pipeline 模式，detect 不可用）
	configPath := filepath.Join(configDir, "config.yaml")

	var keywordsYAML strings.Builder
	if len(keywords) == 0 {
		keywordsYAML.WriteString("[]")
	} else {
		keywordsYAML.WriteString("\n")
		for _, kw := range keywords {
			fmt.Fprintf(&keywordsYAML, `    - value: %q
      category: "TEST"
`, kw)
		}
	}

	configYAML := fmt.Sprintf(`proxy:
  listen: "%s"
  intercept_mode: "global"
patterns:
  keywords: %s
  regex: []
  builtin: []
  rule_lists: []
  ner:
    enabled: false
session:
  ttl: "1h"
  max_mappings: 1000
log:
  level: "error"
`, listenAddr, keywordsYAML.String())
	if err := os.WriteFile(configPath, []byte(configYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// 4. 启动进程
	cmd := exec.Command(bin, "start", "--foreground", "--config", configPath)
	cmd.Env = append(os.Environ(),
		"HOME="+tmpHome,
		"VIBEGUARD_LANG=en",
	)
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	cmd.Stdout = stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start vibeguard: %v", err)
	}

	// 5. 等待端口就绪
	baseURL = "http://" + listenAddr
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", listenAddr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 6. 触发 token 生成
	probe, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", bytes.NewReader([]byte("{}")))
	probe.Header.Set("Content-Type", "application/json")
	if r, err := http.DefaultClient.Do(probe); err == nil {
		r.Body.Close()
	}

	// 7. 读取 token 文件
	tokenPath := filepath.Join(configDir, "mcp_token")
	tokenDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(tokenDeadline) {
		data, err := os.ReadFile(tokenPath)
		if err == nil && len(data) > 0 {
			token = strings.TrimSpace(string(data))
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	cleanup = func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			t.Logf("vibeguard stderr:\n%s", stderr.String())
		}
	}

	if token == "" {
		cleanup()
		t.Fatalf("token not generated within timeout (config dir: %s)", configDir)
	}

	return baseURL, token, cleanup
}

// postMCP 发送一个 MCP JSON-RPC 请求，返回响应 map。
func postMCP(t *testing.T, baseURL, token string, body map[string]any) map[string]any {
	t.Helper()
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post /mcp: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, string(respBody))
	}
	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		t.Fatalf("parse response: %v\nbody: %s", err, string(respBody))
	}
	return result
}

func TestE2E_Initialize(t *testing.T) {
	if testing.Short() {
		t.Skip("skip E2E in short mode")
	}

	baseURL, token, cleanup := startVibeguard(t)
	defer cleanup()

	resp := postMCP(t, baseURL, token, map[string]any{
		"jsonrpc": "2.0",
		"method":  "initialize",
		"id":      1,
	})

	if resp["jsonrpc"] != "2.0" {
		t.Errorf("expected jsonrpc=2.0, got %v", resp["jsonrpc"])
	}
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected result object, got %v", resp)
	}
	serverInfo := result["serverInfo"].(map[string]any)
	if serverInfo["name"] != "vibeguard" {
		t.Errorf("expected name=vibeguard, got %v", serverInfo["name"])
	}
}

func TestE2E_ToolsList(t *testing.T) {
	if testing.Short() {
		t.Skip("skip E2E in short mode")
	}

	baseURL, token, cleanup := startVibeguard(t)
	defer cleanup()

	resp := postMCP(t, baseURL, token, map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/list",
		"id":      1,
	})

	result := resp["result"].(map[string]any)
	tools := result["tools"].([]any)

	// 5 个工具：get_proxy_status, detect_sensitive, preview_redacted, list_keywords, list_rule_lists
	if len(tools) != 5 {
		t.Errorf("expected 5 tools, got %d", len(tools))
	}

	names := make(map[string]bool)
	for _, tool := range tools {
		t := tool.(map[string]any)
		names[t["name"].(string)] = true
	}
	expected := []string{"get_proxy_status", "detect_sensitive", "preview_redacted", "list_keywords", "list_rule_lists"}
	for _, name := range expected {
		if !names[name] {
			t.Errorf("expected tool %s in list", name)
		}
	}
}

func TestE2E_GetProxyStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skip E2E in short mode")
	}

	baseURL, token, cleanup := startVibeguard(t)
	defer cleanup()

	resp := postMCP(t, baseURL, token, map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "get_proxy_status",
			"arguments": map[string]any{},
		},
		"id": 1,
	})

	result := resp["result"].(map[string]any)
	content := result["content"].([]any)
	textItem := content[0].(map[string]any)

	var status map[string]any
	if err := json.Unmarshal([]byte(textItem["text"].(string)), &status); err != nil {
		t.Fatalf("parse status: %v", err)
	}

	for _, field := range []string{"version", "started_at", "total_requests", "intercept_mode", "listen_address"} {
		if _, ok := status[field]; !ok {
			t.Errorf("missing field: %s", field)
		}
	}
}

func TestE2E_DetectSensitive(t *testing.T) {
	if testing.Short() {
		t.Skip("skip E2E in short mode")
	}

	baseURL, token, cleanup := startVibeguardWithKeywords(t, "topsecret123")
	defer cleanup()

	resp := postMCP(t, baseURL, token, map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": map[string]any{
			"name": "detect_sensitive",
			"arguments": map[string]any{
				"text": "this contains topsecret123 keyword",
			},
		},
		"id": 1,
	})

	if errObj, ok := resp["error"]; ok {
		t.Fatalf("unexpected error: %v", errObj)
	}
	result := resp["result"].(map[string]any)
	content := result["content"].([]any)
	textItem := content[0].(map[string]any)

	var detect map[string]any
	if err := json.Unmarshal([]byte(textItem["text"].(string)), &detect); err != nil {
		t.Fatalf("parse detect: %v", err)
	}

	if detect["has_sensitive"] != true {
		t.Errorf("expected has_sensitive=true, got %v", detect["has_sensitive"])
	}
	matches := detect["matches"].([]any)
	if len(matches) == 0 {
		t.Fatal("expected at least one match")
	}
	hit := matches[0].(map[string]any)
	if hit["category"] != "TEST" {
		t.Errorf("expected category=TEST, got %v", hit["category"])
	}
	// 默认不返回 original
	if _, ok := hit["original"]; ok {
		t.Error("expected no original field by default")
	}
}

func TestE2E_DetectSensitive_WithOriginals(t *testing.T) {
	if testing.Short() {
		t.Skip("skip E2E in short mode")
	}

	baseURL, token, cleanup := startVibeguardWithKeywords(t, "topsecret123")
	defer cleanup()

	resp := postMCP(t, baseURL, token, map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": map[string]any{
			"name": "detect_sensitive",
			"arguments": map[string]any{
				"text":              "this contains topsecret123 keyword",
				"include_originals": true,
			},
		},
		"id": 1,
	})

	result := resp["result"].(map[string]any)
	content := result["content"].([]any)
	textItem := content[0].(map[string]any)

	var detect map[string]any
	json.Unmarshal([]byte(textItem["text"].(string)), &detect)

	matches := detect["matches"].([]any)
	hit := matches[0].(map[string]any)
	if hit["original"] != "topsecret123" {
		t.Errorf("expected original=topsecret123, got %v", hit["original"])
	}
}

func TestE2E_PreviewRedacted(t *testing.T) {
	if testing.Short() {
		t.Skip("skip E2E in short mode")
	}

	baseURL, token, cleanup := startVibeguardWithKeywords(t, "mysecret")
	defer cleanup()

	resp := postMCP(t, baseURL, token, map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": map[string]any{
			"name": "preview_redacted",
			"arguments": map[string]any{
				"text": "leak: mysecret here",
			},
		},
		"id": 1,
	})

	if errObj, ok := resp["error"]; ok {
		t.Fatalf("unexpected error: %v", errObj)
	}
	result := resp["result"].(map[string]any)
	content := result["content"].([]any)
	textItem := content[0].(map[string]any)

	var preview map[string]any
	json.Unmarshal([]byte(textItem["text"].(string)), &preview)

	if preview["match_count"] != float64(1) {
		t.Errorf("expected match_count=1, got %v", preview["match_count"])
	}
	redacted := preview["redacted_text"].(string)
	if strings.Contains(redacted, "mysecret") {
		t.Errorf("expected mysecret to be redacted, got: %s", redacted)
	}
	if !strings.Contains(redacted, "__VG_TEST_PREVIEW__") {
		t.Errorf("expected placeholder in redacted text, got: %s", redacted)
	}
}

func TestE2E_ListKeywords(t *testing.T) {
	if testing.Short() {
		t.Skip("skip E2E in short mode")
	}

	baseURL, token, cleanup := startVibeguard(t)
	defer cleanup()

	resp := postMCP(t, baseURL, token, map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "list_keywords",
			"arguments": map[string]any{},
		},
		"id": 1,
	})

	if errObj, ok := resp["error"]; ok {
		t.Fatalf("unexpected error: %v", errObj)
	}
	result := resp["result"].(map[string]any)
	content := result["content"].([]any)
	textItem := content[0].(map[string]any)

	var listResult map[string]any
	if err := json.Unmarshal([]byte(textItem["text"].(string)), &listResult); err != nil {
		t.Fatalf("parse list_keywords: %v", err)
	}

	if _, ok := listResult["keywords"]; !ok {
		t.Error("missing keywords field")
	}
	if _, ok := listResult["count"]; !ok {
		t.Error("missing count field")
	}
}

func TestE2E_ListRuleLists(t *testing.T) {
	if testing.Short() {
		t.Skip("skip E2E in short mode")
	}

	baseURL, token, cleanup := startVibeguard(t)
	defer cleanup()

	resp := postMCP(t, baseURL, token, map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "list_rule_lists",
			"arguments": map[string]any{},
		},
		"id": 1,
	})

	if errObj, ok := resp["error"]; ok {
		t.Fatalf("unexpected error: %v", errObj)
	}
	result := resp["result"].(map[string]any)
	content := result["content"].([]any)
	textItem := content[0].(map[string]any)

	var listResult map[string]any
	if err := json.Unmarshal([]byte(textItem["text"].(string)), &listResult); err != nil {
		t.Fatalf("parse list_rule_lists: %v", err)
	}

	if _, ok := listResult["rule_lists"]; !ok {
		t.Error("missing rule_lists field")
	}
	if _, ok := listResult["count"]; !ok {
		t.Error("missing count field")
	}
}

func TestE2E_AuthRequired(t *testing.T) {
	if testing.Short() {
		t.Skip("skip E2E in short mode")
	}

	baseURL, _, cleanup := startVibeguard(t)
	defer cleanup()

	// 不带 token
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", bytes.NewReader([]byte(`{"jsonrpc":"2.0","method":"initialize","id":1}`)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", resp.StatusCode)
	}
}

func TestE2E_InvalidToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skip E2E in short mode")
	}

	baseURL, _, cleanup := startVibeguard(t)
	defer cleanup()

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/mcp", bytes.NewReader([]byte(`{"jsonrpc":"2.0","method":"initialize","id":1}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 with invalid token, got %d", resp.StatusCode)
	}
}
