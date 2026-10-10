package mcp

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/inkdust2021/vibeguard/internal/config"
)

const mcpTokenFile = "mcp_token"

var (
	mcpTokenOnce sync.Once
	mcpTokenVal  string
	mcpTokenErr  error
)

// AuthMiddleware 包装 MCP handler，进行 Bearer Token 认证
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := getOrCreateMcpToken()
		if err != nil {
			http.Error(w, "MCP auth not available", http.StatusServiceUnavailable)
			return
		}

		bearer := extractBearerToken(r)
		if bearer == "" || bearer != token {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func extractBearerToken(r *http.Request) string {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// getOrCreateMcpToken 返回 MCP token，如果不存在则自动生成
func getOrCreateMcpToken() (string, error) {
	mcpTokenOnce.Do(func() {
		mcpTokenVal, mcpTokenErr = loadOrGenerateMcpToken()
	})
	return mcpTokenVal, mcpTokenErr
}

func mcpTokenPath() string {
	return filepath.Join(config.GetConfigDir(), mcpTokenFile)
}

func loadOrGenerateMcpToken() (string, error) {
	path := mcpTokenPath()

	// 尝试读取已有 token
	data, err := os.ReadFile(path)
	if err == nil {
		tok := strings.TrimSpace(string(data))
		if tok != "" {
			return tok, nil
		}
	}

	// 不存在则生成新的随机 token
	tok, err := generateRandomToken(32)
	if err != nil {
		return "", err
	}

	// 写入文件（权限 0600）
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
		return "", err
	}

	return tok, nil
}

func generateRandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ResetMcpTokenForTesting 重置 token（仅用于测试）
func ResetMcpTokenForTesting() {
	mcpTokenOnce = sync.Once{}
	mcpTokenVal = ""
	mcpTokenErr = nil
}
