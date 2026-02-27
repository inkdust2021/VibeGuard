package admin

import (
	"embed"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

//go:embed static
var staticFS embed.FS

// Handler returns the HTTP handler for the admin UI
func (a *Admin) Handler() http.Handler {
	mux := http.NewServeMux()

	// API routes (under /manager/api/)
	mux.HandleFunc("/manager/api/auth/status", a.handleAuthStatus)
	mux.HandleFunc("/manager/api/auth/setup", a.handleAuthSetup)
	mux.HandleFunc("/manager/api/auth/login", a.handleAuthLogin)
	mux.HandleFunc("/manager/api/auth/logout", a.handleAuthLogout)
	mux.HandleFunc("/manager/api/stats", a.handleStats)
	mux.HandleFunc("/manager/api/stats/stream", a.handleStatsStream)
	mux.HandleFunc("/manager/api/patterns", a.handlePatterns)
	mux.HandleFunc("/manager/api/patterns/", a.handlePatternsItem)
	mux.HandleFunc("/manager/api/sessions", a.handleSessions)
	mux.HandleFunc("/manager/api/certificates", a.handleCertificates)
	mux.HandleFunc("/manager/api/certificates/trust", a.handleCertTrust)
	mux.HandleFunc("/manager/api/certificates/regenerate", a.handleCertRegenerate)
	mux.HandleFunc("/manager/api/audit", a.handleAudit)
	mux.HandleFunc("/manager/api/audit/privacy", a.handleAuditPrivacy)
	mux.HandleFunc("/manager/api/audit/stream", a.handleAuditStream)
	mux.HandleFunc("/manager/api/logs", a.handleLogs)
	mux.HandleFunc("/manager/api/logs/stream", a.handleLogsStream)
	mux.HandleFunc("/manager/api/settings", a.handleSettings)

	// Static files - serve from embedded FS
	staticContent, err := fs.Sub(staticFS, "static")
	if err != nil {
		slog.Error("Failed to load static files", "error", err)
	}

	fileServer := http.FileServer(http.FS(staticContent))

	// Serve static files at /manager/*
	mux.Handle("/manager/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// SPA fallback - serve index.html for non-file routes
		path := strings.TrimPrefix(r.URL.Path, "/manager/")

		// If path is empty or looks like a route (no extension), serve index.html
		if path == "" || !strings.Contains(path, ".") {
			r.URL.Path = "/manager/"
			http.StripPrefix("/manager", http.FileServer(http.FS(staticContent))).ServeHTTP(w, r)
			return
		}

		// Serve static file
		http.StripPrefix("/manager", fileServer).ServeHTTP(w, r)
	}))

	// Add logging middleware
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		// 管理端鉴权：所有 /manager/api/* 默认需要先登录（首访未设置密码则先走 setup）。
		if strings.HasPrefix(r.URL.Path, "/manager/api/") && !isManagerPublicAPI(r.URL.Path) {
			if a == nil || a.auth == nil {
				http.Error(w, "Admin auth not initialized", http.StatusInternalServerError)
				return
			}
			if ok := a.auth.Require(w, r); !ok {
				return
			}
		}

		mux.ServeHTTP(w, r)
		slog.Debug("Admin request", "method", r.Method, "path", r.URL.Path, "duration", time.Since(start))
	})
}

func isManagerPublicAPI(path string) bool {
	switch path {
	case "/manager/api/settings",
		"/manager/api/auth/status",
		"/manager/api/auth/setup",
		"/manager/api/auth/login",
		"/manager/api/auth/logout":
		return true
	default:
		return false
	}
}
