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
		mux.ServeHTTP(w, r)
		slog.Debug("Admin request", "method", r.Method, "path", r.URL.Path, "duration", time.Since(start))
	})
}
