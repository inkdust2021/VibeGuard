package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/inkdust2021/vibeguard/internal/config"
)

func settingsAdmin(t *testing.T) *Admin {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("VIBEGUARD_CONFIG", filepath.Join(dir, "config.yaml"))
	t.Setenv("HOME", dir)
	m := config.NewManager()
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	return &Admin{config: m}
}

func TestSettingsCleanupPartialUpdate(t *testing.T) {
	a := settingsAdmin(t)
	r := httptest.NewRequest(http.MethodPost, "/manager/api/settings", bytes.NewBufferString(`{"cleanup":{"log":{"enabled":false,"interval":"2h"}}}`))
	w := httptest.NewRecorder()
	a.updateSettings(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var resp SettingsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Cleanup.Log.IsEnabled() || resp.Cleanup.Log.Interval != "2h" || resp.Cleanup.Log.MaxSizeMB != 10 || !resp.Cleanup.SessionWAL.IsEnabled() {
		t.Fatalf("unexpected response: %+v", resp)
	}
	m := config.NewManager()
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	if m.Get().Cleanup.Log.IsEnabled() {
		t.Fatal("disable was not persisted")
	}
}

func TestSettingsInvalidCleanupDoesNotChangeConfig(t *testing.T) {
	for _, body := range []string{`{"cleanup":{"log":{"interval":"0s"}}}`, `{"cleanup":{"session_wal":{"interval":"invalid"}}}`, `{"cleanup":{"log":{"max_backups":0}}}`, `{"cleanup":{"log":{"max_size_mb":-1}}}`} {
		t.Run(body, func(t *testing.T) {
			a := settingsAdmin(t)
			if err := a.config.Update(func(c *config.Config) {}); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(config.ConfigPath())
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			a.updateSettings(w, httptest.NewRequest(http.MethodPost, "/manager/api/settings", bytes.NewBufferString(body)))
			if w.Code != 400 {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			after, err := os.ReadFile(config.ConfigPath())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("invalid settings persisted")
			}
			if a.config.Get().Cleanup.Log.Interval != "24h" {
				t.Fatal("invalid settings changed memory")
			}
		})
	}
}

func TestSettingsCleanupWriteRequiresAuthentication(t *testing.T) {
	a := settingsAdmin(t)
	a.auth = NewAuthManager(filepath.Join(t.TempDir(), "auth.json"))
	w := httptest.NewRecorder()
	a.handleSettings(w, httptest.NewRequest(http.MethodPost, "/manager/api/settings", bytes.NewBufferString(`{"cleanup":{"log":{"enabled":false}}}`)))
	if w.Code == 200 || !a.config.Get().Cleanup.Log.IsEnabled() {
		t.Fatal("unauthenticated write allowed")
	}
}
