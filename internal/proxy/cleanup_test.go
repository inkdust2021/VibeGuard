package proxy

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/inkdust2021/vibeguard/internal/cert"
	"github.com/inkdust2021/vibeguard/internal/config"
	"github.com/inkdust2021/vibeguard/internal/session"
)

func TestRestoreFailurePreservesOriginalWAL(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("VIBEGUARD_CONFIG", filepath.Join(dir, "config.yaml"))
	path := filepath.Join(dir, "session.wal")
	original := []byte("synthetic recoverable history")
	if err := os.WriteFile(path, original, 0200); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(path); err == nil {
		t.Skip("file read permissions are not enforced on this platform/user")
	}
	caPath, keyPath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	ca, err := cert.LoadOrGenerateCA(caPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.NewManager()
	if err := cfg.Update(func(c *config.Config) { c.Session.WALPath = path; c.Patterns.RuleLists = nil }); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(cfg, ca, caPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Stop()
	// Later hot reload/cleanup must not erase a WAL that was never successfully restored.
	server.ReloadFromConfig()
	if err := server.session.CompactWAL(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("unrestored WAL overwritten: %q %v", got, err)
	}
}

func TestUndecryptableRestorePreservesOriginalWAL(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("VIBEGUARD_CONFIG", filepath.Join(dir, "config.yaml"))
	path := filepath.Join(dir, "session.wal")
	wal, err := session.NewWAL(path, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := wal.Append(session.WALEntry{Placeholder: "old", Original: "synthetic-secret", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := wal.Close(); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	caPath, keyPath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	ca, err := cert.LoadOrGenerateCA(caPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.NewManager()
	if err := cfg.Update(func(c *config.Config) { c.Session.WALPath = path; c.Patterns.RuleLists = nil }); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(cfg, ca, caPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Stop()
	server.ReloadFromConfig()
	server.session.Register("new", "new-value")
	if err := server.session.CompactWAL(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatal("WAL encrypted with another key overwritten after restore failure")
	}
}
