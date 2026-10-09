package config

import (
	"os"
	"path/filepath"
	"testing"
)

func cleanupManager(t *testing.T, global, project string) *Manager {
	t.Helper()
	dir := t.TempDir()
	m := NewManager()
	m.configPath = filepath.Join(dir, "config.yaml")
	m.projectPath = filepath.Join(dir, "project.yaml")
	if err := os.WriteFile(m.configPath, []byte(global), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.projectPath, []byte(project), 0600); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestCleanupDefaultsAndOverrides(t *testing.T) {
	m := cleanupManager(t, "log:\n  level: warn\n", "")
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	c := m.Get().Cleanup
	if !c.Log.IsEnabled() || c.Log.Interval != "24h" || c.Log.MaxSizeMB != 10 || c.Log.MaxBackups != 3 || !c.SessionWAL.IsEnabled() || c.SessionWAL.Interval != "1h" {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	m = cleanupManager(t, "cleanup:\n  log:\n    interval: 2h\n    max_size_mb: 5\n  session_wal:\n    enabled: false\n", "cleanup:\n  log:\n    enabled: false\n    max_backups: 2\n  session_wal:\n    interval: 3h\n")
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	c = m.Get().Cleanup
	if c.Log.IsEnabled() || c.Log.Interval != "2h" || c.Log.MaxSizeMB != 5 || c.Log.MaxBackups != 2 || c.SessionWAL.IsEnabled() || c.SessionWAL.Interval != "3h" {
		t.Fatalf("incorrect partial override: %+v", c)
	}
}

func TestCleanupRejectsInvalidConfig(t *testing.T) {
	for _, fields := range []string{"interval: nonsense", "interval: -1h", "interval: 0s", "interval: 1s", "max_size_mb: -1", "max_backups: -1"} {
		t.Run(fields, func(t *testing.T) {
			m := cleanupManager(t, "cleanup:\n  log:\n    "+fields+"\n", "")
			if err := m.Load(); err == nil {
				t.Fatal("invalid cleanup policy accepted")
			}
		})
	}
}

func TestCleanupDurationDays(t *testing.T) {
	d, err := ParseCleanupInterval("7d")
	if err != nil || d.Hours() != 168 {
		t.Fatalf("days: %v, %v", d, err)
	}
}
