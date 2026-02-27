package admin

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAuthManager_SetupAndVerify(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "admin_auth.json")

	a := NewAuthManager(path)
	if cfg, _, broken, _ := a.Status(nil); cfg || broken {
		t.Fatalf("unexpected status: configured=%v broken=%v", cfg, broken)
	}

	if err := a.Setup("short"); err == nil {
		t.Fatalf("Setup() expected error for short password")
	}

	if err := a.Setup("password123"); err != nil {
		t.Fatalf("Setup() error: %v", err)
	}

	if err := a.Setup("password123"); err == nil {
		t.Fatalf("Setup() expected error when already configured")
	}

	if runtime.GOOS != "windows" {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat() error: %v", err)
		}
		if got, want := st.Mode().Perm(), os.FileMode(0o600); got != want {
			t.Fatalf("auth file perms=%#o, want %#o", got, want)
		}
	}

	a2 := NewAuthManager(path)
	if cfg, _, broken, _ := a2.Status(nil); !cfg || broken {
		t.Fatalf("unexpected status after reload: configured=%v broken=%v", cfg, broken)
	}

	if err := a2.Verify("wrong"); err == nil {
		t.Fatalf("Verify() expected error for wrong password")
	}
	if err := a2.Verify("password123"); err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
}
