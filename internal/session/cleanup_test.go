package session

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func cleanupWAL(t *testing.T) *WAL {
	t.Helper()
	w, err := NewWAL(filepath.Join(t.TempDir(), "session.wal"), bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

func TestWALCompactionPreservesLiveMappings(t *testing.T) {
	w := cleanupWAL(t)
	m := NewManager(time.Hour, 2)
	defer m.Close()
	m.AttachWAL(w)
	old := time.Now().Add(-2 * time.Hour)
	m.register("old", "expired-secret", old, true)
	created := time.Now().Add(-time.Minute)
	m.register("live", "synthetic-secret", created, true)
	before, err := os.Stat(w.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.CompactWAL(); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(w.path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() >= before.Size() {
		t.Fatal("WAL did not shrink")
	}
	entries, err := w.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Placeholder != "live" || !entries[0].CreatedAt.Equal(created) {
		t.Fatalf("live mapping damaged: %+v", entries)
	}
	raw, err := os.ReadFile(w.path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("synthetic-secret")) {
		t.Fatal("plaintext WAL")
	}
	// Windows FileMode does not represent Unix permission bits.
	if runtime.GOOS != "windows" && after.Mode().Perm() != 0600 {
		t.Fatalf("unsafe permissions: %v", after.Mode())
	}
	m.Register("new", "another-secret")
	restored := NewManager(time.Hour, 2)
	defer restored.Close()
	if err := w.RestoreInto(restored); err != nil {
		t.Fatal(err)
	}
	if restored.Size() != 2 {
		t.Fatalf("failed restore after append: %d", restored.Size())
	}
}

func TestWALCleanupDisabledThenEnabled(t *testing.T) {
	w := cleanupWAL(t)
	m := NewManager(time.Hour, 2)
	defer m.Close()
	m.AttachWAL(w)
	m.register("expired", "old", time.Now().Add(-2*time.Hour), true)
	m.Register("live", "current")
	m.ConfigureWALCleanup(false, time.Minute)
	m.cleanup()
	entries, err := w.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatal("disabled cleanup changed WAL")
	}
	m.ConfigureWALCleanup(true, time.Minute)
	m.mu.Lock()
	m.lastWALCleanup = time.Now().Add(-2 * time.Minute)
	m.mu.Unlock()
	m.cleanup()
	entries, err = w.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Placeholder != "live" {
		t.Fatalf("scheduled cleanup failed: %+v", entries)
	}
}

func TestWALCompactionDropsEvictedMappings(t *testing.T) {
	w := cleanupWAL(t)
	m := NewManager(time.Hour, 1)
	defer m.Close()
	m.AttachWAL(w)
	m.Register("first", "one")
	m.Register("second", "two")
	if err := m.CompactWAL(); err != nil {
		t.Fatal(err)
	}
	entries, err := w.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Placeholder != "second" {
		t.Fatalf("evicted mapping survived: %+v", entries)
	}
}

func TestWALReplaceFailurePreservesPreviousFile(t *testing.T) {
	w := cleanupWAL(t)
	if err := w.Append(WALEntry{Placeholder: "one", Original: "original", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(w.path)
	if err != nil {
		t.Fatal(err)
	}
	// Replacing a directory must fail without removing that directory or the previous WAL.
	original := w.path
	blocked := filepath.Join(filepath.Dir(original), "blocked")
	if err := os.Mkdir(blocked, 0700); err != nil {
		t.Fatal(err)
	}
	w.path = blocked
	if err := w.Replace(nil); err == nil {
		t.Fatal("replace directory succeeded")
	}
	w.path = original
	after, err := os.ReadFile(original)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("previous WAL lost: %v", err)
	}
	if err := w.Append(WALEntry{Placeholder: "two", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	entries, err := w.Load()
	if err != nil || len(entries) != 2 {
		t.Fatalf("append after failure: %+v %v", entries, err)
	}
	files, err := os.ReadDir(filepath.Dir(original))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatal("temporary file leaked")
	}
}

func TestWALConcurrentCompactionAndRegistration(t *testing.T) {
	w := cleanupWAL(t)
	m := NewManager(time.Hour, 100)
	defer m.Close()
	m.AttachWAL(w)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 30; i++ {
			m.Register(fmt.Sprintf("p%d", i), fmt.Sprintf("v%d", i))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			if err := m.CompactWAL(); err != nil {
				t.Error(err)
			}
		}
	}()
	wg.Wait()
	entries, err := w.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 30 {
		t.Fatalf("lost concurrent mappings: %d", len(entries))
	}
}

func TestWALCompactionKeepsChronologicalRestoreOrder(t *testing.T) {
	w := cleanupWAL(t)
	m := NewManager(time.Hour, 100)
	defer m.Close()
	m.AttachWAL(w)
	base := time.Now().Add(-30 * time.Minute)
	for i := 0; i < 100; i++ {
		m.register(fmt.Sprintf("p%03d", i), fmt.Sprintf("v%03d", i), base.Add(time.Duration(i)*time.Second), true)
	}
	if err := m.CompactWAL(); err != nil {
		t.Fatal(err)
	}
	restored := NewManager(time.Hour, 5)
	defer restored.Close()
	if err := w.RestoreInto(restored); err != nil {
		t.Fatal(err)
	}
	for i := 95; i < 100; i++ {
		if _, ok := restored.Lookup(fmt.Sprintf("p%03d", i)); !ok {
			t.Fatalf("newest mapping %d lost after capacity reduction", i)
		}
	}
}

func TestWALPartialRestoreReportsIntegrityError(t *testing.T) {
	for _, tail := range [][]byte{{0, 0, 0, 2, 1, 2}, {0, 0, 0}} {
		t.Run(fmt.Sprintf("tail-%d", len(tail)), func(t *testing.T) {
			w := cleanupWAL(t)
			if err := w.Append(WALEntry{Placeholder: "valid", Original: "synthetic", CreatedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			f, err := os.OpenFile(w.path, os.O_WRONLY|os.O_APPEND, 0600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.Write(tail); err != nil {
				t.Fatal(err)
			}
			if err = f.Close(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(w.path)
			if err != nil {
				t.Fatal(err)
			}
			m := NewManager(time.Hour, 10)
			defer m.Close()
			if err := w.RestoreInto(m); err == nil {
				t.Fatal("partial restore incorrectly reported success")
			}
			if _, ok := m.Lookup("valid"); !ok {
				t.Fatal("valid prefix not recovered")
			}
			after, err := os.ReadFile(w.path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("partial restore changed original WAL")
			}
		})
	}
}
