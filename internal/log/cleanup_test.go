package log

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/inkdust2021/vibeguard/internal/config"
)

func logPolicy(enabled bool) config.LogCleanupConfig {
	return config.LogCleanupConfig{Enabled: &enabled, Interval: "1h", MaxSizeMB: 1, MaxBackups: 2}
}

func TestLogSizeRotationBoundsBackups(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.log")
	w, err := newFileWriter(path, logPolicy(true))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for i := 0; i < 5; i++ {
		if _, err := w.Write(bytes.Repeat([]byte{byte('a' + i)}, 700*1024)); err != nil {
			t.Fatal(err)
		}
	}
	for suffix, want := range map[string]byte{"": 'e', ".1": 'd', ".2": 'c'} {
		b, err := os.ReadFile(path + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) != 700*1024 || b[0] != want {
			t.Fatalf("bad log %s: length %d", suffix, len(b))
		}
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Fatalf("too many backups: %v", err)
	}
}

func TestLogDisabledAndLiveEnable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.log")
	w, err := newFileWriter(path, logPolicy(false))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	chunk := bytes.Repeat([]byte("x"), 700*1024)
	for i := 0; i < 3; i++ {
		if _, err := w.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.rotateIfDue(time.Now().Add(48 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Size() != int64(3*len(chunk)) {
		t.Fatalf("disabled log changed: %v %v", st, err)
	}
	w.UpdateCleanup(logPolicy(true))
	if _, err := w.Write([]byte("new")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "new" {
		t.Fatalf("enable failed: %q %v", b, err)
	}
}

func TestLogIntervalAndBackupReduction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.log")
	w, err := newFileWriter(path, logPolicy(true))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	now := time.Now()
	for i := 0; i < 3; i++ {
		if _, err := w.Write([]byte("line\n")); err != nil {
			t.Fatal(err)
		}
		if err := w.rotateIfDue(now.Add(time.Duration(i+1)*time.Hour + time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	policy := logPolicy(true)
	policy.MaxBackups = 1
	policy.Interval = "2h"
	w.UpdateCleanup(policy)
	if _, err := w.Write([]byte("latest\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.rotateIfDue(now.Add(5 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path + ".1")
	if err != nil || string(b) != "latest\n" {
		t.Fatalf("time rotation failed: %q %v", b, err)
	}
	if _, err := os.Stat(path + ".2"); !os.IsNotExist(err) {
		t.Fatal("old backup not pruned")
	}
}

func TestLogConcurrentRotationPreservesWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.log")
	policy := logPolicy(true)
	policy.MaxBackups = 100
	w, err := newFileWriter(path, policy)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if _, err := w.Write(bytes.Repeat([]byte("x"), 20*1024)); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, f := range files {
		st, err := f.Info()
		if err != nil {
			t.Fatal(err)
		}
		total += st.Size()
	}
	if total != 4*20*20*1024 {
		t.Fatalf("lost log data: %d", total)
	}
	if _, err := w.Write([]byte("closed")); err == nil {
		t.Fatal("write after close accepted")
	}
}
