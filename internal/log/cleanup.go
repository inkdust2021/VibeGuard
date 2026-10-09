package log

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/inkdust2021/vibeguard/internal/config"
)

// fileWriter serializes writes, rotation, and policy changes to the same file.
type fileWriter struct {
	mu           sync.Mutex
	path         string
	file         *os.File
	size         int64
	policy       config.LogCleanupConfig
	lastRotation time.Time
	closed       bool
	stop         chan struct{}
	done         chan struct{}
}

func newFileWriter(path string, policy config.LogCleanupConfig) (*fileWriter, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	w := &fileWriter{path: path, policy: policy, lastRotation: time.Now(), stop: make(chan struct{}), done: make(chan struct{})}
	if err := w.openLocked(); err != nil {
		return nil, err
	}
	go func() {
		defer close(w.done)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case now := <-ticker.C:
				if err := w.rotateIfDue(now); err != nil {
					// Avoid recursively logging an error through this same writer.
					fmt.Fprintf(os.Stderr, "VibeGuard log rotation failed: %v\n", err)
				}
			case <-w.stop:
				return
			}
		}
	}()
	return w, nil
}

func (w *fileWriter) openLocked() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	w.file = f
	w.size = st.Size()
	return nil
}

func (w *fileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, os.ErrClosed
	}
	if w.file == nil {
		if err := w.openLocked(); err != nil {
			return 0, err
		}
	}
	if w.policy.IsEnabled() {
		maxBytes := int64(w.policy.MaxSizeMB) * 1024 * 1024
		if int64(len(p)) > maxBytes {
			return 0, fmt.Errorf("log entry exceeds maximum file size of %d bytes", maxBytes)
		}
		if w.size+int64(len(p)) > maxBytes {
			if err := w.rotateLocked(time.Now()); err != nil {
				return 0, err
			}
		}
	}
	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

// UpdateCleanup takes effect without replacing the writer or interrupting logging.
func (w *fileWriter) UpdateCleanup(policy config.LogCleanupConfig) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.policy.IsEnabled() != policy.IsEnabled() || w.policy.Interval != policy.Interval {
		w.lastRotation = time.Now()
	}
	w.policy = policy
}

func (w *fileWriter) rotateIfDue(now time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || !w.policy.IsEnabled() {
		return nil
	}
	interval, err := config.ParseCleanupInterval(w.policy.Interval)
	if err != nil {
		return err
	}
	if now.Sub(w.lastRotation) < interval {
		return nil
	}
	// Even an empty active log can have old backups that need pruning.
	if w.size == 0 {
		w.lastRotation = now
		return w.pruneLocked()
	}
	return w.rotateLocked(now)
}

func (w *fileWriter) pruneLocked() error {
	files, err := os.ReadDir(filepath.Dir(w.path))
	if err != nil {
		return err
	}
	prefix := filepath.Base(w.path) + "."
	for _, f := range files {
		if f.IsDir() || !strings.HasPrefix(f.Name(), prefix) {
			continue
		}
		suffix := strings.TrimPrefix(f.Name(), prefix)
		number, err := strconv.Atoi(suffix)
		if err == nil && strconv.Itoa(number) == suffix && number > w.policy.MaxBackups {
			if err := os.Remove(filepath.Join(filepath.Dir(w.path), f.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w *fileWriter) rotateLocked(now time.Time) error {
	if err := w.pruneLocked(); err != nil {
		return err
	}
	if w.file != nil {
		if err := w.file.Close(); err != nil {
			return err
		}
		w.file = nil
	}
	// The active path remains stable for the manager's tail/stream endpoints.
	oldest := w.path + "." + strconv.Itoa(w.policy.MaxBackups)
	if err := os.Remove(oldest); err != nil && !os.IsNotExist(err) {
		return err
	}
	for i := w.policy.MaxBackups - 1; i >= 1; i-- {
		from := w.path + "." + strconv.Itoa(i)
		if err := os.Rename(from, w.path+"."+strconv.Itoa(i+1)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.Rename(w.path, w.path+".1"); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := w.openLocked(); err != nil {
		return err
	}
	w.lastRotation = now
	return nil
}

func (w *fileWriter) Close() error {
	w.mu.Lock()
	var err error
	if !w.closed {
		w.closed = true
		close(w.stop)
		if w.file != nil {
			err = w.file.Close()
			w.file = nil
		}
	}
	w.mu.Unlock()
	<-w.done
	return err
}
