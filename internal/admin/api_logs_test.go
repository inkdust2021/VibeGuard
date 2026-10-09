package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/inkdust2021/vibeguard/internal/config"
)

type streamLogRecorder struct {
	*httptest.ResponseRecorder
	events chan string
}

func (w *streamLogRecorder) Flush() { w.events <- w.Body.String(); w.Body.Reset() }

func TestLogStreamFollowsReplacementLargerThanOldFile(t *testing.T) {
	a := settingsAdmin(t)
	path := filepath.Join(t.TempDir(), "runtime.log")
	if err := os.WriteFile(path, []byte("old line\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.config.Update(func(c *config.Config) { c.Log.File = path }); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	w := &streamLogRecorder{ResponseRecorder: httptest.NewRecorder(), events: make(chan string, 10)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.handleLogsStream(w, httptest.NewRequest(http.MethodGet, "/manager/api/logs/stream", nil).WithContext(ctx))
	}()
	defer func() { cancel(); <-done }()
	select {
	case <-w.events:
	case <-time.After(5 * time.Second):
		t.Fatal("no initial stream event")
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	// Same path, new inode, and a larger size: size-only rotation detection misses the start.
	if err := os.WriteFile(path, []byte("new first line\nnew second line\n"), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-w.events:
		if !strings.Contains(event, "new first line") {
			t.Fatalf("new file beginning skipped: %s", event)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no replacement stream event")
	}
}
