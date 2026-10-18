package stream

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/inkdust2021/vibeguard/internal/restore"
	"github.com/inkdust2021/vibeguard/internal/session"
)

func responsesDelta(t *testing.T, text string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"type": "response.output_text.delta", "delta": text})
	if err != nil {
		t.Fatal(err)
	}
	return "event: response.output_text.delta\ndata: " + string(b) + "\n\n"
}

// A delta ending in "_" is held back (it may start a placeholder). The emitted part must not be
// overwritten when the held-back tail is compacted to the front of the buffer.
func TestTextStreamRestorerDoesNotAliasBuffer(t *testing.T) {
	eng := restore.NewEngine(session.NewManager(time.Hour, 100), "__VG_")
	stream := responsesDelta(t, "snake_") + responsesDelta(t, "case done") + "event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n"
	out, err := io.ReadAll(NewSSERestoringReader(io.NopCloser(strings.NewReader(stream)), eng))
	if err != nil {
		t.Fatal(err)
	}
	var text strings.Builder
	for _, ev := range strings.Split(string(out), "\n\n") {
		for _, ln := range strings.Split(ev, "\n") {
			if !strings.HasPrefix(ln, "data: {") {
				continue
			}
			var obj struct {
				Delta string `json:"delta"`
			}
			_ = json.Unmarshal([]byte(strings.TrimPrefix(ln, "data: ")), &obj)
			text.WriteString(obj.Delta)
		}
	}
	if text.String() != "snake_case done" {
		t.Fatalf("got %q, want %q", text.String(), "snake_case done")
	}
}
