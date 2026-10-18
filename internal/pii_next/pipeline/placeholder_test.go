package pipeline

import (
	"strings"
	"testing"
	"time"

	"github.com/inkdust2021/vibeguard/internal/pii_next/rulelist"
	"github.com/inkdust2021/vibeguard/internal/session"
)

func TestPipelineNeverWrapsExistingPlaceholder(t *testing.T) {
	rec, err := rulelist.Parse(strings.NewReader("regex ENV (?:^|[^A-Z0-9_])[A-Z0-9_]*TOKEN=([^\\s]{6,})\n"), rulelist.ParseOptions{Name: "t", Priority: 50})
	if err != nil {
		t.Fatal(err)
	}
	p := New(session.NewManager(time.Hour, 100), "__VG_", rec)
	first, ms := p.RedactWithMatches([]byte("API_TOKEN=hunter2-FAKE-canary"))
	if len(ms) != 1 {
		t.Fatalf("first pass matches = %d", len(ms))
	}
	second, ms := p.RedactWithMatches(first)
	if len(ms) != 0 || string(second) != string(first) {
		t.Fatalf("placeholder re-redacted: %q -> %q", first, second)
	}
}
