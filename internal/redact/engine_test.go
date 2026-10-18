package redact

import (
	"testing"
	"time"

	"github.com/inkdust2021/vibeguard/internal/session"
)

// A placeholder that comes back in a later request (e.g. the model wrote `TOKEN=__VG_...__`)
// must not be wrapped in a second placeholder: restore is single-pass, so the client would
// receive the inner placeholder instead of the original value.
func TestEngineNeverWrapsExistingPlaceholder(t *testing.T) {
	e := NewEngine(session.NewManager(time.Hour, 100), "__VG_")
	if err := e.AddRegex(`TOKEN=(\S{6,})`, "ENV"); err != nil {
		t.Fatal(err)
	}
	first, ms := e.RedactWithMatches([]byte("API_TOKEN=hunter2-FAKE-canary"))
	if len(ms) != 1 {
		t.Fatalf("first pass matches = %d", len(ms))
	}
	second, ms := e.RedactWithMatches(first)
	if len(ms) != 0 || string(second) != string(first) {
		t.Fatalf("placeholder re-redacted: %q -> %q", first, second)
	}
}
