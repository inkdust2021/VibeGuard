package rulelist

import (
	"strings"
	"testing"
)

func TestParse_KeywordAndRegex(t *testing.T) {
	in := strings.NewReader(strings.TrimSpace(`
		# comment
		keyword TEXT  Samuel Porter
		regex   EMAIL (?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}
	`))
	r, err := Parse(in, ParseOptions{Name: "demo", Priority: 60})
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if r == nil {
		t.Fatalf("expected recognizer")
	}
	if got, want := r.priority, 60; got != want {
		t.Fatalf("priority=%d, want %d", got, want)
	}
	if got, want := len(r.keywords), 1; got != want {
		t.Fatalf("keywords=%d, want %d", got, want)
	}
	if got, want := len(r.regex), 1; got != want {
		t.Fatalf("regex=%d, want %d", got, want)
	}
	if got := r.Name(); got != "rulelist:demo" {
		t.Fatalf("Name()=%q", got)
	}

	text := []byte("hi I'm Samuel Porter. My email is Samuel@gmail.com.")
	ms := r.Recognize(text)
	if len(ms) < 2 {
		t.Fatalf("expected >=2 matches, got %d", len(ms))
	}
}

func TestParse_InvalidLine(t *testing.T) {
	in := strings.NewReader("unknown TEXT abc")
	_, err := Parse(in, ParseOptions{})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestRecognizer_RegexUsesFirstCaptureGroup(t *testing.T) {
	in := strings.NewReader(`regex EMAIL (?i)(?:^|\D)([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})(?:$|\D)`)
	r, err := Parse(in, ParseOptions{Priority: 50})
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	text := []byte("x Samuel@gmail.com y")
	ms := r.Recognize(text)
	if len(ms) != 1 {
		t.Fatalf("expected 1 match, got %d", len(ms))
	}
	m := ms[0]
	if got := string(text[m.Start:m.End]); got != "Samuel@gmail.com" {
		t.Fatalf("matched=%q, want %q", got, "Samuel@gmail.com")
	}
}
