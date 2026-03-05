package secretsources

import (
	"strings"
	"testing"
)

func TestParseDotenvValues_Basic(t *testing.T) {
	in := strings.Join([]string{
		"# comment",
		"OPENAI_API_KEY=sk-1234567890",
		"export ANTHROPIC_API_KEY=\"abc#notcomment\"",
		"FOO=bar # inline comment",
		"EMPTY=",
		"INVALID LINE",
		"QUOTED='hello world'",
		"SPACES =   value   ",
	}, "\n")

	values, err := parseDotenvValues([]byte(in), 1)
	if err != nil {
		t.Fatalf("parseDotenvValues error: %v", err)
	}

	want := map[string]bool{
		"sk-1234567890":  false,
		"abc#notcomment": false,
		"bar":            false,
		"hello world":    false,
		"value":          false,
	}
	for _, v := range values {
		if _, ok := want[v]; ok {
			want[v] = true
		}
	}
	for v, ok := range want {
		if !ok {
			t.Fatalf("missing value %q, got: %#v", v, values)
		}
	}
}

func TestParseDotenvValues_MinLen(t *testing.T) {
	in := "A=short\nB=long-enough\n"
	values, err := parseDotenvValues([]byte(in), 8)
	if err != nil {
		t.Fatalf("parseDotenvValues error: %v", err)
	}
	if len(values) != 1 || values[0] != "long-enough" {
		t.Fatalf("unexpected values: %#v", values)
	}
}

func TestParseLineValues(t *testing.T) {
	in := strings.Join([]string{
		"",
		"# comment",
		"secret1",
		"  secret2  ",
		"shrt",
	}, "\n")
	values, err := parseLineValues([]byte(in), 6)
	if err != nil {
		t.Fatalf("parseLineValues error: %v", err)
	}
	if len(values) != 2 || values[0] != "secret1" || values[1] != "secret2" {
		t.Fatalf("unexpected values: %#v", values)
	}
}

func TestFullContentVariants_NormalizesLineEndingsAndTrims(t *testing.T) {
	in := []byte("\ufeffline1\r\nline2\r\n\r\n")
	out := fullContentVariants(in, 1)
	if len(out) == 0 {
		t.Fatalf("expected variants, got none")
	}
	seen := map[string]bool{}
	for _, v := range out {
		seen[v] = true
	}
	if !seen["line1\r\nline2\r\n\r\n"] {
		t.Fatalf("missing raw variant, got: %#v", out)
	}
	if !seen["line1\nline2\n\n"] {
		t.Fatalf("missing normalized variant, got: %#v", out)
	}
	if !seen["line1\nline2"] {
		t.Fatalf("missing trimmed variant, got: %#v", out)
	}
}
