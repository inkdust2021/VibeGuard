package textsafe

import "testing"

func TestRedactableSpansSkipsANSISequences(t *testing.T) {
	input := []byte("foo\x1b[90mbar\x1b[0mbaz")

	got := RedactableSpans(input)
	if len(got) != 3 {
		t.Fatalf("expected 3 spans, got %d", len(got))
	}

	want := []Span{
		{Start: 0, End: 3},
		{Start: 8, End: 11},
		{Start: 15, End: 18},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("span %d mismatch: got %+v want %+v", i, got[i], want[i])
		}
	}
}

func TestRedactableSpansSkipsFormatRunes(t *testing.T) {
	input := []byte("A\u200bB")

	got := RedactableSpans(input)
	if len(got) != 2 {
		t.Fatalf("expected 2 spans, got %d", len(got))
	}
	if string(input[got[0].Start:got[0].End]) != "A" {
		t.Fatalf("unexpected first span: %q", input[got[0].Start:got[0].End])
	}
	if string(input[got[1].Start:got[1].End]) != "B" {
		t.Fatalf("unexpected second span: %q", input[got[1].Start:got[1].End])
	}
}
