package presidio

import "testing"

func TestPhoneLabeledRecognizer_MatchesPlainDigits(t *testing.T) {
	t.Parallel()

	rec := NewPhoneLabeledRecognizer()
	input := []byte("phone: 4155552671; my phone number is 130130130130; 手机号：13800138000; tel 02012345678 end")

	matches := rec.Recognize(input)
	var got []string
	for _, m := range matches {
		got = append(got, string(input[m.Start:m.End]))
	}

	want := []string{"4155552671", "130130130130", "13800138000", "02012345678"}
	for _, w := range want {
		found := false
		for _, s := range got {
			if s == w {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected to match %q, got %v", w, got)
		}
	}
}

func TestPhoneLabeledRecognizer_AvoidsDates(t *testing.T) {
	t.Parallel()

	rec := NewPhoneLabeledRecognizer()
	input := []byte("phone 2026-03-02 手机号：20260302 end")

	matches := rec.Recognize(input)
	for _, m := range matches {
		s := string(input[m.Start:m.End])
		if s == "2026-03-02" || s == "20260302" {
			t.Fatalf("should not match date: %q", s)
		}
	}
}
