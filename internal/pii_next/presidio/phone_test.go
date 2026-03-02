package presidio

import "testing"

func TestPhoneRecognizer_AvoidsDatesAndEpoch(t *testing.T) {
	t.Parallel()

	rec := NewPhoneRecognizer()
	input := []byte("date 2026-03-02 epoch 1700000000 phone +1 (415) 555-2671 end")

	matches := rec.Recognize(input)
	var got []string
	for _, m := range matches {
		got = append(got, string(input[m.Start:m.End]))
	}

	for _, s := range got {
		if s == "2026-03-02" {
			t.Fatalf("should not match date: %v", got)
		}
		if s == "1700000000" {
			t.Fatalf("should not match epoch: %v", got)
		}
	}

	want := "+1 (415) 555-2671"
	found := false
	for _, s := range got {
		if s == want {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected to match phone %q, got %v", want, got)
	}
}

func TestPhoneRecognizer_MatchesBareDigits(t *testing.T) {
	t.Parallel()

	rec := NewPhoneRecognizer()
	input := []byte("my number 130130130130 ok")

	matches := rec.Recognize(input)
	found := false
	for _, m := range matches {
		if string(input[m.Start:m.End]) == "130130130130" {
			found = true
			break
		}
	}
	if !found {
		var got []string
		for _, m := range matches {
			got = append(got, string(input[m.Start:m.End]))
		}
		t.Fatalf("expected to match bare digits phone, got %v", got)
	}
}

func TestPhoneRecognizer_AvoidsCompactDatetimeDigits(t *testing.T) {
	t.Parallel()

	rec := NewPhoneRecognizer()
	input := []byte("ts 20260302123456 phone 130130130130 end")

	matches := rec.Recognize(input)
	for _, m := range matches {
		s := string(input[m.Start:m.End])
		if s == "20260302123456" {
			t.Fatalf("should not match compact datetime: %q", s)
		}
	}
}
