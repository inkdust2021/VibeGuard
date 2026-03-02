package presidio

import "testing"

func TestCreditCardRecognizer_DoesNotMatchCompactDatetime(t *testing.T) {
	t.Parallel()

	rec := NewCreditCardRecognizer()
	// 14 位紧凑日期时间（YYYYMMDDHHMMSS），不应被当作信用卡号命中。
	input := []byte("ts 20260302123456 end")

	matches := rec.Recognize(input)
	for _, m := range matches {
		if string(input[m.Start:m.End]) == "20260302123456" {
			t.Fatalf("should not match compact datetime as credit card")
		}
	}
}

func TestCreditCardRecognizer_DoesNotConsumeTrailingSpace(t *testing.T) {
	t.Parallel()

	rec := NewCreditCardRecognizer()
	input := []byte("cc 4111 1111 1111 1111 phone")

	matches := rec.Recognize(input)
	if len(matches) == 0 {
		t.Fatalf("expected to match a credit card number")
	}
	got := string(input[matches[0].Start:matches[0].End])
	if got != "4111 1111 1111 1111" {
		t.Fatalf("expected exact match without trailing space, got %q", got)
	}
}

