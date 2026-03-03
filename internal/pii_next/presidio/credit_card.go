package presidio

import (
	"strings"

	"github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
)

// CreditCardRecognizer 识别信用卡号并用 Luhn 校验过滤误报。
type CreditCardRecognizer struct{ *regexRecognizer }

func NewCreditCardRecognizer() recognizer.Recognizer {
	return &CreditCardRecognizer{&regexRecognizer{
		name:     "presidio-credit-card",
		category: "CREDIT_CARD",
		priority: 130,
		re:       mustCompile(`\b\d(?:[ -]?\d){12,18}\b`),
		validate: func(matched []byte) bool {
			digits := digitsOnly(string(matched))
			if len(digits) < 13 || len(digits) > 19 {
				return false
			}
			if looksLikeDateOrTimestamp(digits) {
				return false
			}
			return luhnValid(digits)
		},
	}}
}

func digitsOnly(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			b = append(b, c)
		}
	}
	return string(b)
}
