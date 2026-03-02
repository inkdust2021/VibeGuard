package presidio

import "testing"

func TestLuhnValid(t *testing.T) {
	t.Parallel()

	cases := []struct {
		digits string
		want   bool
	}{
		{"4111111111111111", true},  // Visa
		{"5555555555554444", true},  // Mastercard
		{"378282246310005", true},   // Amex
		{"6011111111111117", true},  // Discover
		{"4111111111111112", false}, // wrong checksum
		{"", false},
		{"abcd", false},
	}

	for _, tc := range cases {
		if got := luhnValid(tc.digits); got != tc.want {
			t.Fatalf("luhnValid(%q)=%v, want %v", tc.digits, got, tc.want)
		}
	}
}
