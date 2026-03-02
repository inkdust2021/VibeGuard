package presidio

import "testing"

func TestIBANValid(t *testing.T) {
	t.Parallel()

	cases := []struct {
		iban string
		want bool
	}{
		{"GB82 WEST 1234 5698 7654 32", true},
		{"DE89 3704 0044 0532 0130 00", true},
		{"fr14 2004 1010 0505 0001 3m02 606", true}, // lowercase + spaces
		{"GB82 WEST 1234 5698 7654 33", false},      // checksum wrong
		{"GB82WEST12345698765432", true},            // no spaces
		{"", false},
	}

	for _, tc := range cases {
		if got := ibanValid(tc.iban); got != tc.want {
			t.Fatalf("ibanValid(%q)=%v, want %v", tc.iban, got, tc.want)
		}
	}
}
