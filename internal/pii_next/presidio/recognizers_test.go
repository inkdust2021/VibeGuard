package presidio

import "testing"

func TestRecognizers_Smoke(t *testing.T) {
	t.Parallel()

	input := []byte("email Samuel@gmail.com phone +1 (415) 555-2671 url https://example.com). ip 192.168.0.1 mac aa:bb:cc:dd:ee:ff uuid 550e8400-e29b-41d4-a716-446655440000 btc 1BoatSLRHtKNngkdXEeobR76b53LETtpyT eth 0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe iban GB82 WEST 1234 5698 7654 32 ssn 123-45-6789 cc 4111 1111 1111 1111")

	recs := DefaultRecognizers()
	if len(recs) == 0 {
		t.Fatalf("DefaultRecognizers() returned empty")
	}

	seen := map[string]bool{}
	for _, r := range recs {
		matches := r.Recognize(input)
		for _, m := range matches {
			if m.Start < 0 || m.End > len(input) || m.Start >= m.End {
				t.Fatalf("%s produced invalid span: %+v", r.Name(), m)
			}
			seen[m.Category] = true
		}
	}

	// 至少应覆盖这些常见类型（原型阶段的最低验收）。
	wantCats := []string{"EMAIL", "PHONE", "URL", "IP", "MAC", "UUID", "CRYPTO", "IBAN", "SSN", "CREDIT_CARD"}
	for _, cat := range wantCats {
		if !seen[cat] {
			t.Fatalf("expected category %q to be detected at least once", cat)
		}
	}
}
