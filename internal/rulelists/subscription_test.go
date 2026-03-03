package rulelists

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestSafeCacheKey(t *testing.T) {
	got := safeCacheKey("../../etc/passwd")
	if got == "" {
		t.Fatalf("expected non-empty key")
	}
	if bytes.ContainsAny([]byte(got), `/\.`) {
		t.Fatalf("key contains unsafe chars: %q", got)
	}

	long := safeCacheKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if len(long) > 64 {
		t.Fatalf("expected key length <= 64, got %d", len(long))
	}
}

func TestParseEd25519PublicKey_HexAndBase64(t *testing.T) {
	key := make([]byte, 32)
	for i := 0; i < 32; i++ {
		key[i] = byte(i)
	}

	hexStr := hex.EncodeToString(key)
	gotHex, err := parseEd25519PublicKey(hexStr)
	if err != nil {
		t.Fatalf("hex parse failed: %v", err)
	}
	if !bytes.Equal(gotHex, key) {
		t.Fatalf("hex key mismatch")
	}

	b64 := base64.StdEncoding.EncodeToString(key)
	gotB64, err := parseEd25519PublicKey(b64)
	if err != nil {
		t.Fatalf("base64 parse failed: %v", err)
	}
	if !bytes.Equal(gotB64, key) {
		t.Fatalf("base64 key mismatch")
	}
}

func TestParseEd25519Signature_RawHexBase64(t *testing.T) {
	sig := make([]byte, 64)
	for i := 0; i < 64; i++ {
		sig[i] = byte(255 - i)
	}

	gotRaw, err := parseEd25519Signature(sig)
	if err != nil {
		t.Fatalf("raw parse failed: %v", err)
	}
	if !bytes.Equal(gotRaw, sig) {
		t.Fatalf("raw signature mismatch")
	}

	hexStr := hex.EncodeToString(sig)
	gotHex, err := parseEd25519Signature([]byte(hexStr))
	if err != nil {
		t.Fatalf("hex parse failed: %v", err)
	}
	if !bytes.Equal(gotHex, sig) {
		t.Fatalf("hex signature mismatch")
	}

	b64 := base64.StdEncoding.EncodeToString(sig)
	gotB64, err := parseEd25519Signature([]byte(b64))
	if err != nil {
		t.Fatalf("base64 parse failed: %v", err)
	}
	if !bytes.Equal(gotB64, sig) {
		t.Fatalf("base64 signature mismatch")
	}
}

func TestNormalizeHexHash(t *testing.T) {
	if got := normalizeHexHash("sha256: " + stringsRepeat("a", 64)); got != stringsRepeat("a", 64) {
		t.Fatalf("unexpected hash: %q", got)
	}
	if got := normalizeHexHash("not-a-hash"); got != "" {
		t.Fatalf("expected empty hash for invalid input, got %q", got)
	}
}

func stringsRepeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}
