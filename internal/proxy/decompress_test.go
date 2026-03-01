package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"testing"

	"github.com/andybalholm/brotli"
)

func TestDecompressBytes_Gzip(t *testing.T) {
	in := []byte("hello gzip")
	encoded := mustGzip(t, in)

	out, err := decompressBytes(encoded, "gzip", 1024)
	if err != nil {
		t.Fatalf("decompressBytes: %v", err)
	}
	if !bytes.Equal(out, in) {
		t.Fatalf("unexpected output: %q", string(out))
	}
}

func TestDecompressBytes_Brotli(t *testing.T) {
	in := []byte("hello brotli")
	encoded := mustBrotli(t, in)

	out, err := decompressBytes(encoded, "br", 1024)
	if err != nil {
		t.Fatalf("decompressBytes: %v", err)
	}
	if !bytes.Equal(out, in) {
		t.Fatalf("unexpected output: %q", string(out))
	}
}

func TestDecompressBytes_Zstd(t *testing.T) {
	// Encoded from: printf 'hello zstd' | zstd -q -c
	encoded := []byte{
		0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x58, 0x51, 0x00, 0x00, 0x68, 0x65, 0x6c,
		0x6c, 0x6f, 0x20, 0x7a, 0x73, 0x74, 0x64, 0xcf, 0xdb, 0x60, 0x9c,
	}
	in := []byte("hello zstd")

	out, err := decompressBytes(encoded, "zstd", 1024)
	if err != nil {
		t.Fatalf("decompressBytes: %v", err)
	}
	if !bytes.Equal(out, in) {
		t.Fatalf("unexpected output: %q", string(out))
	}
}

func TestDecompressBytes_DeflateZlib(t *testing.T) {
	in := []byte("hello deflate zlib")
	encoded := mustZlibDeflate(t, in)

	out, err := decompressBytes(encoded, "deflate", 1024)
	if err != nil {
		t.Fatalf("decompressBytes: %v", err)
	}
	if !bytes.Equal(out, in) {
		t.Fatalf("unexpected output: %q", string(out))
	}
}

func TestDecompressBytes_DeflateRaw(t *testing.T) {
	in := []byte("hello deflate raw")
	encoded := mustRawDeflate(t, in)

	out, err := decompressBytes(encoded, "deflate", 1024)
	if err != nil {
		t.Fatalf("decompressBytes: %v", err)
	}
	if !bytes.Equal(out, in) {
		t.Fatalf("unexpected output: %q", string(out))
	}
}

func TestDecompressBytes_MultiEncoding(t *testing.T) {
	in := []byte("hello multi encoding")

	// Content-Encoding: "gzip, br" means gzip applied first, then brotli.
	gz := mustGzip(t, in)
	encoded := mustBrotli(t, gz)

	out, err := decompressBytes(encoded, "gzip, br", 1024)
	if err != nil {
		t.Fatalf("decompressBytes: %v", err)
	}
	if !bytes.Equal(out, in) {
		t.Fatalf("unexpected output: %q", string(out))
	}
}

func TestDecompressBytes_TooLarge(t *testing.T) {
	in := bytes.Repeat([]byte("a"), 128)
	encoded := mustGzip(t, in)

	_, err := decompressBytes(encoded, "gzip", 64)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func mustGzip(t *testing.T, in []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(in); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func mustBrotli(t *testing.T, in []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	w := brotli.NewWriter(&buf)
	if _, err := w.Write(in); err != nil {
		t.Fatalf("brotli write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("brotli close: %v", err)
	}
	return buf.Bytes()
}

func mustZlibDeflate(t *testing.T, in []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(in); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

func mustRawDeflate(t *testing.T, in []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		t.Fatalf("flate new writer: %v", err)
	}
	if _, err := w.Write(in); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("flate close: %v", err)
	}
	return buf.Bytes()
}
