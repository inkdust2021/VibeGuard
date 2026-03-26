package wsproxy

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/inkdust2021/vibeguard/internal/redact"
	"github.com/inkdust2021/vibeguard/internal/restore"
	"github.com/inkdust2021/vibeguard/internal/session"
)

func TestTransformConnWrite_RedactsMaskedTextFrame(t *testing.T) {
	sess := session.NewManager(time.Minute, 16)
	t.Cleanup(sess.Close)

	eng := redact.NewEngine(sess, "__VG_")
	eng.AddKeyword("Alice", "NAME")

	clientSide, upstreamSide := io.Pipe()
	defer upstreamSide.Close()

	conn := NewTransformConn(pipeReadWriteCloser{Reader: bytes.NewReader(nil), Writer: upstreamSide, closer: io.NopCloser(bytes.NewReader(nil))}, eng, restore.NewEngine(sess, "__VG_"))

	raw, err := buildFrame(true, wsOpcodeText, true, []byte("hello Alice"))
	if err != nil {
		t.Fatalf("build frame: %v", err)
	}

	done := make(chan []byte, 1)
	go func() {
		buf, _ := io.ReadAll(clientSide)
		done <- buf
	}()

	if n, err := conn.Write(raw); err != nil || n != len(raw) {
		t.Fatalf("write failed: n=%d err=%v", n, err)
	}
	_ = upstreamSide.Close()

	out := <-done
	frame, ok, err := parseFrame(out)
	if err != nil || !ok {
		t.Fatalf("parse output frame failed: ok=%v err=%v", ok, err)
	}
	if bytes.Contains(frame.payload, []byte("Alice")) {
		t.Fatalf("expected Alice to be redacted, got %q", frame.payload)
	}
	if !strings.Contains(string(frame.payload), "__VG_NAME_") {
		t.Fatalf("expected placeholder in payload, got %q", frame.payload)
	}
}

func TestTransformConnRead_RestoresTextFrame(t *testing.T) {
	sess := session.NewManager(time.Minute, 16)
	t.Cleanup(sess.Close)

	eng := redact.NewEngine(sess, "__VG_")
	eng.AddKeyword("Alice", "NAME")
	redacted, _ := eng.RedactWithMatches([]byte("hello Alice"))

	serverFrame, err := buildFrame(true, wsOpcodeText, false, redacted)
	if err != nil {
		t.Fatalf("build frame: %v", err)
	}

	conn := NewTransformConn(pipeReadWriteCloser{
		Reader: bytes.NewReader(serverFrame),
		Writer: io.Discard,
		closer: io.NopCloser(bytes.NewReader(nil)),
	}, eng, restore.NewEngine(sess, "__VG_"))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read failed: %v", err)
	}

	frame, ok, err := parseFrame(buf[:n])
	if err != nil || !ok {
		t.Fatalf("parse restored frame failed: ok=%v err=%v", ok, err)
	}
	if string(frame.payload) != "hello Alice" {
		t.Fatalf("expected restored payload, got %q", frame.payload)
	}
}

func TestTransformConnWrite_RedactsJSONPromptOnly(t *testing.T) {
	sess := session.NewManager(time.Minute, 16)
	t.Cleanup(sess.Close)

	eng := redact.NewEngine(sess, "__VG_")
	eng.AddKeyword("Alice", "NAME")

	clientSide, upstreamSide := io.Pipe()
	defer upstreamSide.Close()

	conn := NewTransformConn(pipeReadWriteCloser{
		Reader: bytes.NewReader(nil),
		Writer: upstreamSide,
		closer: io.NopCloser(bytes.NewReader(nil)),
	}, eng, restore.NewEngine(sess, "__VG_"))

	payload := []byte(`{"type":"response.create","metadata":{"note":"Alice"},"input":[{"role":"user","content":[{"type":"input_text","text":"hello Alice"}]}]}`)
	raw, err := buildFrame(true, wsOpcodeText, true, payload)
	if err != nil {
		t.Fatalf("build frame: %v", err)
	}

	done := make(chan []byte, 1)
	go func() {
		buf, _ := io.ReadAll(clientSide)
		done <- buf
	}()

	if n, err := conn.Write(raw); err != nil || n != len(raw) {
		t.Fatalf("write failed: n=%d err=%v", n, err)
	}
	_ = upstreamSide.Close()

	out := <-done
	frame, ok, err := parseFrame(out)
	if err != nil || !ok {
		t.Fatalf("parse output frame failed: ok=%v err=%v", ok, err)
	}

	var body map[string]any
	if err := json.Unmarshal(frame.payload, &body); err != nil {
		t.Fatalf("unmarshal output payload: %v", err)
	}

	if got := body["type"]; got != "response.create" {
		t.Fatalf("expected type to stay unchanged, got %#v", got)
	}

	metadata, _ := body["metadata"].(map[string]any)
	if got := metadata["note"]; got != "Alice" {
		t.Fatalf("expected metadata.note to remain unchanged, got %#v", got)
	}

	input, _ := body["input"].([]any)
	msg, _ := input[0].(map[string]any)
	content, _ := msg["content"].([]any)
	part, _ := content[0].(map[string]any)
	text, _ := part["text"].(string)
	if !strings.Contains(text, "__VG_NAME_") {
		t.Fatalf("expected prompt text to contain placeholder, got %q", text)
	}
}

type pipeReadWriteCloser struct {
	io.Reader
	io.Writer
	closer io.Closer
}

func (p pipeReadWriteCloser) Close() error {
	if p.closer == nil {
		return nil
	}
	return p.closer.Close()
}
