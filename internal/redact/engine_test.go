package redact

import (
	"testing"

	"github.com/inkdust2021/vibeguard/internal/session"
)

func TestEngine_Detect_FindsKeyword(t *testing.T) {
	sess := session.NewManager(0, 1000)
	eng := NewEngine(sess, "__VG_")
	eng.AddKeyword("secret123", "TEXT")

	matches := eng.Detect([]byte("hello secret123 world"))
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Original != "secret123" {
		t.Errorf("expected original=secret123, got %s", matches[0].Original)
	}
	if matches[0].Category != "TEXT" {
		t.Errorf("expected category=TEXT, got %s", matches[0].Category)
	}
}

func TestEngine_Detect_FindsRegex(t *testing.T) {
	sess := session.NewManager(0, 1000)
	eng := NewEngine(sess, "__VG_")
	eng.AddRegex(`\b\d{11}\b`, "CHINA_PHONE")

	input := []byte("call 13912345678 now")
	matches := eng.Detect(input)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Original != "13912345678" {
		t.Errorf("expected original=13912345678, got %s", matches[0].Original)
	}
}

func TestEngine_Detect_NoSideEffects(t *testing.T) {
	sess := session.NewManager(0, 1000)
	eng := NewEngine(sess, "__VG_")
	eng.AddKeyword("password", "TEXT")

	// 检测前 session 应为空
	if count := sess.Size(); count != 0 {
		t.Fatalf("expected 0 session entries before detect, got %d", count)
	}

	eng.Detect([]byte("my password is abc"))

	// 检测后 session 仍应为空
	if count := sess.Size(); count != 0 {
		t.Errorf("expected 0 session entries after detect (read-only), got %d", count)
	}
}

func TestEngine_Detect_NoPlaceholder(t *testing.T) {
	sess := session.NewManager(0, 1000)
	eng := NewEngine(sess, "__VG_")
	eng.AddKeyword("secret", "TEXT")

	matches := eng.Detect([]byte("top secret info"))
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Placeholder != "" {
		t.Errorf("expected empty placeholder in detect mode, got %s", matches[0].Placeholder)
	}
}

func TestEngine_Detect_EmptyInput(t *testing.T) {
	sess := session.NewManager(0, 1000)
	eng := NewEngine(sess, "__VG_")
	eng.AddKeyword("secret", "TEXT")

	matches := eng.Detect([]byte(""))
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for empty input, got %d", len(matches))
	}
}

func TestEngine_Detect_Exclude(t *testing.T) {
	sess := session.NewManager(0, 1000)
	eng := NewEngine(sess, "__VG_")
	eng.AddKeyword("safe_value", "TEXT")
	eng.AddExclude("safe_value")

	matches := eng.Detect([]byte("contains safe_value here"))
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for excluded keyword, got %d", len(matches))
	}
}
