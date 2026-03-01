package restore

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/inkdust2021/vibeguard/internal/session"
)

func TestRestore_能还原已注册占位符(t *testing.T) {
	sess := session.NewManager(time.Hour, 1000)
	t.Cleanup(sess.Close)

	original := "test123"
	placeholder := sess.GeneratePlaceholder(original, "TEST", "__VG_")
	sess.Register(placeholder, original)

	eng := NewEngine(sess, "__VG_")
	in := []byte("a " + placeholder + " b")
	out := eng.Restore(in)

	if !bytes.Contains(out, []byte(original)) {
		t.Fatalf("期望输出包含原文 %q，实际：%q", original, string(out))
	}
	if bytes.Contains(out, []byte(placeholder)) {
		t.Fatalf("期望输出不包含占位符 %q，实际：%q", placeholder, string(out))
	}
}

func TestRestore_支持带下划线的分类(t *testing.T) {
	sess := session.NewManager(time.Hour, 1000)
	t.Cleanup(sess.Close)

	original := "13800138000"
	placeholder := sess.GeneratePlaceholder(original, "CHINA_PHONE", "__VG_")
	sess.Register(placeholder, original)

	eng := NewEngine(sess, "__VG_")
	in := []byte("a" + placeholder + "b")
	out := eng.Restore(in)

	if !bytes.Contains(out, []byte(original)) {
		t.Fatalf("期望输出包含原文 %q，实际：%q", original, string(out))
	}
	if bytes.Contains(out, []byte(placeholder)) {
		t.Fatalf("期望输出不包含占位符 %q，实际：%q", placeholder, string(out))
	}
}

func TestRestore_未知占位符保持原样(t *testing.T) {
	sess := session.NewManager(time.Hour, 1000)
	t.Cleanup(sess.Close)

	unknown := "__VG_TEST_0123456789ab__"
	eng := NewEngine(sess, "__VG_")
	in := []byte("x " + unknown + " y")
	out := eng.Restore(in)

	if string(out) != string(in) {
		t.Fatalf("期望输出保持不变，输入：%q 输出：%q", string(in), string(out))
	}
}

func TestRestore_混合已知与未知占位符不应崩溃(t *testing.T) {
	sess := session.NewManager(time.Hour, 1000)
	t.Cleanup(sess.Close)

	orig1 := "short"
	ph1 := sess.GeneratePlaceholder(orig1, "A", "__VG_")
	sess.Register(ph1, orig1)

	orig2 := "this one is not registered"
	ph2 := sess.GeneratePlaceholder(orig2, "B", "__VG_")

	eng := NewEngine(sess, "__VG_")
	in := []byte("p:" + ph1 + "|q:" + ph2 + "|end")
	out := eng.Restore(in)

	if !bytes.Contains(out, []byte(orig1)) {
		t.Fatalf("期望输出包含原文 %q，实际：%q", orig1, string(out))
	}
	if bytes.Contains(out, []byte(ph1)) {
		t.Fatalf("期望已知占位符被替换，输出：%q", string(out))
	}
	if !bytes.Contains(out, []byte(ph2)) {
		t.Fatalf("期望未知占位符保持原样，输出：%q", string(out))
	}
}

func TestRestore_支持去掉前后下划线的占位符(t *testing.T) {
	sess := session.NewManager(time.Hour, 1000)
	t.Cleanup(sess.Close)

	original := "test123"
	placeholder := sess.GeneratePlaceholder(original, "TEXT", "__VG_")
	sess.Register(placeholder, original)

	// "__VG_TEXT_hash__" -> "VG_TEXT_hash"
	stripped := strings.TrimSuffix(strings.TrimPrefix(placeholder, "__"), "__")

	eng := NewEngine(sess, "__VG_")
	in := []byte("a " + stripped + " b")
	out := eng.Restore(in)

	if !bytes.Contains(out, []byte(original)) {
		t.Fatalf("期望输出包含原文 %q，实际：%q", original, string(out))
	}
	if bytes.Contains(out, []byte(stripped)) {
		t.Fatalf("期望输出不包含占位符变体 %q，实际：%q", stripped, string(out))
	}
}

func TestRestore_支持缺失尾部双下划线的占位符(t *testing.T) {
	sess := session.NewManager(time.Hour, 1000)
	t.Cleanup(sess.Close)

	original := "test123"
	placeholder := sess.GeneratePlaceholder(original, "TEXT", "__VG_")
	sess.Register(placeholder, original)

	noSuffix := strings.TrimSuffix(placeholder, "__")

	eng := NewEngine(sess, "__VG_")
	in := []byte("a " + noSuffix + " b")
	out := eng.Restore(in)

	if !bytes.Contains(out, []byte(original)) {
		t.Fatalf("期望输出包含原文 %q，实际：%q", original, string(out))
	}
	if bytes.Contains(out, []byte(noSuffix)) {
		t.Fatalf("期望输出不包含占位符变体 %q，实际：%q", noSuffix, string(out))
	}
}

func TestRestore_支持缺失前导下划线但保留尾部双下划线的占位符(t *testing.T) {
	sess := session.NewManager(time.Hour, 1000)
	t.Cleanup(sess.Close)

	original := "test123"
	placeholder := sess.GeneratePlaceholder(original, "TEXT", "__VG_")
	sess.Register(placeholder, original)

	// "__VG_TEXT_hash__" -> "VG_TEXT_hash__"
	noLeading := strings.TrimPrefix(placeholder, "__")

	eng := NewEngine(sess, "__VG_")
	in := []byte("a " + noLeading + " b")
	out := eng.Restore(in)

	if !bytes.Contains(out, []byte(original)) {
		t.Fatalf("期望输出包含原文 %q，实际：%q", original, string(out))
	}
	if bytes.Contains(out, []byte(noLeading)) {
		t.Fatalf("期望输出不包含占位符变体 %q，实际：%q", noLeading, string(out))
	}
}
