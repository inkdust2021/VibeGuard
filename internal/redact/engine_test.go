package redact

import (
	"bytes"
	"regexp"
	"testing"
	"time"

	"github.com/inkdust2021/vibeguard/internal/session"
)

func TestRedact_多处匹配都会被替换(t *testing.T) {
	sess := session.NewManager(time.Hour, 1000)
	t.Cleanup(sess.Close)

	eng := NewEngine(sess, "__VG_")
	eng.AddKeyword("Alice", "NAME")
	eng.AddKeyword("Bob", "NAME")

	out, count := eng.Redact([]byte("Alice and Bob"))
	if count != 2 {
		t.Fatalf("期望替换 2 次，实际 %d 次", count)
	}
	if bytes.Contains(out, []byte("Alice")) || bytes.Contains(out, []byte("Bob")) {
		t.Fatalf("输出仍包含原文：%q", string(out))
	}
	if bytes.Count(out, []byte("__VG_NAME_")) != 2 {
		t.Fatalf("期望出现 2 个占位符，输出：%q", string(out))
	}
	if sess.Size() != 2 {
		t.Fatalf("期望 session 存储 2 条映射，实际 %d 条", sess.Size())
	}
}

func TestRedact_优先使用第一个捕获组范围替换(t *testing.T) {
	sess := session.NewManager(time.Hour, 1000)
	t.Cleanup(sess.Close)

	eng := NewEngine(sess, "__VG_")
	if err := eng.AddRegex(`(?:^|\D)(1[3-9]\d{9})(?:$|\D)`, "PHONE"); err != nil {
		t.Fatalf("添加正则失败：%v", err)
	}

	out, count := eng.Redact([]byte("a13800138000b"))
	if count != 1 {
		t.Fatalf("期望替换 1 次，实际 %d 次", count)
	}
	if bytes.Contains(out, []byte("13800138000")) {
		t.Fatalf("输出仍包含原手机号：%q", string(out))
	}
	if !bytes.HasPrefix(out, []byte("a")) || !bytes.HasSuffix(out, []byte("b")) {
		t.Fatalf("期望保留边界字符 a/b，输出：%q", string(out))
	}

	phRe := regexp.MustCompile(`^a__VG_PHONE_[a-f0-9]{12}(?:_\d+)?__b$`)
	if !phRe.Match(out) {
		t.Fatalf("占位符格式不符合预期，输出：%q", string(out))
	}
	if sess.Size() != 1 {
		t.Fatalf("期望 session 存储 1 条映射，实际 %d 条", sess.Size())
	}
}

func TestAddBuiltin_常用内置规则可直接生效(t *testing.T) {
	cases := []struct {
		name       string
		input      string
		original   string
		wantMarker string
	}{
		{name: "email", input: "a test@example.com b", original: "test@example.com", wantMarker: "__VG_EMAIL_"},
		{name: "china_phone", input: "a13800138000b", original: "13800138000", wantMarker: "__VG_CHINA_PHONE_"},
		{name: "uuid", input: "id=550e8400-e29b-41d4-a716-446655440000", original: "550e8400-e29b-41d4-a716-446655440000", wantMarker: "__VG_UUID_"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess := session.NewManager(time.Hour, 1000)
			t.Cleanup(sess.Close)

			eng := NewEngine(sess, "__VG_")
			if err := eng.AddBuiltin(tc.name); err != nil {
				t.Fatalf("添加内置规则失败：%v", err)
			}

			out, count := eng.Redact([]byte(tc.input))
			if count != 1 {
				t.Fatalf("期望替换 1 次，实际 %d 次，输出：%q", count, string(out))
			}
			if bytes.Contains(out, []byte(tc.original)) {
				t.Fatalf("输出仍包含原文：%q", string(out))
			}
			if !bytes.Contains(out, []byte(tc.wantMarker)) {
				t.Fatalf("占位符分类标记不符合预期（%s），输出：%q", tc.wantMarker, string(out))
			}
			if sess.Size() != 1 {
				t.Fatalf("期望 session 存储 1 条映射，实际 %d 条", sess.Size())
			}
		})
	}
}

func TestAddBuiltin_未知规则返回错误(t *testing.T) {
	sess := session.NewManager(time.Hour, 1000)
	t.Cleanup(sess.Close)

	eng := NewEngine(sess, "__VG_")
	if err := eng.AddBuiltin("not-exists"); err == nil {
		t.Fatalf("期望未知内置规则返回错误，但实际为 nil")
	}
}

func TestRedact_重叠命中不会破坏占位符或漏出原文(t *testing.T) {
	sess := session.NewManager(time.Hour, 1000)
	t.Cleanup(sess.Close)

	eng := NewEngine(sess, "__VG_")
	if err := eng.AddBuiltin("email"); err != nil {
		t.Fatalf("添加内置规则失败：%v", err)
	}
	if err := eng.AddRegex(`.*@gmail\.com`, "AFFIX"); err != nil {
		t.Fatalf("添加正则失败：%v", err)
	}
	if err := eng.AddRegex(`Samuel Porter`, "TEXT"); err != nil {
		t.Fatalf("添加正则失败：%v", err)
	}

	in := []byte("hi I'm Samuel Porter.My email is Samuel@gmail.com.Pls paraphrase my first name and my email without the suffix")
	out, _ := eng.Redact(in)

	// 原文本体不应出现在输出中
	if bytes.Contains(out, []byte("Samuel Porter")) {
		t.Fatalf("输出仍包含姓名原文：%q", string(out))
	}
	if bytes.Contains(out, []byte("Samuel@gmail.com")) {
		t.Fatalf("输出仍包含邮箱原文：%q", string(out))
	}

	// 内置 email 的占位符前缀不应被破坏（历史 bug 会出现缺少前缀的 \"EMAIL_xxx__\" 片段）
	if !bytes.Contains(out, []byte("__VG_EMAIL_")) {
		t.Fatalf("期望输出包含 email 占位符前缀，输出：%q", string(out))
	}
}
