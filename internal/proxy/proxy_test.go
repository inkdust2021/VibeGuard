package proxy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/inkdust2021/vibeguard/internal/redact"
	"github.com/inkdust2021/vibeguard/internal/restore"
	"github.com/inkdust2021/vibeguard/internal/session"
)

func TestRedactJSONBody_RegexDoesNotBreakJSON(t *testing.T) {
	sess := session.NewManager(time.Hour, 1000)
	defer sess.Close()

	eng := redact.NewEngine(sess, "__VG_")
	if err := eng.AddRegex(`.*@gmail\.com`, "EMAIL"); err != nil {
		t.Fatalf("AddRegex: %v", err)
	}

	in := []byte(`{"input":"hi I'm Samuel Porter.My email is Samuel@gmail.com.Pls paraphrase my first name and my email without the suffix."}`)
	out, matches, changed, err := redactJSONBody(eng, in)
	if err != nil {
		t.Fatalf("redactJSONBody: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true")
	}
	if len(matches) == 0 {
		t.Fatalf("expected matches>0")
	}
	if !json.Valid(out) {
		t.Fatalf("expected valid JSON after redaction: %q", string(out))
	}
	if bytes.Contains(out, []byte("Samuel@gmail.com")) {
		t.Fatalf("expected email to be redacted, got: %q", string(out))
	}
	if !bytes.Contains(out, []byte("__VG_")) {
		t.Fatalf("expected placeholder in output, got: %q", string(out))
	}

	restoreEng := restore.NewEngine(sess, "__VG_")
	restored := restoreEng.Restore(out)
	if !json.Valid(restored) {
		t.Fatalf("expected valid JSON after restore: %q", string(restored))
	}
	if !bytes.Contains(restored, []byte("Samuel@gmail.com")) {
		t.Fatalf("expected email restored, got: %q", string(restored))
	}
}

func TestRedactJSONBody_PromptOnly_SkipsNonPromptFields(t *testing.T) {
	sess := session.NewManager(time.Hour, 1000)
	defer sess.Close()

	eng := redact.NewEngine(sess, "__VG_")
	if err := eng.AddRegex(`.*@gmail\.com`, "EMAIL"); err != nil {
		t.Fatalf("AddRegex: %v", err)
	}

	in := []byte(`{"model":"Samuel@gmail.com","messages":[{"role":"user","content":"Samuel@gmail.com"}]}`)
	out, matches, changed, err := redactJSONBody(eng, in)
	if err != nil {
		t.Fatalf("redactJSONBody: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true")
	}
	if len(matches) != 1 {
		t.Fatalf("expected matches=1, got %d", len(matches))
	}
	if !json.Valid(out) {
		t.Fatalf("expected valid JSON after redaction: %q", string(out))
	}
	// model 不属于提示词/对话内容：不应被脱敏
	if !bytes.Contains(out, []byte(`"model":"Samuel@gmail.com"`)) {
		t.Fatalf("expected model to stay unchanged, got: %q", string(out))
	}
	// messages[].content 属于提示词/对话内容：应被脱敏
	if bytes.Contains(out, []byte(`"content":"Samuel@gmail.com"`)) {
		t.Fatalf("expected content to be redacted, got: %q", string(out))
	}
	if !bytes.Contains(out, []byte(`"content":"__VG_`)) {
		t.Fatalf("expected placeholder in content, got: %q", string(out))
	}

	restoreEng := restore.NewEngine(sess, "__VG_")
	restored := restoreEng.Restore(out)
	if !json.Valid(restored) {
		t.Fatalf("expected valid JSON after restore: %q", string(restored))
	}
	// 恢复只针对占位符字段：model 仍保持原值（未脱敏，无需还原）
	if !bytes.Contains(restored, []byte(`"model":"Samuel@gmail.com"`)) {
		t.Fatalf("expected model to stay unchanged after restore, got: %q", string(restored))
	}
	if !bytes.Contains(restored, []byte(`"content":"Samuel@gmail.com"`)) {
		t.Fatalf("expected content restored, got: %q", string(restored))
	}
}

func TestRedactJSONBody_PromptOnly_DoesNotTouchSystemOrMetadata(t *testing.T) {
	sess := session.NewManager(time.Hour, 1000)
	defer sess.Close()

	eng := redact.NewEngine(sess, "__VG_")
	if err := eng.AddRegex(`Claude Code`, "TEXT"); err != nil {
		t.Fatalf("AddRegex(Claude): %v", err)
	}
	if err := eng.AddRegex(`ae74d4a2-b7ca-4d04-a109-111c99b3a001`, "UUID"); err != nil {
		t.Fatalf("AddRegex(uuid): %v", err)
	}
	if err := eng.AddRegex(`.*@gmail\.com`, "EMAIL"); err != nil {
		t.Fatalf("AddRegex(email): %v", err)
	}

	in := []byte(`{
  "model": "claude-haiku-4-5-20251001",
  "messages": [
    {"role":"user","content":[{"type":"text","text":"My email is Samuel@gmail.com"}]}
  ],
  "system": [
    {"type":"text","text":"You are Claude Code, Anthropic's official CLI for Claude."}
  ],
  "metadata": {
    "user_id": "user_x_account__session_ae74d4a2-b7ca-4d04-a109-111c99b3a001"
  }
}`)
	out, _, _, err := redactJSONBody(eng, in)
	if err != nil {
		t.Fatalf("redactJSONBody: %v", err)
	}
	if !json.Valid(out) {
		t.Fatalf("expected valid JSON after redaction: %q", string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("Unmarshal(out): %v", err)
	}

	if got["model"] != "claude-haiku-4-5-20251001" {
		t.Fatalf("expected model unchanged, got %#v", got["model"])
	}

	// system 不应被改写（即使命中关键词）
	sys, _ := got["system"].([]any)
	if len(sys) != 1 {
		t.Fatalf("expected system len=1, got %#v", got["system"])
	}
	sys0, _ := sys[0].(map[string]any)
	if sys0["text"] != "You are Claude Code, Anthropic's official CLI for Claude." {
		t.Fatalf("expected system.text unchanged, got %#v", sys0["text"])
	}

	// metadata 不应被改写（即使命中关键词）
	meta, _ := got["metadata"].(map[string]any)
	if meta["user_id"] != "user_x_account__session_ae74d4a2-b7ca-4d04-a109-111c99b3a001" {
		t.Fatalf("expected metadata.user_id unchanged, got %#v", meta["user_id"])
	}

	// messages 仍应脱敏
	msgs, _ := got["messages"].([]any)
	if len(msgs) != 1 {
		t.Fatalf("expected messages len=1, got %#v", got["messages"])
	}
	m0, _ := msgs[0].(map[string]any)
	content, _ := m0["content"].([]any)
	if len(content) != 1 {
		t.Fatalf("expected content len=1, got %#v", m0["content"])
	}
	part0, _ := content[0].(map[string]any)
	txt, _ := part0["text"].(string)
	if strings.Contains(txt, "Samuel@gmail.com") {
		t.Fatalf("expected email redacted in messages text, got %q", txt)
	}
	if !strings.Contains(txt, "__VG_") {
		t.Fatalf("expected placeholder in messages text, got %q", txt)
	}
}

func TestRedactJSONBody_PromptOnly_SkipsSystemReminderPartsInContent(t *testing.T) {
	sess := session.NewManager(time.Hour, 1000)
	defer sess.Close()

	eng := redact.NewEngine(sess, "__VG_")
	// 如果不跳过 system-reminder，这里会命中并被替换
	if err := eng.AddRegex(`SessionStart`, "TEXT"); err != nil {
		t.Fatalf("AddRegex(SessionStart): %v", err)
	}
	if err := eng.AddRegex(`.*@gmail\.com`, "EMAIL"); err != nil {
		t.Fatalf("AddRegex(email): %v", err)
	}

	in := []byte(`{
  "messages": [
    {"role":"user","content":[
      {"type":"text","text":"<system-reminder>\nSessionStart:startup hook success: Success\n</system-reminder>"},
      {"type":"text","text":"My email is Samuel@gmail.com"}
    ]}
  ]
}`)
	out, _, _, err := redactJSONBody(eng, in)
	if err != nil {
		t.Fatalf("redactJSONBody: %v", err)
	}
	if !json.Valid(out) {
		t.Fatalf("expected valid JSON after redaction: %q", string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("Unmarshal(out): %v", err)
	}
	msgs, _ := got["messages"].([]any)
	if len(msgs) != 1 {
		t.Fatalf("expected messages len=1, got %#v", got["messages"])
	}
	m0, _ := msgs[0].(map[string]any)
	content, _ := m0["content"].([]any)
	if len(content) != 2 {
		t.Fatalf("expected content len=2, got %#v", m0["content"])
	}

	p0, _ := content[0].(map[string]any)
	t0, _ := p0["text"].(string)
	if !strings.Contains(t0, "SessionStart") {
		t.Fatalf("expected system-reminder text unchanged, got %q", t0)
	}
	if strings.Contains(t0, "__VG_") {
		t.Fatalf("expected system-reminder part to NOT be redacted, got %q", t0)
	}

	p1, _ := content[1].(map[string]any)
	t1, _ := p1["text"].(string)
	if strings.Contains(t1, "Samuel@gmail.com") {
		t.Fatalf("expected email redacted in user text part, got %q", t1)
	}
	if !strings.Contains(t1, "__VG_") {
		t.Fatalf("expected placeholder in user text part, got %q", t1)
	}
}
