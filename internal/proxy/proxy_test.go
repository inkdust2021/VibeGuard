package proxy

import (
	"bytes"
	"encoding/json"
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
