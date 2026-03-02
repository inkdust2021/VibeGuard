package pipeline

import (
	"strings"
	"testing"
	"time"

	"github.com/inkdust2021/vibeguard/internal/pii_next/keywords"
	"github.com/inkdust2021/vibeguard/internal/pii_next/presidio"
	"github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
	"github.com/inkdust2021/vibeguard/internal/session"
)

func TestPipeline_RedactWithMatches(t *testing.T) {
	t.Parallel()

	sess := session.NewManager(1*time.Hour, 100000)
	t.Cleanup(sess.Close)

	// 固定 key，避免测试中出现随机占位符导致断言困难。
	key32 := make([]byte, 32)
	for i := range key32 {
		key32[i] = byte(i)
	}
	if err := sess.SetDeterministicPlaceholders(true, key32); err != nil {
		t.Fatalf("SetDeterministicPlaceholders: %v", err)
	}

	kw := keywords.New([]keywords.Keyword{
		{Text: "Samuel Porter", Category: "TEXT"},
	})

	recs := []recognizer.Recognizer{kw}
	recs = append(recs, presidio.DefaultRecognizers()...)
	p := New(sess, "__VG_", recs...)

	input := []byte("hi I'm Samuel Porter. My email is Samuel@gmail.com.")
	out, matches := p.RedactWithMatches(input)
	outStr := string(out)

	if strings.Contains(outStr, "Samuel Porter") {
		t.Fatalf("expected keyword to be redacted, got %q", outStr)
	}
	if strings.Contains(outStr, "Samuel@gmail.com") {
		t.Fatalf("expected email to be redacted, got %q", outStr)
	}

	if len(matches) < 2 {
		t.Fatalf("expected at least 2 matches, got %d", len(matches))
	}
	for _, m := range matches {
		if !strings.HasPrefix(m.Placeholder, "__VG_") || !strings.HasSuffix(m.Placeholder, "__") {
			t.Fatalf("unexpected placeholder format: %q", m.Placeholder)
		}
		if strings.Contains(outStr, m.Original) {
			t.Fatalf("output still contains original %q", m.Original)
		}
	}
}
