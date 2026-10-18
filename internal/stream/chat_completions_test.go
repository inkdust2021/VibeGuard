package stream

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/inkdust2021/vibeguard/internal/restore"
	"github.com/inkdust2021/vibeguard/internal/session"
)

const testPlaceholder = "__VG_SECRET_010d9221706c__"
const testOriginal = "hunter2-FAKE-canary-7Q9xZ"

func chatEngine(t *testing.T) *restore.Engine {
	t.Helper()
	s := session.NewManager(time.Hour, 100)
	s.Register(testPlaceholder, testOriginal)
	return restore.NewEngine(s, "__VG_")
}

func chunk(t *testing.T, delta map[string]any, finish any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"id": "chatcmpl-1", "object": "chat.completion.chunk", "created": 1792335158, "model": "m",
		"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return "data: " + string(b) + "\n\n"
}

// collect re-assembles content and tool-call arguments from a restored Chat Completions stream.
func collect(t *testing.T, out string) (content, args string) {
	t.Helper()
	for _, ev := range strings.Split(out, "\n\n") {
		ev = strings.TrimSpace(ev)
		if !strings.HasPrefix(ev, "data: {") {
			continue
		}
		var obj struct {
			Created json.Number `json:"created"`
			Choices []struct {
				Delta struct {
					Content   string `json:"content"`
					ToolCalls []struct {
						Function struct {
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(ev, "data: ")), &obj); err != nil {
			t.Fatalf("invalid JSON event %q: %v", ev, err)
		}
		if obj.Created.String() != "1792335158" {
			t.Fatalf("created mangled: %q", obj.Created)
		}
		for _, c := range obj.Choices {
			content += c.Delta.Content
			for _, tc := range c.Delta.ToolCalls {
				args += tc.Function.Arguments
			}
		}
	}
	return content, args
}

func runStream(t *testing.T, events []string) string {
	t.Helper()
	r := NewSSERestoringReader(io.NopCloser(strings.NewReader(strings.Join(events, ""))), chatEngine(t))
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestChatCompletionsSplitContent(t *testing.T) {
	out := runStream(t, []string{
		chunk(t, map[string]any{"role": "assistant", "content": "pw: __V"}, nil),
		chunk(t, map[string]any{"content": "G_SECRET_010d92"}, nil),
		chunk(t, map[string]any{"content": "21706c_"}, nil),
		chunk(t, map[string]any{"content": "_ done"}, nil),
		chunk(t, map[string]any{}, "stop"),
		"data: [DONE]\n\n",
	})
	content, _ := collect(t, out)
	if content != "pw: "+testOriginal+" done" {
		t.Fatalf("content = %q", content)
	}
	if strings.Contains(out, "__VG_") {
		t.Fatalf("placeholder leaked downstream: %s", out)
	}
}

func TestChatCompletionsSplitToolArguments(t *testing.T) {
	out := runStream(t, []string{
		chunk(t, map[string]any{"tool_calls": []any{map[string]any{"index": 0, "id": "call_1", "type": "function",
			"function": map[string]any{"name": "bash", "arguments": ""}}}}, nil),
		chunk(t, map[string]any{"tool_calls": []any{map[string]any{"index": 0, "function": map[string]any{"arguments": `{"command":"login --pw __VG_SEC`}}}}, nil),
		chunk(t, map[string]any{"tool_calls": []any{map[string]any{"index": 0, "function": map[string]any{"arguments": `RET_010d9221706c__"}`}}}}, nil),
		chunk(t, map[string]any{}, "tool_calls"),
		"data: [DONE]\n\n",
	})
	_, args := collect(t, out)
	if args != `{"command":"login --pw `+testOriginal+`"}` {
		t.Fatalf("args = %q", args)
	}
}

func TestChatCompletionsTailFlushedBeforeFinish(t *testing.T) {
	// Stream ends right after an ambiguous "_" tail; it must not be lost or reordered after finish.
	out := runStream(t, []string{
		chunk(t, map[string]any{"content": "snake_"}, nil),
		chunk(t, map[string]any{}, "stop"),
		"data: [DONE]\n\n",
	})
	content, _ := collect(t, out)
	if content != "snake_" {
		t.Fatalf("content = %q", content)
	}
	if strings.Index(out, `"snake"`) > strings.Index(out, `"stop"`) {
		t.Fatalf("tail emitted after finish chunk: %s", out)
	}
}
