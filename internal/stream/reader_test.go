package stream

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/inkdust2021/vibeguard/internal/restore"
	"github.com/inkdust2021/vibeguard/internal/session"
)

type chunkReadCloser struct {
	data   []byte
	pos    int
	chunks []int
}

func (c *chunkReadCloser) Read(p []byte) (int, error) {
	if c.pos >= len(c.data) {
		return 0, io.EOF
	}

	n := len(p)
	if len(c.chunks) > 0 {
		n = c.chunks[0]
		c.chunks = c.chunks[1:]
		if n > len(p) {
			n = len(p)
		}
	}
	if c.pos+n > len(c.data) {
		n = len(c.data) - c.pos
	}
	copy(p, c.data[c.pos:c.pos+n])
	c.pos += n
	return n, nil
}

func (c *chunkReadCloser) Close() error { return nil }

func collectDeltasFromSSE(t *testing.T, sse []byte) string {
	t.Helper()
	// 统一换行符，便于解析（兼容 \n\n 与 \r\n\r\n）
	sse = bytes.ReplaceAll(sse, []byte("\r\n"), []byte("\n"))
	blocks := bytes.Split(sse, []byte("\n\n"))
	var out stringsBuilder
	for _, b := range blocks {
		if len(bytes.TrimSpace(b)) == 0 {
			continue
		}
		var dataLines [][]byte
		for _, line := range bytes.Split(b, []byte("\n")) {
			line = bytes.TrimSuffix(line, []byte("\r"))
			if bytes.HasPrefix(line, []byte("data:")) {
				d := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
				dataLines = append(dataLines, d)
			}
		}
		if len(dataLines) == 0 {
			continue
		}
		payload := bytes.Join(dataLines, []byte("\n"))
		payload = bytes.TrimSpace(payload)
		if bytes.Equal(payload, []byte("[DONE]")) {
			continue
		}
		if len(payload) == 0 || payload[0] != '{' {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal(payload, &obj); err != nil {
			continue
		}
		if d, ok := obj["delta"].(string); ok {
			out.WriteString(d)
			continue
		}
		if m, ok := obj["delta"].(map[string]any); ok {
			if text, ok := m["text"].(string); ok {
				out.WriteString(text)
			}
		}
	}
	return out.String()
}

// stringsBuilder 是一个极简的 strings.Builder 替代品，避免引入额外依赖/导入冲突。
type stringsBuilder struct {
	b bytes.Buffer
}

func (s *stringsBuilder) WriteString(v string) {
	_, _ = s.b.WriteString(v)
}

func (s *stringsBuilder) String() string { return s.b.String() }

func TestSSERestoringReader_跨多个DeltaEvent还能还原占位符(t *testing.T) {
	sess := session.NewManager(time.Hour, 1000)
	t.Cleanup(sess.Close)

	original := "test123"
	placeholder := sess.GeneratePlaceholder(original, "TEXT", "__VG_")
	sess.Register(placeholder, original)
	eng := restore.NewEngine(sess, "__VG_")

	// 模拟占位符被拆分成多个 delta event（客户端会把 delta 拼起来展示）
	p1 := placeholder[:5]
	p2 := placeholder[5:13]
	p3 := placeholder[13:]

	upstream := []byte(
		"event: response.output_text.delta\n" +
			"data: {\"type\":\"response.output_text.delta\",\"delta\":\"" + p1 + "\"}\n\n" +
			"event: response.output_text.delta\n" +
			"data: {\"type\":\"response.output_text.delta\",\"delta\":\"" + p2 + "\"}\n\n" +
			"event: response.output_text.delta\n" +
			"data: {\"type\":\"response.output_text.delta\",\"delta\":\"" + p3 + "\"}\n\n" +
			"event: response.completed\n" +
			"data: {\"type\":\"response.completed\"}\n\n",
	)

	rc := &chunkReadCloser{data: upstream, chunks: []int{7, 3, 1, 2, 5, 13, 8, 21, 34}}
	reader := NewSSERestoringReader(rc, eng)

	out, err := io.ReadAll(reader)
	if err != nil && err != io.EOF {
		t.Fatalf("读取失败: %v", err)
	}

	got := collectDeltasFromSSE(t, out)
	if got != original {
		t.Fatalf("期望 delta 拼接后为 %q，实际：%q", original, got)
	}
	if bytes.Contains(out, []byte(placeholder)) {
		t.Fatalf("期望输出不再包含占位符 %q", placeholder)
	}
}

func TestSSERestoringReader_支持CRLF分隔符(t *testing.T) {
	sess := session.NewManager(time.Hour, 1000)
	t.Cleanup(sess.Close)

	original := "hello"
	placeholder := sess.GeneratePlaceholder(original, "TEXT", "__VG_")
	sess.Register(placeholder, original)
	eng := restore.NewEngine(sess, "__VG_")

	upstream := []byte(
		"event: response.output_text.delta\r\n" +
			"data: {\"type\":\"response.output_text.delta\",\"delta\":\"" + placeholder + "\"}\r\n\r\n" +
			"event: response.completed\r\n" +
			"data: [DONE]\r\n\r\n",
	)

	reader := NewSSERestoringReader(&chunkReadCloser{data: upstream, chunks: []int{1, 2, 3, 4, 5}}, eng)
	out, err := io.ReadAll(reader)
	if err != nil && err != io.EOF {
		t.Fatalf("读取失败: %v", err)
	}

	got := collectDeltasFromSSE(t, out)
	if got != original {
		t.Fatalf("期望 delta 拼接后为 %q，实际：%q", original, got)
	}
}

func TestSSERestoringReader_兼容AnthropicDelta嵌套结构(t *testing.T) {
	sess := session.NewManager(time.Hour, 1000)
	t.Cleanup(sess.Close)

	original := "test123"
	placeholder := sess.GeneratePlaceholder(original, "TEXT", "__VG_")
	sess.Register(placeholder, original)
	eng := restore.NewEngine(sess, "__VG_")

	upstream := []byte(
		"event: content_block_delta\n" +
			"data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"" + placeholder + "\"}}\n\n" +
			"event: message_stop\n" +
			"data: {\"type\":\"message_stop\"}\n\n",
	)

	rc := &chunkReadCloser{data: upstream, chunks: []int{1, 2, 3, 4, 5, 8, 13, 21}}
	reader := NewSSERestoringReader(rc, eng)

	out, err := io.ReadAll(reader)
	if err != nil && err != io.EOF {
		t.Fatalf("读取失败: %v", err)
	}

	if bytes.Contains(out, []byte(placeholder)) {
		t.Fatalf("期望输出不再包含占位符 %q", placeholder)
	}

	// 验证还原后的结构仍是嵌套 delta.text，而不是把 delta 整体替换为 string
	normalized := bytes.ReplaceAll(out, []byte("\r\n"), []byte("\n"))
	blocks := bytes.Split(normalized, []byte("\n\n"))
	for _, b := range blocks {
		if len(bytes.TrimSpace(b)) == 0 {
			continue
		}
		var dataLines [][]byte
		for _, line := range bytes.Split(b, []byte("\n")) {
			line = bytes.TrimSuffix(line, []byte("\r"))
			if bytes.HasPrefix(line, []byte("data:")) {
				d := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
				dataLines = append(dataLines, d)
			}
		}
		if len(dataLines) == 0 {
			continue
		}
		payload := bytes.TrimSpace(bytes.Join(dataLines, []byte("\n")))
		if len(payload) == 0 || payload[0] != '{' {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal(payload, &obj); err != nil {
			continue
		}
		typ, _ := obj["type"].(string)
		if typ != "content_block_delta" {
			continue
		}
		delta, ok := obj["delta"].(map[string]any)
		if !ok {
			t.Fatalf("期望 delta 为 object，实际：%T", obj["delta"])
		}
		text, ok := delta["text"].(string)
		if !ok {
			t.Fatalf("期望 delta.text 为 string，实际：%T", delta["text"])
		}
		if text != original {
			t.Fatalf("期望 delta.text 还原为 %q，实际：%q", original, text)
		}
		return
	}

	t.Fatalf("未找到 content_block_delta 事件")
}

func TestSSERestoringReader_支持去掉前后下划线的占位符(t *testing.T) {
	sess := session.NewManager(time.Hour, 1000)
	t.Cleanup(sess.Close)

	original := "test123"
	placeholder := sess.GeneratePlaceholder(original, "TEXT", "__VG_")
	sess.Register(placeholder, original)
	eng := restore.NewEngine(sess, "__VG_")

	// "__VG_TEXT_hash__" -> "VG_TEXT_hash"
	stripped := strings.TrimSuffix(strings.TrimPrefix(placeholder, "__"), "__")

	upstream := []byte(
		"event: response.output_text.delta\n" +
			"data: {\"type\":\"response.output_text.delta\",\"delta\":\"" + stripped + "\"}\n\n" +
			"event: response.completed\n" +
			"data: {\"type\":\"response.completed\"}\n\n",
	)

	reader := NewSSERestoringReader(&chunkReadCloser{data: upstream, chunks: []int{1, 2, 3, 4, 5, 8, 13, 21}}, eng)
	out, err := io.ReadAll(reader)
	if err != nil && err != io.EOF {
		t.Fatalf("读取失败: %v", err)
	}

	got := collectDeltasFromSSE(t, out)
	if got != original {
		t.Fatalf("期望 delta 还原为 %q，实际：%q", original, got)
	}
	if bytes.Contains(out, []byte(stripped)) {
		t.Fatalf("期望输出不再包含占位符变体 %q", stripped)
	}
}

func TestSSERestoringReader_占位符尾部双下划线跨Delta不残留(t *testing.T) {
	sess := session.NewManager(time.Hour, 1000)
	t.Cleanup(sess.Close)

	original := "test123"
	placeholder := sess.GeneratePlaceholder(original, "TEXT", "__VG_")
	sess.Register(placeholder, original)
	eng := restore.NewEngine(sess, "__VG_")

	// 模拟：占位符主体与尾部 "__" 被拆到两个 delta 里。
	// 若流式切割不当，可能会先还原主体，再把 "__" 当普通文本输出，导致用户看到 "test123__"。
	mainPart := strings.TrimSuffix(strings.TrimPrefix(placeholder, "__"), "__") // "VG_TEXT_xxx"
	tail := "__"

	upstream := []byte(
		"event: response.output_text.delta\n" +
			"data: {\"type\":\"response.output_text.delta\",\"delta\":\"" + mainPart + "\"}\n\n" +
			"event: response.output_text.delta\n" +
			"data: {\"type\":\"response.output_text.delta\",\"delta\":\"" + tail + "\"}\n\n" +
			"event: response.completed\n" +
			"data: {\"type\":\"response.completed\"}\n\n",
	)

	reader := NewSSERestoringReader(&chunkReadCloser{data: upstream, chunks: []int{7, 5, 3, 2, 11, 1, 2, 3}}, eng)
	out, err := io.ReadAll(reader)
	if err != nil && err != io.EOF {
		t.Fatalf("读取失败: %v", err)
	}

	got := collectDeltasFromSSE(t, out)
	if got != original {
		t.Fatalf("期望 delta 还原为 %q，实际：%q", original, got)
	}
	if strings.Contains(got, "__") {
		t.Fatalf("不应残留占位符尾部下划线，实际：%q", got)
	}
}
