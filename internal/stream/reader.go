package stream

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"github.com/inkdust2021/vibeguard/internal/restore"
)

// SSERestoringReader wraps an io.ReadCloser and restores placeholders in SSE events。
//
// 关键点：OpenAI/兼容 API 的 SSE 流式输出通常以“delta 片段”逐段发送文本，
// 占位符可能被拆成多段（跨多个 SSE event），这会导致“逐 event 直接替换”失效。
// 因此这里针对 delta 做“跨 event 的流式还原”，并仍保留对整段 event 的兜底还原。
type SSERestoringReader struct {
	upstream io.ReadCloser
	restorer *restore.Engine
	buf      bytes.Buffer // accumulated bytes from upstream
	outBuf   bytes.Buffer // restored bytes ready for downstream
	readBuf  []byte       // reusable upstream read buffer

	// pendingDelta 暂存“最近一个 delta event”，用于在流结束时把最后的尾巴 flush 到它里面，
	// 避免尾部保留的前缀片段丢失（例如恰好以 "__V" 结尾）。
	pendingDelta *pendingDeltaEvent
	textRestorer *textStreamRestorer
}

// NewSSERestoringReader creates a new SSE restoring reader
func NewSSERestoringReader(upstream io.ReadCloser, restorer *restore.Engine) *SSERestoringReader {
	return &SSERestoringReader{
		upstream: upstream,
		restorer: restorer,
		readBuf:  make([]byte, 4096),
		// 这里暂按“单一文本流”处理（Codex/Responses API 的常见场景）。
		// 如后续需要支持多输出并行（output_index/content_index），可扩展为 map。
		textRestorer: newTextStreamRestorer(restorer),
	}
}

// Read implements io.Reader
func (r *SSERestoringReader) Read(p []byte) (int, error) {
	for {
		// If we have restored bytes ready, return them
		if r.outBuf.Len() > 0 {
			return r.outBuf.Read(p)
		}

		// Read from upstream into internal buffer
		n, err := r.upstream.Read(r.readBuf)
		if n > 0 {
			r.buf.Write(r.readBuf[:n])
		}

		// Process complete SSE events (delimited by \n\n or \r\n\r\n)
		for {
			data := r.buf.Bytes()
			idx, sepLen := findSSEEventDelimiter(data)
			if idx == -1 {
				break // No complete event yet
			}

			// Extract complete event (including delimiter)
			event := r.buf.Next(idx + sepLen)
			r.handleEvent(event)
		}

		if r.outBuf.Len() > 0 {
			return r.outBuf.Read(p)
		}

		if err != nil {
			// On EOF/error, flush remaining buffered bytes
			r.flushPendingDelta(true)
			if r.buf.Len() > 0 {
				remaining := make([]byte, r.buf.Len())
				copy(remaining, r.buf.Bytes())
				r.buf.Reset()

				// 流末尾的残余数据仍做一次兜底还原
				restored := r.restorer.Restore(remaining)
				r.outBuf.Write(restored)
				if r.outBuf.Len() > 0 {
					return r.outBuf.Read(p)
				}
			}
			return 0, err
		}
	}
}

// Close implements io.Closer
func (r *SSERestoringReader) Close() error {
	return r.upstream.Close()
}

type pendingDeltaEvent struct {
	lineSep  []byte   // "\n" or "\r\n"
	eventSep []byte   // "\n\n" or "\r\n\r\n"
	before   [][]byte // non-data lines before the first data line
	after    [][]byte // non-data lines after data lines
	deltaLoc deltaTextLocation
	obj      map[string]any
}

func (e *pendingDeltaEvent) emit(extra string) []byte {
	if e == nil {
		return nil
	}
	if extra != "" {
		appendDeltaText(e.obj, e.deltaLoc, extra)
	}
	b, _ := json.Marshal(e.obj)

	var out bytes.Buffer
	for _, ln := range e.before {
		if len(ln) == 0 {
			continue
		}
		out.Write(ln)
		out.Write(e.lineSep)
	}
	// data 支持多行，这里输出单行 JSON（更利于下游解析）
	out.Write([]byte("data: "))
	out.Write(b)
	out.Write(e.lineSep)
	for _, ln := range e.after {
		if len(ln) == 0 {
			continue
		}
		out.Write(ln)
		out.Write(e.lineSep)
	}
	out.Write(e.eventSep)
	return out.Bytes()
}

type textStreamRestorer struct {
	eng *restore.Engine
	buf []byte
}

func newTextStreamRestorer(eng *restore.Engine) *textStreamRestorer {
	return &textStreamRestorer{eng: eng}
}

func (t *textStreamRestorer) Feed(fragment string) string {
	if fragment == "" {
		return ""
	}
	t.buf = append(t.buf, fragment...)

	cut := safeEmitCut(t.buf, t.eng)
	if cut <= 0 {
		return ""
	}

	out := t.eng.Restore(t.buf[:cut])
	// 保留尾巴（可能是占位符前缀/未完整占位符），等待下一段补齐
	t.buf = append(t.buf[:0], t.buf[cut:]...)
	return string(out)
}

func (t *textStreamRestorer) Flush() string {
	if len(t.buf) == 0 {
		return ""
	}
	out := t.eng.Restore(t.buf)
	t.buf = t.buf[:0]
	return string(out)
}

func safeEmitCut(data []byte, eng *restore.Engine) int {
	if len(data) == 0 || eng == nil {
		return len(data)
	}
	prefixFullStr := eng.Prefix()
	if prefixFullStr == "" {
		return len(data)
	}
	prefixFull := []byte(prefixFullStr)
	prefixBareStr := strings.TrimLeft(prefixFullStr, "_")
	prefixBare := []byte(prefixBareStr)
	if len(prefixBare) == 0 {
		prefixBare = prefixFull
	}
	leadingUnderscores := len(prefixFullStr) - len(prefixBareStr)
	if leadingUnderscores < 0 {
		leadingUnderscores = 0
	}

	// 1) 处理“完整前缀已出现但占位符还没完整到达”的情况：保留从最后一个前缀开始到末尾。
	//
	// 特别注意：占位符本身以 "__" 结尾，而 prefix 也以 "_" 开头，简单的“保留后缀前缀片段”
	// 会误把占位符末尾 "__" 当作“下一个占位符前缀的开始”，从而把完整占位符拆开输出，导致无法还原。
	// 因此这里优先判断“最后一个 prefix 是否已构成完整占位符且刚好到末尾”，若是则可直接输出全部。
	lastBare := bytes.LastIndex(data, prefixBare)
	if lastBare != -1 {
		start := lastBare
		// 若 bare 前面正好有 prefix 的前导下划线，把起点回退到完整 prefix，避免把 "__" 拆开输出。
		if leadingUnderscores > 0 && lastBare >= leadingUnderscores {
			all := true
			for i := lastBare - leadingUnderscores; i < lastBare; i++ {
				if data[i] != '_' {
					all = false
					break
				}
			}
			if all {
				start = lastBare - leadingUnderscores
			}
		}

		end, ok := eng.MatchAt(data, start)
		if ok {
			// 注意：引擎为了兼容“模型丢掉尾部 __”的情况，允许占位符末尾 "__" 可选。
			// 但在流式场景中，"__" 可能被拆到下一段输出；若此时提前输出并还原占位符，
			// 下一段再到来的 "__" 就会作为普通文本残留（表现为原文后多出 "__"）。
			//
			// 因此当匹配到的占位符刚好贴着 buffer 末尾，且本段未包含尾部 "__" 时，先保留不输出，等待下一段补齐。
			token := data[start:end]
			hasSuffix := bytes.HasSuffix(token, []byte("__"))
			const maxTail = 512

			if end == len(data) {
				if !hasSuffix && len(data)-start <= maxTail {
					return start
				}
				return len(data)
			}

			// end < len(data)：后面还有数据。若剩余部分仅由 "_" 组成（常见于 "__" 被拆分），也需要保留。
			if !hasSuffix && len(data)-start <= maxTail {
				rem := data[end:]
				if len(rem) > 0 && len(rem) <= 2 {
					onlyUnderscore := true
					for _, b := range rem {
						if b != '_' {
							onlyUnderscore = false
							break
						}
					}
					if onlyUnderscore {
						return start
					}
				}
			}

			// 末尾的占位符已完整（且后面还有数据）：可以安全输出全部
			return len(data)
		}
		if !ok {
			// 最大保留长度：避免误把普通文本中的 "__VG_" 当作占位符导致无限缓存
			const maxTail = 512
			if len(data)-start <= maxTail {
				return start
			}
		}
	}

	// 2) 处理“前缀被拆分到末尾”的情况：保留最长后缀（最多 len(prefix)-1）
	partial := suffixPrefixLen(data, prefixFull)
	if !bytes.Equal(prefixBare, prefixFull) {
		if p := suffixPrefixLen(data, prefixBare); p > partial {
			partial = p
		}
	}
	cut := len(data) - partial

	if cut < 0 {
		return 0
	}
	if cut > len(data) {
		return len(data)
	}
	return cut
}

func suffixPrefixLen(data, prefix []byte) int {
	if len(data) == 0 || len(prefix) <= 1 {
		return 0
	}
	max := len(prefix) - 1
	if max > len(data) {
		max = len(data)
	}
	for k := max; k > 0; k-- {
		if bytes.HasSuffix(data, prefix[:k]) {
			return k
		}
	}
	return 0
}

func findSSEEventDelimiter(data []byte) (idx int, sepLen int) {
	// Prefer CRLFCRLF if present earlier than LFLF
	idxCRLF := bytes.Index(data, []byte("\r\n\r\n"))
	idxLF := bytes.Index(data, []byte("\n\n"))

	switch {
	case idxCRLF != -1 && (idxLF == -1 || idxCRLF < idxLF):
		return idxCRLF, 4
	case idxLF != -1:
		return idxLF, 2
	default:
		return -1, 0
	}
}

// RestoringReader 对任意“连续字节流”做占位符还原（支持跨 chunk 边界）。
//
// 适用场景：
//   - 上游返回 application/json 但使用 chunked/长连接方式流式输出（非标准 SSE），
//     这时若整段 ReadAll 再还原，会导致下游长时间无输出（表现为“卡住”）。
//
// 注意：该 Reader 不尝试理解 JSON 结构，仅做字节级占位符匹配与还原。
type RestoringReader struct {
	upstream  io.ReadCloser
	restorer  *restore.Engine
	readBuf   []byte
	outBuf    bytes.Buffer
	textState *textStreamRestorer
	flushed   bool
}

func NewRestoringReader(upstream io.ReadCloser, restorer *restore.Engine) *RestoringReader {
	return &RestoringReader{
		upstream:  upstream,
		restorer:  restorer,
		readBuf:   make([]byte, 4096),
		textState: newTextStreamRestorer(restorer),
	}
}

func (r *RestoringReader) Read(p []byte) (int, error) {
	for {
		if r.outBuf.Len() > 0 {
			return r.outBuf.Read(p)
		}

		n, err := r.upstream.Read(r.readBuf)
		if n > 0 {
			// 使用与 SSE 同一套“安全切割”策略，避免把占位符拆开输出导致无法还原
			if r.textState != nil {
				emitted := r.textState.Feed(string(r.readBuf[:n]))
				if emitted != "" {
					r.outBuf.WriteString(emitted)
				}
			} else {
				r.outBuf.Write(r.restorer.Restore(r.readBuf[:n]))
			}
		}

		if r.outBuf.Len() > 0 {
			return r.outBuf.Read(p)
		}

		if err != nil {
			// flush 尾巴（仅一次）
			if !r.flushed {
				r.flushed = true
				if r.textState != nil {
					if extra := r.textState.Flush(); extra != "" {
						r.outBuf.WriteString(extra)
					}
				}
			}
			if r.outBuf.Len() > 0 {
				return r.outBuf.Read(p)
			}
			return 0, err
		}
	}
}

func (r *RestoringReader) Close() error {
	return r.upstream.Close()
}

func (r *SSERestoringReader) flushPendingDelta(final bool) {
	if r.pendingDelta == nil {
		return
	}
	extra := ""
	if final && r.textRestorer != nil {
		extra = r.textRestorer.Flush()
	}
	r.outBuf.Write(r.pendingDelta.emit(extra))
	r.pendingDelta = nil
}

func (r *SSERestoringReader) handleEvent(event []byte) {
	if len(event) == 0 {
		return
	}

	parsed, ok := parseSSEEvent(event)
	if !ok {
		// 无法解析就按字节兜底还原
		r.flushPendingDelta(false)
		r.outBuf.Write(r.restorer.Restore(event))
		return
	}

	// [DONE] / done / completed 等终止事件：先 flush pendingDelta（带尾巴），再输出终止事件
	if parsed.isTerminal {
		r.flushPendingDelta(true)
		r.outBuf.Write(r.restorer.Restore(event))
		return
	}

	// 尝试把 data 当 JSON 解析，看是否是 delta event
	obj, loc, isDelta := parseDeltaJSON(parsed)
	if !isDelta {
		// 非 delta：若 JSON 的 type 显示为 done/completed，则认为是终止事件，flush 尾巴
		if terminalByJSONType(parsed) {
			r.flushPendingDelta(true)
		} else {
			r.flushPendingDelta(false)
		}
		r.outBuf.Write(r.restorer.Restore(event))
		return
	}

	// delta event：先输出上一个 pendingDelta，再暂存当前 delta（延迟一个 event，用于流结束 flush 尾巴）
	r.flushPendingDelta(false)

	deltaStr, ok := getDeltaText(obj, loc)
	if !ok {
		// 理论上 parseDeltaJSON 已保证 loc 可用；若异常，回退为逐字节还原，避免破坏下游协议
		r.outBuf.Write(r.restorer.Restore(event))
		return
	}
	emitted := ""
	if r.textRestorer != nil {
		emitted = r.textRestorer.Feed(deltaStr)
	} else {
		emitted = string(r.restorer.Restore([]byte(deltaStr)))
	}
	setDeltaText(obj, loc, emitted)

	r.pendingDelta = &pendingDeltaEvent{
		lineSep:  parsed.lineSep,
		eventSep: parsed.eventSep,
		before:   parsed.before,
		after:    parsed.after,
		deltaLoc: loc,
		obj:      obj,
	}
}

type parsedEvent struct {
	lineSep    []byte
	eventSep   []byte
	before     [][]byte
	after      [][]byte
	eventName  string
	data       []byte
	isTerminal bool
}

func parseSSEEvent(event []byte) (parsedEvent, bool) {
	var p parsedEvent
	if len(event) == 0 {
		return p, false
	}

	// Determine separator style
	p.eventSep = []byte("\n\n")
	p.lineSep = []byte("\n")
	if bytes.HasSuffix(event, []byte("\r\n\r\n")) {
		p.eventSep = []byte("\r\n\r\n")
		p.lineSep = []byte("\r\n")
	}

	body := event
	if len(event) >= len(p.eventSep) && bytes.HasSuffix(event, p.eventSep) {
		body = event[:len(event)-len(p.eventSep)]
	}

	lines := bytes.Split(body, []byte("\n"))
	seenData := false
	var dataLines [][]byte

	for _, raw := range lines {
		if len(raw) == 0 {
			continue
		}
		ln := bytes.TrimSuffix(raw, []byte("\r"))
		if len(ln) == 0 {
			continue
		}

		if bytes.HasPrefix(ln, []byte("event:")) {
			p.eventName = strings.TrimSpace(string(ln[len("event:"):]))
		}

		if bytes.HasPrefix(ln, []byte("data:")) {
			seenData = true
			d := ln[len("data:"):]
			if len(d) > 0 && d[0] == ' ' {
				d = d[1:]
			}
			dataLines = append(dataLines, d)
			continue
		}

		if !seenData {
			p.before = append(p.before, ln)
		} else {
			p.after = append(p.after, ln)
		}
	}

	p.data = bytes.Join(dataLines, []byte("\n"))
	dataTrim := bytes.TrimSpace(p.data)

	// 终止判定：尽量宽松，避免尾巴丢失
	if bytes.Equal(dataTrim, []byte("[DONE]")) {
		p.isTerminal = true
		return p, true
	}
	lowerName := strings.ToLower(p.eventName)
	if strings.Contains(lowerName, "done") || strings.Contains(lowerName, "completed") || strings.Contains(lowerName, "complete") {
		p.isTerminal = true
		return p, true
	}

	return p, true
}

type deltaTextLocation struct {
	root   string
	nested string // optional
}

func getDeltaText(obj map[string]any, loc deltaTextLocation) (string, bool) {
	if obj == nil || loc.root == "" {
		return "", false
	}
	v, ok := obj[loc.root]
	if !ok {
		return "", false
	}
	if loc.nested == "" {
		s, ok := v.(string)
		return s, ok
	}
	m, ok := v.(map[string]any)
	if !ok {
		return "", false
	}
	s, ok := m[loc.nested].(string)
	return s, ok
}

func setDeltaText(obj map[string]any, loc deltaTextLocation, text string) bool {
	if obj == nil || loc.root == "" {
		return false
	}
	v, ok := obj[loc.root]
	if loc.nested == "" {
		obj[loc.root] = text
		return true
	}
	if !ok {
		return false
	}
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	m[loc.nested] = text
	return true
}

func appendDeltaText(obj map[string]any, loc deltaTextLocation, extra string) bool {
	if extra == "" {
		return true
	}
	cur, ok := getDeltaText(obj, loc)
	if !ok {
		return false
	}
	return setDeltaText(obj, loc, cur+extra)
}

func parseDeltaJSON(p parsedEvent) (obj map[string]any, loc deltaTextLocation, ok bool) {
	dataTrim := bytes.TrimSpace(p.data)
	if len(dataTrim) == 0 || dataTrim[0] != '{' {
		return nil, deltaTextLocation{}, false
	}

	if err := json.Unmarshal(dataTrim, &obj); err != nil {
		return nil, deltaTextLocation{}, false
	}

	// 判定 delta event：优先看 SSE event 名，其次看 JSON 内的 type
	nameLower := strings.ToLower(p.eventName)
	typLower := ""
	if typ, ok := obj["type"].(string); ok {
		typLower = strings.ToLower(typ)
	}
	isDeltaEvent := strings.Contains(nameLower, "delta") || strings.Contains(typLower, "delta")
	if !isDeltaEvent {
		return nil, deltaTextLocation{}, false
	}

	// OpenAI/兼容实现：{"delta":"..."}
	if _, ok := obj["delta"].(string); ok {
		return obj, deltaTextLocation{root: "delta"}, true
	}
	// Anthropic：{"delta":{"text":"...","type":"text_delta"}}
	if m, ok := obj["delta"].(map[string]any); ok {
		if _, ok := m["text"].(string); ok {
			return obj, deltaTextLocation{root: "delta", nested: "text"}, true
		}
	}

	// 未识别：不要把 delta map 误当成 string 写回，否则会破坏协议结构。
	return nil, deltaTextLocation{}, false
}

func terminalByJSONType(p parsedEvent) bool {
	dataTrim := bytes.TrimSpace(p.data)
	if len(dataTrim) == 0 || dataTrim[0] != '{' {
		return false
	}

	var obj map[string]any
	if err := json.Unmarshal(dataTrim, &obj); err != nil {
		return false
	}
	typ, ok := obj["type"].(string)
	if !ok || typ == "" {
		return false
	}
	tl := strings.ToLower(typ)
	return strings.Contains(tl, "done") || strings.Contains(tl, "completed") || strings.Contains(tl, "complete")
}
