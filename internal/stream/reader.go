package stream

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"github.com/inkdust2021/vibeguard/internal/restore"
)

// SSERestoringReader wraps an io.ReadCloser and restores placeholders in SSE events.
//
// Key point: SSE streaming outputs from OpenAI-compatible APIs often deliver text as incremental "delta" fragments.
// Placeholders may be split across multiple SSE events, so "replace per event" can fail.
// This reader restores placeholders across delta events, while still keeping a whole-event fallback.
type SSERestoringReader struct {
	upstream io.ReadCloser
	restorer *restore.Engine
	buf      bytes.Buffer // accumulated bytes from upstream
	outBuf   bytes.Buffer // restored bytes ready for downstream
	readBuf  []byte       // reusable upstream read buffer

	// pendingDelta stores the most recent delta event. On stream end, we flush the tail into it
	// to avoid losing buffered placeholder prefixes (e.g. the stream ends with "__V").
	pendingDelta *pendingDeltaEvent
	textRestorer *textStreamRestorer
	// chat holds per-channel restorers for Chat Completions streams (see chat_completions.go).
	chat *chatStreamState
}

// NewSSERestoringReader creates a new SSE restoring reader
func NewSSERestoringReader(upstream io.ReadCloser, restorer *restore.Engine) *SSERestoringReader {
	return &SSERestoringReader{
		upstream: upstream,
		restorer: restorer,
		readBuf:  make([]byte, 4096),
		// Treat this as a single text stream for now (common in Codex/Responses API).
		// If we need parallel outputs later (output_index/content_index), extend to a map.
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
			r.flushChatAll()
			if r.buf.Len() > 0 {
				remaining := make([]byte, r.buf.Len())
				copy(remaining, r.buf.Bytes())
				r.buf.Reset()

				// Still do one fallback restore for remaining tail bytes at end of stream.
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
	// data may span multiple lines; emit single-line JSON for easier downstream parsing.
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

	// Copy out before compacting: Restore returns its input slice unchanged when nothing matched,
	// so `out` may alias t.buf and would be overwritten by the compaction below.
	out := string(t.eng.Restore(t.buf[:cut]))
	// Keep the tail (placeholder prefix or incomplete placeholder) and wait for the next fragment.
	t.buf = append(t.buf[:0], t.buf[cut:]...)
	return out
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

	// 1) Handle "full prefix exists but the placeholder has not fully arrived yet":
	// keep bytes from the last prefix to the end.
	//
	// Important: placeholders may end with "__", and the prefix also starts with "_".
	// Naively keeping a suffix can misread the ending "__" as the start of the next prefix,
	// splitting a complete placeholder and breaking restoration.
	// Prefer detecting whether the last prefix already forms a complete placeholder at EOF; if so, we can emit all bytes.
	lastBare := bytes.LastIndex(data, prefixBare)
	if lastBare != -1 {
		start := lastBare
		// If the bare prefix is preceded by the prefix's leading underscores, rewind to the full prefix
		// to avoid splitting "__" across emissions.
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
			// Note: to handle cases where models drop the trailing "__", the engine allows the "__" suffix to be optional.
			// In streaming scenarios, however, "__" can be split into the next chunk; if we restore too early,
			// the later "__" will remain as plain text (appearing as extra "__" after the restored text).
			//
			// So if the matched placeholder is exactly at the buffer end and this chunk does not include "__",
			// keep it and wait for the next chunk.
			token := data[start:end]
			hasSuffix := bytes.HasSuffix(token, []byte("__"))
			const maxTail = 512

			if end == len(data) {
				if !hasSuffix && len(data)-start <= maxTail {
					return start
				}
				return len(data)
			}

			// end < len(data): there is more data. If the remainder contains only "_" (common when "__" is split),
			// keep it as well.
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

			// The trailing placeholder is complete (and there is more data): safe to emit all bytes.
			return len(data)
		}
		if !ok {
			// Max tail length: avoid infinite buffering when "__VG_" appears in normal text.
			const maxTail = 512
			if len(data)-start <= maxTail {
				return start
			}
		}
	}

	// 2) Handle "prefix split at the end": keep the longest suffix (at most len(prefix)-1).
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

// RestoringReader restores placeholders for arbitrary "continuous byte streams" (supports across chunk boundaries).
//
// Use cases:
//   - Upstream returns application/json but streams via chunked/long connections (non-standard SSE).
//     Reading all before restoring can cause long periods of no downstream output (appears "stuck").
//
// Note: this Reader does not attempt to understand JSON structure; it only does byte-level placeholder matching/restoring.
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
			// Use the same "safe cut" strategy as SSE to avoid splitting placeholders across reads.
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
			// Flush tail (only once).
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
		// If parsing fails, do a byte-level fallback restore.
		r.flushPendingDelta(false)
		r.outBuf.Write(r.restorer.Restore(event))
		return
	}

	// Terminal events like [DONE] / done / completed: flush pendingDelta (with tail) first, then emit the terminal event.
	if parsed.isTerminal {
		r.flushPendingDelta(true)
		r.flushChatAll()
		r.outBuf.Write(r.restorer.Restore(event))
		return
	}

	// Chat Completions chunks ({"choices":[{"delta":...}]}) carry no "delta" type; handle them per channel.
	if r.handleChatChunk(parsed) {
		return
	}

	// Try parsing data as JSON to check whether this is a delta event.
	obj, loc, isDelta := parseDeltaJSON(parsed)
	if !isDelta {
		// Non-delta: if JSON type indicates done/completed, treat it as terminal and flush tail.
		if terminalByJSONType(parsed) {
			r.flushPendingDelta(true)
		} else {
			r.flushPendingDelta(false)
		}
		r.outBuf.Write(r.restorer.Restore(event))
		return
	}

	// Delta event: emit the previous pendingDelta first, then store current delta (one-event delay for tail flush on EOF).
	r.flushPendingDelta(false)

	deltaStr, ok := getDeltaText(obj, loc)
	if !ok {
		// parseDeltaJSON should guarantee a valid loc; if not, fall back to byte-level restore to avoid breaking downstream protocol.
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

	// Terminal detection: keep it permissive to avoid losing buffered tail.
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

	// Delta detection: prefer SSE event name, then fall back to JSON type.
	nameLower := strings.ToLower(p.eventName)
	typLower := ""
	if typ, ok := obj["type"].(string); ok {
		typLower = strings.ToLower(typ)
	}
	isDeltaEvent := strings.Contains(nameLower, "delta") || strings.Contains(typLower, "delta")
	if !isDeltaEvent {
		return nil, deltaTextLocation{}, false
	}

	// OpenAI-compatible implementations: {"delta":"..."}
	if _, ok := obj["delta"].(string); ok {
		return obj, deltaTextLocation{root: "delta"}, true
	}
	// Anthropic：{"delta":{"text":"...","type":"text_delta"}}
	if m, ok := obj["delta"].(map[string]any); ok {
		if _, ok := m["text"].(string); ok {
			return obj, deltaTextLocation{root: "delta", nested: "text"}, true
		}
	}

	// Unrecognized: do not write delta maps back as strings, or the protocol structure would be corrupted.
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
