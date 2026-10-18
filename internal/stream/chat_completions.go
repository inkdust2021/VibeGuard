package stream

import (
	"bytes"
	"encoding/json"
)

// Chat Completions streaming support.
//
// OpenAI-compatible Chat Completions streams (used by OpenRouter, OpenCode Zen, DeepSeek, vLLM, ...)
// deliver text as {"choices":[{"index":0,"delta":{"content":"..."}}]} and tool-call arguments as
// {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"..."}}]}}]}.
// These events have no "type"/"event" containing "delta", so the generic delta handling does not see
// them and a placeholder split across chunks would never be restored. Worse, tool-call arguments are
// where restoration matters most: that is how the model "uses" a secret it never saw.
//
// Each incrementally streamed string (per choice: content / reasoning, and per tool call: arguments)
// gets its own textStreamRestorer so channels never mix. Buffered tails are flushed as a synthetic
// chunk right before the chunk carrying finish_reason, and again before [DONE] / EOF as a fallback.

// chatChannel identifies one incrementally streamed string inside a Chat Completions stream.
type chatChannel struct {
	choice int
	field  string // "content", "reasoning_content", "reasoning", or "tool_calls"
	tool   int    // tool_calls[].index; only meaningful when field == "tool_calls"
}

type chatStreamState struct {
	restorers map[chatChannel]*textStreamRestorer
	order     []chatChannel
	meta      map[string]any // id/object/created/model copied into synthetic flush chunks
	lineSep   []byte
	eventSep  []byte
}

var chatTextFields = []string{"content", "reasoning_content", "reasoning"}

func (r *SSERestoringReader) chatRestorer(ch chatChannel) *textStreamRestorer {
	if r.chat == nil {
		r.chat = &chatStreamState{restorers: map[chatChannel]*textStreamRestorer{}}
	}
	t, ok := r.chat.restorers[ch]
	if !ok {
		t = newTextStreamRestorer(r.restorer)
		r.chat.restorers[ch] = t
		r.chat.order = append(r.chat.order, ch)
	}
	return t
}

// decodeJSONObject decodes with UseNumber so integers (created, token counts) round-trip exactly.
func decodeJSONObject(data []byte) (map[string]any, bool) {
	dataTrim := bytes.TrimSpace(data)
	if len(dataTrim) == 0 || dataTrim[0] != '{' {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(dataTrim))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		return nil, false
	}
	return obj, true
}

func intField(v any, fallback int) int {
	switch n := v.(type) {
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return int(i)
		}
	case float64:
		return int(n)
	}
	return fallback
}

// handleChatChunk processes a Chat Completions chunk. It returns false when the event is not one.
func (r *SSERestoringReader) handleChatChunk(parsed parsedEvent) bool {
	obj, ok := decodeJSONObject(parsed.data)
	if !ok {
		return false
	}
	choices, ok := obj["choices"].([]any)
	if !ok {
		return false
	}
	hasDelta := false
	for _, c := range choices {
		if cm, ok := c.(map[string]any); ok {
			if _, ok := cm["delta"].(map[string]any); ok {
				hasDelta = true
				break
			}
		}
	}
	if !hasDelta {
		return false
	}

	// Never interleave with the generic one-event-delay delta path.
	r.flushPendingDelta(true)

	if r.chat == nil {
		r.chat = &chatStreamState{restorers: map[chatChannel]*textStreamRestorer{}}
	}
	r.chat.lineSep, r.chat.eventSep = parsed.lineSep, parsed.eventSep
	meta := map[string]any{}
	for _, k := range []string{"id", "object", "created", "model", "system_fingerprint"} {
		if v, ok := obj[k]; ok {
			meta[k] = v
		}
	}
	r.chat.meta = meta

	var finished []int
	for pos, c := range choices {
		cm, ok := c.(map[string]any)
		if !ok {
			continue
		}
		choiceIdx := intField(cm["index"], pos)
		if delta, ok := cm["delta"].(map[string]any); ok {
			for _, field := range chatTextFields {
				if s, ok := delta[field].(string); ok && s != "" {
					delta[field] = r.chatRestorer(chatChannel{choice: choiceIdx, field: field}).Feed(s)
				}
			}
			if tcs, ok := delta["tool_calls"].([]any); ok {
				for tpos, tc := range tcs {
					tcm, ok := tc.(map[string]any)
					if !ok {
						continue
					}
					fn, ok := tcm["function"].(map[string]any)
					if !ok {
						continue
					}
					if s, ok := fn["arguments"].(string); ok && s != "" {
						ch := chatChannel{choice: choiceIdx, field: "tool_calls", tool: intField(tcm["index"], tpos)}
						fn["arguments"] = r.chatRestorer(ch).Feed(s)
					}
				}
			}
		}
		if fr, ok := cm["finish_reason"]; ok && fr != nil {
			finished = append(finished, choiceIdx)
		}
	}

	// Flush tails of finished choices before the chunk that announces the finish.
	for _, idx := range finished {
		r.flushChatChoice(idx, true)
	}

	ev := &pendingDeltaEvent{
		lineSep:  parsed.lineSep,
		eventSep: parsed.eventSep,
		before:   parsed.before,
		after:    parsed.after,
		obj:      obj,
	}
	r.outBuf.Write(ev.emit(""))
	return true
}

// flushChatChoice emits a synthetic chunk with the buffered tails of one choice
// (filter=false flushes every channel into that choice index).
func (r *SSERestoringReader) flushChatChoice(choiceIdx int, filter bool) {
	if r.chat == nil || len(r.chat.order) == 0 {
		return
	}
	delta := map[string]any{}
	var toolCalls []any
	for _, ch := range r.chat.order {
		if filter && ch.choice != choiceIdx {
			continue
		}
		tail := r.chat.restorers[ch].Flush()
		if tail == "" {
			continue
		}
		if ch.field == "tool_calls" {
			toolCalls = append(toolCalls, map[string]any{
				"index":    ch.tool,
				"function": map[string]any{"arguments": tail},
			})
		} else {
			delta[ch.field] = tail
		}
	}
	if len(toolCalls) > 0 {
		delta["tool_calls"] = toolCalls
	}
	if len(delta) == 0 {
		return
	}
	obj := map[string]any{}
	for k, v := range r.chat.meta {
		obj[k] = v
	}
	obj["choices"] = []any{map[string]any{"index": choiceIdx, "delta": delta, "finish_reason": nil}}
	ev := &pendingDeltaEvent{lineSep: r.chat.lineSep, eventSep: r.chat.eventSep, obj: obj}
	if ev.lineSep == nil {
		ev.lineSep, ev.eventSep = []byte("\n"), []byte("\n\n")
	}
	r.outBuf.Write(ev.emit(""))
}

// flushChatAll flushes every buffered Chat Completions tail (stream end / [DONE]).
func (r *SSERestoringReader) flushChatAll() {
	if r.chat == nil {
		return
	}
	seen := map[int]bool{}
	for _, ch := range r.chat.order {
		if seen[ch.choice] {
			continue
		}
		seen[ch.choice] = true
		r.flushChatChoice(ch.choice, true)
	}
}
