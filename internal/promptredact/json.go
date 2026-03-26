package promptredact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/inkdust2021/vibeguard/internal/redact"
)

// RedactJSONBody 只对 JSON 里的 prompt-like 字段做结构化脱敏，
// 避免误改模型、schema、metadata 等协议字段。
func RedactJSONBody(redactEng redact.Redactor, body []byte) (out []byte, matches []redact.Match, changed bool, err error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()

	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, nil, false, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, nil, false, fmt.Errorf("trailing JSON data")
	}

	redacted, matches, changed, err := redactJSONValuePromptOnly(redactEng, v)
	if err != nil {
		return nil, nil, false, err
	}
	if !changed {
		return body, nil, false, nil
	}

	out, err = json.Marshal(redacted)
	if err != nil {
		return nil, nil, false, err
	}
	return out, matches, true, nil
}

func redactPromptJSONStringValue(redactEng redact.Redactor, s string) (out any, matches []redact.Match, changed bool, err error) {
	redactedRaw, ms := redactEng.RedactWithMatches([]byte(s))
	if len(ms) == 0 {
		return s, nil, false, nil
	}

	b, err := json.Marshal(string(redactedRaw))
	if err != nil {
		return s, nil, false, err
	}

	raw := json.RawMessage(b)
	if !json.Valid(raw) {
		return s, nil, false, nil
	}

	return raw, ms, true, nil
}

func redactJSONValuePromptOnly(redactEng redact.Redactor, v any) (out any, matches []redact.Match, changed bool, err error) {
	switch vv := v.(type) {
	case []any:
		anyChanged := false
		var all []redact.Match
		for i := range vv {
			nv, ms, ch, err := redactJSONValuePromptOnly(redactEng, vv[i])
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv[i] = nv
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}
		return vv, all, anyChanged, nil

	case map[string]any:
		anyChanged := false
		var all []redact.Match
		for k, val := range vv {
			var (
				nv any
				ms []redact.Match
				ch bool
			)

			switch k {
			case "messages", "input", "contents":
				nv, ms, ch, err = redactJSONMessagesLike(redactEng, val)
			default:
				nv, ms, ch, err = redactJSONValuePromptOnly(redactEng, val)
			}
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv[k] = nv
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}
		return vv, all, anyChanged, nil

	default:
		return v, nil, false, nil
	}
}

func redactJSONStringLike(redactEng redact.Redactor, v any) (out any, matches []redact.Match, changed bool, err error) {
	s, ok := v.(string)
	if !ok {
		return v, nil, false, nil
	}
	return redactPromptJSONStringValue(redactEng, s)
}

func redactJSONMessagesLike(redactEng redact.Redactor, v any) (out any, matches []redact.Match, changed bool, err error) {
	switch vv := v.(type) {
	case string:
		return redactPromptJSONStringValue(redactEng, vv)
	case []any:
		anyChanged := false
		var all []redact.Match
		for i := range vv {
			nv, ms, ch, err := redactJSONMessageItem(redactEng, vv[i])
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv[i] = nv
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}
		return vv, all, anyChanged, nil
	case map[string]any:
		return redactJSONValuePromptOnly(redactEng, vv)
	default:
		return v, nil, false, nil
	}
}

func redactJSONMessageItem(redactEng redact.Redactor, v any) (out any, matches []redact.Match, changed bool, err error) {
	switch vv := v.(type) {
	case string:
		return redactPromptJSONStringValue(redactEng, vv)
	case map[string]any:
		anyChanged := false
		var all []redact.Match

		if c, ok := vv["content"]; ok {
			nc, ms, ch, err := redactJSONMessageContent(redactEng, c)
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv["content"] = nc
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}

		if p, ok := vv["parts"]; ok {
			np, ms, ch, err := redactJSONTextParts(redactEng, p)
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv["parts"] = np
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}

		if t, ok := vv["text"]; ok {
			nt, ms, ch, err := redactJSONStringLike(redactEng, t)
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv["text"] = nt
				anyChanged = true
			}
			if len(ms) > 0 {
				all = append(all, ms...)
			}
		}

		return vv, all, anyChanged, nil
	default:
		return v, nil, false, nil
	}
}

func redactJSONMessageContent(redactEng redact.Redactor, v any) (out any, matches []redact.Match, changed bool, err error) {
	switch vv := v.(type) {
	case string:
		return redactPromptJSONStringValue(redactEng, vv)
	case []any:
		return redactJSONTextParts(redactEng, vv)
	case map[string]any:
		return redactJSONTextPart(redactEng, vv)
	default:
		return v, nil, false, nil
	}
}

func redactJSONTextParts(redactEng redact.Redactor, v any) (out any, matches []redact.Match, changed bool, err error) {
	parts, ok := v.([]any)
	if !ok {
		return v, nil, false, nil
	}

	anyChanged := false
	var all []redact.Match
	for i := range parts {
		nv, ms, ch, err := redactJSONTextPart(redactEng, parts[i])
		if err != nil {
			return v, nil, false, err
		}
		if ch {
			parts[i] = nv
			anyChanged = true
		}
		if len(ms) > 0 {
			all = append(all, ms...)
		}
	}
	return parts, all, anyChanged, nil
}

func redactJSONTextPart(redactEng redact.Redactor, v any) (out any, matches []redact.Match, changed bool, err error) {
	switch vv := v.(type) {
	case string:
		return redactPromptJSONStringValue(redactEng, vv)
	case map[string]any:
		if t, ok := vv["text"]; ok {
			if ts, ok := t.(string); ok && isSystemReminderText(ts) {
				return vv, nil, false, nil
			}
			nt, ms, ch, err := redactJSONStringLike(redactEng, t)
			if err != nil {
				return v, nil, false, err
			}
			if ch {
				vv["text"] = nt
			}
			return vv, ms, ch, err
		}
		return v, nil, false, nil
	default:
		return v, nil, false, nil
	}
}

func isSystemReminderText(s string) bool {
	t := strings.TrimSpace(s)
	if t == "" {
		return false
	}
	if !strings.HasPrefix(t, "<system-reminder") {
		return false
	}
	return strings.Contains(t, "</system-reminder>")
}
