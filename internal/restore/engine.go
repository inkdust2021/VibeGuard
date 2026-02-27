package restore

import (
	"regexp"

	"github.com/inkdust2021/vibeguard/internal/session"
)

// Engine handles placeholder restoration
type Engine struct {
	session *session.Manager
	prefix  string
	regex   *regexp.Regexp
}

// NewEngine creates a new restoration engine
func NewEngine(s *session.Manager, prefix string) *Engine {
	// Pattern: __VG_CATEGORY_HASH12__ or __VG_CATEGORY_HASH12_N__
	escapedPrefix := regexp.QuoteMeta(prefix)
	// category 允许包含下划线（如 CHINA_PHONE），也允许用户自定义更宽松的命名。
	pattern := escapedPrefix + `[A-Za-z0-9_]+_[a-f0-9]{12}(?:_\d+)?__`

	return &Engine{
		session: s,
		prefix:  prefix,
		regex:   regexp.MustCompile(pattern),
	}
}

// Restore replaces placeholders with original values
func (e *Engine) Restore(input []byte) []byte {
	if len(input) == 0 {
		return input
	}

	matches := e.regex.FindAllIndex(input, -1)
	if len(matches) == 0 {
		return input
	}

	// 采用“按原始 input 构造新切片”的方式，避免在原切片上做多次 append 导致索引失效与 panic。
	var out []byte
	last := 0

	for _, m := range matches {
		start, end := m[0], m[1]
		if start < 0 || end < 0 || start >= end || end > len(input) {
			continue
		}

		placeholder := string(input[start:end])
		original, ok := e.session.Lookup(placeholder)

		if out == nil {
			// 直到遇到第一个“能还原”的占位符才分配输出，减少不必要的拷贝。
			if !ok {
				continue
			}
			out = make([]byte, 0, len(input))
			out = append(out, input[:start]...)
			out = append(out, []byte(original)...)
			last = end
			continue
		}

		out = append(out, input[last:start]...)
		if ok {
			out = append(out, []byte(original)...)
		} else {
			out = append(out, input[start:end]...)
		}
		last = end
	}

	if out == nil {
		return input
	}
	out = append(out, input[last:]...)
	return out
}

// RestoreString is a convenience method for string input
func (e *Engine) RestoreString(input string) string {
	return string(e.Restore([]byte(input)))
}

// Prefix 返回占位符前缀（例如 "__VG_"）。
func (e *Engine) Prefix() string {
	return e.prefix
}

// MatchAt 判断 input[start:] 是否以一个“完整占位符”开头；若是，返回匹配结束位置。
// 该方法用于流式场景判断是否存在“未完整到达的占位符”，避免把前缀片段提前输出导致无法还原。
func (e *Engine) MatchAt(input []byte, start int) (end int, ok bool) {
	if start < 0 || start >= len(input) {
		return 0, false
	}
	loc := e.regex.FindIndex(input[start:])
	if loc == nil || loc[0] != 0 {
		return 0, false
	}
	if loc[1] <= 0 || start+loc[1] > len(input) {
		return 0, false
	}
	return start + loc[1], true
}
