package restore

import (
	"regexp"
	"sort"
	"strings"

	"github.com/inkdust2021/vibeguard/internal/session"
)

// Engine handles placeholder restoration
type Engine struct {
	session *session.Manager
	prefix  string
	// regexFull matches placeholders that start with the full prefix (e.g. "__VG_"),
	// with an optional trailing "__" (some models/clients may drop it).
	regexFull *regexp.Regexp
	// regexBare matches placeholders that start with the prefix without leading underscores (e.g. "VG_"),
	// with an optional trailing "__". It uses a boundary to avoid matching inside full placeholders.
	regexBare *regexp.Regexp
	// regexBareAtStart is like regexBare but anchored at start, for streaming boundary detection.
	regexBareAtStart *regexp.Regexp
	barePrefix       string
	leading          string
}

// NewEngine creates a new restoration engine
func NewEngine(s *session.Manager, prefix string) *Engine {
	// Pattern: __VG_CATEGORY_HASH12__ or __VG_CATEGORY_HASH12_N__
	escapedPrefix := regexp.QuoteMeta(prefix)
	// category 允许包含下划线（如 CHINA_PHONE），也允许用户自定义更宽松的命名。
	//
	// 注意：占位符两侧的 "__" 在 Markdown 里可能被模型/渲染器当作强调标记而省略，
	// 因此这里支持“可选尾部 __”，并额外支持“去掉前导下划线”的变体（如 VG_TEXT_xxx）。
	patternFull := escapedPrefix + `[A-Za-z0-9_]+_[a-f0-9]{12}(?:_\d+)?(?:__)?`

	leadingUnderscores := countLeadingUnderscores(prefix)
	leading := ""
	barePrefix := prefix
	if leadingUnderscores > 0 && leadingUnderscores <= len(prefix) {
		leading = prefix[:leadingUnderscores]
		barePrefix = prefix[leadingUnderscores:]
	}

	var reBare, reBareAtStart *regexp.Regexp
	if barePrefix != "" && barePrefix != prefix {
		escapedBare := regexp.QuoteMeta(barePrefix)
		// boundary: start or a non-underscore char, to avoid matching the "VG_" inside "__VG_".
		patternBare := `(?:^|[^_])(` + escapedBare + `[A-Za-z0-9_]+_[a-f0-9]{12}(?:_\d+)?(?:__)?` + `)`
		reBare = regexp.MustCompile(patternBare)
		reBareAtStart = regexp.MustCompile(`^` + escapedBare + `[A-Za-z0-9_]+_[a-f0-9]{12}(?:_\d+)?(?:__)?`)
	}

	return &Engine{
		session:          s,
		prefix:           prefix,
		regexFull:        regexp.MustCompile(patternFull),
		regexBare:        reBare,
		regexBareAtStart: reBareAtStart,
		barePrefix:       barePrefix,
		leading:          leading,
	}
}

// Restore replaces placeholders with original values
func (e *Engine) Restore(input []byte) []byte {
	if len(input) == 0 {
		return input
	}

	type repl struct {
		start int
		end   int
		orig  string
	}
	var repls []repl

	// 1) Full prefix placeholders (e.g. "__VG_...__" or "__VG_..." without trailing "__")
	full := e.regexFull.FindAllIndex(input, -1)
	for _, m := range full {
		start, end := m[0], m[1]
		if start < 0 || end < 0 || start >= end || end > len(input) {
			continue
		}
		token := string(input[start:end])
		normalized := e.normalizeToken(token)
		original, ok := e.session.Lookup(normalized)
		if ok {
			repls = append(repls, repl{start: start, end: end, orig: original})
		}
	}

	// 2) Bare prefix placeholders (e.g. "VG_...__" or "VG_..." without leading/trailing "__")
	if e.regexBare != nil {
		locs := e.regexBare.FindAllSubmatchIndex(input, -1)
		for _, loc := range locs {
			// loc[0:2] is the whole match; loc[2:4] is the capturing group
			if len(loc) < 4 {
				continue
			}
			start, end := loc[2], loc[3]
			if start < 0 || end < 0 || start >= end || end > len(input) {
				continue
			}
			token := string(input[start:end])
			normalized := e.normalizeToken(token)
			original, ok := e.session.Lookup(normalized)
			if ok {
				repls = append(repls, repl{start: start, end: end, orig: original})
			}
		}
	}

	if len(repls) == 0 {
		return input
	}

	// Order by start asc; drop overlaps defensively.
	sort.Slice(repls, func(i, j int) bool {
		if repls[i].start != repls[j].start {
			return repls[i].start < repls[j].start
		}
		return repls[i].end < repls[j].end
	})

	out := make([]byte, 0, len(input))
	last := 0
	for _, r := range repls {
		if r.start < last {
			continue
		}
		out = append(out, input[last:r.start]...)
		out = append(out, []byte(r.orig)...)
		last = r.end
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
	if loc := e.regexFull.FindIndex(input[start:]); loc != nil && loc[0] == 0 && loc[1] > 0 && start+loc[1] <= len(input) {
		return start + loc[1], true
	}
	if e.regexBareAtStart != nil {
		if loc := e.regexBareAtStart.FindIndex(input[start:]); loc != nil && loc[0] == 0 && loc[1] > 0 && start+loc[1] <= len(input) {
			return start + loc[1], true
		}
	}
	return 0, false
}

func (e *Engine) normalizeToken(token string) string {
	p := strings.TrimSpace(token)
	if p == "" {
		return ""
	}
	// Ensure leading underscores (if the token starts from barePrefix).
	if !strings.HasPrefix(p, e.prefix) && e.barePrefix != "" && strings.HasPrefix(p, e.barePrefix) {
		p = e.leading + p
	}
	// Ensure trailing "__" (GeneratePlaceholder always appends it).
	if !strings.HasSuffix(p, "__") {
		p += "__"
	}
	return p
}

func countLeadingUnderscores(s string) int {
	n := 0
	for n < len(s) && s[n] == '_' {
		n++
	}
	return n
}
