package redact

import (
	"bytes"
	"regexp"
	"sort"

	"github.com/inkdust2021/vibeguard/internal/session"
)

// Match represents a detected sensitive data match
type Match struct {
	Start    int
	End      int
	Original string
	Category string
	// Placeholder 是替换后的占位符（例如 "__VG_EMAIL_..."）。
	// 仅在替换阶段生成；用于“拦截审计”等需要展示命中结果的场景。
	Placeholder string
}

// Engine handles sensitive data detection and replacement
type Engine struct {
	keywords  map[string]string // keyword -> category
	regex     []*regexp.Regexp
	regexCats []string // category for each regex
	exclude   map[string]bool
	session   *session.Manager
	prefix    string
}

// NewEngine creates a new redaction engine
func NewEngine(s *session.Manager, prefix string) *Engine {
	return &Engine{
		keywords:  make(map[string]string),
		regex:     nil,
		regexCats: nil,
		exclude:   make(map[string]bool),
		session:   s,
		prefix:    prefix,
	}
}

// AddKeyword adds a keyword pattern
func (e *Engine) AddKeyword(keyword, category string) {
	e.keywords[keyword] = category
}

// AddRegex adds a regex pattern
func (e *Engine) AddRegex(pattern, category string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	e.regex = append(e.regex, re)
	e.regexCats = append(e.regexCats, category)
	return nil
}

// AddExclude adds an exclude pattern
func (e *Engine) AddExclude(pattern string) {
	e.exclude[pattern] = true
}

// Redact scans and redacts sensitive data from the input
func (e *Engine) Redact(input []byte) ([]byte, int) {
	out, matches := e.RedactWithMatches(input)
	return out, len(matches)
}

// RedactWithMatches 扫描并替换敏感信息，同时返回本次命中的详细匹配信息。
// 注意：matches 中的 Original 为原始命中内容，调用方如需展示到管理端，应遵循隐私配置进行脱敏/截断。
func (e *Engine) RedactWithMatches(input []byte) ([]byte, []Match) {
	var matches []Match

	// Keyword matching using simple search (Aho-Corasick will be added later)
	for keyword, category := range e.keywords {
		idx := 0
		for {
			pos := bytes.Index(input[idx:], []byte(keyword))
			if pos == -1 {
				break
			}
			start := idx + pos
			end := start + len(keyword)

			// Check exclude
			if !e.isExcluded(string(input[start:end])) {
				matches = append(matches, Match{
					Start:    start,
					End:      end,
					Original: string(input[start:end]),
					Category: category,
				})
			}
			idx = end
		}
	}

	// Regex matching
	for i, re := range e.regex {
		locs := re.FindAllSubmatchIndex(input, -1)
		for _, loc := range locs {
			if len(loc) < 2 {
				continue
			}

			start, end := loc[0], loc[1]
			// 如果存在捕获组，优先使用第一个捕获组范围进行脱敏替换
			if len(loc) >= 4 && loc[2] >= 0 && loc[3] >= 0 {
				start, end = loc[2], loc[3]
			}
			if start < 0 || end < 0 || start >= end || end > len(input) {
				continue
			}

			original := string(input[start:end])
			if !e.isExcluded(original) {
				matches = append(matches, Match{
					Start:    start,
					End:      end,
					Original: original,
					Category: e.regexCats[i],
				})
			}
		}
	}

	// 重要：不同规则之间可能出现“重叠命中”（例如用户配置了过宽的正则 `.*@gmail\.com`，
	// 同时又启用了内置 `email` 规则）。如果直接按 start 逆序替换，会在重叠区域把占位符切开，
	// 造成输出出现破碎占位符（甚至把原文漏出来）。
	// 这里先把重叠命中拆分为“互不重叠的替换片段”，确保每个 byte 只会被替换一次。
	type span struct {
		start int
		end   int
	}
	subtractCovered := func(start, end int, covered []span) []span {
		if start >= end {
			return nil
		}
		var out []span
		cur := start
		for _, c := range covered {
			if c.end <= cur {
				continue
			}
			if c.start >= end {
				break
			}
			if c.start > cur {
				out = append(out, span{start: cur, end: min(c.start, end)})
			}
			if c.end >= end {
				cur = end
				break
			}
			cur = max(cur, c.end)
		}
		if cur < end {
			out = append(out, span{start: cur, end: end})
		}
		return out
	}
	insertCovered := func(covered []span, s span) []span {
		if s.start >= s.end {
			return covered
		}
		i := sort.Search(len(covered), func(i int) bool { return covered[i].start > s.start })
		covered = append(covered, span{})
		copy(covered[i+1:], covered[i:])
		covered[i] = s
		// 合并相邻/重叠区间，保持 covered 非重叠且有序，简化后续 subtract。
		if len(covered) <= 1 {
			return covered
		}
		merged := covered[:0]
		for _, c := range covered {
			if len(merged) == 0 {
				merged = append(merged, c)
				continue
			}
			last := &merged[len(merged)-1]
			if c.start <= last.end { // overlap or adjacent
				if c.end > last.end {
					last.end = c.end
				}
				continue
			}
			merged = append(merged, c)
		}
		return merged
	}

	// 先按 start 逆序、end 逆序排序：优先处理“更靠右/更长”的命中，便于把左侧的大范围命中拆分掉。
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Start != matches[j].Start {
			return matches[i].Start > matches[j].Start
		}
		return matches[i].End > matches[j].End
	})

	var (
		planned []Match
		covered []span // start 升序、互不重叠
	)
	for _, m := range matches {
		for _, seg := range subtractCovered(m.Start, m.End, covered) {
			if seg.start < 0 || seg.end > len(input) || seg.start >= seg.end {
				continue
			}
			planned = append(planned, Match{
				Start:    seg.start,
				End:      seg.end,
				Original: string(input[seg.start:seg.end]),
				Category: m.Category,
			})
			covered = insertCovered(covered, seg)
		}
	}

	// planned 片段互不重叠；按 start 逆序排序以安全替换。
	sort.Slice(planned, func(i, j int) bool {
		return planned[i].Start > planned[j].Start
	})

	// Apply replacements
	result := make([]byte, len(input))
	copy(result, input)

	for i := range planned {
		m := &planned[i]
		// Get or create placeholder
		placeholder := e.session.GeneratePlaceholder(m.Original, m.Category, e.prefix)
		e.session.Register(placeholder, m.Original)

		m.Placeholder = placeholder

		// Replace in result
		result = append(result[:m.Start], append([]byte(placeholder), result[m.End:]...)...)
	}

	return result, planned
}

// isExcluded checks if a value is in the exclude list
func (e *Engine) isExcluded(value string) bool {
	_, ok := e.exclude[value]
	return ok
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
