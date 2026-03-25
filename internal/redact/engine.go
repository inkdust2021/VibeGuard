package redact

import (
	"regexp"
	"sort"
	"sync"

	"github.com/inkdust2021/vibeguard/internal/ahocorasick"
	"github.com/inkdust2021/vibeguard/internal/session"
	"github.com/inkdust2021/vibeguard/internal/textsafe"
)

// Match represents a detected sensitive data match
type Match struct {
	Start    int
	End      int
	Original string
	Category string
	// Placeholder is the generated placeholder (e.g. "__VG_EMAIL_...").
	// It is only generated during replacement; used for audit/inspection displays that need to show redaction hits.
	Placeholder string
}

// Engine handles sensitive data detection and replacement
type Engine struct {
	keywords  map[string]string // keyword -> category
	kwOnce    sync.Once
	kwAC      *ahocorasick.Matcher
	kwCats    []string // pattern id -> category
	kwScratch sync.Pool

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

// RedactWithMatches scans and redacts sensitive data, returning detailed match information for this run.
// Note: matches.Original contains the original hit content; callers that display it in the admin UI must apply privacy settings (redaction/truncation).
func (e *Engine) RedactWithMatches(input []byte) ([]byte, []Match) {
	var matches []Match

	e.ensureKeywordMatcher()
	spans := textsafe.RedactableSpans(input)
	if e.kwAC != nil {
		// Rough estimate: each keyword hits ~0-1 times; preallocation reduces growth.
		matches = make([]Match, 0, min(len(e.kwCats), 64))
	}

	for _, span := range spans {
		segment := input[span.Start:span.End]
		if len(segment) == 0 {
			continue
		}

		if e.kwAC != nil {
			scratchAny := e.kwScratch.Get()
			lastEnd, _ := scratchAny.([]int)

			e.kwAC.EachMatchNonOverlappingPerPattern(segment, lastEnd, func(id, start, end int) bool {
				cat := ""
				if id >= 0 && id < len(e.kwCats) {
					cat = e.kwCats[id]
				}

				globalStart := span.Start + start
				globalEnd := span.Start + end
				orig := string(input[globalStart:globalEnd])
				if e.isExcluded(orig) {
					return true
				}
				matches = append(matches, Match{
					Start:    globalStart,
					End:      globalEnd,
					Original: orig,
					Category: cat,
				})
				return true
			})

			if lastEnd != nil {
				e.kwScratch.Put(lastEnd)
			}
		}

		// 正则也只在安全文本段内执行，避免把 ANSI/控制字节吞进去。
		for i, re := range e.regex {
			locs := re.FindAllSubmatchIndex(segment, -1)
			for _, loc := range locs {
				if len(loc) < 2 {
					continue
				}

				start, end := loc[0], loc[1]
				// If capture groups exist, prefer the first capture group's range for redaction replacement.
				if len(loc) >= 4 && loc[2] >= 0 && loc[3] >= 0 {
					start, end = loc[2], loc[3]
				}

				globalStart := span.Start + start
				globalEnd := span.Start + end
				if globalStart < 0 || globalEnd < 0 || globalStart >= globalEnd || globalEnd > len(input) {
					continue
				}

				original := string(input[globalStart:globalEnd])
				if !e.isExcluded(original) {
					matches = append(matches, Match{
						Start:    globalStart,
						End:      globalEnd,
						Original: original,
						Category: e.regexCats[i],
					})
				}
			}
		}
	}

	// Important: different rules can produce overlapping matches (e.g. a too-broad regex like `.*@gmail\.com`
	// plus the built-in `email` rule). If we replace purely by reverse start order, overlaps can slice placeholders,
	// producing broken placeholders (and potentially leaking original content).
	// Split overlaps into non-overlapping replacement segments so each byte is replaced at most once.
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
		// Merge adjacent/overlapping spans to keep covered non-overlapping and ordered, simplifying subtract.
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

	// Sort by start desc, then end desc: process "further right / longer" matches first,
	// making it easier to split large left-side matches.
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Start != matches[j].Start {
			return matches[i].Start > matches[j].Start
		}
		return matches[i].End > matches[j].End
	})

	var (
		planned []Match
		covered []span // sorted by start, non-overlapping
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

	// planned segments are non-overlapping; sort by start desc for safe in-place replacement.
	sort.Slice(planned, func(i, j int) bool {
		return planned[i].Start > planned[j].Start
	})

	// Apply replacements
	result := make([]byte, len(input))
	copy(result, input)

	for i := range planned {
		m := &planned[i]
		// Reuse existing mapping first (important for WAL restore across restarts),
		// otherwise generate and register a new placeholder.
		placeholder, ok := e.session.LookupReverse(m.Original)
		if !ok {
			placeholder = e.session.GeneratePlaceholder(m.Original, m.Category, e.prefix)
			e.session.Register(placeholder, m.Original)
		}

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

func (e *Engine) ensureKeywordMatcher() {
	if e == nil {
		return
	}
	e.kwOnce.Do(func() {
		if len(e.keywords) == 0 {
			return
		}

		// To avoid nondeterminism from map iteration order, sort keywords before building the automaton.
		keys := make([]string, 0, len(e.keywords))
		for k := range e.keywords {
			if k == "" {
				continue
			}
			keys = append(keys, k)
		}
		if len(keys) == 0 {
			return
		}
		sort.Strings(keys)

		pats := make([]string, 0, len(keys))
		cats := make([]string, 0, len(keys))
		for _, k := range keys {
			pats = append(pats, k)
			cats = append(cats, e.keywords[k])
		}

		e.kwAC = ahocorasick.New(pats)
		e.kwCats = cats
		e.kwScratch.New = func() any { return make([]int, e.kwAC.PatternCount()) }
	})
}
