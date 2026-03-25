package pipeline

import (
	"sort"

	"github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
	"github.com/inkdust2021/vibeguard/internal/redact"
	"github.com/inkdust2021/vibeguard/internal/session"
	"github.com/inkdust2021/vibeguard/internal/textsafe"
)

// Pipeline merges hits from multiple Recognizers and performs unified replacement.
type Pipeline struct {
	reg    *recognizer.Registry
	sess   *session.Manager
	prefix string
	// exclude is an exact-match allowlist: if a hit's value equals any entry, it will not be replaced.
	// Note: regex/fuzzy matching is intentionally not supported to match existing vibeguard exclude semantics.
	exclude map[string]struct{}
}

func New(sess *session.Manager, prefix string, recs ...recognizer.Recognizer) *Pipeline {
	return &Pipeline{
		reg:    recognizer.NewRegistry(recs...),
		sess:   sess,
		prefix: prefix,
	}
}

// SetExclude sets the exact-match skip list.
func (p *Pipeline) SetExclude(values []string) {
	if p == nil {
		return
	}
	if len(values) == 0 {
		p.exclude = nil
		return
	}
	m := make(map[string]struct{}, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		m[v] = struct{}{}
	}
	if len(m) == 0 {
		p.exclude = nil
		return
	}
	p.exclude = m
}

// RedactWithMatches runs recognition + replacement and returns detailed match info.
func (p *Pipeline) RedactWithMatches(input []byte) ([]byte, []redact.Match) {
	if p == nil || p.reg == nil || p.sess == nil {
		return append([]byte(nil), input...), nil
	}

	cands := make([]recognizer.Match, 0, 16)
	for _, span := range textsafe.RedactableSpans(input) {
		segment := input[span.Start:span.End]
		if len(segment) == 0 {
			continue
		}

		raw := p.reg.RecognizeAll(segment)
		for _, m := range raw {
			globalStart := span.Start + m.Start
			globalEnd := span.Start + m.End
			if globalStart < 0 || globalEnd < 0 || globalStart >= globalEnd || globalEnd > len(input) {
				continue
			}
			if m.Category == "" {
				continue
			}
			if p.exclude != nil {
				original := string(input[globalStart:globalEnd])
				if _, ok := p.exclude[original]; ok {
					continue
				}
			}

			m.Start = globalStart
			m.End = globalEnd
			cands = append(cands, m)
		}
	}
	if len(cands) == 0 {
		return append([]byte(nil), input...), nil
	}

	// Sort by priority/length, then greedily select non-overlapping matches to avoid fragmented replacements.
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].Priority != cands[j].Priority {
			return cands[i].Priority > cands[j].Priority
		}
		li := cands[i].End - cands[i].Start
		lj := cands[j].End - cands[j].Start
		if li != lj {
			return li > lj
		}
		if cands[i].Start != cands[j].Start {
			return cands[i].Start < cands[j].Start
		}
		return cands[i].End > cands[j].End
	})

	type span struct {
		start int
		end   int
	}
	var covered []span // Ordered by start asc; non-overlapping.
	overlaps := func(s span) bool {
		i := sort.Search(len(covered), func(i int) bool { return covered[i].start >= s.end })
		if i == 0 {
			return false
		}
		return covered[i-1].end > s.start
	}
	insert := func(s span) {
		i := sort.Search(len(covered), func(i int) bool { return covered[i].start > s.start })
		covered = append(covered, span{})
		copy(covered[i+1:], covered[i:])
		covered[i] = s
	}

	var selected []recognizer.Match
	for _, m := range cands {
		s := span{start: m.Start, end: m.End}
		if overlaps(s) {
			continue
		}
		selected = append(selected, m)
		insert(s)
	}

	// Replace in reverse start order to avoid index shifting.
	sort.Slice(selected, func(i, j int) bool {
		if selected[i].Start != selected[j].Start {
			return selected[i].Start > selected[j].Start
		}
		return selected[i].End > selected[j].End
	})

	result := make([]byte, len(input))
	copy(result, input)

	outMatches := make([]redact.Match, 0, len(selected))
	for _, m := range selected {
		original := string(input[m.Start:m.End])

		placeholder, ok := p.sess.LookupReverse(original)
		if !ok {
			placeholder = p.sess.GeneratePlaceholder(original, m.Category, p.prefix)
			p.sess.Register(placeholder, original)
		}

		outMatches = append(outMatches, redact.Match{
			Start:       m.Start,
			End:         m.End,
			Original:    original,
			Category:    m.Category,
			Placeholder: placeholder,
		})

		result = append(result[:m.Start], append([]byte(placeholder), result[m.End:]...)...)
	}

	return result, outMatches
}
