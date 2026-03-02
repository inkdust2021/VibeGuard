package pipeline

import (
	"sort"

	"github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
	"github.com/inkdust2021/vibeguard/internal/redact"
	"github.com/inkdust2021/vibeguard/internal/session"
)

// Pipeline 将多个 Recognizer 的命中结果合并，并执行统一替换。
type Pipeline struct {
	reg    *recognizer.Registry
	sess   *session.Manager
	prefix string
	// exclude 为“精确跳过替换”的白名单：命中值完全等于其中任意一项时，不进行替换。
	// 说明：这里不支持正则/模糊匹配，保持与现有 vibeguard exclude 语义一致。
	exclude map[string]struct{}
}

func New(sess *session.Manager, prefix string, recs ...recognizer.Recognizer) *Pipeline {
	return &Pipeline{
		reg:    recognizer.NewRegistry(recs...),
		sess:   sess,
		prefix: prefix,
	}
}

// SetExclude 设置精确跳过列表。
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

// RedactWithMatches 执行识别+替换并返回详细命中信息。
func (p *Pipeline) RedactWithMatches(input []byte) ([]byte, []redact.Match) {
	if p == nil || p.reg == nil || p.sess == nil {
		return append([]byte(nil), input...), nil
	}

	raw := p.reg.RecognizeAll(input)
	cands := make([]recognizer.Match, 0, len(raw))
	for _, m := range raw {
		if m.Start < 0 || m.End < 0 || m.Start >= m.End || m.End > len(input) {
			continue
		}
		if m.Category == "" {
			continue
		}
		if p.exclude != nil {
			original := string(input[m.Start:m.End])
			if _, ok := p.exclude[original]; ok {
				continue
			}
		}
		cands = append(cands, m)
	}
	if len(cands) == 0 {
		return append([]byte(nil), input...), nil
	}

	// 先按优先级/长度排序，再做“贪心选取”以避免重叠导致的碎片替换。
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
	var covered []span // 按 start 升序且互不重叠
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

	// 按 start 逆序替换，避免下标漂移。
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
