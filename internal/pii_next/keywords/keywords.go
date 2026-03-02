package keywords

import (
	"bytes"

	"github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
)

// Keyword 是一个精确字符串匹配规则。
type Keyword struct {
	Text     string
	Category string
}

// Recognizer 使用简单的 bytes.Index 做关键词扫描（原型阶段）。
// 注意：后续若接入主流程，可替换为 Aho-Corasick 以提升性能。
type Recognizer struct {
	keywords []Keyword
	priority int
}

func New(keywords []Keyword) *Recognizer {
	return &Recognizer{
		keywords: append([]Keyword(nil), keywords...),
		priority: 100, // 用户显式配置的关键词应当拥有最高优先级
	}
}

func (r *Recognizer) Name() string { return "keywords" }

func (r *Recognizer) Recognize(input []byte) []recognizer.Match {
	var out []recognizer.Match
	for _, kw := range r.keywords {
		if kw.Text == "" {
			continue
		}
		idx := 0
		for {
			pos := bytes.Index(input[idx:], []byte(kw.Text))
			if pos == -1 {
				break
			}
			start := idx + pos
			end := start + len(kw.Text)
			out = append(out, recognizer.Match{
				Start:    start,
				End:      end,
				Category: kw.Category,
				Priority: r.priority,
				Source:   r.Name(),
			})
			idx = end
		}
	}
	return out
}
