package presidio

import (
	"regexp"

	"github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
)

type regexRecognizer struct {
	name     string
	category string
	priority int
	re       *regexp.Regexp
	group    int
	validate func(matched []byte) bool
}

func (r *regexRecognizer) Name() string { return r.name }

func (r *regexRecognizer) Recognize(input []byte) []recognizer.Match {
	if r == nil || r.re == nil {
		return nil
	}
	locs := r.re.FindAllSubmatchIndex(input, -1)
	if len(locs) == 0 {
		return nil
	}

	var out []recognizer.Match
	for _, loc := range locs {
		start, end := -1, -1
		if r.group <= 0 {
			if len(loc) < 2 {
				continue
			}
			start, end = loc[0], loc[1]
		} else {
			need := (r.group + 1) * 2
			if len(loc) < need {
				continue
			}
			start, end = loc[r.group*2], loc[r.group*2+1]
		}
		if start < 0 || end < 0 || start >= end || end > len(input) {
			continue
		}

		matched := input[start:end]
		if r.validate != nil && !r.validate(matched) {
			continue
		}

		out = append(out, recognizer.Match{
			Start:    start,
			End:      end,
			Category: r.category,
			Priority: r.priority,
			Source:   r.name,
		})
	}
	return out
}

func mustCompile(pattern string) *regexp.Regexp {
	re, err := regexp.Compile(pattern)
	if err != nil {
		panic(err)
	}
	return re
}
