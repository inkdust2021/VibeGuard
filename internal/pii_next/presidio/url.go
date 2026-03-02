package presidio

import (
	"bytes"
	"regexp"

	"github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
)

// URLRecognizer 使用自定义后处理去掉常见尾随标点，避免把 ")" "." 等一起替换。
type URLRecognizer struct {
	re *regexp.Regexp
}

func NewURLRecognizer() recognizer.Recognizer {
	return &URLRecognizer{
		re: mustCompile(`(?i)\b(?:https?://|www\.)[a-z0-9][a-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*`),
	}
}

func (r *URLRecognizer) Name() string { return "presidio-url" }

func (r *URLRecognizer) Recognize(input []byte) []recognizer.Match {
	if r == nil || r.re == nil {
		return nil
	}
	locs := r.re.FindAllIndex(input, -1)
	if len(locs) == 0 {
		return nil
	}

	var out []recognizer.Match
	for _, loc := range locs {
		if len(loc) != 2 {
			continue
		}
		start, end := loc[0], loc[1]
		if start < 0 || end < 0 || start >= end || end > len(input) {
			continue
		}

		// 去掉尾随标点（保留 URL 本体）
		for end > start {
			last := input[end-1]
			if bytes.IndexByte([]byte(".,;:!?)]}\"'"), last) >= 0 {
				end--
				continue
			}
			break
		}
		if end <= start {
			continue
		}

		out = append(out, recognizer.Match{
			Start:    start,
			End:      end,
			Category: "URL",
			Priority: 80,
			Source:   r.Name(),
		})
	}
	return out
}
