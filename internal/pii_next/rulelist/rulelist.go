package rulelist

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/inkdust2021/vibeguard/internal/config"
	"github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
)

type keywordRule struct {
	text string
	cat  string
}

// Recognizer 用于加载并执行“规则列表”匹配。
//
// 规则格式（逐行解析，忽略空行/注释行）：
// - keyword <CATEGORY> <TEXT...>
// - regex   <CATEGORY> <RE2_PATTERN...>
//
// 注释行：以 #、//、;、! 开头（去除前导空白后判断）。
// CATEGORY 会被规范化为 [A-Z0-9_]；TEXT 会移除不可见字符并去除首尾空白。
type Recognizer struct {
	name     string
	priority int

	keywords []keywordRule
	regex    []*regexp.Regexp
	regexCat []string
}

func (r *Recognizer) Name() string {
	if r == nil {
		return "rulelist"
	}
	if strings.TrimSpace(r.name) == "" {
		return "rulelist"
	}
	return "rulelist:" + r.name
}

func (r *Recognizer) KeywordCount() int {
	if r == nil {
		return 0
	}
	return len(r.keywords)
}

func (r *Recognizer) RegexCount() int {
	if r == nil {
		return 0
	}
	return len(r.regex)
}

func (r *Recognizer) Recognize(input []byte) []recognizer.Match {
	if r == nil || len(input) == 0 {
		return nil
	}

	var out []recognizer.Match

	for _, kw := range r.keywords {
		if kw.text == "" || kw.cat == "" {
			continue
		}
		idx := 0
		for {
			pos := bytes.Index(input[idx:], []byte(kw.text))
			if pos == -1 {
				break
			}
			start := idx + pos
			end := start + len(kw.text)
			out = append(out, recognizer.Match{
				Start:    start,
				End:      end,
				Category: kw.cat,
				Priority: r.priority,
				Source:   r.Name(),
			})
			idx = end
		}
	}

	for i, re := range r.regex {
		if re == nil {
			continue
		}
		locs := re.FindAllSubmatchIndex(input, -1)
		for _, loc := range locs {
			if len(loc) < 2 {
				continue
			}
			start, end := loc[0], loc[1]
			// 若存在捕获组，优先替换第一个捕获组范围（与 redact.Engine 语义保持一致）。
			if len(loc) >= 4 && loc[2] >= 0 && loc[3] >= 0 {
				start, end = loc[2], loc[3]
			}
			if start < 0 || end < 0 || start >= end || end > len(input) {
				continue
			}
			cat := ""
			if i >= 0 && i < len(r.regexCat) {
				cat = r.regexCat[i]
			}
			if cat == "" {
				cat = "REGEX"
			}
			out = append(out, recognizer.Match{
				Start:    start,
				End:      end,
				Category: cat,
				Priority: r.priority,
				Source:   r.Name(),
			})
		}
	}

	return out
}

type ParseOptions struct {
	// Name 会用于识别器名称（用于审计/调试）。
	Name string
	// Priority 越大越优先保留（用于与关键词/其他规则列表发生重叠时的冲突消解）。
	// 注意：关键词匹配默认优先级为 100；建议规则列表默认在 10~90 之间。
	Priority int
}

func Parse(r io.Reader, opts ParseOptions) (*Recognizer, error) {
	if r == nil {
		return nil, fmt.Errorf("规则列表读取器为空")
	}

	priority := opts.Priority
	if priority <= 0 {
		priority = 50
	}
	if priority > 99 {
		priority = 99
	}

	out := &Recognizer{
		name:     strings.TrimSpace(opts.Name),
		priority: priority,
	}

	sc := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024) // 允许较长正则行

	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if isCommentLine(s) {
			continue
		}

		kind, rest, ok := cutFirstField(s)
		if !ok {
			return nil, fmt.Errorf("规则列表第 %d 行：无效格式", lineNo)
		}
		kind = strings.ToLower(strings.TrimSpace(kind))
		rest = strings.TrimSpace(rest)

		switch kind {
		case "keyword", "k":
			catToken, value, ok := cutFirstField(rest)
			if !ok {
				return nil, fmt.Errorf("规则列表第 %d 行：keyword 缺少 CATEGORY/TEXT", lineNo)
			}
			cat := config.SanitizeCategory(catToken)
			if cat == "" {
				return nil, fmt.Errorf("规则列表第 %d 行：keyword CATEGORY 非法：%q", lineNo, catToken)
			}
			text := config.SanitizePatternValue(value)
			if text == "" {
				return nil, fmt.Errorf("规则列表第 %d 行：keyword TEXT 为空", lineNo)
			}
			out.keywords = append(out.keywords, keywordRule{text: text, cat: cat})

		case "regex", "r":
			catToken, pattern, ok := cutFirstField(rest)
			if !ok {
				return nil, fmt.Errorf("规则列表第 %d 行：regex 缺少 CATEGORY/PATTERN", lineNo)
			}
			cat := config.SanitizeCategory(catToken)
			if cat == "" {
				return nil, fmt.Errorf("规则列表第 %d 行：regex CATEGORY 非法：%q", lineNo, catToken)
			}
			pat := strings.TrimSpace(pattern)
			if pat == "" {
				return nil, fmt.Errorf("规则列表第 %d 行：regex PATTERN 为空", lineNo)
			}
			re, err := regexp.Compile(pat)
			if err != nil {
				return nil, fmt.Errorf("规则列表第 %d 行：regex 编译失败：%w", lineNo, err)
			}
			out.regex = append(out.regex, re)
			out.regexCat = append(out.regexCat, cat)

		default:
			return nil, fmt.Errorf("规则列表第 %d 行：未知规则类型：%q", lineNo, kind)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	return out, nil
}

func ParseFile(path string, opts ParseOptions) (*Recognizer, error) {
	p := strings.TrimSpace(path)
	if p == "" {
		return nil, fmt.Errorf("规则列表路径为空")
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f, opts)
}

func isCommentLine(s string) bool {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(s, "#"):
		return true
	case strings.HasPrefix(s, ";"):
		return true
	case strings.HasPrefix(s, "!"):
		return true
	case strings.HasPrefix(s, "//"):
		return true
	default:
		return false
	}
}

func cutFirstField(s string) (first, rest string, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", false
	}
	i := strings.IndexFunc(s, func(r rune) bool { return r == ' ' || r == '\t' })
	if i == -1 {
		return s, "", true
	}
	return s[:i], strings.TrimSpace(s[i:]), true
}
