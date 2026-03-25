package textsafe

import (
	"unicode"
	"unicode/utf8"
)

// Span 表示输入中“允许参与脱敏匹配”的连续字节区间。
// 控制字符、ANSI 转义序列、零宽/格式字符都会被当作边界跳过。
type Span struct {
	Start int
	End   int
}

// RedactableSpans 将输入拆成若干安全文本段。
// 这样可以避免规则跨越终端控制符或 ANSI 样式序列，把格式字节一并替换掉。
func RedactableSpans(input []byte) []Span {
	if len(input) == 0 {
		return nil
	}

	var spans []Span
	segStart := -1

	for i := 0; i < len(input); {
		if n := protectedSeqLen(input[i:]); n > 0 {
			if segStart >= 0 && segStart < i {
				spans = append(spans, Span{Start: segStart, End: i})
			}
			segStart = -1
			i += n
			continue
		}

		if segStart < 0 {
			segStart = i
		}

		_, size := utf8.DecodeRune(input[i:])
		if size <= 0 {
			size = 1
		}
		i += size
	}

	if segStart >= 0 && segStart < len(input) {
		spans = append(spans, Span{Start: segStart, End: len(input)})
	}

	return spans
}

func protectedSeqLen(input []byte) int {
	if len(input) == 0 {
		return 0
	}

	if n := ansiEscapeSeqLen(input); n > 0 {
		return n
	}

	r, size := utf8.DecodeRune(input)
	if r == utf8.RuneError && size == 1 {
		if isASCIITextByte(input[0]) {
			return 0
		}
		return 1
	}

	if isProtectedRune(r) {
		return size
	}
	return 0
}

func isASCIITextByte(b byte) bool {
	switch b {
	case '\n', '\r', '\t':
		return true
	}
	return b >= 0x20 && b != 0x7f
}

func isProtectedRune(r rune) bool {
	switch r {
	case '\n', '\r', '\t':
		return false
	}
	if r < 0x20 || r == 0x7f {
		return true
	}
	return unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r)
}

func ansiEscapeSeqLen(input []byte) int {
	if len(input) == 0 || input[0] != 0x1b {
		return 0
	}
	if len(input) == 1 {
		return 1
	}

	switch input[1] {
	case '[':
		// CSI: ESC [ ... final-byte(0x40~0x7E)
		for i := 2; i < len(input); i++ {
			if input[i] >= 0x40 && input[i] <= 0x7e {
				return i + 1
			}
		}
		return len(input)
	case ']', 'P', 'X', '^', '_':
		// OSC/DCS/SOS/PM/APC：以 BEL 或 ST(ESC \) 结束。
		for i := 2; i < len(input); i++ {
			if input[i] == 0x07 {
				return i + 1
			}
			if input[i] == 0x1b && i+1 < len(input) && input[i+1] == '\\' {
				return i + 2
			}
		}
		return len(input)
	default:
		// 其它两字节 ESC 序列。
		return 2
	}
}
