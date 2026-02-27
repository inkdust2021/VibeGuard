package config

import (
	"strings"
	"unicode"
)

// SanitizePatternValue 清理用户输入的匹配值：
// - 去除前后空白
// - 移除不可见控制字符/格式字符（如 0x1F、BOM、零宽字符等）
//
// 目的：避免“看起来一样但实际不匹配”的隐形字符导致规则不生效。
func SanitizePatternValue(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		// C0 控制字符与 DEL
		if r < 0x20 || r == 0x7f {
			continue
		}
		// 其他控制/格式字符（包含常见零宽字符、BOM 等）
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// SanitizeCategory 清理并规范化分类名，确保占位符可被稳定识别与还原。
// 规则：
// - 仅保留 [A-Z0-9_]
// - 将空白与 '-' 归一为 '_'
// - 自动转大写；空结果返回空字符串（由上层回退默认值）
func SanitizeCategory(s string) string {
	s = SanitizePatternValue(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	lastUnderscore := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			r = r - 'a' + 'A'
			b.WriteRune(r)
			lastUnderscore = false
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
			lastUnderscore = false
		case r >= '0' && r <= '9':
			b.WriteRune(r)
			lastUnderscore = false
		case r == '_' || r == '-' || unicode.IsSpace(r):
			if !lastUnderscore {
				b.WriteByte('_')
				lastUnderscore = true
			}
		default:
			// drop
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return ""
	}
	return out
}
