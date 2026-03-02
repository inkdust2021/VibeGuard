package presidio

import (
	"strings"
	"unicode"
)

// ibanValid 使用 ISO 13616 的 mod-97 校验。
// 规则：
// 1) 将前 4 位移到末尾
// 2) 字母 A..Z 映射为 10..35
// 3) 对得到的超长数字做 mod-97，结果应为 1
func ibanValid(iban string) bool {
	iban = strings.TrimSpace(iban)
	if iban == "" {
		return false
	}

	// 去掉空格并大写
	var compact []rune
	for _, r := range iban {
		if unicode.IsSpace(r) {
			continue
		}
		compact = append(compact, unicode.ToUpper(r))
	}
	if len(compact) < 15 || len(compact) > 34 {
		return false
	}

	// 国家码 + 校验位的基础校验
	if compact[0] < 'A' || compact[0] > 'Z' || compact[1] < 'A' || compact[1] > 'Z' {
		return false
	}
	if compact[2] < '0' || compact[2] > '9' || compact[3] < '0' || compact[3] > '9' {
		return false
	}

	// 旋转：前 4 位移到末尾
	rotated := append(compact[4:], compact[:4]...)

	// 流式计算 mod-97，避免大整数。
	mod := 0
	pushDigits := func(s string) {
		for i := 0; i < len(s); i++ {
			mod = (mod*10 + int(s[i]-'0')) % 97
		}
	}

	for _, r := range rotated {
		switch {
		case r >= '0' && r <= '9':
			pushDigits(string(r))
		case r >= 'A' && r <= 'Z':
			// A=10 ... Z=35
			v := int(r-'A') + 10
			if v < 10 || v > 35 {
				return false
			}
			if v < 10 {
				pushDigits("0")
				pushDigits(string('0' + byte(v)))
				continue
			}
			pushDigits(twoDigits(v))
		default:
			return false
		}
	}
	return mod == 1
}

func twoDigits(v int) string {
	t := v / 10
	o := v % 10
	return string([]byte{byte('0' + t), byte('0' + o)})
}
