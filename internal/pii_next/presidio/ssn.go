package presidio

import "github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"

type SSNRecognizer struct{ *regexRecognizer }

func NewSSNRecognizer() recognizer.Recognizer {
	return &SSNRecognizer{&regexRecognizer{
		name:     "presidio-ssn",
		category: "SSN",
		priority: 130,
		// Go regexp 不支持 Perl lookahead；这里先用宽松格式匹配，再在 validate 中做规则过滤：
		// - 区段：000 / 666 / 9xx 无效
		// - 组：00 无效
		// - 序列号：0000 无效
		re: mustCompile(`\b\d{3}[- ]?\d{2}[- ]?\d{4}\b`),
		validate: func(matched []byte) bool {
			d := digitsOnly(string(matched))
			if len(d) != 9 {
				return false
			}
			area := d[:3]
			group := d[3:5]
			serial := d[5:]
			if area == "000" || area == "666" || area[0] == '9' {
				return false
			}
			if group == "00" {
				return false
			}
			if serial == "0000" {
				return false
			}
			return true
		},
	}}
}
