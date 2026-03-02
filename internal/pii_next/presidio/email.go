package presidio

import (
	"strings"

	"github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
)

// EmailRecognizer 识别常见邮箱格式。
// 注意：这里偏向“泛化覆盖”，允许较宽松的域名与后缀；后续可按误报反馈收紧。
type EmailRecognizer struct{ *regexRecognizer }

func NewEmailRecognizer() recognizer.Recognizer {
	return &EmailRecognizer{&regexRecognizer{
		name:     "presidio-email",
		category: "EMAIL",
		priority: 120,
		re:       mustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b`),
		validate: func(matched []byte) bool {
			// 极端误报：连续 ".." 等可后续优化；原型阶段做基础过滤。
			s := string(matched)
			return !strings.Contains(s, "..")
		},
	}}
}
