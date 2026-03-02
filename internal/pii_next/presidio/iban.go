package presidio

import (
	"strings"

	"github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
)

type IBANRecognizer struct{ *regexRecognizer }

func NewIBANRecognizer() recognizer.Recognizer {
	return &IBANRecognizer{&regexRecognizer{
		name:     "presidio-iban",
		category: "IBAN",
		priority: 130,
		// 允许空格分隔（常见为每 4 位一组）。
		// 注意：避免贪婪吞掉后续单词（例如 "... 32 ssn ..." 被误认为 IBAN 的一部分），
		// 这里按分组格式匹配：后续主要以 4 字符一组，末尾允许 1-4 字符的收尾组。
		re: mustCompile(`(?i)\b[a-z]{2}\d{2}(?: ?[a-z0-9]{4}){2,7}(?: ?[a-z0-9]{1,4})?\b`),
		validate: func(matched []byte) bool {
			compact := strings.ReplaceAll(string(matched), " ", "")
			return ibanValid(compact)
		},
	}}
}
