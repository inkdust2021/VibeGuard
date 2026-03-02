package presidio

import (
	"strings"

	"github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
)

// PhoneLabeledRecognizer 识别“带电话语义标签”的号码（覆盖各地区长度差异）。
//
// 设计目标：
// - 覆盖面：允许纯数字手机号（例如 10/11 位）在常见文本中被识别；
// - 降误报：仅在出现电话语义标签（tel/phone/手机号/电话等）时启用更宽松的匹配；
// - 仍保留日期/时间戳的过滤，避免误伤日志/代码中的必要信息。
type PhoneLabeledRecognizer struct{ *regexRecognizer }

func NewPhoneLabeledRecognizer() recognizer.Recognizer {
	return &PhoneLabeledRecognizer{&regexRecognizer{
		name:     "presidio-phone-labeled",
		category: "PHONE",
		priority: 111,
		// 带“电话语义标签”的号码：
		// - 标签：tel/phone/mobile/手机号/电话/联系方式/联系...
		// - 分隔：空格/冒号/中文冒号/点号/短横线
		// - 号码：允许 +、空格、括号、短横线、点号；且必须以数字结尾
		//
		// 使用第 1 个捕获组作为命中范围，避免把标签一起替换。
		// 支持常见口语写法：phone number is 130... / 手机号是 130... / tel: 020...
		re:    mustCompile(`(?i)(?:^|[^0-9A-Za-z_])(?:tel|telephone|phone|mobile|cell|contact|call|whatsapp|wechat|fax|热线|电话|手机|手机号|联系方式|联系电话|联系)(?:\s+(?:number|no\.?|num|#|号码|号))?(?:\s*(?:is|are|为|是|:|：|\-|—))?\s*([+\d][\d()\-\.\s]{5,}\d)\b`),
		group: 1,
		validate: func(matched []byte) bool {
			s := strings.TrimSpace(string(matched))
			if s == "" {
				return false
			}
			if looksLikeDateOrTimestamp(s) {
				return false
			}

			d := digitsOnly(s)
			// E.164 上限 15 位；下限取 7 位，覆盖各地区本地号码差异（7~15）。
			if len(d) < 7 || len(d) > 15 {
				return false
			}
			return true
		},
	}}
}
