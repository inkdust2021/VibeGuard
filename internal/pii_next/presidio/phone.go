package presidio

import (
	"regexp"
	"strings"

	"github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
)

type PhoneRecognizer struct{ *regexRecognizer }

func NewPhoneRecognizer() recognizer.Recognizer {
	return &PhoneRecognizer{&regexRecognizer{
		name:     "presidio-phone",
		category: "PHONE",
		priority: 110,
		// 尽量宽松的国际电话格式：允许 +、空格、括号、短横线、点号。
		//
		// 注意：为了兼容 "+1 ..." 这种以非单词字符开头的号码，这里用捕获组避开 \b 的限制：
		// - 前置用 (^|非单词字符) 做锚定
		// - 命中范围使用第 1 个捕获组，避免把前置字符一起替换
		re:    mustCompile(`(?:^|[^0-9A-Za-z_])(\+?\d[\d()\-\.\s]{6,}\d)\b`),
		group: 1,
		validate: func(matched []byte) bool {
			s := strings.TrimSpace(string(matched))
			if s == "" {
				return false
			}

			// 明确规避常见日期/时间戳（避免把日志/代码里的时间信息错误脱敏）。
			if looksLikeDateOrTimestamp(s) {
				return false
			}

			d := digitsOnly(s)
			// E.164 上限 15 位。
			// 说明：各地区号码长度差异很大，最低位数不能按“固定 10/11 位”处理。
			// 这里对“非纯数字（带格式符）/带 + 的号码”放宽到 7 位起，避免覆盖面过窄。
			if len(d) < 7 || len(d) > 15 {
				return false
			}

			// 纯数字串（无 +、无分隔符）误报概率更高：至少要求 10 位数字，
			// 避免把短数字（端口/状态码/小 ID）误识别为手机号。
			if isAllDigits(s) && !strings.HasPrefix(s, "+") && len(d) < 10 {
				return false
			}

			return true
		},
	}}
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

var (
	reYMD     = regexp.MustCompile(`^\d{4}[-/.]\d{2}[-/.]\d{2}$`)
	reYMDHMS  = regexp.MustCompile(`^\d{4}[-/.]\d{2}[-/.]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$`)
)

func looksLikeDateOrTimestamp(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	// ISO/常见日期
	if reYMD.MatchString(s) {
		return true
	}
	// 常见 ISO 时间戳
	if reYMDHMS.MatchString(s) {
		return true
	}
	if isAllDigits(s) {
		// 纯 8 位日期（YYYYMMDD）
		if len(s) == 8 {
			year := atoi2(s[0:4])
			month := atoi2(s[4:6])
			day := atoi2(s[6:8])
			if year >= 1900 && year <= 2100 && month >= 1 && month <= 12 && day >= 1 && day <= 31 {
				return true
			}
		}
		// 紧凑日期时间（YYYYMMDDHHMM / YYYYMMDDHHMMSS）
		if looksLikeCompactDateTimeDigits(s) {
			return true
		}
		// epoch 秒（10 位）/毫秒（13 位）常见于 API/日志字段（例如 created/ts），不应当被当作手机号脱敏。
		// 这里做保守过滤：只针对以 '1' 开头的 epoch（2001~2033/2001~2033ms）以降低误伤电话号码的概率。
		if len(s) == 10 && s[0] == '1' {
			v := atoi64(s)
			if v >= 946684800 && v <= 4102444800 {
				return true
			}
		}
		if len(s) == 13 && s[0] == '1' {
			v := atoi64(s)
			if v >= 946684800000 && v <= 4102444800000 {
				return true
			}
		}
	}
	return false
}

func atoi2(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func atoi64(s string) int64 {
	var n int64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int64(c-'0')
	}
	return n
}

func looksLikeCompactDateTimeDigits(s string) bool {
	if len(s) != 12 && len(s) != 14 {
		return false
	}
	year := atoi2(s[0:4])
	month := atoi2(s[4:6])
	day := atoi2(s[6:8])
	hour := atoi2(s[8:10])
	minute := atoi2(s[10:12])
	if year < 1900 || year > 2100 || month < 1 || month > 12 || day < 1 || day > 31 || hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return false
	}
	if len(s) == 12 {
		return true
	}
	second := atoi2(s[12:14])
	if second < 0 || second > 59 {
		return false
	}
	return true
}
