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
		re:       mustCompile(`(?:^|[^0-9A-Za-z_])(\+?\d[\d()\-\.\s]{6,}\d)\b`),
		group:    1,
		validate: func(matched []byte) bool {
			s := strings.TrimSpace(string(matched))
			if s == "" {
				return false
			}

			if looksLikeDateOrTimestamp(s) {
				return false
			}

			d := digitsOnly(s)
			if len(d) < 7 || len(d) > 15 {
				return false
			}

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
	reYMD    = regexp.MustCompile(`^\d{4}[-/.]\d{2}[-/.]\d{2}$`)
	reYMDHMS = regexp.MustCompile(`^\d{4}[-/.]\d{2}[-/.]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$`)
)

func looksLikeDateOrTimestamp(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}

	ns := normalizeForDateCheck(s)

	if reYMD.MatchString(s) || (ns != s && reYMD.MatchString(ns)) {
		return true
	}
	if reYMDHMS.MatchString(s) || (ns != s && reYMDHMS.MatchString(ns)) {
		return true
	}
	if looksLikeDateWithSeparators(ns) {
		return true
	}
	if isAllDigits(ns) {
		if len(ns) == 8 {
			year := atoi2(ns[0:4])
			month := atoi2(ns[4:6])
			day := atoi2(ns[6:8])
			if year >= 1900 && year <= 2100 && month >= 1 && month <= 12 && day >= 1 && day <= 31 {
				return true
			}
		}
		if looksLikeCompactDateTimeDigits(ns) {
			return true
		}
		if len(ns) == 10 && ns[0] == '1' {
			v := atoi64(ns)
			if v >= 946684800 && v <= 4102444800 {
				return true
			}
		}
		if len(ns) == 13 && ns[0] == '1' {
			v := atoi64(ns)
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

func normalizeForDateCheck(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\n', '\r', '(', ')':
			continue
		default:
			b.WriteByte(s[i])
		}
	}
	return strings.TrimSpace(b.String())
}

func looksLikeDateWithSeparators(s string) bool {
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, "+") {
		return false
	}
	if !strings.ContainsAny(s, "-/.") {
		return false
	}

	parts := splitOnSeparators(s)
	if len(parts) != 3 {
		return false
	}
	p0, p1, p2 := parts[0], parts[1], parts[2]
	if p0 == "" || p1 == "" || p2 == "" {
		return false
	}

	if len(p0) == 4 && isAllDigits(p0) && isAllDigits(p1) && isAllDigits(p2) && len(p1) <= 2 && len(p2) <= 2 {
		year := atoi2(p0)
		month := atoi2(p1)
		day := atoi2(p2)
		if year >= 1900 && year <= 2100 && month >= 1 && month <= 12 && day >= 1 && day <= 31 {
			return true
		}
	}

	if len(p2) == 4 && isAllDigits(p2) && isAllDigits(p0) && isAllDigits(p1) && len(p0) <= 2 && len(p1) <= 2 {
		month := atoi2(p0)
		day := atoi2(p1)
		year := atoi2(p2)
		if year >= 1900 && year <= 2100 && month >= 1 && month <= 12 && day >= 1 && day <= 31 {
			return true
		}
	}

	if len(p2) == 8 && isAllDigits(p2) && isAllDigits(p0) && isAllDigits(p1) && len(p0) <= 2 && len(p1) <= 2 {
		month := atoi2(p0)
		day := atoi2(p1)
		year2 := atoi2(p2[0:4])
		month2 := atoi2(p2[4:6])
		day2 := atoi2(p2[6:8])
		if month >= 1 && month <= 12 && day >= 1 && day <= 31 &&
			year2 >= 1900 && year2 <= 2100 && month2 >= 1 && month2 <= 12 && day2 >= 1 && day2 <= 31 {
			return true
		}
	}

	return false
}

func splitOnSeparators(s string) []string {
	if s == "" {
		return nil
	}
	parts := make([]string, 0, 4)
	last := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '-', '/', '.':
			if last < i {
				parts = append(parts, s[last:i])
			} else {
				parts = append(parts, "")
			}
			last = i + 1
		}
	}
	if last <= len(s) {
		parts = append(parts, s[last:])
	}
	out := parts[:0]
	for _, p := range parts {
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}
