package presidio

import (
	"strings"

	"github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
)

// DefaultRecognizers 返回一组“Presidio 风格”的内置识别器（纯 Go，无外部 HTTP）。
// 原型阶段固定开启常见类型；接入主流程后再做可配置化（按需启用/关闭）。
func DefaultRecognizers() []recognizer.Recognizer {
	return []recognizer.Recognizer{
		NewEmailRecognizer(),
		NewCreditCardRecognizer(),
		NewIBANRecognizer(),
		NewSSNRecognizer(),
		NewPhoneRecognizer(),
		NewURLRecognizer(),
		NewIPv4Recognizer(),
		NewIPv6Recognizer(),
		NewMACRecognizer(),
		NewUUIDRecognizer(),
		NewBTCAddressRecognizer(),
		NewETHAddressRecognizer(),
	}
}

var safeRecognizerNames = []string{"email", "credit_card", "iban", "ssn"}

// SafeRecognizerNames 返回“保守默认”的识别器名称集合。
// 说明：这些规则带强校验/高置信度，且不容易误伤代码/日志中的必要信息。
func SafeRecognizerNames() []string {
	return append([]string(nil), safeRecognizerNames...)
}

// SafeRecognizers 返回“保守默认”的识别器集合：
// - email
// - credit_card（Luhn 校验）
// - iban（mod-97 校验）
// - ssn
func SafeRecognizers() []recognizer.Recognizer {
	return []recognizer.Recognizer{
		NewEmailRecognizer(),
		NewCreditCardRecognizer(),
		NewIBANRecognizer(),
		NewSSNRecognizer(),
	}
}

// NewRecognizers 根据配置名称返回指定的识别器集合。
//
// names 为空或包含 "all" 时，返回 DefaultRecognizers。
// 支持别名：
// - "ip" → ipv4 + ipv6
// - "crypto" → btc + eth
func NewRecognizers(names []string) (recs []recognizer.Recognizer, unknown []string) {
	if len(names) == 0 {
		return SafeRecognizers(), nil
	}
	normalized := make([]string, 0, len(names))
	hasAll := false
	for _, n := range names {
		v := normalizeRecognizerName(n)
		if v == "" {
			continue
		}
		if v == "all" {
			hasAll = true
			break
		}
		normalized = append(normalized, v)
	}
	if hasAll || len(normalized) == 0 {
		return DefaultRecognizers(), nil
	}

	seen := map[string]bool{}
	push := func(key string, r recognizer.Recognizer) {
		if key == "" || r == nil {
			return
		}
		if seen[key] {
			return
		}
		seen[key] = true
		recs = append(recs, r)
	}

	for _, n := range normalized {
		switch n {
		case "email":
			push("email", NewEmailRecognizer())
		case "credit_card":
			push("credit_card", NewCreditCardRecognizer())
		case "iban":
			push("iban", NewIBANRecognizer())
		case "ssn":
			push("ssn", NewSSNRecognizer())
		case "phone":
			push("phone", NewPhoneRecognizer())
		case "url":
			push("url", NewURLRecognizer())
		case "ipv4":
			push("ipv4", NewIPv4Recognizer())
		case "ipv6":
			push("ipv6", NewIPv6Recognizer())
		case "ip":
			push("ipv4", NewIPv4Recognizer())
			push("ipv6", NewIPv6Recognizer())
		case "mac":
			push("mac", NewMACRecognizer())
		case "uuid":
			push("uuid", NewUUIDRecognizer())
		case "btc":
			push("btc", NewBTCAddressRecognizer())
		case "eth":
			push("eth", NewETHAddressRecognizer())
		case "crypto":
			push("btc", NewBTCAddressRecognizer())
			push("eth", NewETHAddressRecognizer())
		default:
			unknown = append(unknown, n)
		}
	}

	return recs, unknown
}

func normalizeRecognizerName(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, " ", "_")
	var b strings.Builder
	b.Grow(len(s))
	lastUnderscore := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			b.WriteByte(c)
			lastUnderscore = false
		case c >= '0' && c <= '9':
			b.WriteByte(c)
			lastUnderscore = false
		case c == '_':
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
