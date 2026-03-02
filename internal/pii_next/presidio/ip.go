package presidio

import (
	"net"
	"strings"

	"github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
)

type IPv4Recognizer struct{ *regexRecognizer }

func NewIPv4Recognizer() recognizer.Recognizer {
	return &IPv4Recognizer{&regexRecognizer{
		name:     "presidio-ipv4",
		category: "IP",
		priority: 90,
		re:       mustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
		validate: func(matched []byte) bool {
			ip := net.ParseIP(string(matched))
			return ip != nil && ip.To4() != nil
		},
	}}
}

type IPv6Recognizer struct{ *regexRecognizer }

func NewIPv6Recognizer() recognizer.Recognizer {
	return &IPv6Recognizer{&regexRecognizer{
		name:     "presidio-ipv6",
		category: "IP",
		priority: 90,
		// 至少两个冒号；用 net.ParseIP 做最终校验以降低误报（例如时间戳）。
		re: mustCompile(`(?i)\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b`),
		validate: func(matched []byte) bool {
			s := strings.TrimSpace(string(matched))
			if strings.Count(s, ":") < 2 {
				return false
			}
			ip := net.ParseIP(s)
			return ip != nil && ip.To4() == nil
		},
	}}
}
