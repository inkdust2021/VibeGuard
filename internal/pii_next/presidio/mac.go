package presidio

import "github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"

type MACRecognizer struct{ *regexRecognizer }

func NewMACRecognizer() recognizer.Recognizer {
	return &MACRecognizer{&regexRecognizer{
		name:     "presidio-mac",
		category: "MAC",
		priority: 90,
		re:       mustCompile(`\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`),
	}}
}
