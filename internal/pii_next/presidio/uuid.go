package presidio

import "github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"

type UUIDRecognizer struct{ *regexRecognizer }

func NewUUIDRecognizer() recognizer.Recognizer {
	return &UUIDRecognizer{&regexRecognizer{
		name:     "presidio-uuid",
		category: "UUID",
		priority: 85,
		re:       mustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`),
	}}
}
