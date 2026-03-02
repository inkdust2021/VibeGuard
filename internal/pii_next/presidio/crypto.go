package presidio

import "github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"

type BTCAddressRecognizer struct{ *regexRecognizer }

func NewBTCAddressRecognizer() recognizer.Recognizer {
	return &BTCAddressRecognizer{&regexRecognizer{
		name:     "presidio-btc-address",
		category: "CRYPTO",
		priority: 100,
		// legacy / P2SH / bech32（仅做格式识别，不做校验和）
		re: mustCompile(`\b(?:bc1[0-9a-z]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b`),
	}}
}

type ETHAddressRecognizer struct{ *regexRecognizer }

func NewETHAddressRecognizer() recognizer.Recognizer {
	return &ETHAddressRecognizer{&regexRecognizer{
		name:     "presidio-eth-address",
		category: "CRYPTO",
		priority: 100,
		re:       mustCompile(`\b0x[a-fA-F0-9]{40}\b`),
	}}
}
