//go:build !onnx || !cgo

package nlp

import "github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"

func OnnxAvailable() bool { return false }

func newOnnxRecognizer(opts Options) (recognizer.Recognizer, error) {
	return nil, ErrOnnxNotAvailable
}

func newOnnxRouterRecognizer(opts Options) (recognizer.Recognizer, error) {
	return nil, ErrOnnxNotAvailable
}
