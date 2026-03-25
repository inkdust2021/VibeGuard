package wsproxy

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"sync"
	"unicode/utf8"

	"github.com/inkdust2021/vibeguard/internal/redact"
	"github.com/inkdust2021/vibeguard/internal/restore"
)

const (
	wsOpcodeContinuation = 0x0
	wsOpcodeText         = 0x1
	wsOpcodeBinary       = 0x2
	wsOpcodeClose        = 0x8
	wsOpcodePing         = 0x9
	wsOpcodePong         = 0xa
)

type readTransformFn func([]byte) []byte

// TransformConn 在 WebSocket 升级后的双向连接上做“上行脱敏、下行还原”。
// 当前实现只处理未压缩的文本消息；控制帧、二进制帧和带 RSV 位的数据帧全部透传。
type TransformConn struct {
	conn io.ReadWriteCloser

	readState  *frameTransformer
	writeState *frameTransformer

	readMu  sync.Mutex
	writeMu sync.Mutex
}

func NewTransformConn(conn io.ReadWriteCloser, redactor redact.Redactor, restorer *restore.Engine) *TransformConn {
	return &TransformConn{
		conn: conn,
		readState: newFrameTransformer(false, func(payload []byte) []byte {
			if restorer == nil {
				return append([]byte(nil), payload...)
			}
			return restorer.Restore(payload)
		}),
		writeState: newFrameTransformer(true, func(payload []byte) []byte {
			if redactor == nil {
				return append([]byte(nil), payload...)
			}
			out, _ := redactor.RedactWithMatches(payload)
			return out
		}),
	}
}

func (c *TransformConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	return c.readState.ReadFrom(c.conn, p)
}

func (c *TransformConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	return c.writeState.WriteTo(c.conn, p)
}

func (c *TransformConn) Close() error {
	return c.conn.Close()
}

type frameTransformer struct {
	maskOutput bool
	transform  readTransformFn

	inBuf  bytes.Buffer
	outBuf bytes.Buffer
	tmp    []byte

	msgMode     messageMode
	msgBuf      bytes.Buffer
	passthrough bool
	pendingErr  error
}

type messageMode int

const (
	messageModeNone messageMode = iota
	messageModeBufferText
	messageModePassthroughText
	messageModePassthroughBinary
)

func newFrameTransformer(maskOutput bool, transform readTransformFn) *frameTransformer {
	return &frameTransformer{
		maskOutput: maskOutput,
		transform:  transform,
		tmp:        make([]byte, 4096),
	}
}

func (t *frameTransformer) ReadFrom(src io.Reader, p []byte) (int, error) {
	for {
		if t.outBuf.Len() > 0 {
			return t.outBuf.Read(p)
		}
		if t.passthrough {
			return src.Read(p)
		}
		if t.pendingErr != nil {
			err := t.pendingErr
			t.pendingErr = nil
			return 0, err
		}

		n, err := src.Read(t.tmp)
		if n > 0 {
			t.inBuf.Write(t.tmp[:n])
			if perr := t.processIncoming(); perr != nil {
				t.outBuf.Write(t.inBuf.Bytes())
				t.inBuf.Reset()
				t.msgBuf.Reset()
				t.msgMode = messageModeNone
				t.passthrough = true
			}
		}

		if t.outBuf.Len() > 0 {
			if err != nil {
				t.pendingErr = err
			}
			return t.outBuf.Read(p)
		}
		if err != nil {
			return 0, err
		}
	}
}

func (t *frameTransformer) WriteTo(dst io.Writer, p []byte) (int, error) {
	if t.passthrough {
		n, err := dst.Write(p)
		if err != nil {
			return n, err
		}
		return len(p), nil
	}

	t.inBuf.Write(p)
	if err := t.processIncoming(); err != nil {
		t.passthrough = true
		raw := append([]byte(nil), t.inBuf.Bytes()...)
		t.inBuf.Reset()
		t.msgBuf.Reset()
		t.msgMode = messageModeNone
		if werr := writeAll(dst, raw); werr != nil {
			return len(p), werr
		}
		return len(p), nil
	}

	if t.outBuf.Len() > 0 {
		raw := append([]byte(nil), t.outBuf.Bytes()...)
		t.outBuf.Reset()
		if err := writeAll(dst, raw); err != nil {
			return len(p), err
		}
	}

	return len(p), nil
}

func (t *frameTransformer) processIncoming() error {
	for {
		frame, ok, err := parseFrame(t.inBuf.Bytes())
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		t.inBuf.Next(frame.totalLen)

		out, err := t.handleFrame(frame)
		if err != nil {
			return err
		}
		if len(out) > 0 {
			t.outBuf.Write(out)
		}
	}
}

func (t *frameTransformer) handleFrame(frame wsFrame) ([]byte, error) {
	if frame.isControl() {
		return frame.raw, nil
	}

	switch frame.opcode {
	case wsOpcodeText:
		if frame.rsv != 0 {
			if !frame.fin {
				t.msgMode = messageModePassthroughText
			}
			return frame.raw, nil
		}
		if frame.fin {
			return t.transformTextMessage(frame.payload)
		}
		t.msgBuf.Reset()
		t.msgBuf.Write(frame.payload)
		t.msgMode = messageModeBufferText
		return nil, nil

	case wsOpcodeBinary:
		if !frame.fin {
			t.msgMode = messageModePassthroughBinary
		}
		return frame.raw, nil

	case wsOpcodeContinuation:
		switch t.msgMode {
		case messageModeBufferText:
			t.msgBuf.Write(frame.payload)
			if !frame.fin {
				return nil, nil
			}
			payload := append([]byte(nil), t.msgBuf.Bytes()...)
			t.msgBuf.Reset()
			t.msgMode = messageModeNone
			return t.transformTextMessage(payload)

		case messageModePassthroughText, messageModePassthroughBinary:
			if frame.fin {
				t.msgMode = messageModeNone
			}
			return frame.raw, nil

		default:
			return frame.raw, nil
		}

	default:
		return frame.raw, nil
	}
}

func (t *frameTransformer) transformTextMessage(payload []byte) ([]byte, error) {
	if !utf8.Valid(payload) || t.transform == nil {
		return buildFrame(true, wsOpcodeText, t.maskOutput, payload)
	}
	return buildFrame(true, wsOpcodeText, t.maskOutput, t.transform(payload))
}

type wsFrame struct {
	fin      bool
	rsv      byte
	opcode   byte
	masked   bool
	payload  []byte
	raw      []byte
	totalLen int
}

func (f wsFrame) isControl() bool {
	return f.opcode >= 0x8
}

func parseFrame(buf []byte) (wsFrame, bool, error) {
	var frame wsFrame
	if len(buf) < 2 {
		return frame, false, nil
	}

	b0 := buf[0]
	b1 := buf[1]
	frame.fin = b0&0x80 != 0
	frame.rsv = b0 & 0x70
	frame.opcode = b0 & 0x0f
	frame.masked = b1&0x80 != 0

	payloadLen := uint64(b1 & 0x7f)
	offset := 2
	switch payloadLen {
	case 126:
		if len(buf) < offset+2 {
			return frame, false, nil
		}
		payloadLen = uint64(binary.BigEndian.Uint16(buf[offset : offset+2]))
		offset += 2
	case 127:
		if len(buf) < offset+8 {
			return frame, false, nil
		}
		payloadLen = binary.BigEndian.Uint64(buf[offset : offset+8])
		offset += 8
	}

	maskKeyLen := 0
	if frame.masked {
		maskKeyLen = 4
	}
	total := offset + maskKeyLen
	if len(buf) < total {
		return frame, false, nil
	}
	if payloadLen > uint64(len(buf)-total) {
		return frame, false, nil
	}
	total += int(payloadLen)

	frame.totalLen = total
	frame.raw = append([]byte(nil), buf[:total]...)

	payloadOffset := offset
	var maskKey []byte
	if frame.masked {
		maskKey = frame.raw[offset : offset+4]
		payloadOffset += 4
	}
	payload := append([]byte(nil), frame.raw[payloadOffset:total]...)
	if frame.masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	frame.payload = payload

	return frame, true, nil
}

func buildFrame(fin bool, opcode byte, masked bool, payload []byte) ([]byte, error) {
	header := make([]byte, 0, 14)
	b0 := opcode & 0x0f
	if fin {
		b0 |= 0x80
	}
	header = append(header, b0)

	payloadLen := len(payload)
	b1 := byte(0)
	if masked {
		b1 |= 0x80
	}

	switch {
	case payloadLen < 126:
		header = append(header, b1|byte(payloadLen))
	case payloadLen <= 65535:
		header = append(header, b1|126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(payloadLen))
		header = append(header, ext[:]...)
	default:
		header = append(header, b1|127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(payloadLen))
		header = append(header, ext[:]...)
	}

	out := make([]byte, 0, len(header)+payloadLen+4)
	out = append(out, header...)

	if masked {
		var maskKey [4]byte
		if _, err := rand.Read(maskKey[:]); err != nil {
			return nil, err
		}
		out = append(out, maskKey[:]...)
		for i, b := range payload {
			out = append(out, b^maskKey[i%4])
		}
		return out, nil
	}

	out = append(out, payload...)
	return out, nil
}

func writeAll(dst io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := dst.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
