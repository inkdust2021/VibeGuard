package proxy

import (
	"io"
	"sync"
)

type captureBuffer struct {
	max int

	total     int
	truncated bool
	buf       []byte
}

func newCaptureBuffer(max int) *captureBuffer {
	if max < 0 {
		max = 0
	}
	return &captureBuffer{max: max}
}

func (b *captureBuffer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	b.total += len(p)
	if b.max == 0 {
		// max=0 表示不抓取 body（仅统计大小）。
		b.truncated = true
		return len(p), nil
	}
	if len(b.buf) >= b.max {
		b.truncated = true
		return len(p), nil
	}
	remain := b.max - len(b.buf)
	if remain <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if len(p) > remain {
		b.buf = append(b.buf, p[:remain]...)
		b.truncated = true
		return len(p), nil
	}
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *captureBuffer) Text() string {
	if b == nil || len(b.buf) == 0 {
		return ""
	}
	return string(b.buf)
}

func (b *captureBuffer) TotalBytes() int {
	if b == nil {
		return 0
	}
	return b.total
}

func (b *captureBuffer) Truncated() bool {
	if b == nil {
		return false
	}
	return b.truncated
}

type captureReadCloser struct {
	rc io.ReadCloser
	w  io.Writer

	closeOnce sync.Once
	onClose   func()
}

func clipBodyForDebug(b []byte, max int) (text string, totalBytes int, truncated bool) {
	totalBytes = len(b)
	if max <= 0 || len(b) <= max {
		return string(b), totalBytes, false
	}
	return string(b[:max]), totalBytes, true
}

func (c *captureReadCloser) Read(p []byte) (int, error) {
	if c == nil || c.rc == nil {
		return 0, io.EOF
	}
	n, err := c.rc.Read(p)
	if n > 0 && c.w != nil {
		_, _ = c.w.Write(p[:n])
	}
	return n, err
}

func (c *captureReadCloser) Close() error {
	var err error
	if c != nil && c.rc != nil {
		err = c.rc.Close()
	}
	if c != nil && c.onClose != nil {
		c.closeOnce.Do(c.onClose)
	}
	return err
}
