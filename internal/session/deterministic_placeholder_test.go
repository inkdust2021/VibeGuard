package session

import (
	"bytes"
	"testing"
	"time"
)

func TestDeterministicPlaceholders_跨进程稳定(t *testing.T) {
	keyA := bytes.Repeat([]byte{0x42}, 32)
	keyB := bytes.Repeat([]byte{0x43}, 32)

	m1 := NewManager(time.Hour, 1000)
	t.Cleanup(m1.Close)
	if err := m1.SetDeterministicPlaceholders(true, keyA); err != nil {
		t.Fatalf("开启确定性占位符失败: %v", err)
	}

	m2 := NewManager(time.Hour, 1000)
	t.Cleanup(m2.Close)
	if err := m2.SetDeterministicPlaceholders(true, keyA); err != nil {
		t.Fatalf("开启确定性占位符失败: %v", err)
	}

	orig := "test123"
	cat := "TEXT"
	prefix := "__VG_"

	p1 := m1.GeneratePlaceholder(orig, cat, prefix)
	p2 := m2.GeneratePlaceholder(orig, cat, prefix)
	if p1 != p2 {
		t.Fatalf("同一 key 的占位符应跨进程一致：%q vs %q", p1, p2)
	}

	m3 := NewManager(time.Hour, 1000)
	t.Cleanup(m3.Close)
	if err := m3.SetDeterministicPlaceholders(true, keyB); err != nil {
		t.Fatalf("开启确定性占位符失败: %v", err)
	}
	p3 := m3.GeneratePlaceholder(orig, cat, prefix)
	if p3 == p1 {
		t.Fatalf("不同 key 的占位符不应相同：%q", p3)
	}

	if !m1.DeterministicPlaceholdersEnabled() {
		t.Fatalf("期望 deterministic 模式生效")
	}
	if err := m1.SetDeterministicPlaceholders(false, nil); err != nil {
		t.Fatalf("关闭 deterministic 失败: %v", err)
	}
	if m1.DeterministicPlaceholdersEnabled() {
		t.Fatalf("关闭后不应处于 deterministic 生效状态")
	}
}

