package session

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"
)

func TestWALRestore_保留CreatedAt且不重复追加(t *testing.T) {
	dir := t.TempDir()
	walPath := filepath.Join(dir, "session.wal")
	key := bytes.Repeat([]byte{0x11}, 32)

	wal, err := NewWAL(walPath, key)
	if err != nil {
		t.Fatalf("创建 WAL 失败: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })

	placeholder := "__VG_TEXT_aaaaaaaaaaaa__"
	original := "test123"
	createdAt := time.Now().Add(-30 * time.Minute)

	if err := wal.Append(WALEntry{
		Placeholder: placeholder,
		Original:    original,
		CreatedAt:   createdAt,
	}); err != nil {
		t.Fatalf("写入 WAL 失败: %v", err)
	}

	m := NewManager(time.Hour, 1000)
	t.Cleanup(m.Close)
	// 模拟：调用方可能先 AttachWAL 再 RestoreInto（不应导致恢复时“再写一遍”）。
	m.AttachWAL(wal)

	if err := wal.RestoreInto(m); err != nil {
		t.Fatalf("从 WAL 恢复失败: %v", err)
	}

	gotCreated, ok := m.created[placeholder]
	if !ok {
		t.Fatalf("期望恢复后存在 createdAt 记录")
	}
	// 不要求毫秒级完全一致，给 2s 容差；关键是不能被重置成 time.Now()
	if d := gotCreated.Sub(createdAt); d < -2*time.Second || d > 2*time.Second {
		t.Fatalf("期望 createdAt 被保留（≈%s），实际：%s", createdAt.Format(time.RFC3339Nano), gotCreated.Format(time.RFC3339Nano))
	}

	entries, err := wal.Load()
	if err != nil {
		t.Fatalf("读取 WAL 失败: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("期望恢复过程不重复追加 WAL，entries=%d", len(entries))
	}
}
