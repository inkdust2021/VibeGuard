package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestPatternCrypto_加解密往返(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	c, err := newPatternCrypto(key)
	if err != nil {
		t.Fatalf("newPatternCrypto() error: %v", err)
	}

	plain := "SensitiveKeyword"
	enc, err := c.encryptString(plain)
	if err != nil {
		t.Fatalf("encryptString() error: %v", err)
	}
	if !strings.HasPrefix(enc, encryptedPatternPrefix) {
		t.Fatalf("encryptString()=%q, want prefix %q", enc, encryptedPatternPrefix)
	}

	dec, wasEnc, err := c.decryptMaybeEncrypted(enc)
	if err != nil {
		t.Fatalf("decryptMaybeEncrypted() error: %v", err)
	}
	if !wasEnc {
		t.Fatalf("decryptMaybeEncrypted() wasEnc=false, want true")
	}
	if dec != plain {
		t.Fatalf("decryptMaybeEncrypted()=%q, want %q", dec, plain)
	}
}

func TestManager_encryptPatternsForSave_不污染运行时明文(t *testing.T) {
	m := NewManager()
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x42
	}
	if err := m.SetPatternEncryptionKey(key); err != nil {
		t.Fatalf("SetPatternEncryptionKey() error: %v", err)
	}

	in := Config{
		Patterns: PatternsConfig{
			Keywords: []KeywordPattern{{Value: "SensitiveKeyword", Category: "TEXT"}},
			Exclude:  []string{"ExcludeValue"},
		},
	}
	out, err := m.encryptPatternsForSave(in)
	if err != nil {
		t.Fatalf("encryptPatternsForSave() error: %v", err)
	}

	// 返回值应为密文
	if got := out.Patterns.Keywords[0].Value; !strings.HasPrefix(got, encryptedPatternPrefix) {
		t.Fatalf("saved keywords[0]=%q, want prefix %q", got, encryptedPatternPrefix)
	}
	if got := out.Patterns.Exclude[0]; !strings.HasPrefix(got, encryptedPatternPrefix) {
		t.Fatalf("saved exclude[0]=%q, want prefix %q", got, encryptedPatternPrefix)
	}

	// 传入的明文不应被污染
	if got := in.Patterns.Keywords[0].Value; got != "SensitiveKeyword" {
		t.Fatalf("input keywords[0]=%q, want %q", got, "SensitiveKeyword")
	}
	if got := in.Patterns.Exclude[0]; got != "ExcludeValue" {
		t.Fatalf("input exclude[0]=%q, want %q", got, "ExcludeValue")
	}
}

func TestManager_Save_匹配值落盘为密文(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	m := NewManager()
	m.configPath = cfgPath
	m.projectPath = filepath.Join(dir, ".vibeguard.yaml") // 避免读取工作区真实文件

	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x11
	}
	if err := m.SetPatternEncryptionKey(key); err != nil {
		t.Fatalf("SetPatternEncryptionKey() error: %v", err)
	}

	if err := m.Update(func(c *Config) {
		c.Patterns.Keywords = []KeywordPattern{{Value: "SensitiveKeyword", Category: "TEXT"}}
		c.Patterns.Exclude = []string{"ExcludeValue"}
	}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}
	if !strings.Contains(string(data), encryptedPatternPrefix) {
		t.Fatalf("config file does not contain %q prefix", encryptedPatternPrefix)
	}

	var onDisk Config
	if err := yaml.Unmarshal(data, &onDisk); err != nil {
		t.Fatalf("yaml.Unmarshal() error: %v", err)
	}
	if got := onDisk.Patterns.Keywords[0].Value; !strings.HasPrefix(got, encryptedPatternPrefix) {
		t.Fatalf("on-disk keywords[0]=%q, want prefix %q", got, encryptedPatternPrefix)
	}

	// 权限应为 0600（Windows 上 chmod 语义不同，这里跳过）
	if runtime.GOOS != "windows" {
		st, err := os.Stat(cfgPath)
		if err != nil {
			t.Fatalf("Stat() error: %v", err)
		}
		if got, want := st.Mode().Perm(), os.FileMode(0o600); got != want {
			t.Fatalf("config perms=%#o, want %#o", got, want)
		}
	}
}
