package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

// encryptedPatternPrefix 是“加密后的匹配值”在配置文件中的前缀标识。
//
// 设计目标：
// - 配置文件落盘不出现明文关键词（减少误提交/拷贝泄露风险）
// - 进程内仍使用明文进行匹配；管理面板也显示明文
//
// 注意：
// - 该机制只保护“配置文件静态内容”；能访问管理面板/进程内存的人仍可看到明文
// - 解密依赖运行时注入的密钥（由上层从 CA 私钥派生）
const encryptedPatternPrefix = "__VG_ENC_V1__:"

type patternCrypto struct {
	gcm cipher.AEAD
}

func newPatternCrypto(key32 []byte) (*patternCrypto, error) {
	if len(key32) != 32 {
		return nil, fmt.Errorf("pattern encryption key must be 32 bytes, got %d", len(key32))
	}
	block, err := aes.NewCipher(key32)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &patternCrypto{gcm: gcm}, nil
}

func (c *patternCrypto) encryptString(plain string) (string, error) {
	if c == nil {
		return "", fmt.Errorf("pattern crypto not configured")
	}
	if plain == "" {
		return "", nil
	}

	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := c.gcm.Seal(nil, nonce, []byte(plain), nil)
	raw := append(nonce, ciphertext...)
	return encryptedPatternPrefix + base64.RawStdEncoding.EncodeToString(raw), nil
}

func (c *patternCrypto) decryptMaybeEncrypted(s string) (plain string, wasEncrypted bool, err error) {
	if !strings.HasPrefix(s, encryptedPatternPrefix) {
		return s, false, nil
	}
	if c == nil {
		return "", true, fmt.Errorf("pattern crypto not configured")
	}
	b64 := strings.TrimPrefix(s, encryptedPatternPrefix)
	raw, err := base64.RawStdEncoding.DecodeString(b64)
	if err != nil {
		return "", true, fmt.Errorf("invalid base64: %w", err)
	}
	ns := c.gcm.NonceSize()
	if len(raw) < ns {
		return "", true, fmt.Errorf("ciphertext too short")
	}
	nonce := raw[:ns]
	ciphertext := raw[ns:]
	out, err := c.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", true, err
	}
	return string(out), true, nil
}

// SetPatternEncryptionKey 启用“匹配值落盘加密”能力。
// key32 必须为 32 字节（AES-256）。
//
// 注意：该方法只配置加密器，不会自动重写配置文件；调用方通常需要随后执行一次 Load() 以解密已加载的配置。
func (m *Manager) SetPatternEncryptionKey(key32 []byte) error {
	if m == nil {
		return fmt.Errorf("config manager is nil")
	}
	c, err := newPatternCrypto(key32)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.patternCrypto = c
	m.mu.Unlock()
	return nil
}

func (m *Manager) decryptLoadedPatterns(cfg *Config) error {
	if m == nil || cfg == nil || m.patternCrypto == nil {
		return nil
	}

	for i := range cfg.Patterns.Keywords {
		v := cfg.Patterns.Keywords[i].Value
		plain, wasEnc, err := m.patternCrypto.decryptMaybeEncrypted(v)
		if err != nil {
			return fmt.Errorf("解密 keywords[%d] 失败：%w", i, err)
		}
		if wasEnc {
			cfg.Patterns.Keywords[i].Value = plain
		}
	}

	for i := range cfg.Patterns.Exclude {
		v := cfg.Patterns.Exclude[i]
		plain, wasEnc, err := m.patternCrypto.decryptMaybeEncrypted(v)
		if err != nil {
			return fmt.Errorf("解密 exclude[%d] 失败：%w", i, err)
		}
		if wasEnc {
			cfg.Patterns.Exclude[i] = plain
		}
	}

	return nil
}

func (m *Manager) encryptPatternsForSave(cfg Config) (Config, error) {
	if m == nil || m.patternCrypto == nil {
		return cfg, nil
	}

	// 注意：cfg 是浅拷贝，内部 slice 与原对象共享底层数组；必须 deep copy 后再改值，避免污染运行时明文配置。
	if len(cfg.Patterns.Keywords) > 0 {
		kw := append([]KeywordPattern(nil), cfg.Patterns.Keywords...)
		for i := range kw {
			enc, err := m.patternCrypto.encryptString(kw[i].Value)
			if err != nil {
				return Config{}, fmt.Errorf("加密 keywords[%d] 失败：%w", i, err)
			}
			kw[i].Value = enc
		}
		cfg.Patterns.Keywords = kw
	}

	if len(cfg.Patterns.Exclude) > 0 {
		ex := append([]string(nil), cfg.Patterns.Exclude...)
		for i := range ex {
			enc, err := m.patternCrypto.encryptString(ex[i])
			if err != nil {
				return Config{}, fmt.Errorf("加密 exclude[%d] 失败：%w", i, err)
			}
			ex[i] = enc
		}
		cfg.Patterns.Exclude = ex
	}

	return cfg, nil
}
