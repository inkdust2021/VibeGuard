package rulelists

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/inkdust2021/vibeguard/internal/config"
	"github.com/inkdust2021/vibeguard/internal/pii_next/rulelist"
)

const (
	defaultSubscriptionUpdateInterval = 24 * time.Hour
	defaultSubscriptionTimeout        = 20 * time.Second
	maxSubscriptionRuleListBytes      = 10 * 1024 * 1024 // 10MB
)

// SubscriptionMeta 用于记录订阅缓存的状态（用于条件请求与管理端展示）。
type SubscriptionMeta struct {
	URL          string `json:"url"`
	SigURL       string `json:"sig_url,omitempty"`
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`

	CheckedAt int64 `json:"checked_at,omitempty"`
	UpdatedAt int64 `json:"updated_at,omitempty"`

	VerifiedSHA256 string `json:"verified_sha256,omitempty"`
	VerifiedSig    bool   `json:"verified_sig,omitempty"`
	VerifiedHash   bool   `json:"verified_hash,omitempty"`

	Bytes     int    `json:"bytes,omitempty"`
	LastError string `json:"last_error,omitempty"`
}

func SubscriptionsDir() string {
	return filepath.Join(config.GetConfigDir(), "rule_lists", "subscriptions")
}

func IsSubscription(rl config.RuleListConfig) bool {
	return strings.TrimSpace(rl.URL) != ""
}

func SubscriptionKey(rl config.RuleListConfig) (string, bool) {
	if id := safeCacheKey(rl.ID); id != "" {
		return id, true
	}
	u := strings.TrimSpace(rl.URL)
	if u == "" {
		return "", false
	}
	sum := sha256.Sum256([]byte(u))
	return "url_" + hex.EncodeToString(sum[:]), true
}

func safeCacheKey(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	lastUnderscore := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			b.WriteByte(c)
			lastUnderscore = false
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c - 'A' + 'a')
			lastUnderscore = false
		case c >= '0' && c <= '9':
			b.WriteByte(c)
			lastUnderscore = false
		case c == '_' || c == '-':
			b.WriteByte(c)
			lastUnderscore = false
		default:
			if !lastUnderscore {
				b.WriteByte('_')
				lastUnderscore = true
			}
		}
	}
	out := strings.Trim(b.String(), "_-")
	if out == "" {
		return ""
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

func SubscriptionRulesPath(rl config.RuleListConfig) (string, bool) {
	key, ok := SubscriptionKey(rl)
	if !ok {
		return "", false
	}
	return filepath.Join(SubscriptionsDir(), key+".vgrules"), true
}

func SubscriptionMetaPath(rl config.RuleListConfig) (string, bool) {
	key, ok := SubscriptionKey(rl)
	if !ok {
		return "", false
	}
	return filepath.Join(SubscriptionsDir(), key+".json"), true
}

func LoadSubscriptionMeta(metaPath string) (SubscriptionMeta, bool, error) {
	p := strings.TrimSpace(metaPath)
	if p == "" {
		return SubscriptionMeta{}, false, nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return SubscriptionMeta{}, false, nil
		}
		return SubscriptionMeta{}, false, err
	}
	var m SubscriptionMeta
	if err := json.Unmarshal(b, &m); err != nil {
		return SubscriptionMeta{}, false, err
	}
	return m, true, nil
}

func SaveSubscriptionMeta(metaPath string, meta SubscriptionMeta) error {
	p := strings.TrimSpace(metaPath)
	if p == "" {
		return fmt.Errorf("empty meta path")
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	_ = os.Chmod(tmp, 0o600)
	if err := renameReplace(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Chmod(p, 0o600)
	return nil
}

func SubscriptionUpdateInterval(rl config.RuleListConfig) time.Duration {
	if !IsSubscription(rl) {
		return 0
	}
	s := strings.TrimSpace(rl.UpdateInterval)
	if s == "" {
		return defaultSubscriptionUpdateInterval
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return defaultSubscriptionUpdateInterval
	}
	// 防止误配成过于频繁的拉取（既浪费带宽也更容易被上游限流）。
	if d < 10*time.Minute {
		return 10 * time.Minute
	}
	return d
}

type SyncSubscriptionOptions struct {
	Client   *http.Client
	Force    bool
	Now      time.Time
	MaxBytes int
}

// SyncSubscriptionIfDue 会在“到期/强制”时拉取订阅并进行校验与落盘。
// 返回值 updated 表示缓存内容发生变化（或首次写入）；err 仅表示本次同步失败，不应导致代理不可用。
func SyncSubscriptionIfDue(ctx context.Context, rl config.RuleListConfig, opts SyncSubscriptionOptions) (updated bool, meta SubscriptionMeta, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !rl.Enabled {
		return false, SubscriptionMeta{}, nil
	}
	if strings.TrimSpace(rl.URL) == "" {
		return false, SubscriptionMeta{}, nil
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	rulesPath, ok := SubscriptionRulesPath(rl)
	if !ok {
		return false, SubscriptionMeta{}, fmt.Errorf("无法生成订阅缓存路径")
	}
	metaPath, ok := SubscriptionMetaPath(rl)
	if !ok {
		return false, SubscriptionMeta{}, fmt.Errorf("无法生成订阅元数据路径")
	}

	prev, prevOK, prevErr := LoadSubscriptionMeta(metaPath)
	if prevErr != nil {
		prev = SubscriptionMeta{}
		prevOK = false
	}

	meta = prev
	meta.URL = strings.TrimSpace(rl.URL)
	meta.SigURL = strings.TrimSpace(rl.SigURL)

	interval := SubscriptionUpdateInterval(rl)
	if !opts.Force && prevOK && prev.CheckedAt > 0 && interval > 0 {
		last := time.Unix(prev.CheckedAt, 0)
		if now.Sub(last) < interval {
			return false, meta, nil
		}
	}

	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: defaultSubscriptionTimeout}
	}
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = maxSubscriptionRuleListBytes
	}

	// 校验 URL 合法性（默认仅允许 https；显式 allow_http 才允许 http）。
	if err := validateRemoteURL(meta.URL, rl.AllowHTTP); err != nil {
		meta.CheckedAt = now.Unix()
		meta.LastError = err.Error()
		_ = SaveSubscriptionMeta(metaPath, meta)
		return false, meta, err
	}
	if strings.TrimSpace(meta.SigURL) != "" {
		if err := validateRemoteURL(meta.SigURL, rl.AllowHTTP); err != nil {
			meta.CheckedAt = now.Unix()
			meta.LastError = err.Error()
			_ = SaveSubscriptionMeta(metaPath, meta)
			return false, meta, err
		}
	}

	// 远端订阅必须至少提供一种校验：签名（SigURL+PubKey）或固定 SHA256。
	wantSig := strings.TrimSpace(meta.SigURL) != "" && strings.TrimSpace(rl.PubKey) != ""
	wantHash := strings.TrimSpace(rl.SHA256) != ""
	if !wantSig && !wantHash {
		err := fmt.Errorf("订阅缺少校验信息：请配置 sig_url+pubkey 或 sha256")
		meta.CheckedAt = now.Unix()
		meta.LastError = err.Error()
		_ = SaveSubscriptionMeta(metaPath, meta)
		return false, meta, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, meta.URL, nil)
	if err != nil {
		meta.CheckedAt = now.Unix()
		meta.LastError = err.Error()
		_ = SaveSubscriptionMeta(metaPath, meta)
		return false, meta, err
	}
	if strings.TrimSpace(prev.ETag) != "" {
		req.Header.Set("If-None-Match", prev.ETag)
	}
	if strings.TrimSpace(prev.LastModified) != "" {
		req.Header.Set("If-Modified-Since", prev.LastModified)
	}

	resp, err := client.Do(req)
	if err != nil {
		meta.CheckedAt = now.Unix()
		meta.LastError = err.Error()
		_ = SaveSubscriptionMeta(metaPath, meta)
		return false, meta, err
	}
	defer resp.Body.Close()

	meta.CheckedAt = now.Unix()

	if resp.StatusCode == http.StatusNotModified {
		meta.LastError = ""
		_ = SaveSubscriptionMeta(metaPath, meta)
		return false, meta, nil
	}
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("订阅拉取失败：HTTP %d", resp.StatusCode)
		meta.LastError = err.Error()
		_ = SaveSubscriptionMeta(metaPath, meta)
		return false, meta, err
	}

	body, err := readAllLimited(resp.Body, maxBytes)
	if err != nil {
		meta.LastError = err.Error()
		_ = SaveSubscriptionMeta(metaPath, meta)
		return false, meta, err
	}

	sum := sha256.Sum256(body)
	sumHex := hex.EncodeToString(sum[:])
	meta.VerifiedSHA256 = sumHex
	meta.Bytes = len(body)
	meta.ETag = strings.TrimSpace(resp.Header.Get("ETag"))
	meta.LastModified = strings.TrimSpace(resp.Header.Get("Last-Modified"))
	meta.VerifiedSig = false
	meta.VerifiedHash = false

	// 固定 SHA256 校验（适合“锁定版本”）
	if wantHash {
		exp := normalizeHexHash(rl.SHA256)
		if exp == "" {
			err := fmt.Errorf("无效 sha256（需要 64 位 hex）")
			meta.LastError = err.Error()
			_ = SaveSubscriptionMeta(metaPath, meta)
			return false, meta, err
		}
		if !strings.EqualFold(exp, sumHex) {
			err := fmt.Errorf("sha256 校验失败：期望 %s，实际 %s", exp, sumHex)
			meta.LastError = err.Error()
			_ = SaveSubscriptionMeta(metaPath, meta)
			return false, meta, err
		}
		meta.VerifiedHash = true
	}

	// 签名校验（适合“可自动更新的订阅”）
	if wantSig {
		pub, err := parseEd25519PublicKey(rl.PubKey)
		if err != nil {
			meta.LastError = err.Error()
			_ = SaveSubscriptionMeta(metaPath, meta)
			return false, meta, err
		}
		sigRaw, err := fetchSmall(ctx, client, meta.SigURL, 8*1024)
		if err != nil {
			meta.LastError = err.Error()
			_ = SaveSubscriptionMeta(metaPath, meta)
			return false, meta, err
		}
		sig, err := parseEd25519Signature(sigRaw)
		if err != nil {
			meta.LastError = err.Error()
			_ = SaveSubscriptionMeta(metaPath, meta)
			return false, meta, err
		}
		if !ed25519.Verify(pub, body, sig) {
			err := fmt.Errorf("签名校验失败")
			meta.LastError = err.Error()
			_ = SaveSubscriptionMeta(metaPath, meta)
			return false, meta, err
		}
		meta.VerifiedSig = true
	}

	// 语法校验：提前解析（含 regex 编译），避免“更新成功但不生效”的困惑。
	if _, err := rulelist.Parse(bytes.NewReader(body), rulelist.ParseOptions{
		Name:     strings.TrimSpace(rl.Name),
		Priority: rl.Priority,
	}); err != nil {
		meta.LastError = err.Error()
		_ = SaveSubscriptionMeta(metaPath, meta)
		return false, meta, err
	}

	// 若内容未变化，仅更新元数据即可。
	if prevOK && strings.TrimSpace(prev.VerifiedSHA256) != "" && strings.EqualFold(prev.VerifiedSHA256, sumHex) {
		meta.UpdatedAt = prev.UpdatedAt
		meta.LastError = ""
		_ = SaveSubscriptionMeta(metaPath, meta)
		return false, meta, nil
	}

	if err := writeFile0600(rulesPath, bytes.NewReader(body)); err != nil {
		meta.LastError = err.Error()
		_ = SaveSubscriptionMeta(metaPath, meta)
		return false, meta, err
	}

	meta.UpdatedAt = now.Unix()
	meta.LastError = ""
	_ = SaveSubscriptionMeta(metaPath, meta)
	return true, meta, nil
}

func normalizeHexHash(s string) string {
	v := strings.ToLower(strings.TrimSpace(s))
	if strings.HasPrefix(v, "sha256:") {
		v = strings.TrimSpace(strings.TrimPrefix(v, "sha256:"))
	}
	if len(v) != 64 {
		return ""
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return ""
	}
	return v
}

func validateRemoteURL(raw string, allowHTTP bool) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("无效 URL：%w", err)
	}
	if u == nil || strings.TrimSpace(u.Scheme) == "" || strings.TrimSpace(u.Host) == "" {
		return fmt.Errorf("无效 URL：缺少 scheme/host")
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	switch scheme {
	case "https":
		return nil
	case "http":
		if allowHTTP {
			return nil
		}
		return fmt.Errorf("不允许使用 http 订阅（可设置 allow_http: true 解除限制）")
	default:
		return fmt.Errorf("不支持的订阅 URL scheme：%s", scheme)
	}
}

func parseEd25519PublicKey(raw string) (ed25519.PublicKey, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, fmt.Errorf("pubkey 为空")
	}
	if strings.HasPrefix(strings.ToLower(s), "ed25519:") {
		s = strings.TrimSpace(s[len("ed25519:"):])
	}

	// hex（64 字符）
	if len(s) == 64 {
		if b, err := hex.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
			return ed25519.PublicKey(b), nil
		}
	}

	// base64（标准/无 padding）
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}
	return nil, fmt.Errorf("无效 pubkey：需要 ed25519 公钥（base64/hex）")
}

func parseEd25519Signature(raw []byte) ([]byte, error) {
	b := bytes.TrimSpace(raw)
	if len(b) == 0 {
		return nil, fmt.Errorf("签名为空")
	}

	// raw bytes
	if len(b) == ed25519.SignatureSize {
		return append([]byte(nil), b...), nil
	}

	// 如果是文本（hex/base64），优先按 hex 再按 base64
	if len(b) <= 2048 {
		s := strings.TrimSpace(string(b))
		if len(s) == 128 {
			if out, err := hex.DecodeString(s); err == nil && len(out) == ed25519.SignatureSize {
				return out, nil
			}
		}
		if out, err := base64.StdEncoding.DecodeString(s); err == nil && len(out) == ed25519.SignatureSize {
			return out, nil
		}
		if out, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(out) == ed25519.SignatureSize {
			return out, nil
		}
	}
	return nil, fmt.Errorf("无效签名：需要 ed25519 签名（raw/base64/hex）")
}

func fetchSmall(ctx context.Context, client *http.Client, url string, limit int) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("拉取签名失败：HTTP %d", resp.StatusCode)
	}
	return readAllLimited(resp.Body, limit)
}

func readAllLimited(r io.Reader, limit int) ([]byte, error) {
	limited := io.LimitReader(r, int64(limit)+1)
	out, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(out) > limit {
		return nil, fmt.Errorf("订阅内容过大（>%d bytes）", limit)
	}
	return out, nil
}

func writeFile0600(path string, r io.Reader) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("empty path")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(f, r)
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	if err := renameReplace(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Chmod(path, 0o600)
	return nil
}

func renameReplace(src, dst string) error {
	// POSIX 上 os.Rename 会覆盖；Windows 上会失败，因此做一次兼容处理。
	if err := os.Rename(src, dst); err == nil {
		return nil
	} else if runtime.GOOS == "windows" {
		_ = os.Remove(dst)
		return os.Rename(src, dst)
	} else {
		// 某些文件系统可能也不支持覆盖：尝试 remove 再 rename（不保证完全原子）。
		if _, statErr := os.Stat(dst); statErr == nil {
			_ = os.Remove(dst)
			return os.Rename(src, dst)
		}
		return err
	}
}
