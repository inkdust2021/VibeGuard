package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/inkdust2021/vibeguard/internal/config"
	"github.com/inkdust2021/vibeguard/internal/pii_next/rulelist"
	"github.com/inkdust2021/vibeguard/internal/rulelists"
)

type RuleListItem struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Path     string `json:"path,omitempty"`
	URL      string `json:"url,omitempty"`
	Kind     string `json:"kind"` // local|subscription
	Enabled  bool   `json:"enabled"`
	Priority int    `json:"priority"`
	Exists   bool   `json:"exists"`

	// 仅订阅模式使用（用于管理端展示订阅健康状况）。
	Verified  bool   `json:"verified,omitempty"`
	LastError string `json:"last_error,omitempty"`
	CheckedAt int64  `json:"checked_at,omitempty"`
	UpdatedAt int64  `json:"updated_at,omitempty"`
}

type RuleListsResponse struct {
	RuleLists []RuleListItem `json:"rule_lists"`
}

type updateRuleListRequest struct {
	ID       *string `json:"id"`
	Path     *string `json:"path"`
	URL      *string `json:"url"`
	Name     *string `json:"name"`
	Enabled  *bool   `json:"enabled"`
	Priority *int    `json:"priority"`
}

type subscribeRuleListRequest struct {
	URL            string `json:"url"`
	SigURL         string `json:"sig_url"`
	PubKey         string `json:"pubkey"`
	SHA256         string `json:"sha256"`
	UpdateInterval string `json:"update_interval"`
	AllowHTTP      bool   `json:"allow_http"`

	Name     string `json:"name"`
	Enabled  *bool  `json:"enabled"`
	Priority *int   `json:"priority"`
}

// handleRuleLists handles GET/POST /manager/api/rule_lists
func (a *Admin) handleRuleLists(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.getRuleLists(w, r)
	case http.MethodPost:
		a.updateRuleList(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRuleListsSubscribe handles POST /manager/api/rule_lists/subscribe
func (a *Admin) handleRuleListsSubscribe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req subscribeRuleListRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	urlStr := strings.TrimSpace(req.URL)
	if urlStr == "" {
		http.Error(w, "Missing url", http.StatusBadRequest)
		return
	}

	priority := 50
	if req.Priority != nil {
		if *req.Priority < 1 || *req.Priority > 99 {
			http.Error(w, "Invalid priority", http.StatusBadRequest)
			return
		}
		priority = *req.Priority
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	id, err := newRuleListID()
	if err != nil {
		http.Error(w, "Failed to generate id", http.StatusInternalServerError)
		return
	}

	rl := config.RuleListConfig{
		ID:             id,
		Name:           config.SanitizePatternValue(req.Name),
		URL:            config.SanitizePatternValue(urlStr),
		SigURL:         config.SanitizePatternValue(req.SigURL),
		PubKey:         config.SanitizePatternValue(req.PubKey),
		SHA256:         config.SanitizePatternValue(req.SHA256),
		UpdateInterval: strings.TrimSpace(req.UpdateInterval),
		AllowHTTP:      req.AllowHTTP,
		Enabled:        enabled,
		Priority:       priority,
	}

	// 订阅添加时做一次“拉取+校验+语法解析”：
	// - 避免用户保存后才发现 URL/签名/格式错误
	// - 先写缓存文件，配置落盘后可立即生效（热重载会加载缓存文件）
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	_, meta, syncErr := rulelists.SyncSubscriptionIfDue(ctx, rl, rulelists.SyncSubscriptionOptions{
		Force: true,
		Now:   time.Now(),
	})
	if syncErr != nil {
		http.Error(w, "Invalid subscription: "+syncErr.Error(), http.StatusBadRequest)
		return
	}

	if err := a.config.Update(func(c *config.Config) {
		c.Patterns.RuleLists = append(c.Patterns.RuleLists, rl)
	}); err != nil {
		// 配置保存失败：尽量清理缓存文件，避免“孤儿文件”堆积。
		if rp, ok := rulelists.SubscriptionRulesPath(rl); ok {
			_ = os.Remove(rp)
		}
		if mp, ok := rulelists.SubscriptionMetaPath(rl); ok {
			_ = os.Remove(mp)
		}
		http.Error(w, "Failed to save: "+err.Error(), http.StatusInternalServerError)
		return
	}

	exists := false
	if rp, ok := rulelists.SubscriptionRulesPath(rl); ok {
		if _, err := os.Stat(rp); err == nil {
			exists = true
		}
	}

	item := RuleListItem{
		ID:       rl.ID,
		Name:     rl.Name,
		URL:      rl.URL,
		Kind:     "subscription",
		Enabled:  rl.Enabled,
		Priority: rl.Priority,
		Exists:   exists,
		Verified: meta.VerifiedSig || meta.VerifiedHash,
		LastError: func() string {
			return strings.TrimSpace(meta.LastError)
		}(),
		CheckedAt: meta.CheckedAt,
		UpdatedAt: meta.UpdatedAt,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(item)
}

// handleRuleListsUpload handles POST /manager/api/rule_lists/upload (multipart form)
func (a *Admin) handleRuleListsUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	const maxUploadBytes = 10 * 1024 * 1024
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	if err := r.ParseMultipartForm(maxUploadBytes); err != nil {
		http.Error(w, "Invalid multipart form", http.StatusBadRequest)
		return
	}

	f, hdr, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Missing file", http.StatusBadRequest)
		return
	}
	defer f.Close()

	displayName := config.SanitizePatternValue(r.FormValue("name"))
	if displayName == "" && hdr != nil {
		displayName = config.SanitizePatternValue(hdr.Filename)
	}

	priority := 50
	if v := strings.TrimSpace(r.FormValue("priority")); v != "" {
		// 简单解析：只接受 1~99；非法则回退默认。
		if p, err := parseInt(v); err == nil && p >= 1 && p <= 99 {
			priority = p
		}
	}

	id, err := newRuleListID()
	if err != nil {
		http.Error(w, "Failed to generate id", http.StatusInternalServerError)
		return
	}

	// 保存到 ~/.vibeguard/rule_lists/ 下，避免与配置/证书等文件混在一起。
	rulesDir := filepath.Join(config.GetConfigDir(), "rule_lists")
	if err := os.MkdirAll(rulesDir, 0700); err != nil {
		http.Error(w, "Failed to create rules dir", http.StatusInternalServerError)
		return
	}

	base := safeFileBase(displayName)
	if base == "" {
		base = "rules"
	}
	filename := id + "_" + base + ".vgrules"
	absPath := filepath.Join(rulesDir, filename)

	// 写入文件（0600），再进行解析校验，避免“添加成功但不生效”的困惑。
	if err := writeFile0600(absPath, f); err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	rec, err := rulelist.ParseFile(absPath, rulelist.ParseOptions{Name: displayName, Priority: priority})
	if err != nil {
		_ = os.Remove(absPath)
		http.Error(w, "Invalid rule list: "+err.Error(), http.StatusBadRequest)
		return
	}

	tildePath := filepath.ToSlash(filepath.Join("~", ".vibeguard", "rule_lists", filename))
	if err := a.config.Update(func(c *config.Config) {
		c.Patterns.RuleLists = append(c.Patterns.RuleLists, config.RuleListConfig{
			ID:       id,
			Name:     displayName,
			Path:     tildePath,
			Enabled:  true,
			Priority: priority,
		})
	}); err != nil {
		_ = os.Remove(absPath)
		http.Error(w, "Failed to save: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := RuleListItem{
		ID:       id,
		Name:     displayName,
		Path:     tildePath,
		Enabled:  true,
		Priority: priority,
		Exists:   true,
	}
	_ = rec // 未来可返回统计信息；当前仅做校验。

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// handleRuleListsItem handles DELETE /manager/api/rule_lists/{id}
func (a *Admin) handleRuleListsItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/manager/api/rule_lists/")
	id = strings.TrimSpace(id)
	if id == "" {
		http.Error(w, "Invalid id", http.StatusBadRequest)
		return
	}

	// 先从配置里移除；同时尽量删除由管理端创建的本地文件（仅限管理目录内）。
	var removed config.RuleListConfig
	if err := a.config.Update(func(c *config.Config) {
		out := c.Patterns.RuleLists[:0]
		for _, rl := range c.Patterns.RuleLists {
			key := strings.TrimSpace(rl.ID)
			if key == "" {
				key = strings.TrimSpace(rl.Path)
			}
			if key == "" {
				key = strings.TrimSpace(rl.URL)
			}
			if strings.TrimSpace(key) == strings.TrimSpace(id) {
				removed = rl
				continue
			}
			out = append(out, rl)
		}
		c.Patterns.RuleLists = out
	}); err != nil {
		http.Error(w, "Failed to save: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if strings.TrimSpace(removed.URL) != "" {
		tryRemoveManagedRuleListSubscriptionFiles(removed)
	} else if strings.TrimSpace(removed.Path) != "" {
		abs := expandTildePath(removed.Path)
		_ = tryRemoveManagedRuleListFile(abs)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (a *Admin) getRuleLists(w http.ResponseWriter, r *http.Request) {
	c := a.config.Get()
	out := make([]RuleListItem, 0, len(c.Patterns.RuleLists))
	for _, rl := range c.Patterns.RuleLists {
		id := strings.TrimSpace(rl.ID)
		name := strings.TrimSpace(rl.Name)
		path := strings.TrimSpace(rl.Path)
		urlStr := strings.TrimSpace(rl.URL)

		item := RuleListItem{
			ID:       id,
			Name:     name,
			Path:     path,
			URL:      urlStr,
			Enabled:  rl.Enabled,
			Priority: rl.Priority,
		}

		if urlStr != "" {
			item.Kind = "subscription"
			if rp, ok := rulelists.SubscriptionRulesPath(rl); ok {
				if _, err := os.Stat(rp); err == nil {
					item.Exists = true
				}
			}
			if mp, ok := rulelists.SubscriptionMetaPath(rl); ok {
				if meta, ok, _ := rulelists.LoadSubscriptionMeta(mp); ok {
					item.Verified = meta.VerifiedSig || meta.VerifiedHash
					item.LastError = strings.TrimSpace(meta.LastError)
					item.CheckedAt = meta.CheckedAt
					item.UpdatedAt = meta.UpdatedAt
				}
			}
		} else {
			item.Kind = "local"
			abs := expandTildePath(path)
			_, err := os.Stat(abs)
			item.Exists = err == nil
		}

		out = append(out, item)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(RuleListsResponse{RuleLists: out})
}

func (a *Admin) updateRuleList(w http.ResponseWriter, r *http.Request) {
	var req updateRuleListRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	id := ""
	if req.ID != nil {
		id = config.SanitizePatternValue(*req.ID)
	}
	path := ""
	if req.Path != nil {
		path = strings.TrimSpace(*req.Path)
	}
	urlStr := ""
	if req.URL != nil {
		urlStr = strings.TrimSpace(*req.URL)
	}
	if id == "" && path == "" && urlStr == "" {
		http.Error(w, "Missing id/path", http.StatusBadRequest)
		return
	}

	if req.Priority != nil {
		if *req.Priority < 1 || *req.Priority > 99 {
			http.Error(w, "Invalid priority", http.StatusBadRequest)
			return
		}
	}

	if err := a.config.Update(func(c *config.Config) {
		for i := range c.Patterns.RuleLists {
			rl := &c.Patterns.RuleLists[i]
			key := strings.TrimSpace(rl.ID)
			if key == "" {
				key = strings.TrimSpace(rl.Path)
			}
			if key == "" {
				key = strings.TrimSpace(rl.URL)
			}
			if key != id && (path == "" || strings.TrimSpace(rl.Path) != path) && (urlStr == "" || strings.TrimSpace(rl.URL) != urlStr) {
				continue
			}

			if req.Name != nil {
				rl.Name = config.SanitizePatternValue(*req.Name)
			}
			if req.Enabled != nil {
				rl.Enabled = *req.Enabled
			}
			if req.Priority != nil {
				rl.Priority = *req.Priority
			}
			// Path/URL/ID 不允许在管理端更新：避免“指向任意文件/远端”的风险。
			return
		}
	}); err != nil {
		http.Error(w, "Failed to save: "+err.Error(), http.StatusInternalServerError)
		return
	}

	a.getRuleLists(w, r)
}

func newRuleListID() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func safeFileBase(name string) string {
	s := strings.TrimSpace(name)
	if s == "" {
		return ""
	}
	s = strings.ToLower(s)
	var b strings.Builder
	b.Grow(len(s))
	lastUnderscore := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			b.WriteByte(c)
			lastUnderscore = false
		case c >= '0' && c <= '9':
			b.WriteByte(c)
			lastUnderscore = false
		case c == '_' || c == '-' || c == '.' || c == ' ':
			if !lastUnderscore {
				b.WriteByte('_')
				lastUnderscore = true
			}
		default:
			// drop
		}
	}
	out := strings.Trim(b.String(), "_")
	if len(out) > 48 {
		out = out[:48]
	}
	return out
}

func writeFile0600(path string, r io.Reader) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("empty path")
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
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
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Chmod(path, 0600)
	return nil
}

func parseInt(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid")
		}
		n = n*10 + int(c-'0')
		if n > 1000000 {
			return 0, fmt.Errorf("too large")
		}
	}
	return n, nil
}

func expandTildePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if p == "~" {
		if h, err := os.UserHomeDir(); err == nil && strings.TrimSpace(h) != "" {
			return h
		}
		return p
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "~"+string(os.PathSeparator)) {
		if h, err := os.UserHomeDir(); err == nil && strings.TrimSpace(h) != "" {
			return filepath.Join(h, p[2:])
		}
	}
	return p
}

func tryRemoveManagedRuleListFile(absPath string) error {
	absPath = strings.TrimSpace(absPath)
	if absPath == "" {
		return nil
	}
	rulesDir := filepath.Join(config.GetConfigDir(), "rule_lists")
	rulesDir = filepath.Clean(rulesDir)

	ap, err := filepath.Abs(absPath)
	if err != nil {
		return nil
	}
	rel, err := filepath.Rel(rulesDir, ap)
	if err != nil {
		return nil
	}
	if rel == "." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || rel == ".." {
		// 不允许删除非管理目录内文件
		return nil
	}
	_ = os.Remove(ap)
	return nil
}

func tryRemoveManagedRuleListSubscriptionFiles(rl config.RuleListConfig) {
	rp, ok := rulelists.SubscriptionRulesPath(rl)
	if ok {
		_ = tryRemoveManagedSubscriptionFile(rp)
	}
	mp, ok := rulelists.SubscriptionMetaPath(rl)
	if ok {
		_ = tryRemoveManagedSubscriptionFile(mp)
	}
}

func tryRemoveManagedSubscriptionFile(absPath string) error {
	absPath = strings.TrimSpace(absPath)
	if absPath == "" {
		return nil
	}
	baseDir := filepath.Clean(rulelists.SubscriptionsDir())
	ap, err := filepath.Abs(absPath)
	if err != nil {
		return nil
	}
	rel, err := filepath.Rel(baseDir, ap)
	if err != nil {
		return nil
	}
	if rel == "." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || rel == ".." {
		// 仅允许删除订阅缓存目录内文件
		return nil
	}
	_ = os.Remove(ap)
	return nil
}
