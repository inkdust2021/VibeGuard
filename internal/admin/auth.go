package admin

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/inkdust2021/vibeguard/internal/config"
	"golang.org/x/crypto/bcrypt"
)

const (
	adminSessionCookieName = "VG_ADMIN_SESSION"
	adminAuthFileName      = "admin_auth.json"
)

var (
	adminSessionTTL     = 12 * time.Hour
	adminPasswordMinLen = 8
	adminPasswordMaxLen = 200
)

type authFile struct {
	Version    int    `json:"version"`
	BcryptHash string `json:"bcrypt_hash"`
	CreatedAt  string `json:"created_at"`
}

type AuthManager struct {
	mu sync.Mutex

	filePath   string
	configured bool
	broken     bool
	brokenErr  string

	bcryptHash []byte
	sessions   map[string]time.Time // token -> expiresAt
}

func defaultAuthFilePath() string {
	return filepath.Join(config.GetConfigDir(), adminAuthFileName)
}

func NewAuthManager(filePath string) *AuthManager {
	a := &AuthManager{
		filePath: strings.TrimSpace(filePath),
		sessions: make(map[string]time.Time),
	}
	a.loadFromDisk()
	return a
}

func (a *AuthManager) tryRecoverLocked() {
	if !a.broken {
		return
	}
	// 仅在 broken 状态下尝试恢复：避免每次请求都读文件。
	data, err := os.ReadFile(a.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// 用户手动删除鉴权文件：允许无重启恢复到“未配置”状态。
			a.configured = false
			a.broken = false
			a.brokenErr = ""
			a.bcryptHash = nil
			a.sessions = make(map[string]time.Time)
			return
		}
		a.brokenErr = err.Error()
		return
	}

	var f authFile
	if err := json.Unmarshal(data, &f); err != nil {
		a.brokenErr = "invalid json: " + err.Error()
		return
	}
	if strings.TrimSpace(f.BcryptHash) == "" {
		a.brokenErr = "missing bcrypt_hash"
		return
	}

	a.configured = true
	a.bcryptHash = []byte(f.BcryptHash)
	a.broken = false
	a.brokenErr = ""
}

func (a *AuthManager) loadFromDisk() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.filePath == "" {
		a.broken = true
		a.brokenErr = "empty auth file path"
		return
	}

	data, err := os.ReadFile(a.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		a.configured = true
		a.broken = true
		a.brokenErr = err.Error()
		slog.Error("Failed to read admin auth file", "path", a.filePath, "error", err)
		return
	}

	var f authFile
	if err := json.Unmarshal(data, &f); err != nil {
		a.configured = true
		a.broken = true
		a.brokenErr = "invalid json: " + err.Error()
		slog.Error("Failed to parse admin auth file", "path", a.filePath, "error", err)
		return
	}
	if strings.TrimSpace(f.BcryptHash) == "" {
		a.configured = true
		a.broken = true
		a.brokenErr = "missing bcrypt_hash"
		slog.Error("Invalid admin auth file (missing bcrypt_hash)", "path", a.filePath)
		return
	}

	a.configured = true
	a.bcryptHash = []byte(f.BcryptHash)
}

func (a *AuthManager) IsConfigured() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.configured && !a.broken
}

func (a *AuthManager) isAuthenticatedLocked(r *http.Request) bool {
	if r == nil {
		return false
	}
	c, err := r.Cookie(adminSessionCookieName)
	if err != nil {
		return false
	}
	token := strings.TrimSpace(c.Value)
	if token == "" {
		return false
	}

	now := time.Now()
	exp, ok := a.sessions[token]
	if !ok {
		return false
	}
	if now.After(exp) {
		delete(a.sessions, token)
		return false
	}
	return true
}

func (a *AuthManager) Status(r *http.Request) (configured bool, authenticated bool, broken bool, brokenErr string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.tryRecoverLocked()
	return a.configured && !a.broken, a.isAuthenticatedLocked(r), a.broken, a.brokenErr
}

func (a *AuthManager) Setup(password string) error {
	password = strings.TrimSpace(password)
	if password == "" {
		return fmt.Errorf("password is required")
	}
	if len(password) < adminPasswordMinLen {
		return fmt.Errorf("password must be at least %d characters", adminPasswordMinLen)
	}
	if len(password) > adminPasswordMaxLen {
		return fmt.Errorf("password must be at most %d characters", adminPasswordMaxLen)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.broken {
		return fmt.Errorf("admin auth store is broken: %s", a.brokenErr)
	}
	if a.configured {
		return fmt.Errorf("admin password already configured")
	}
	if a.filePath == "" {
		return fmt.Errorf("empty auth file path")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	f := authFile{
		Version:    1,
		BcryptHash: string(hash),
		CreatedAt:  time.Now().Format(time.RFC3339),
	}
	data, err := json.MarshalIndent(&f, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(a.filePath), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(a.filePath, data, 0o600); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(a.filePath, 0o600)
	}

	a.configured = true
	a.bcryptHash = hash
	return nil
}

func (a *AuthManager) Verify(password string) error {
	password = strings.TrimSpace(password)
	if password == "" {
		return fmt.Errorf("password is required")
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.broken {
		return fmt.Errorf("admin auth store is broken: %s", a.brokenErr)
	}
	if !a.configured {
		return fmt.Errorf("admin password not configured")
	}
	return bcrypt.CompareHashAndPassword(a.bcryptHash, []byte(password))
}

func (a *AuthManager) CreateSessionLocked() (token string, expiresAt time.Time, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", time.Time{}, err
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	expiresAt = time.Now().Add(adminSessionTTL)
	a.sessions[token] = expiresAt
	return token, expiresAt, nil
}

func (a *AuthManager) DestroySession(r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if r == nil {
		return
	}
	c, err := r.Cookie(adminSessionCookieName)
	if err != nil {
		return
	}
	token := strings.TrimSpace(c.Value)
	if token == "" {
		return
	}
	delete(a.sessions, token)
}

func (a *AuthManager) Require(w http.ResponseWriter, r *http.Request) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.tryRecoverLocked()
	if a.broken {
		http.Error(w, "Admin auth store is corrupted. Delete ~/.vibeguard/admin_auth.json to reset.", http.StatusInternalServerError)
		return false
	}
	if !a.configured {
		http.Error(w, "Admin password not configured (setup required)", http.StatusForbidden)
		return false
	}
	if !a.isAuthenticatedLocked(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func setAdminSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookieName,
		Value:    token,
		Path:     "/manager/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(adminSessionTTL.Seconds()),
	})
}

func clearAdminSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookieName,
		Value:    "",
		Path:     "/manager/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
