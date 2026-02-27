package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"
)

// Manager handles session mapping state
type Manager struct {
	forward  map[string]string // placeholder -> original
	reverse  map[string]string // original -> placeholder
	mu       sync.RWMutex
	ttl      time.Duration
	maxSize  int
	created  map[string]time.Time // placeholder -> creation time
	stopChan chan struct{}
	// secret 用于生成占位符的不可逆 token（避免把原文哈希直接暴露给上游）。
	// 该值只存在于本进程内，不会写入配置/日志。
	secret []byte
}

// NewManager creates a new session manager
func NewManager(ttl time.Duration, maxSize int) *Manager {
	secret := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		// 极端情况下（例如系统熵源不可用），退化为时间种子；仍可避免“可被上游离线撞库”的确定性哈希占位符。
		sum := sha256.Sum256([]byte(fmt.Sprintf("fallback-%d", time.Now().UnixNano())))
		secret = sum[:]
	}

	m := &Manager{
		forward:  make(map[string]string),
		reverse:  make(map[string]string),
		created:  make(map[string]time.Time),
		ttl:      ttl,
		maxSize:  maxSize,
		stopChan: make(chan struct{}),
		secret:   secret,
	}

	// Start TTL cleanup goroutine
	go m.cleanupLoop()

	return m
}

// Register adds a new mapping
func (m *Manager) Register(placeholder, original string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already exists
	if _, exists := m.reverse[original]; exists {
		return
	}

	// Evict if at capacity
	if len(m.forward) >= m.maxSize {
		m.evictOldestLocked()
	}

	m.forward[placeholder] = original
	m.reverse[original] = placeholder
	m.created[placeholder] = time.Now()
}

// Lookup returns the original value for a placeholder
func (m *Manager) Lookup(placeholder string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	original, ok := m.forward[placeholder]
	return original, ok
}

// LookupReverse returns the placeholder for an original value
func (m *Manager) LookupReverse(original string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	placeholder, ok := m.reverse[original]
	return placeholder, ok
}

// GeneratePlaceholder creates a placeholder for the given original value (does NOT register it).
// 说明：
//   - 旧版使用 SHA-256(original) 的截断作为 token，容易被上游用字典攻击/撞库反推出原文；
//   - 这里改为 HMAC-SHA256(secret, original) 的截断：仍保持“同一 original → 同一 placeholder”的稳定性，
//     但 token 不可被上游反推。
func (m *Manager) GeneratePlaceholder(original, category, prefix string) string {
	h := hmac.New(sha256.New, m.secret)
	_, _ = h.Write([]byte(original))
	sum := h.Sum(nil)
	hash12 := hex.EncodeToString(sum)[:12]
	placeholder := fmt.Sprintf("%s%s_%s__", prefix, category, hash12)

	// Check for collision
	if existing, exists := m.Lookup(placeholder); exists && existing != original {
		// Collision detected, add disambiguator
		for i := 2; ; i++ {
			ph := fmt.Sprintf("%s%s_%s_%d__", prefix, category, hash12, i)
			if existing, ok := m.Lookup(ph); !ok || existing == original {
				placeholder = ph
				break
			}
		}
	}

	return placeholder
}

// Size returns the number of mappings
func (m *Manager) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.forward)
}

// Clear removes all mappings
func (m *Manager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.forward = make(map[string]string)
	m.reverse = make(map[string]string)
	m.created = make(map[string]time.Time)
	slog.Debug("Session mapping cleared")
}

// Close stops the cleanup goroutine
func (m *Manager) Close() {
	select {
	case <-m.stopChan:
		// Already closed
	default:
		close(m.stopChan)
	}
}

// MappingInfo represents a mapping entry for listing (without original value)
type MappingInfo struct {
	Placeholder string
	Category    string
}

// ListMappings returns all mappings (without original values for privacy)
func (m *Manager) ListMappings() []MappingInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]MappingInfo, 0, len(m.forward))
	for placeholder := range m.forward {
		// Extract category from placeholder format: __VG_CATEGORY_hash__
		category := "UNKNOWN"
		if len(placeholder) > 6 && placeholder[:6] == "__VG_" {
			// Find the second underscore after __VG_
			for i := 6; i < len(placeholder); i++ {
				if placeholder[i] == '_' {
					category = placeholder[6:i]
					break
				}
			}
		}

		result = append(result, MappingInfo{
			Placeholder: placeholder,
			Category:    category,
		})
	}
	return result
}

// cleanupLoop periodically removes expired entries
func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.cleanup()
		case <-m.stopChan:
			return
		}
	}
}

// cleanup removes expired entries
func (m *Manager) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	expired := 0

	for placeholder, createdAt := range m.created {
		if now.Sub(createdAt) > m.ttl {
			original := m.forward[placeholder]
			delete(m.forward, placeholder)
			delete(m.reverse, original)
			delete(m.created, placeholder)
			expired++
		}
	}

	if expired > 0 {
		slog.Debug("Cleaned up expired mappings", "count", expired)
	}
}

// evictOldestLocked removes the oldest entry (must hold lock)
func (m *Manager) evictOldestLocked() {
	var oldestPlaceholder string
	var oldestTime time.Time

	for placeholder, createdAt := range m.created {
		if oldestPlaceholder == "" || createdAt.Before(oldestTime) {
			oldestPlaceholder = placeholder
			oldestTime = createdAt
		}
	}

	if oldestPlaceholder != "" {
		original := m.forward[oldestPlaceholder]
		delete(m.forward, oldestPlaceholder)
		delete(m.reverse, original)
		delete(m.created, oldestPlaceholder)
		slog.Debug("Evicted oldest mapping", "placeholder", oldestPlaceholder)
	}
}
