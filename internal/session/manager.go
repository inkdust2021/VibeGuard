package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"sync"
	"time"
)

// Manager handles session mapping state
type Manager struct {
	forward            map[string]string // placeholder -> original
	reverse            map[string]string // original -> placeholder
	mu                 sync.RWMutex
	ttl                time.Duration
	maxSize            int
	created            map[string]time.Time // placeholder -> creation time
	stopChan           chan struct{}
	wal                *WAL
	walCleanupEnabled  bool
	walCleanupInterval time.Duration
	lastWALCleanup     time.Time
	// randomSecret is a random key generated on process start (default mode: stable within this process only).
	// deterministicSecret is the key used in "deterministic placeholders" mode (typically derived from the CA private key).
	// Notes:
	// - Neither key is written to config/logs.
	// - If deterministicSecret changes (e.g. the CA is regenerated), the same original text will produce different placeholders.
	randomSecret        []byte
	deterministicSecret []byte
	deterministicOn     bool
}

// NewManager creates a new session manager
func NewManager(ttl time.Duration, maxSize int) *Manager {
	randomSecret := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, randomSecret); err != nil {
		// In extreme cases (e.g. entropy source unavailable), fall back to a time-based seed.
		// This still avoids deterministic placeholders that can be brute-forced offline by an upstream.
		sum := sha256.Sum256([]byte(fmt.Sprintf("fallback-%d", time.Now().UnixNano())))
		randomSecret = make([]byte, 32)
		copy(randomSecret, sum[:])
	}

	m := &Manager{
		forward:      make(map[string]string),
		reverse:      make(map[string]string),
		created:      make(map[string]time.Time),
		ttl:          ttl,
		maxSize:      maxSize,
		stopChan:     make(chan struct{}),
		randomSecret: randomSecret,
	}

	// Start TTL cleanup goroutine
	go m.cleanupLoop()

	return m
}

// Register adds a new mapping
func (m *Manager) Register(placeholder, original string) {
	m.register(placeholder, original, time.Now(), true)
}

func (m *Manager) register(placeholder, original string, createdAt time.Time, appendToWAL bool) {
	if createdAt.IsZero() {
		createdAt = time.Now()
	}

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
	m.created[placeholder] = createdAt
	wal := m.wal

	if appendToWAL && wal != nil {
		if err := wal.Append(WALEntry{
			Placeholder: placeholder,
			Original:    original,
			CreatedAt:   createdAt,
		}); err != nil {
			slog.Warn("Failed to append session mapping to WAL", "error", err)
		}
	}
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
// Uses a truncated HMAC-SHA256(key, original) token: stable mapping for the same original, while reducing dictionary-guessing risk.
func (m *Manager) GeneratePlaceholder(original, category, prefix string) string {
	key := m.placeholderKey()
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(original))
	sum := h.Sum(nil)
	hash12 := hex.EncodeToString(sum)[:12]
	placeholder := fmt.Sprintf("%s%s_%s__", prefix, category, hash12)

	m.mu.RLock()
	existing, exists := m.forward[placeholder]
	m.mu.RUnlock()
	if exists && existing != original {
		for i := 2; ; i++ {
			ph := fmt.Sprintf("%s%s_%s_%d__", prefix, category, hash12, i)
			m.mu.RLock()
			existing, ok := m.forward[ph]
			m.mu.RUnlock()
			if !ok || existing == original {
				placeholder = ph
				break
			}
		}
	}

	return placeholder
}

func (m *Manager) placeholderKey() []byte {
	m.mu.RLock()
	useDet := m.deterministicOn && len(m.deterministicSecret) == 32
	det := m.deterministicSecret
	randKey := m.randomSecret
	m.mu.RUnlock()
	if useDet {
		return det
	}
	return randKey
}

// SetDeterministicPlaceholders toggles "deterministic placeholders" mode:
// - enabled=false: use a per-process random key (stable within this process only).
// - enabled=true: use the provided key32 (should be derived from the CA private key).
func (m *Manager) SetDeterministicPlaceholders(enabled bool, key32 []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !enabled {
		m.deterministicOn = false
		return nil
	}
	if len(key32) != 32 {
		return fmt.Errorf("deterministic placeholder key must be 32 bytes, got %d", len(key32))
	}
	m.deterministicSecret = append([]byte(nil), key32...)
	m.deterministicOn = true
	return nil
}

// DeterministicPlaceholdersEnabled reports whether deterministic placeholders are currently active.
func (m *Manager) DeterministicPlaceholdersEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.deterministicOn && len(m.deterministicSecret) == 32
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
	wal := m.wal

	if wal != nil {
		if err := wal.Delete(); err != nil && !os.IsNotExist(err) {
			slog.Warn("Failed to clear session WAL", "error", err)
		}
	}

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

	m.mu.Lock()
	wal := m.wal
	m.wal = nil
	m.mu.Unlock()
	if wal != nil {
		_ = wal.Close()
	}
}

// AttachWAL binds a WAL instance for persisting newly registered mappings.
func (m *Manager) AttachWAL(wal *WAL) {
	m.mu.Lock()
	old := m.wal
	m.wal = wal
	m.mu.Unlock()

	if old != nil && old != wal {
		_ = old.Close()
	}
}

// ConfigureWALCleanup changes the disk cleanup policy; mapping TTL cleanup stays enabled.
func (m *Manager) ConfigureWALCleanup(enabled bool, interval time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.walCleanupEnabled != enabled || m.walCleanupInterval != interval {
		m.lastWALCleanup = time.Now()
	}
	m.walCleanupEnabled = enabled
	m.walCleanupInterval = interval
}

// CompactWAL snapshots only live mappings, including their original creation times.
func (m *Manager) CompactWAL() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.compactWALLocked(time.Now())
}

func (m *Manager) compactWALLocked(now time.Time) error {
	if m.wal == nil {
		return nil
	}
	entries := make([]WALEntry, 0, len(m.forward))
	for placeholder, original := range m.forward {
		created := m.created[placeholder]
		if now.Sub(created) > m.ttl {
			continue
		}
		entries = append(entries, WALEntry{Placeholder: placeholder, Original: original, CreatedAt: created})
	}
	// Restore registers oldest first so reducing max_mappings retains the newest entries.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].CreatedAt.Equal(entries[j].CreatedAt) {
			return entries[i].Placeholder < entries[j].Placeholder
		}
		return entries[i].CreatedAt.Before(entries[j].CreatedAt)
	})
	if err := m.wal.Replace(entries); err != nil {
		return err
	}
	m.lastWALCleanup = now
	return nil
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
	if m.walCleanupEnabled && m.walCleanupInterval > 0 && now.Sub(m.lastWALCleanup) >= m.walCleanupInterval {
		if err := m.compactWALLocked(now); err != nil {
			slog.Warn("Failed to compact session WAL", "error", err)
		}
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
