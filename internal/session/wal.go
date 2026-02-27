package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// WAL entry structure
type WALEntry struct {
	Placeholder string    `json:"placeholder"`
	Original    string    `json:"original"`
	Category    string    `json:"category"`
	CreatedAt   time.Time `json:"created_at"`
}

// WAL handles persistent storage of session mappings
type WAL struct {
	path       string
	key        []byte
	block      cipher.Block
	gcm        cipher.AEAD
	mu         sync.Mutex
	file       *os.File
}

// NewWAL creates a new WAL instance
func NewWAL(path string, caKey *ecdsa.PrivateKey) (*WAL, error) {
	// Derive encryption key from CA private key
	keyBytes := caKey.D.Bytes()

	// Use SHA-256 to get exactly 32 bytes for AES-256
	hash := sha256.Sum256(keyBytes)
	key := hash[:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	wal := &WAL{
		path:  path,
		key:   key,
		block: block,
		gcm:   gcm,
	}

	return wal, nil
}

// Append adds a new entry to the WAL
func (w *WAL) Append(entry WALEntry) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Ensure directory exists
	dir := filepath.Dir(w.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create WAL directory: %w", err)
	}

	// Open file if not already open
	if w.file == nil {
		f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return fmt.Errorf("failed to open WAL file: %w", err)
		}
		w.file = f
	}

	// Serialize entry
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal entry: %w", err)
	}

	// Encrypt
	encrypted, err := w.encrypt(data)
	if err != nil {
		return fmt.Errorf("failed to encrypt entry: %w", err)
	}

	// Write length prefix + encrypted data
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(encrypted)))

	if _, err := w.file.Write(append(lenBuf, encrypted...)); err != nil {
		return fmt.Errorf("failed to write entry: %w", err)
	}

	return w.file.Sync()
}

// Load reads all entries from the WAL
func (w *WAL) Load() ([]WALEntry, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		w.file.Close()
		w.file = nil
	}

	data, err := os.ReadFile(w.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read WAL: %w", err)
	}

	var entries []WALEntry
	offset := 0

	for offset < len(data) {
		if offset+4 > len(data) {
			break
		}

		length := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		if offset+int(length) > len(data) {
			break
		}

		encrypted := data[offset : offset+int(length)]
		offset += int(length)

		decrypted, err := w.decrypt(encrypted)
		if err != nil {
			slog.Warn("Failed to decrypt WAL entry", "error", err)
			continue
		}

		var entry WALEntry
		if err := json.Unmarshal(decrypted, &entry); err != nil {
			slog.Warn("Failed to unmarshal WAL entry", "error", err)
			continue
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// Close closes the WAL file
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		err := w.file.Close()
		w.file = nil
		return err
	}
	return nil
}

// Delete removes the WAL file
func (w *WAL) Delete() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		w.file.Close()
		w.file = nil
	}

	return os.Remove(w.path)
}

// encrypt encrypts data using AES-GCM
func (w *WAL) encrypt(data []byte) ([]byte, error) {
	nonce := make([]byte, w.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := w.gcm.Seal(nil, nonce, data, nil)
	return append(nonce, ciphertext...), nil
}

// decrypt decrypts data using AES-GCM
func (w *WAL) decrypt(data []byte) ([]byte, error) {
	if len(data) < w.gcm.NonceSize() {
		return nil, fmt.Errorf("data too short")
	}

	nonce := data[:w.gcm.NonceSize()]
	ciphertext := data[w.gcm.NonceSize():]

	return w.gcm.Open(nil, nonce, ciphertext, nil)
}

// RestoreInto loads WAL entries into a session manager
func (w *WAL) RestoreInto(m *Manager) error {
	entries, err := w.Load()
	if err != nil {
		return err
	}

	for _, entry := range entries {
		// Check if entry is expired
		if time.Since(entry.CreatedAt) > m.ttl {
			continue
		}
		m.Register(entry.Placeholder, entry.Original)
	}

	slog.Info("Restored mappings from WAL", "count", len(entries))
	return nil
}
