package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
	path string
	gcm  cipher.AEAD
	mu   sync.Mutex
	file *os.File
}

// NewWAL creates a new WAL instance
func NewWAL(path string, key32 []byte) (*WAL, error) {
	if len(key32) != 32 {
		return nil, fmt.Errorf("WAL encryption key must be 32 bytes, got %d", len(key32))
	}
	key := append([]byte(nil), key32...)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	wal := &WAL{
		path: path,
		gcm:  gcm,
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

	if err := w.writeEntry(w.file, entry); err != nil {
		return err
	}

	return w.file.Sync()
}

// writeEntry retains the existing encrypted length-prefixed WAL format.
func (w *WAL) writeEntry(file *os.File, entry WALEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal entry: %w", err)
	}
	encrypted, err := w.encrypt(data)
	if err != nil {
		return fmt.Errorf("failed to encrypt entry: %w", err)
	}
	record := make([]byte, 4+len(encrypted))
	binary.BigEndian.PutUint32(record[:4], uint32(len(encrypted)))
	copy(record[4:], encrypted)
	if _, err := file.Write(record); err != nil {
		return fmt.Errorf("failed to write entry: %w", err)
	}
	return nil
}

// Replace syncs an encrypted snapshot before replacing the old WAL. It never truncates the original.
func (w *WAL) Replace(entries []WALEntry) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(w.path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(w.path), ".session-wal-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	for _, entry := range entries {
		if err := w.writeEntry(tmp, entry); err != nil {
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Close before rename so replacement also works on Windows.
	if w.file != nil {
		err := w.file.Close()
		w.file = nil
		if err != nil {
			return err
		}
	}
	return os.Rename(tmp.Name(), w.path)
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
	var integrityErr error
	offset := 0

	for offset < len(data) {
		if offset+4 > len(data) {
			integrityErr = fmt.Errorf("truncated WAL length prefix")
			break
		}

		length := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		if uint64(length) > uint64(len(data)-offset) {
			integrityErr = fmt.Errorf("truncated WAL entry")
			break
		}

		encrypted := data[offset : offset+int(length)]
		offset += int(length)

		decrypted, err := w.decrypt(encrypted)
		if err != nil {
			integrityErr = fmt.Errorf("failed to decrypt WAL entry: %w", err)
			continue
		}

		var entry WALEntry
		if err := json.Unmarshal(decrypted, &entry); err != nil {
			integrityErr = fmt.Errorf("failed to unmarshal WAL entry: %w", err)
			continue
		}

		entries = append(entries, entry)
	}

	return entries, integrityErr
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

	for _, entry := range entries {
		// Check if entry is expired
		if time.Since(entry.CreatedAt) > m.ttl {
			continue
		}
		// Preserve CreatedAt from the WAL:
		// - otherwise a restart would reset createdAt to time.Now(), effectively extending TTL
		// - also avoid appending to the WAL during restore (even if the caller already called AttachWAL)
		m.register(entry.Placeholder, entry.Original, entry.CreatedAt, false)
	}

	slog.Info("Restored mappings from WAL", "count", len(entries))
	return err
}
