package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"
)

const (
	leafCertValidHours = 24
	leafCertCacheSize  = 1000
)

// LeafCertManager manages per-host leaf certificate generation and caching
type LeafCertManager struct {
	ca    *CA
	cache map[string]*tls.Certificate
	mu    sync.RWMutex
}

// NewLeafCertManager creates a new leaf certificate manager
func NewLeafCertManager(ca *CA) *LeafCertManager {
	return &LeafCertManager{
		ca:    ca,
		cache: make(map[string]*tls.Certificate),
	}
}

// GetCertificate returns a TLS certificate for the given host
func (m *LeafCertManager) GetCertificate(host string) (*tls.Certificate, error) {
	m.mu.RLock()
	if cert, ok := m.cache[host]; ok {
		m.mu.RUnlock()
		return cert, nil
	}
	m.mu.RUnlock()

	// Generate new certificate
	cert, err := m.generateLeafCert(host)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	// Check if another goroutine added it while we were generating
	if existing, ok := m.cache[host]; ok {
		m.mu.Unlock()
		return existing, nil
	}

	// Evict oldest if cache is full
	if len(m.cache) >= leafCertCacheSize {
		m.evictOldest()
	}

	m.cache[host] = cert
	m.mu.Unlock()

	return cert, nil
}

// generateLeafCert creates a leaf certificate for the given host
func (m *LeafCertManager) generateLeafCert(host string) (*tls.Certificate, error) {
	// Generate ECDSA P-256 key for the leaf
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate leaf key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(leafCertValidHours * time.Hour)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		DNSNames:     []string{host},
	}

	// Sign with CA
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, m.ca.cert, &key.PublicKey, m.ca.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create leaf certificate: %w", err)
	}

	// Create TLS certificate
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal leaf key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	slog.Debug("Generated leaf certificate", "host", host)
	return &tlsCert, nil
}

// evictOldest removes the oldest entry from cache (simple FIFO for MVP)
func (m *LeafCertManager) evictOldest() {
	// For MVP, just clear one random entry
	// TODO: Implement proper LRU eviction
	for k := range m.cache {
		delete(m.cache, k)
		return
	}
}

// ClearCache clears all cached leaf certificates
func (m *LeafCertManager) ClearCache() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cache = make(map[string]*tls.Certificate)
	slog.Debug("Leaf certificate cache cleared")
}
