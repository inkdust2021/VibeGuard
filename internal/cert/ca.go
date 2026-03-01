package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	caKeyName    = "ca-key.pem"
	caCertName   = "ca-cert.pem"
	caKeyPerms   = 0600
	caValidYears = 10
)

// CA represents the Certificate Authority
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	mu   sync.RWMutex
}

// LoadOrGenerateCA loads or generates a CA certificate
func LoadOrGenerateCA(caCertPath, caKeyPath string) (*CA, error) {
	ca := &CA{}

	// Try to load existing CA
	keyData, keyErr := os.ReadFile(caKeyPath)
	if os.IsNotExist(keyErr) {
		// Generate new CA
		slog.Info("Generating new CA certificate...")
		if err := ca.generateFromPaths(caCertPath, caKeyPath); err != nil {
			return nil, err
		}
		return ca, nil
	}
	if keyErr != nil {
		return nil, fmt.Errorf("failed to read CA key: %w", keyErr)
	}

	certData, certErr := os.ReadFile(caCertPath)
	if certErr != nil {
		return nil, fmt.Errorf("failed to read CA cert: %w", certErr)
	}

	// Parse key
	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to parse CA key PEM")
	}

	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EC private key: %w", err)
	}
	ca.key = key

	// Parse certificate
	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to parse CA cert PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}
	ca.cert = cert

	slog.Info("Loaded existing CA certificate")
	return ca, nil
}

// generateFromPaths creates a new CA certificate at the specified paths
func (ca *CA) generateFromPaths(caCertPath, caKeyPath string) error {
	// Generate ECDSA P-256 private key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ECDSA key: %w", err)
	}
	ca.key = key

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.AddDate(caValidYears, 0, 0)

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "VibeGuard CA", Organization: []string{"VibeGuard"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Self-sign the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &ca.key.PublicKey, ca.key)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("failed to parse generated CA certificate: %w", err)
	}
	ca.cert = cert

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(caKeyPath), 0700); err != nil {
		return fmt.Errorf("failed to create CA directory: %w", err)
	}

	// Write private key
	keyBytes, err := x509.MarshalECPrivateKey(ca.key)
	if err != nil {
		return fmt.Errorf("failed to marshal EC private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	if err := os.WriteFile(caKeyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write CA key: %w", err)
	}

	// Write certificate
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	if err := os.WriteFile(caCertPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write CA certificate: %w", err)
	}

	slog.Info("CA certificate generated", "path", caCertPath)
	return nil
}

// CertPath returns the path to the CA certificate
func (ca *CA) CertPath(dataDir string) string {
	return filepath.Join(dataDir, caCertName)
}

// KeyPath returns the path to the CA private key
func (ca *CA) KeyPath(dataDir string) string {
	return filepath.Join(dataDir, caKeyName)
}

// DeriveStorageKey 派生一个用于“本机落盘加密”的对称密钥（32 字节）。
//
// 用途示例：
// - 会话映射 WAL
// - 配置文件中的敏感匹配值（关键词）落盘加密
//
// 注意：
// - 该密钥派生自 CA 私钥；一旦 regenerate/丢失 CA 私钥，将无法解密旧数据。
func (ca *CA) DeriveStorageKey() ([]byte, error) {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	if ca.key == nil {
		return nil, fmt.Errorf("CA private key not loaded")
	}
	sum := sha256.Sum256(ca.key.D.Bytes())
	out := make([]byte, 32)
	copy(out, sum[:])
	return out, nil
}

// DerivePlaceholderKey 派生一个用于“确定性占位符生成”的对称密钥（32 字节）。
//
// 该密钥用于在“跨进程稳定占位符”模式下，生成稳定的占位符 token。
// 为避免与其他用途（WAL/配置加密）复用同一 key，这里基于 DeriveStorageKey 做一次域隔离派生。
func (ca *CA) DerivePlaceholderKey() ([]byte, error) {
	base, err := ca.DeriveStorageKey()
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	_, _ = h.Write(base)
	_, _ = h.Write([]byte("vibeguard.placeholder.v1"))
	sum := h.Sum(nil)
	out := make([]byte, 32)
	copy(out, sum)
	return out, nil
}

// GetCertificate returns the CA certificate as PEM bytes
func (ca *CA) GetCertificate() []byte {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.cert.Raw,
	})
}

// GetTLSCertificate returns a tls.Certificate for the CA
func (ca *CA) GetTLSCertificate() (tls.Certificate, error) {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.cert.Raw,
	})

	keyBytes, err := x509.MarshalECPrivateKey(ca.key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to marshal key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	return tls.X509KeyPair(certPEM, keyPEM)
}
