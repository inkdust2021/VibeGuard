package admin

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"time"

	"github.com/inkdust2021/vibeguard/internal/cert"
)

// CertResponse represents the certificate API response
type CertResponse struct {
	CA struct {
		Subject           string `json:"subject"`
		NotBefore         string `json:"not_before"`
		NotAfter          string `json:"not_after"`
		FingerprintSHA256 string `json:"fingerprint_sha256"`
		IsTrusted         bool   `json:"is_trusted"`
		// TrustStatus 表示“当前运行环境”对 CA 的信任检测结果：
		// - trusted: 已检测到受信任
		// - untrusted: 未检测到受信任
		// - unknown: 无法检测（例如容器内运行，无法判断宿主机/浏览器是否已信任）
		TrustStatus string `json:"trust_status"`
		CertPath    string `json:"cert_path"`
	} `json:"ca"`
}

// handleCertificates handles GET /_admin/api/certificates
func (a *Admin) handleCertificates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp := CertResponse{}
	resp.CA.CertPath = a.certPath

	// Get cert info from CA
	if a.ca != nil {
		caCertPEM := a.ca.GetCertificate()
		if len(caCertPEM) > 0 {
			if block, _ := pem.Decode(caCertPEM); block != nil && block.Type == "CERTIFICATE" {
				if caCert, err := x509.ParseCertificate(block.Bytes); err == nil {
					resp.CA.Subject = caCert.Subject.String()
					resp.CA.NotBefore = caCert.NotBefore.Format(time.RFC3339)
					resp.CA.NotAfter = caCert.NotAfter.Format(time.RFC3339)
					resp.CA.FingerprintSHA256 = cert.FingerprintSHA256FromCertificate(caCert)
				}
			}
		}
	}
	if resp.CA.Subject == "" {
		resp.CA.Subject = "VibeGuard CA"
	}

	// Check if trusted by system
	resp.CA.IsTrusted = cert.IsCATrusted(a.certPath)
	if resp.CA.IsTrusted {
		resp.CA.TrustStatus = "trusted"
	} else if isLikelyContainerRuntime() {
		// 容器内运行时，“系统信任库”与宿主机/浏览器并不一致，后端无法可靠判断客户端是否已信任导出的 ca.crt。
		resp.CA.TrustStatus = "unknown"
	} else {
		resp.CA.TrustStatus = "untrusted"
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(resp)
}

// handleCertTrust handles POST /_admin/api/certificates/trust
func (a *Admin) handleCertTrust(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 管理界面运行在服务端进程中，不适合触发 sudo 交互；这里只做用户级信任库安装。
	if err := cert.InstallCAToTrustStore(a.certPath, cert.TrustInstallModeUser); err != nil {
		http.Error(w, "安装到用户信任库失败。若需要安装到系统信任库（sudo），请在终端运行：vibeguard trust --mode system\n\n"+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "trusted_user",
	})
}

// handleCertRegenerate handles POST /_admin/api/certificates/regenerate
func (a *Admin) handleCertRegenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Generate new CA
	newCA, err := cert.LoadOrGenerateCA(a.certPath, a.keyPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Update reference
	a.ca = newCA

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "regenerated",
		"message": "CA certificate regenerated. You may need to re-trust it.",
	})
}
