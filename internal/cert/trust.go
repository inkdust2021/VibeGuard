package cert

import (
	"bufio"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type TrustInstallMode string

const (
	TrustInstallModeAuto   TrustInstallMode = "auto"
	TrustInstallModeUser   TrustInstallMode = "user"
	TrustInstallModeSystem TrustInstallMode = "system"
)

// IsCATrusted checks if the CA certificate is trusted by the system
func IsCATrusted(certPath string) bool {
	// 优先使用系统证书池做验证：更准确且不依赖外部命令输出格式。
	// 这也能覆盖证书名称变更等情况。
	if isTrustedBySystemCertPool(certPath) {
		return true
	}

	switch runtime.GOOS {
	case "darwin":
		return isTrustedDarwin(certPath)
	case "linux":
		return isTrustedLinux(certPath)
	case "windows":
		return isTrustedWindows(certPath)
	default:
		return false
	}
}

// isTrustedDarwin checks if certificate is trusted on macOS
func isTrustedDarwin(certPath string) bool {
	caCert, err := loadPEMCertificateFromFile(certPath)
	if err != nil {
		return false
	}
	want := FingerprintSHA256FromCertificate(caCert)

	var keychains []string
	if home, ok := os.LookupEnv("HOME"); ok && home != "" {
		// 兼容旧版 keychain 文件名
		loginCandidates := []string{
			filepath.Join(home, "Library", "Keychains", "login.keychain-db"),
			filepath.Join(home, "Library", "Keychains", "login.keychain"),
		}
		for _, kc := range loginCandidates {
			if _, err := os.Stat(kc); err == nil {
				keychains = append(keychains, kc)
			}
		}
	}
	// 系统级安装通常会落在 System.keychain
	keychains = append(keychains, "/Library/Keychains/System.keychain")

	// 先按当前证书 CN 搜索，找不到再降级用更宽泛名称。
	names := []string{}
	if caCert.Subject.CommonName != "" {
		names = append(names, caCert.Subject.CommonName)
	}
	if len(caCert.Subject.Organization) > 0 && caCert.Subject.Organization[0] != "" {
		names = append(names, caCert.Subject.Organization[0])
	}
	names = append(names, "VibeGuard CA", "VibeGuard")

	for _, kc := range keychains {
		for _, name := range names {
			out, _ := exec.Command("security", "find-certificate", "-a", "-Z", "-c", name, kc).CombinedOutput()
			if securityFindCertificateHasSHA256(out, want) {
				return true
			}
		}
	}
	return false
}

// isTrustedLinux checks if certificate is trusted on Linux
func isTrustedLinux(certPath string) bool {
	// Check common locations for the installed cert
	locations := []string{
		"/usr/local/share/ca-certificates/vibeguard-ca.crt",
		"/etc/ssl/certs/vibeguard-ca.pem",
		"/etc/pki/ca-trust/source/anchors/vibeguard-ca.crt",
	}
	for _, loc := range locations {
		if _, err := os.Stat(loc); err == nil {
			return true
		}
	}
	return false
}

// isTrustedWindows checks if certificate is trusted on Windows
func isTrustedWindows(certPath string) bool {
	cmd := exec.Command("certutil", "-verifyStore", "Root")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	// Check if our cert is in the store (simplified check)
	return strings.Contains(string(output), "VibeGuard")
}

func loadPEMCertificateFromFile(certPath string) (*x509.Certificate, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// FingerprintSHA256FromCertificate 返回证书原始 DER 的 SHA-256 指纹（大写十六进制，无分隔符）。
func FingerprintSHA256FromCertificate(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func isTrustedBySystemCertPool(certPath string) bool {
	cert, err := loadPEMCertificateFromFile(certPath)
	if err != nil {
		return false
	}

	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		return false
	}

	// 直接验证 CA 证书本身是否能在系统根证书池中建立可信链。
	// 使用 ExtKeyUsageAny 避免因 EKU/用途差异导致的误判。
	opts := x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	_, err = cert.Verify(opts)
	return err == nil
}

func securityFindCertificateHasSHA256(output []byte, want string) bool {
	if len(output) == 0 || want == "" {
		return false
	}
	want = strings.ToUpper(strings.ReplaceAll(want, " ", ""))

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "SHA-256 hash:") {
			continue
		}
		got := strings.TrimSpace(strings.TrimPrefix(line, "SHA-256 hash:"))
		got = strings.ToUpper(strings.ReplaceAll(got, " ", ""))
		if got == want {
			return true
		}
	}
	return false
}

// InstallCAToSystemTrustStore installs the CA certificate into the system trust store
func InstallCAToSystemTrustStore(certPath string) error {
	return InstallCAToTrustStore(certPath, TrustInstallModeAuto)
}

// InstallCAToTrustStore installs the CA certificate into user/system trust store based on mode.
// mode:
// - auto: macOS 优先用户信任库，失败后再尝试系统信任库；Windows 先 user 再 system；Linux 等同 system
// - user: 仅安装到当前用户信任库（macOS/Windows）
// - system: 仅安装到系统信任库（macOS/Linux/Windows，通常需要管理员权限）
func InstallCAToTrustStore(certPath string, mode TrustInstallMode) error {
	if mode == "" {
		mode = TrustInstallModeAuto
	}

	switch runtime.GOOS {
	case "darwin":
		return trustDarwin(certPath, mode)
	case "linux":
		return trustLinux(certPath, mode)
	case "windows":
		return trustWindows(certPath, mode)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

func stdinIsTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// trustDarwin installs the CA certificate on macOS
func trustDarwin(certPath string, mode TrustInstallMode) error {
	switch mode {
	case TrustInstallModeUser:
		return trustDarwinUser(certPath)
	case TrustInstallModeSystem:
		return trustDarwinSystem(certPath)
	case TrustInstallModeAuto:
		if err := trustDarwinUser(certPath); err == nil {
			return nil
		}
		return trustDarwinSystem(certPath)
	default:
		return fmt.Errorf("invalid trust mode: %s", mode)
	}
}

func trustDarwinUser(certPath string) error {
	slog.Info("Installing CA certificate to macOS user trust store (Login Keychain)...")

	args := []string{"add-trusted-cert", "-r", "trustRoot"}
	if home, ok := os.LookupEnv("HOME"); ok && home != "" {
		loginKC := filepath.Join(home, "Library", "Keychains", "login.keychain-db")
		if _, err := os.Stat(loginKC); err == nil {
			args = append(args, "-k", loginKC)
		}
	}
	args = append(args, certPath)

	cmd := exec.Command("security", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install CA certificate to user trust store: %w - %s", err, string(output))
	}

	slog.Info("CA certificate installed to user trust store successfully")
	return nil
}

func trustDarwinSystem(certPath string) error {
	if !stdinIsTTY() {
		return fmt.Errorf("system trust store install requires an interactive terminal. Please run manually:\n  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s", certPath)
	}

	slog.Info("Installing CA certificate to macOS system trust store (System.keychain)...")
	cmd := exec.Command("sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot",
		"-k", "/Library/Keychains/System.keychain", certPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install CA certificate to system trust store. Please run manually:\n  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s\nError: %w - %s", certPath, err, string(output))
	}

	slog.Info("CA certificate installed to system trust store successfully")
	return nil
}

// trustLinux installs the CA certificate on Linux
func trustLinux(certPath string, mode TrustInstallMode) error {
	switch mode {
	case TrustInstallModeSystem, TrustInstallModeAuto:
		// continue
	case TrustInstallModeUser:
		return fmt.Errorf("linux user trust store is not standardized; please use --mode system")
	default:
		return fmt.Errorf("invalid trust mode: %s", mode)
	}

	// Common paths for CA certificates
	destDir := "/usr/local/share/ca-certificates"
	destPath := destDir + "/vibeguard-ca.crt"

	// Check if destination directory exists
	if _, err := os.Stat(destDir); os.IsNotExist(err) {
		// Try alternative locations
		altDirs := []string{
			"/etc/ssl/certs",
			"/etc/pki/ca-trust/source/anchors",
		}
		for _, dir := range altDirs {
			if _, err := os.Stat(dir); err == nil {
				destDir = dir
				destPath = dir + "/vibeguard-ca.crt"
				break
			}
		}
	}

	// Copy certificate
	cmd := exec.Command("cp", certPath, destPath)
	if err := cmd.Run(); err != nil {
		// Try with sudo
		cmd = exec.Command("sudo", "cp", certPath, destPath)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to copy certificate: %w", err)
		}
	}

	// Update CA certificates
	var updateCmd string
	var updateArgs []string
	if _, err := os.Stat("/usr/sbin/update-ca-certificates"); err == nil {
		updateCmd = "/usr/sbin/update-ca-certificates"
		updateArgs = []string{}
	} else if _, err := os.Stat("/usr/bin/update-ca-certificates"); err == nil {
		updateCmd = "/usr/bin/update-ca-certificates"
		updateArgs = []string{}
	} else if _, err := os.Stat("/usr/bin/update-ca-trust"); err == nil {
		updateCmd = "/usr/bin/update-ca-trust"
		updateArgs = []string{"extract"}
	} else {
		return fmt.Errorf("cannot find update-ca-certificates or update-ca-trust command")
	}

	slog.Info("Updating CA certificates...", "command", updateCmd)
	cmd = exec.Command(updateCmd, updateArgs...)
	if err := cmd.Run(); err != nil {
		// Try with sudo
		args := append([]string{updateCmd}, updateArgs...)
		cmd = exec.Command("sudo", args...)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to update CA certificates: %w", err)
		}
	}

	slog.Info("CA certificate installed successfully")
	return nil
}

// trustWindows installs the CA certificate on Windows
func trustWindows(certPath string, mode TrustInstallMode) error {
	switch mode {
	case TrustInstallModeUser:
		return trustWindowsUser(certPath)
	case TrustInstallModeSystem:
		return trustWindowsSystem(certPath)
	case TrustInstallModeAuto:
		if err := trustWindowsUser(certPath); err == nil {
			return nil
		}
		return trustWindowsSystem(certPath)
	default:
		return fmt.Errorf("invalid trust mode: %s", mode)
	}
}

func trustWindowsUser(certPath string) error {
	slog.Info("Installing CA certificate to Windows CurrentUser Root store...")
	cmd := exec.Command("certutil", "-addstore", "-f", "-user", "Root", certPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install CA certificate to CurrentUser store: %w", err)
	}
	slog.Info("CA certificate installed to CurrentUser store successfully")
	return nil
}

func trustWindowsSystem(certPath string) error {
	slog.Info("Installing CA certificate to Windows LocalMachine Root store...")
	cmd := exec.Command("certutil", "-addstore", "-f", "Root", certPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install CA certificate to LocalMachine store: %w", err)
	}
	slog.Info("CA certificate installed to LocalMachine store successfully")
	return nil
}
