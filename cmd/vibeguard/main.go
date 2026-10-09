package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/inkdust2021/vibeguard/internal/cert"
	"github.com/inkdust2021/vibeguard/internal/config"
	"github.com/inkdust2021/vibeguard/internal/defaultrules"
	"github.com/inkdust2021/vibeguard/internal/log"
	"github.com/inkdust2021/vibeguard/internal/proxy"
	"github.com/inkdust2021/vibeguard/internal/redact"
	"github.com/inkdust2021/vibeguard/internal/rulelists"
	"github.com/inkdust2021/vibeguard/internal/session"
	"github.com/inkdust2021/vibeguard/internal/version"
)

var (
	cfgFile         string
	trustMode       string
	startForeground bool
	envShell        string
)

func uiLang() string {
	if v := strings.TrimSpace(os.Getenv("VIBEGUARD_LANG")); v != "" {
		if isLangZh(v) {
			return "zh"
		}
		if isLangEn(v) {
			return "en"
		}
		return "en"
	}

	loc := strings.TrimSpace(os.Getenv("LC_ALL"))
	if loc == "" {
		loc = strings.TrimSpace(os.Getenv("LANG"))
	}
	if isLangZh(loc) {
		return "zh"
	}
	return "en"
}

func isLangZh(v string) bool {
	v = strings.TrimSpace(v)
	switch v {
	case "中文", "cn":
		return true
	}
	vLower := strings.ToLower(v)
	return strings.HasPrefix(vLower, "zh") || strings.Contains(vLower, "zh")
}

func isLangEn(v string) bool {
	vLower := strings.ToLower(strings.TrimSpace(v))
	return strings.HasPrefix(vLower, "en") || strings.Contains(vLower, "en")
}

func uiText(lang, zh, en string) string {
	if lang == "zh" {
		return zh
	}
	return en
}

func uiIsYes(lang, s string) bool {
	s = strings.TrimSpace(s)
	sLower := strings.ToLower(s)
	if sLower == "y" || sLower == "yes" {
		return true
	}
	if lang == "zh" {
		switch s {
		case "是", "好", "确认", "继续", "覆盖":
			return true
		}
	}
	return false
}

func uiIsNo(lang, s string) bool {
	s = strings.TrimSpace(s)
	sLower := strings.ToLower(s)
	if sLower == "n" || sLower == "no" {
		return true
	}
	if lang == "zh" {
		switch s {
		case "否", "不", "不要", "跳过":
			return true
		}
	}
	return false
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "vibeguard",
	Short: "VibeGuard proxy helper (service + launchers)",
	Long: `VibeGuard is a MITM HTTPS proxy that protects your privacy when using
AI coding assistants like Claude Code, Cursor, or Copilot.

It intercepts HTTPS traffic, redacts sensitive data (IDs, names, etc.)
before sending to AI APIs, and restores the original data in responses.`,
	RunE: func(cmd *cobra.Command, args []string) error { return cmd.Help() },
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the proxy server (background by default)",
	RunE:  runStart,
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the proxy service/process",
	RunE:  runStop,
}

var envCmd = &cobra.Command{
	Use:    "env",
	Short:  "Print proxy env exports for your shell",
	Args:   cobra.NoArgs,
	RunE:   runEnv,
	Hidden: true,
}

var runCmd = &cobra.Command{
	Use:                "run <command> [args...]",
	Short:              "Run a command through VibeGuard proxy (process-only)",
	Args:               cobra.MinimumNArgs(1),
	DisableFlagParsing: true,
	RunE:               runWithProxy,
}

var claudeCmd = newAssistantProxyCmd("claude", "Claude Code")
var codexCmd = newAssistantProxyCmd("codex", "Codex")
var geminiCmd = newAssistantProxyCmd("gemini", "Gemini")
var opencodeCmd = newAssistantProxyCmd("opencode", "OpenCode")
var qwenCmd = newAssistantProxyCmd("qwen", "Qwen")

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Interactive first-time setup",
	Long:  `Run an interactive wizard to set up VibeGuard for the first time.`,
	RunE:  runInit,
}

var trustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Install CA certificate to system trust store",
	Long: `Install the VibeGuard CA certificate to your system's trust store.
This is required for the proxy to intercept HTTPS traffic.

On macOS/Linux this may require sudo. On Windows this requires Administrator.`,
	RunE: runTrust,
}

var testCmd = &cobra.Command{
	Use:   "test [pattern] [text]",
	Short: "Test a redaction pattern",
	Long: `Test a redaction pattern against sample text to see how it works.
Pattern is treated as a keyword (exact substring match).`,
	Args: cobra.ExactArgs(2),
	RunE: runTest,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("VibeGuard %s\n", version.Version)
		fmt.Printf("  Git commit: %s\n", version.GitCommit)
		fmt.Printf("  Build date: %s\n", version.BuildDate)
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is ~/.vibeguard/config.yaml)")

	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(stopCmd)
	rootCmd.AddCommand(envCmd)
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(claudeCmd)
	rootCmd.AddCommand(codexCmd)
	rootCmd.AddCommand(geminiCmd)
	rootCmd.AddCommand(opencodeCmd)
	rootCmd.AddCommand(qwenCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(trustCmd)
	rootCmd.AddCommand(testCmd)
	rootCmd.AddCommand(versionCmd)

	trustCmd.Flags().StringVar(&trustMode, "mode", string(cert.TrustInstallModeSystem), "trust store mode: system|user|auto")
	startCmd.Flags().BoolVar(&startForeground, "foreground", false, "run in foreground (for service/debugging)")
	envCmd.Flags().StringVar(&envShell, "shell", "sh", "shell type: sh|bash|zsh|fish|powershell")
}

func newAssistantProxyCmd(exeName, displayName string) *cobra.Command {
	return &cobra.Command{
		Use:                exeName + " [args...]",
		Short:              fmt.Sprintf("Run %s through VibeGuard proxy (process-only)", displayName),
		Args:               cobra.ArbitraryArgs,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			argv := append([]string{exeName}, args...)
			return runWithProxy(cmd, argv)
		},
	}
}

func runStart(cmd *cobra.Command, args []string) error {
	lang := uiLang()

	// If explicitly requested to run in foreground, or a non-default config path is provided, run in foreground.
	if startForeground || strings.TrimSpace(cfgFile) != "" {
		if !startForeground && strings.TrimSpace(cfgFile) != "" {
			fmt.Println(uiText(lang, "检测到 --config：将以前台模式启动（不会走后台服务）。", "Detected --config: starting in foreground (no background service)."))
		}
		return runProxy(cmd, args)
	}

	started, err := tryStartBackgroundService()
	if err != nil {
		fmt.Fprintf(os.Stderr, uiText(lang, "启动后台服务失败：%v\n", "Failed to start background service: %v\n"), err)
	}
	if started && err == nil {
		fmt.Println(uiText(lang, "已启动后台服务。", "Background service started."))
		waitForProxyUp(lang, 2*time.Second)
		return nil
	}

	// If the service is unavailable, fall back to a self-managed background start:
	// spawn a foreground child process and detach it from the terminal.
	if derr := startDetachedProxyProcess(); derr == nil {
		fmt.Println(uiText(lang, "已在后台启动代理进程。", "Proxy process started in background."))
		fmt.Println(uiText(lang, "提示：如需开机自启后台运行，请运行 install.sh 并启用 --autostart。",
			"Tip: to enable autostart background service, run install.sh and enable --autostart."))
		fmt.Println(uiText(lang, "如需在前台调试，请使用：vibeguard start --foreground", "For foreground debugging, use: vibeguard start --foreground"))
		waitForProxyUp(lang, 2*time.Second)
		return nil
	} else {
		fmt.Fprintf(os.Stderr, uiText(lang, "后台启动失败（将改为前台启动）：%v\n", "Background start failed (falling back to foreground): %v\n"), derr)
	}

	fmt.Println(uiText(lang, "将以前台模式启动（Ctrl+C 停止）。", "Starting in foreground (Ctrl+C to stop)."))
	fmt.Println(uiText(lang, "如需开机自启后台运行，请运行 install.sh 并启用 --autostart。",
		"To enable autostart background service, run install.sh and enable --autostart."))
	return runProxy(cmd, args)
}

func runStop(cmd *cobra.Command, args []string) error {
	lang := uiLang()

	stopped, err := tryStopBackgroundService()
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), uiText(lang, "停止后台服务失败：%v\n", "Failed to stop background service: %v\n"), err)
	}
	if stopped && err == nil {
		fmt.Fprintln(cmd.OutOrStdout(), uiText(lang, "已停止后台服务。", "Background service stopped."))
		return nil
	}

	// Fall back to PID-based stop (for cases where no system service is installed and we run detached in the background).
	pid, perr := readProxyPid()
	if perr != nil {
		return fmt.Errorf(uiText(lang, "未检测到后台服务，且读取 PID 失败：%v", "No background service detected and failed to read PID: %v"), perr)
	}
	if pid <= 0 {
		return errors.New(uiText(lang, "未检测到正在运行的代理进程（PID 无效）。", "No running proxy process detected (invalid PID)."))
	}

	if err := stopProcessByPID(pid); err != nil {
		return fmt.Errorf(uiText(lang, "停止代理进程失败：%v", "Failed to stop proxy process: %v"), err)
	}

	// Wait for the port to close (try to provide deterministic feedback).
	hostport, _ := proxyListenHostportForClient()
	if hostport != "" {
		waitForProxyDown(hostport, 2*time.Second)
	}

	_ = removeProxyPidIfMatches(pid)
	fmt.Fprintln(cmd.OutOrStdout(), uiText(lang, "已停止代理进程。", "Proxy process stopped."))
	return nil
}

func waitForProxyUp(lang string, timeout time.Duration) {
	hostport, err := proxyListenHostportForClient()
	if err != nil || strings.TrimSpace(hostport) == "" {
		return
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", hostport, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(150 * time.Millisecond)
	}

	fmt.Fprintln(os.Stderr, uiText(lang,
		"提示：代理可能尚未就绪或启动失败；可尝试访问 /manager/ 或查看日志文件。",
		"Tip: proxy may not be ready or failed to start; try /manager/ or check the log file.",
	))
}

func waitForProxyDown(hostport string, timeout time.Duration) {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", hostport, 200*time.Millisecond)
		if err != nil {
			return
		}
		_ = c.Close()
		time.Sleep(150 * time.Millisecond)
	}
}

func runEnv(cmd *cobra.Command, args []string) error {
	hostport, err := proxyListenHostportForClient()
	if err != nil || strings.TrimSpace(hostport) == "" {
		// Provide a usable default even when config is missing (helps "connect to the proxy first, then run init").
		hostport = "127.0.0.1:28657"
	}

	if err := ensureProxyRunning(hostport, cmd.ErrOrStderr()); err != nil {
		return err
	}

	proxyURL := "http://" + hostport
	noProxy := "127.0.0.1,localhost"

	shell := strings.ToLower(strings.TrimSpace(envShell))
	if shell == "" {
		shell = "sh"
	}

	out, err := formatProxyEnv(shell, proxyURL, noProxy)
	if err != nil {
		return err
	}

	// The env output must be safe to eval/Invoke-Expression: write to stdout only, no extra hints/messages.
	_, _ = io.WriteString(cmd.OutOrStdout(), out)

	return nil
}

func ensureProxyRunning(hostport string, stderr io.Writer) error {
	lang := uiLang()

	if isTCPListening(hostport) {
		return nil
	}

	started, err := tryStartBackgroundService()
	if err != nil {
		fmt.Fprintf(stderr, uiText(lang, "启动后台服务失败（将尝试直接后台启动）：%v\n", "Failed to start background service (will try direct background start): %v\n"), err)
	}
	if started && err == nil {
		waitForProxyUp(lang, 3*time.Second)
		if isTCPListening(hostport) {
			return nil
		}
	}

	if derr := startDetachedProxyProcess(); derr != nil {
		return fmt.Errorf(uiText(lang, "启动后台代理失败：%v", "Failed to start proxy in background: %v"), derr)
	}
	waitForProxyUp(lang, 3*time.Second)
	if isTCPListening(hostport) {
		return nil
	}
	return errors.New(uiText(lang, "代理未就绪：请运行 vibeguard start --foreground 查看错误日志。", "Proxy is not ready: run vibeguard start --foreground to see errors."))
}

func isTCPListening(hostport string) bool {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return false
	}

	c, err := net.DialTimeout("tcp", hostport, 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func formatProxyEnv(shell, proxyURL, noProxy string) (string, error) {
	switch shell {
	case "sh", "bash", "zsh":
		return fmt.Sprintf(
			"export HTTPS_PROXY=%q\nexport HTTP_PROXY=%q\nexport https_proxy=%q\nexport http_proxy=%q\nexport NO_PROXY=%q\nexport no_proxy=%q\n",
			proxyURL, proxyURL, proxyURL, proxyURL, noProxy, noProxy,
		), nil
	case "fish":
		return fmt.Sprintf(
			"set -gx HTTPS_PROXY %q;\nset -gx HTTP_PROXY %q;\nset -gx https_proxy %q;\nset -gx http_proxy %q;\nset -gx NO_PROXY %q;\nset -gx no_proxy %q;\n",
			proxyURL, proxyURL, proxyURL, proxyURL, noProxy, noProxy,
		), nil
	case "powershell", "pwsh", "ps":
		// PowerShell env vars are case-insensitive; set both cases to maximize compatibility.
		return fmt.Sprintf(
			"$env:HTTPS_PROXY=%q\n$env:HTTP_PROXY=%q\n$env:https_proxy=%q\n$env:http_proxy=%q\n$env:NO_PROXY=%q\n$env:no_proxy=%q\n",
			proxyURL, proxyURL, proxyURL, proxyURL, noProxy, noProxy,
		), nil
	default:
		return "", fmt.Errorf("unsupported shell: %s", shell)
	}
}

func runWithProxy(cmd *cobra.Command, args []string) error {
	lang := uiLang()

	if len(args) < 1 || strings.TrimSpace(args[0]) == "" {
		return errors.New(uiText(lang, "缺少要运行的命令。", "Missing command to run."))
	}

	hostport, err := proxyListenHostportForClient()
	if err != nil || strings.TrimSpace(hostport) == "" {
		hostport = "127.0.0.1:28657"
	}
	if err := ensureProxyRunning(hostport, cmd.ErrOrStderr()); err != nil {
		return err
	}

	proxyURL := "http://" + hostport
	// Do not inject NO_PROXY for child processes:
	// - This allows proxying localhost/127.0.0.1 traffic when needed (e.g. local AI gateways that should be redacted).
	// - If the parent environment already sets NO_PROXY, it is preserved (user-controlled bypass list).
	childEnv := withProxyEnv(os.Environ(), proxyURL)
	childEnv = withExtraCAEnv(childEnv, filepath.Join(config.GetConfigDir(), "ca.crt"))

	target := args[0]
	targetArgs := []string{}
	if len(args) > 1 {
		targetArgs = args[1:]
	}

	path, err := exec.LookPath(target)
	if err != nil {
		return fmt.Errorf(uiText(lang, "未找到命令：%s（请确认已安装并在 PATH 中）", "Command not found: %s (ensure it's installed and on PATH)"), target)
	}

	if runtime.GOOS != "windows" {
		// Use direct exec: better for interactive TUIs (signals/TTY behave more naturally).
		return syscall.Exec(path, append([]string{target}, targetArgs...), childEnv)
	}

	c := exec.Command(path, targetArgs...)
	c.Env = childEnv
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.ExitCode())
		}
		return err
	}
	return nil
}

func withExtraCAEnv(base []string, caCertPath string) []string {
	caCertPath = strings.TrimSpace(caCertPath)
	if caCertPath == "" {
		return base
	}
	if _, err := os.Stat(caCertPath); err != nil {
		return base
	}
	if envHasKey(base, "NODE_EXTRA_CA_CERTS") {
		return base
	}
	// Claude Code (Bun) reads NODE_EXTRA_CA_CERTS; Node.js also supports it.
	return append(base, "NODE_EXTRA_CA_CERTS="+caCertPath)
}

func withProxyEnv(base []string, proxyURL string) []string {
	// Simple override: for duplicate keys, the last one wins.
	out := make([]string, 0, len(base)+4)
	for _, kv := range base {
		k := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			k = kv[:i]
		}
		switch strings.ToUpper(k) {
		case "HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy":
			continue
		default:
			out = append(out, kv)
		}
	}
	out = append(out,
		"HTTPS_PROXY="+proxyURL,
		"HTTP_PROXY="+proxyURL,
		"https_proxy="+proxyURL,
		"http_proxy="+proxyURL,
	)
	return out
}

func envHasKey(env []string, key string) bool {
	key = strings.ToUpper(strings.TrimSpace(key))
	if key == "" {
		return false
	}
	for _, kv := range env {
		k := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			k = kv[:i]
		}
		if strings.ToUpper(k) == key {
			return true
		}
	}
	return false
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return (st.Mode() & os.ModeCharDevice) != 0
}

func proxyPidFilePath() string {
	return filepath.Join(config.GetConfigDir(), "vibeguard.pid")
}

func readProxyPid() (int, error) {
	b, err := os.ReadFile(proxyPidFilePath())
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return 0, errors.New("empty pid file")
	}
	pid, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	return pid, nil
}

func removeProxyPidIfMatches(pid int) error {
	b, err := os.ReadFile(proxyPidFilePath())
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(b)) != strconv.Itoa(pid) {
		return nil
	}
	return os.Remove(proxyPidFilePath())
}

func stopProcessByPID(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}

	if runtime.GOOS == "windows" {
		return p.Kill()
	}

	// Try to exit gracefully.
	if err := p.Signal(syscall.SIGTERM); err != nil {
		// The process may already have exited; treat as success.
		if !processAlive(pid) {
			return nil
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			return nil
		}
		time.Sleep(120 * time.Millisecond)
	}

	// Still running after timeout: force kill.
	if err := p.Kill(); err != nil {
		if !processAlive(pid) {
			return nil
		}
		return err
	}
	return nil
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		// On Windows, signal 0 is not reliable; conservatively return true and let callers decide via other signals (e.g. port checks).
		return true
	}
	return p.Signal(syscall.Signal(0)) == nil
}

func proxyListenHostportForClient() (string, error) {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return "", err
	}
	defer func() { _ = cfg.Close() }()

	listen := strings.TrimSpace(cfg.Get().Proxy.Listen)
	if listen == "" {
		listen = "127.0.0.1:28657"
	}
	if strings.HasPrefix(listen, ":") {
		return "127.0.0.1" + listen, nil
	}

	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen, nil
	}

	host = strings.TrimSpace(host)
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port, nil
	}
	return host + ":" + port, nil
}

func tryStartBackgroundService() (bool, error) {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return false, fmt.Errorf("cannot determine home directory: %w", err)
	}

	switch runtime.GOOS {
	case "darwin":
		plist := filepath.Join(home, "Library", "LaunchAgents", "com.vibeguard.proxy.plist")
		if _, err := os.Stat(plist); err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, err
		}
		if _, err := exec.LookPath("launchctl"); err != nil {
			return false, err
		}
		if err := startLaunchAgent(plist); err != nil {
			return false, err
		}
		return true, nil
	case "linux":
		unit := filepath.Join(home, ".config", "systemd", "user", "vibeguard.service")
		if _, err := os.Stat(unit); err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, err
		}
		if _, err := exec.LookPath("systemctl"); err != nil {
			return false, err
		}
		if err := startSystemdUserService(); err != nil {
			return false, err
		}
		return true, nil
	case "windows":
		// Windows autostart is created by the installer (Scheduled Task name is fixed to "VibeGuard").
		if _, err := exec.LookPath("schtasks"); err != nil {
			return false, nil
		}
		if !windowsScheduledTaskExists("VibeGuard") {
			return false, nil
		}
		if err := startWindowsScheduledTask("VibeGuard"); err != nil {
			return false, err
		}
		return true, nil
	default:
		return false, nil
	}
}

func tryStopBackgroundService() (bool, error) {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return false, fmt.Errorf("cannot determine home directory: %w", err)
	}

	switch runtime.GOOS {
	case "darwin":
		plist := filepath.Join(home, "Library", "LaunchAgents", "com.vibeguard.proxy.plist")
		if _, err := os.Stat(plist); err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, err
		}
		if _, err := exec.LookPath("launchctl"); err != nil {
			return false, err
		}
		if err := stopLaunchAgent(plist); err != nil {
			return false, err
		}
		return true, nil
	case "linux":
		unit := filepath.Join(home, ".config", "systemd", "user", "vibeguard.service")
		if _, err := os.Stat(unit); err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, err
		}
		if _, err := exec.LookPath("systemctl"); err != nil {
			return false, err
		}
		if err := stopSystemdUserService(); err != nil {
			return false, err
		}
		return true, nil
	case "windows":
		if _, err := exec.LookPath("schtasks"); err != nil {
			return false, nil
		}
		if !windowsScheduledTaskExists("VibeGuard") {
			return false, nil
		}
		if err := stopWindowsScheduledTask("VibeGuard"); err != nil {
			return false, err
		}
		return true, nil
	default:
		return false, nil
	}
}

func startLaunchAgent(plistPath string) error {
	uid := os.Getuid()
	domain := fmt.Sprintf("gui/%d", uid)
	svc := domain + "/com.vibeguard.proxy"

	// Keep it idempotent: try removing existing registrations before bootstrap/kickstart.
	_ = exec.Command("launchctl", "bootout", domain, plistPath).Run()
	if out, err := exec.Command("launchctl", "bootstrap", domain, plistPath).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl bootstrap failed: %w - %s", err, strings.TrimSpace(string(out)))
	}
	_ = exec.Command("launchctl", "enable", svc).Run()
	if out, err := exec.Command("launchctl", "kickstart", "-k", svc).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl kickstart failed: %w - %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func stopLaunchAgent(plistPath string) error {
	uid := os.Getuid()
	domain := fmt.Sprintf("gui/%d", uid)

	out, err := exec.Command("launchctl", "bootout", domain, plistPath).CombinedOutput()
	if err != nil {
		s := strings.ToLower(strings.TrimSpace(string(out)))
		// Keep it idempotent: bootout may error if not loaded; treat as already stopped.
		if strings.Contains(s, "no such process") || strings.Contains(s, "not loaded") || strings.Contains(s, "could not find") {
			return nil
		}
		return fmt.Errorf("launchctl bootout failed: %w - %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func startSystemdUserService() error {
	if out, err := exec.Command("systemctl", "--user", "start", "vibeguard.service").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl --user start vibeguard.service failed: %w - %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func stopSystemdUserService() error {
	if out, err := exec.Command("systemctl", "--user", "stop", "vibeguard.service").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl --user stop vibeguard.service failed: %w - %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func windowsScheduledTaskExists(taskName string) bool {
	taskName = strings.TrimSpace(taskName)
	if taskName == "" {
		return false
	}
	// schtasks /Query /TN <name>
	c := exec.Command("schtasks", "/Query", "/TN", taskName)
	if err := c.Run(); err != nil {
		return false
	}
	return true
}

func startWindowsScheduledTask(taskName string) error {
	out, err := exec.Command("schtasks", "/Run", "/TN", taskName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks /Run failed: %w - %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func stopWindowsScheduledTask(taskName string) error {
	out, err := exec.Command("schtasks", "/End", "/TN", taskName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks /End failed: %w - %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runProxy(cmd *cobra.Command, args []string) error {
	// Load config
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	defer func() { _ = cfg.Close() }()

	c := cfg.Get()

	// Pre-warm the local cache for the default rules subscription (so offline start works immediately);
	// later the subscription manager updates it.
	for _, rl := range c.Patterns.RuleLists {
		if strings.TrimSpace(rl.ID) != "vibeguard-default" {
			continue
		}
		if strings.TrimSpace(rl.URL) == "" {
			continue
		}
		if p, ok := rulelists.SubscriptionRulesPath(rl); ok && strings.TrimSpace(p) != "" {
			defaultrules.EnsureInstalled(p)
		}
		break
	}

	// Setup logging
	logWriter, err := log.SetupWithCleanup(c.Log.File, c.Log.Level, c.Cleanup)
	if err != nil {
		return fmt.Errorf("failed to setup logging: %w", err)
	}
	defer logWriter.Close()

	// Record PID so `vibeguard stop` can locate and stop the background process.
	pid := os.Getpid()
	if err := os.MkdirAll(config.GetConfigDir(), 0o755); err == nil {
		_ = os.WriteFile(proxyPidFilePath(), []byte(strconv.Itoa(pid)+"\n"), 0o644)
	}
	defer func() { _ = removeProxyPidIfMatches(pid) }()

	slog.Info("Starting VibeGuard", "version", version.Version)

	// Get config dir for CA cert
	configDir := config.GetConfigDir()
	caCertPath := filepath.Join(configDir, "ca.crt")
	caKeyPath := filepath.Join(configDir, "ca.key")

	// Load or generate CA
	ca, err := cert.LoadOrGenerateCA(caCertPath, caKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load/generate CA: %w", err)
	}
	if !cert.IsCATrusted(caCertPath) {
		slog.Warn("CA 证书未被系统信任：启用 MITM 拦截时客户端可能报 TLS 错误；请先运行 vibeguard trust（或 vibeguard trust --mode system）", "cert_path", caCertPath)
	}

	// Derive a local "at-rest encryption" key from the CA private key:
	// used to encrypt keywords/excludes in config so plaintext is not written to disk.
	if key, err := ca.DeriveStorageKey(); err != nil {
		return fmt.Errorf("failed to derive storage key: %w", err)
	} else if err := cfg.SetPatternEncryptionKey(key); err != nil {
		return fmt.Errorf("failed to configure pattern encryption: %w", err)
	}
	// Reload config once to decrypt persisted ciphertext into plaintext in memory,
	// and ensure future saves write ciphertext back to disk.
	if err := cfg.Load(); err != nil {
		return fmt.Errorf("failed to reload config with pattern decryption: %w", err)
	}

	// Create proxy server
	srv, err := proxy.NewServer(cfg, ca, caCertPath, caKeyPath)
	if err != nil {
		return fmt.Errorf("failed to create proxy: %w", err)
	}
	// Enable config hot-reload: changes from the admin UI take effect without restart.
	if err := cfg.Watch(func() {
		logWriter.UpdateCleanup(cfg.Get().Cleanup.Log)
		srv.ReloadFromConfig()
	}); err != nil {
		slog.Warn("Failed to enable config hot-reload; restart may be required after config changes", "error", err)
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Start()
	}()

	select {
	case err := <-errChan:
		return err
	case sig := <-sigChan:
		slog.Info("Received signal, shutting down", "signal", sig)
		srv.Stop()
	}

	return nil
}

func runInit(cmd *cobra.Command, args []string) error {
	lang := uiLang()
	reader := bufio.NewReader(os.Stdin)

	// Get config directory
	configDir := config.GetConfigDir()
	configPath := filepath.Join(configDir, "config.yaml")

	// Check if config already exists
	if _, err := os.Stat(configPath); err == nil {
		fmt.Printf(uiText(lang, "配置文件已存在：%s\n", "Config file already exists at %s\n"), configPath)
		fmt.Print(uiText(lang, "是否覆盖？(y/N): ", "Overwrite? (y/N): "))
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(answer)
		if !uiIsYes(lang, answer) {
			fmt.Println(uiText(lang, "已取消。", "Aborted."))
			return nil
		}
	}

	// Create config directory
	if err := os.MkdirAll(configDir, 0700); err != nil {
		if lang == "zh" {
			return fmt.Errorf("创建配置目录失败：%w", err)
		}
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	fmt.Println(uiText(lang, "VibeGuard 初始化向导", "VibeGuard Setup Wizard"))
	fmt.Println("======================")
	fmt.Println()

	// Prompt for listen address
	fmt.Print(uiText(lang, "监听地址 [127.0.0.1:28657]: ", "Listen address [127.0.0.1:28657]: "))
	listen, _ := reader.ReadString('\n')
	listen = strings.TrimSpace(listen)
	if listen == "" {
		listen = "127.0.0.1:28657"
	}

	// Prompt for session TTL
	fmt.Print(uiText(lang, "会话 TTL（占位符映射保留时长） [1h]: ", "Session TTL (how long to remember redacted values) [1h]: "))
	ttl, _ := reader.ReadString('\n')
	ttl = strings.TrimSpace(ttl)
	if ttl == "" {
		ttl = "1h"
	}

	// Prompt for log file
	fmt.Print(uiText(lang, "日志文件路径 [~/.vibeguard/vibeguard.log]: ", "Log file path [~/.vibeguard/vibeguard.log]: "))
	logFile, _ := reader.ReadString('\n')
	logFile = strings.TrimSpace(logFile)
	if logFile == "" {
		logFile = filepath.Join(configDir, "vibeguard.log")
	}

	// Prompt for CA generation
	fmt.Print(uiText(lang, "生成 CA 证书？(Y/n): ", "Generate CA certificate? (Y/n): "))
	genCAAnswer, _ := reader.ReadString('\n')
	genCAAnswer = strings.TrimSpace(genCAAnswer)
	genCA := !uiIsNo(lang, genCAAnswer) // default: yes

	cfgTemplateZh := `# VibeGuard Configuration
	proxy:
	  listen: %s
	  placeholder_prefix: "__VG_"
	  # HTTPS intercept mode: global (default, intercept all) or targets (only intercept targets below)
	  intercept_mode: global

session:
  ttl: %s
  max_mappings: 100000

log:
  file: %s
  level: info

cleanup:
  log:
    enabled: true
    interval: 24h
    max_size_mb: 10
    max_backups: 3
  session_wal:
    enabled: true
    interval: 1h

	# Target hosts to intercept (AI API endpoints)
	targets:
  - host: api.anthropic.com
    enabled: true
  - host: api.openai.com
    enabled: true
  - host: api2.cursor.sh
    enabled: true
  - host: generativelanguage.googleapis.com
    enabled: true

	# Sensitive data matching rules
	patterns:
	  keywords: []
	  exclude: []
	  # Optional: import secrets from local files (e.g. .env) and redact them automatically.
	  # secret_files:
	  #   - path: .env
	  #     format: dotenv
	  #     enabled: true
	`

	cfgTemplateEn := `# VibeGuard Configuration
proxy:
  listen: %s
  placeholder_prefix: "__VG_"
  # HTTPS intercept mode: global (default, intercept all) or targets (only intercept targets below)
  intercept_mode: global

session:
  ttl: %s
  max_mappings: 100000

log:
  file: %s
  level: info

cleanup:
  log:
    enabled: true
    interval: 24h
    max_size_mb: 10
    max_backups: 3
  session_wal:
    enabled: true
    interval: 1h

# Target hosts to intercept (AI API endpoints)
targets:
  - host: api.anthropic.com
    enabled: true
  - host: api.openai.com
    enabled: true
  - host: api2.cursor.sh
    enabled: true
  - host: generativelanguage.googleapis.com
    enabled: true

# Sensitive data patterns
patterns:
  keywords: []
  exclude: []
  # Optional: import secrets from local files (e.g. .env) and redact them automatically.
  # secret_files:
  #   - path: .env
  #     format: dotenv
  #     enabled: true
`

	// Write config
	var cfgContent string
	if lang == "zh" {
		cfgContent = fmt.Sprintf(cfgTemplateZh, listen, ttl, logFile)
	} else {
		cfgContent = fmt.Sprintf(cfgTemplateEn, listen, ttl, logFile)
	}

	if err := os.WriteFile(configPath, []byte(cfgContent), 0600); err != nil {
		if lang == "zh" {
			return fmt.Errorf("写入配置失败：%w", err)
		}
		return fmt.Errorf("failed to write config: %w", err)
	}

	fmt.Printf(uiText(lang, "\n配置已写入 %s\n", "\nConfig written to %s\n"), configPath)

	// Generate CA if requested
	if genCA {
		caCertPath := filepath.Join(configDir, "ca.crt")
		caKeyPath := filepath.Join(configDir, "ca.key")

		_, err := cert.LoadOrGenerateCA(caCertPath, caKeyPath)
		if err != nil {
			if lang == "zh" {
				return fmt.Errorf("生成 CA 证书失败：%w", err)
			}
			return fmt.Errorf("failed to generate CA: %w", err)
		}

		fmt.Printf(uiText(lang, "CA 证书已生成：%s\n", "CA certificate generated at %s\n"), caCertPath)

		// Ask about trusting (default: system, since many CLI tools won't trust user-only stores)
		fmt.Println(uiText(lang, "\n是否将 CA 证书安装到信任库？", "\nInstall CA certificate to trust store?"))
		fmt.Println(uiText(lang, "  1) 系统信任库（需要 sudo，推荐）", "  1) System trust store (sudo, recommended)"))
		fmt.Println(uiText(lang, "  2) 用户信任库（无需 sudo）", "  2) User trust store (no sudo)"))
		fmt.Println(uiText(lang, "  3) 跳过", "  3) Skip"))
		fmt.Print(uiText(lang, "选择 [1]: ", "Choose [1]: "))
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		var mode cert.TrustInstallMode
		switch choice {
		case "", "1":
			mode = cert.TrustInstallModeSystem
		case "2":
			mode = cert.TrustInstallModeUser
		case "3":
			mode = ""
		default:
			fmt.Println(uiText(lang, "无效选项，已跳过。", "Invalid choice, skipping."))
			mode = ""
		}

		if mode != "" {
			if err := cert.InstallCAToTrustStore(caCertPath, mode); err != nil {
				fmt.Printf(uiText(lang, "安装 CA 失败：%v\n", "Failed to install CA: %v\n"), err)
				fmt.Println(uiText(lang, "你可能需要运行：vibeguard trust --mode system", "You may need to run: vibeguard trust --mode system"))
			} else {
				fmt.Printf(uiText(lang, "CA 证书已安装（%s）！\n", "CA certificate installed (%s)!\n"), mode)
			}
		}
	}

	fmt.Println(uiText(lang, "\n初始化完成！运行 'vibeguard start' 开始使用。", "\nSetup complete! Run 'vibeguard start' to begin."))
	return nil
}

func runTrust(cmd *cobra.Command, args []string) error {
	lang := uiLang()
	configDir := config.GetConfigDir()
	caCertPath := filepath.Join(configDir, "ca.crt")

	// Check if CA cert exists
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		if lang == "zh" {
			return fmt.Errorf("未找到 CA 证书：%s。请先运行 'vibeguard init'", caCertPath)
		}
		return fmt.Errorf("CA certificate not found at %s. Run 'vibeguard init' first", caCertPath)
	}

	fmt.Printf(uiText(lang, "正在安装 CA 证书（来源：%s）\n", "Installing CA certificate from %s\n"), caCertPath)
	fmt.Println(uiText(lang, "可能会提示输入管理员权限...", "This may prompt for administrator privileges..."))

	mode := cert.TrustInstallMode(strings.ToLower(strings.TrimSpace(trustMode)))
	switch mode {
	case cert.TrustInstallModeAuto, cert.TrustInstallModeUser, cert.TrustInstallModeSystem:
	default:
		if lang == "zh" {
			return fmt.Errorf("无效的 --mode %q（可选：system|user|auto）", trustMode)
		}
		return fmt.Errorf("invalid --mode %q (expected: system|user|auto)", trustMode)
	}

	if err := cert.InstallCAToTrustStore(caCertPath, mode); err != nil {
		if lang == "zh" {
			return fmt.Errorf("安装 CA 失败：%w", err)
		}
		return fmt.Errorf("failed to install CA: %w", err)
	}

	fmt.Println(uiText(lang, "CA 证书安装成功！", "CA certificate installed successfully!"))
	return nil
}

func runTest(cmd *cobra.Command, args []string) error {
	pattern := args[0]
	text := args[1]

	// Create a minimal session manager
	sess := session.NewManager(0, 1000)
	eng := redact.NewEngine(sess, "__VG_")

	// Keywords only: replace the keyword substring itself to avoid overly-broad regex-style matches.
	eng.AddKeyword(pattern, "TEST")

	// Perform redaction
	redacted, count := eng.Redact([]byte(text))

	fmt.Printf("Original: %s\n", text)
	fmt.Printf("Redacted: %s\n", string(redacted))
	fmt.Printf("Matches:  %d\n", count)

	if count > 0 {
		fmt.Println("\nPlaceholders registered:")
		// Note: We can't easily iterate the session, so just note that they exist
		fmt.Printf("  %d mapping(s) stored\n", sess.Size())
	}

	return nil
}
