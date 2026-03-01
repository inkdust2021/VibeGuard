package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

// Config represents the main configuration structure
type Config struct {
	Proxy    ProxyConfig    `yaml:"proxy"`
	Patterns PatternsConfig `yaml:"patterns"`
	Targets  []TargetConfig `yaml:"targets"`
	Session  SessionConfig  `yaml:"session"`
	Log      LogConfig      `yaml:"log"`
}

// ProxyConfig holds proxy server settings
type ProxyConfig struct {
	Listen            string `yaml:"listen"`
	PlaceholderPrefix string `yaml:"placeholder_prefix"`
	// InterceptMode 控制 HTTPS CONNECT 的处理方式：
	// - global：对所有域名启用 MITM（默认，更适合通过环境变量 HTTP(S)_PROXY 使用）
	// - targets：仅对 targets 中启用的 host 启用 MITM（更安全，避免影响非目标流量）
	InterceptMode string `yaml:"intercept_mode"`
}

// PatternsConfig holds pattern matching configuration
type PatternsConfig struct {
	Keywords []KeywordPattern `yaml:"keywords"`
	Regex    []RegexPattern   `yaml:"regex"`
	Builtin  []string         `yaml:"builtin"`
	Exclude  []string         `yaml:"exclude"`
}

// KeywordPattern represents a keyword to match
type KeywordPattern struct {
	Value    string `yaml:"value" json:"value"`
	Category string `yaml:"category" json:"category"`
}

// RegexPattern represents a regex pattern to match
type RegexPattern struct {
	Pattern  string `yaml:"pattern" json:"pattern"`
	Category string `yaml:"category" json:"category"`
}

// TargetConfig represents a target host configuration
type TargetConfig struct {
	Host    string `yaml:"host"`
	Enabled bool   `yaml:"enabled"`
}

// SessionConfig holds session management settings
type SessionConfig struct {
	TTL                      string `yaml:"ttl"`
	MaxMappings              int    `yaml:"max_mappings"`
	WALEnabled               bool   `yaml:"wal_enabled"`
	WALPath                  string `yaml:"wal_path"`
	DeterministicPlaceholders bool   `yaml:"deterministic_placeholders"`
}

// LogConfig holds logging configuration
type LogConfig struct {
	Level     string `yaml:"level"`
	File      string `yaml:"file"`
	RedactLog bool   `yaml:"redact_log"`
}

// Default configuration values
var defaultConfig = Config{
	Proxy: ProxyConfig{
		Listen:            "127.0.0.1:28657",
		PlaceholderPrefix: "__VG_",
		InterceptMode:     "global",
	},
	Patterns: PatternsConfig{
		Keywords: []KeywordPattern{},
		Regex:    []RegexPattern{},
		Builtin:  []string{},
		Exclude:  []string{},
	},
	Targets: []TargetConfig{
		{Host: "api.anthropic.com", Enabled: true},
		{Host: "api.openai.com", Enabled: true},
		{Host: "api2.cursor.sh", Enabled: true},
		{Host: "generativelanguage.googleapis.com", Enabled: true},
	},
	Session: SessionConfig{
		TTL:         "1h",
		MaxMappings: 100000,
		WALEnabled:  true,
		WALPath:     "~/.vibeguard/session.wal",
		DeterministicPlaceholders: false,
	},
	Log: LogConfig{
		Level:     "info",
		File:      "~/.vibeguard/vibeguard.log",
		RedactLog: true,
	},
}

// ConfigPath returns the expanded config file path
func ConfigPath() string {
	if cfgPath := os.Getenv("VIBEGUARD_CONFIG"); cfgPath != "" {
		return expandPath(cfgPath)
	}
	return filepath.Join(homeDir(), ".vibeguard", "config.yaml")
}

// ProjectConfigPath returns the project-level config path
func ProjectConfigPath() string {
	return ".vibeguard.yaml"
}

// homeDir returns the user's home directory
func homeDir() string {
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	return os.Getenv("USERPROFILE") // Windows
}

// GetConfigDir returns the config directory path
func GetConfigDir() string {
	return filepath.Join(homeDir(), ".vibeguard")
}

// Load loads configuration from the given file path
func Load(cfgFile string) (*Manager, error) {
	m := NewManager()

	// Determine config path
	var configPath string
	if cfgFile != "" {
		configPath = expandPath(cfgFile)
	} else {
		configPath = ConfigPath()
	}
	if abs, err := filepath.Abs(configPath); err == nil {
		configPath = abs
	}
	m.configPath = configPath

	projectPath := ProjectConfigPath()
	if abs, err := filepath.Abs(projectPath); err == nil {
		projectPath = abs
	}
	m.projectPath = projectPath
	if err := m.Load(); err != nil {
		return nil, err
	}
	return m, nil
}

// expandPath expands ~ in path
func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(homeDir(), path[2:])
	}
	if strings.HasPrefix(path, "~"+string(os.PathSeparator)) {
		return filepath.Join(homeDir(), path[2:])
	}
	return path
}

// DataDir returns the data directory path
func DataDir() string {
	return filepath.Join(homeDir(), ".vibeguard")
}

// Manager handles config loading, merging, and hot-reload
type Manager struct {
	mu      sync.RWMutex
	config  Config
	watcher *fsnotify.Watcher
	// configPath 为全局配置文件路径（用于读写与监听）。当通过 CLI --config 指定时，应写入该路径。
	configPath string
	// projectPath 为项目级覆盖配置路径（默认 .vibeguard.yaml）。
	projectPath string
	// patternCrypto 用于将 patterns.keywords/exclude 的 value 以加密形式落盘（进程内仍为明文）。
	// 该能力需要由上层注入密钥（通常从 CA 私钥派生）。
	patternCrypto *patternCrypto
}

// NewManager creates a new config manager
func NewManager() *Manager {
	globalPath := ConfigPath()
	if abs, err := filepath.Abs(globalPath); err == nil {
		globalPath = abs
	}
	projectPath := ProjectConfigPath()
	if abs, err := filepath.Abs(projectPath); err == nil {
		projectPath = abs
	}
	return &Manager{
		config:      defaultConfig,
		configPath:  globalPath,
		projectPath: projectPath,
	}
}

// Load loads configuration from file
func (m *Manager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Start with default config
	cfg := defaultConfig

	// Load global config if exists
	globalPath := m.configPath
	if globalPath == "" {
		globalPath = ConfigPath()
	}
	if data, err := os.ReadFile(globalPath); err == nil {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return err
		}
		slog.Debug("Loaded config", "path", globalPath)
	} else if !os.IsNotExist(err) {
		return err
	}

	// Load project config if exists (merges with global)
	projectPath := m.projectPath
	if projectPath == "" {
		projectPath = ProjectConfigPath()
	}
	if data, err := os.ReadFile(projectPath); err == nil {
		var projectCfg Config
		if err := yaml.Unmarshal(data, &projectCfg); err != nil {
			return err
		}
		// Merge configs
		cfg = mergeConfigs(cfg, projectCfg)
		slog.Debug("Merged project config", "path", projectPath)
	} else if !os.IsNotExist(err) {
		return err
	}

	// 若启用了“匹配值落盘加密”，先把加载到的密文解密为明文，再做 sanitize。
	if err := m.decryptLoadedPatterns(&cfg); err != nil {
		return err
	}

	// 规范化配置：清理不可见字符、修正分类名等，避免“规则看起来已配置但实际不生效”。
	sanitizeLoadedConfig(&cfg)

	m.config = cfg
	return nil
}

func sanitizeLoadedConfig(cfg *Config) {
	if cfg == nil {
		return
	}

	// Proxy
	cfg.Proxy.Listen = strings.TrimSpace(cfg.Proxy.Listen)
	cfg.Proxy.PlaceholderPrefix = strings.TrimSpace(cfg.Proxy.PlaceholderPrefix)
	cfg.Proxy.InterceptMode = strings.TrimSpace(cfg.Proxy.InterceptMode)

	// Patterns: keywords
	if len(cfg.Patterns.Keywords) > 0 {
		out := make([]KeywordPattern, 0, len(cfg.Patterns.Keywords))
		for _, kw := range cfg.Patterns.Keywords {
			val := SanitizePatternValue(kw.Value)
			if val == "" {
				continue
			}
			cat := SanitizeCategory(kw.Category)
			if cat == "" {
				cat = "TEXT"
			}
			out = append(out, KeywordPattern{Value: val, Category: cat})
		}
		cfg.Patterns.Keywords = out
	}

	// Patterns: exclude
	if len(cfg.Patterns.Exclude) > 0 {
		out := make([]string, 0, len(cfg.Patterns.Exclude))
		for _, ex := range cfg.Patterns.Exclude {
			val := SanitizePatternValue(ex)
			if val == "" {
				continue
			}
			out = append(out, val)
		}
		cfg.Patterns.Exclude = out
	}

	// Patterns: regex/builtin 目前不在管理页编辑，但仍做基础清理，避免分类名导致占位符无法还原。
	if len(cfg.Patterns.Regex) > 0 {
		out := make([]RegexPattern, 0, len(cfg.Patterns.Regex))
		for _, rp := range cfg.Patterns.Regex {
			pat := strings.TrimSpace(rp.Pattern)
			if pat == "" {
				continue
			}
			cat := SanitizeCategory(rp.Category)
			if cat == "" {
				cat = "REGEX"
			}
			out = append(out, RegexPattern{Pattern: pat, Category: cat})
		}
		cfg.Patterns.Regex = out
	}

	if len(cfg.Patterns.Builtin) > 0 {
		out := make([]string, 0, len(cfg.Patterns.Builtin))
		for _, b := range cfg.Patterns.Builtin {
			v := strings.TrimSpace(b)
			if v == "" {
				continue
			}
			out = append(out, v)
		}
		cfg.Patterns.Builtin = out
	}

	// Targets
	if len(cfg.Targets) > 0 {
		out := make([]TargetConfig, 0, len(cfg.Targets))
		for _, t := range cfg.Targets {
			h := strings.TrimSpace(t.Host)
			if h == "" {
				continue
			}
			out = append(out, TargetConfig{Host: h, Enabled: t.Enabled})
		}
		cfg.Targets = out
	}
}

// Get returns the current configuration
func (m *Manager) Get() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

// Update applies a mutation function to the config and saves to disk
func (m *Manager) Update(fn func(*Config)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	fn(&m.config)
	return m.saveLocked()
}

// saveLocked writes the current config to disk (must be called with mu held)
func (m *Manager) saveLocked() error {
	toSave, err := m.encryptPatternsForSave(m.config)
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(&toSave)
	if err != nil {
		return err
	}
	cfgPath := m.configPath
	if cfgPath == "" {
		cfgPath = ConfigPath()
	}
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(cfgPath, data, 0600); err != nil {
		return err
	}
	// 保底：若文件已存在，WriteFile 不一定会覆盖权限；这里再 chmod 一次。
	_ = os.Chmod(cfgPath, 0600)
	return nil
}

// Watch starts watching for config file changes
func (m *Manager) Watch(onChange func()) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.watcher != nil {
		return nil // Already watching
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	m.watcher = watcher

	// Watch global config directory
	cfgPath := m.configPath
	if cfgPath == "" {
		cfgPath = ConfigPath()
	}
	cfgPath = filepath.Clean(cfgPath)
	globalDir := filepath.Dir(cfgPath)
	if err := watcher.Add(globalDir); err != nil {
		return err
	}

	// Watch project config if exists
	projectPath := m.projectPath
	if projectPath == "" {
		projectPath = ProjectConfigPath()
	}
	projectPath = filepath.Clean(projectPath)
	if _, err := os.Stat(projectPath); err == nil {
		if err := watcher.Add(filepath.Dir(projectPath)); err != nil {
			return err
		}
	}

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				// Check if it's a config file change
				name := filepath.Clean(event.Name)
				if name == cfgPath || name == projectPath {
					slog.Info("Config file changed, reloading...")
					if err := m.Load(); err != nil {
						slog.Error("Failed to reload config", "error", err)
					} else if onChange != nil {
						onChange()
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				slog.Error("Config watcher error", "error", err)
			}
		}
	}()

	return nil
}

// Close stops the config watcher
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.watcher != nil {
		return m.watcher.Close()
	}
	return nil
}

// mergeConfigs merges project config over global config
func mergeConfigs(global, project Config) Config {
	result := global

	// Merge keywords (append, not replace)
	if len(project.Patterns.Keywords) > 0 {
		result.Patterns.Keywords = append(result.Patterns.Keywords, project.Patterns.Keywords...)
	}

	// Merge regex patterns (append, not replace)
	if len(project.Patterns.Regex) > 0 {
		result.Patterns.Regex = append(result.Patterns.Regex, project.Patterns.Regex...)
	}

	// Merge builtin patterns (append, not replace)
	if len(project.Patterns.Builtin) > 0 {
		result.Patterns.Builtin = append(result.Patterns.Builtin, project.Patterns.Builtin...)
	}

	// Merge exclude patterns (append, not replace)
	if len(project.Patterns.Exclude) > 0 {
		result.Patterns.Exclude = append(result.Patterns.Exclude, project.Patterns.Exclude...)
	}

	// Merge targets (append, not replace)
	if len(project.Targets) > 0 {
		result.Targets = append(result.Targets, project.Targets...)
	}

	// Override scalar values if set in project
	if project.Proxy.Listen != "" {
		result.Proxy.Listen = project.Proxy.Listen
	}
	if project.Proxy.PlaceholderPrefix != "" {
		result.Proxy.PlaceholderPrefix = project.Proxy.PlaceholderPrefix
	}
	if project.Proxy.InterceptMode != "" {
		result.Proxy.InterceptMode = project.Proxy.InterceptMode
	}
	if project.Session.TTL != "" {
		result.Session.TTL = project.Session.TTL
	}
	if project.Session.MaxMappings != 0 {
		result.Session.MaxMappings = project.Session.MaxMappings
	}
	if project.Log.Level != "" {
		result.Log.Level = project.Log.Level
	}
	if project.Log.File != "" {
		result.Log.File = project.Log.File
	}

	return result
}
