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
	// RuleLists 为“类似 AdGuard 的订阅规则列表”：由用户上传/配置的规则文件，代理启动时加载并参与匹配。
	// 说明：该规则列表更适合“通用模式”（正则/关键短语），而“具体密钥/口令”等建议仍使用 keywords（可配合加密落盘）。
	RuleLists []RuleListConfig `yaml:"rule_lists"`
	// NLP 为“泛化实体识别”开关与配置（可选：ONNX/NLP；默认关闭）。
	NLP NLPConfig `yaml:"nlp"`
}

// NLPConfig controls the optional NLP-based recognizers (e.g. PERSON/ORG/LOCATION).
// 说明：该配置本身不包含敏感信息；仅用于控制识别开关与实体类型。
type NLPConfig struct {
	Enabled bool `yaml:"enabled"`
	// Engine 可选：heuristic|onnx。默认 heuristic（无需额外依赖）。
	Engine string `yaml:"engine"`
	// ModelPath 为 ONNX 模型目录或文件路径（仅 onnx 引擎需要）。
	ModelPath string `yaml:"model_path"`
	// RouteByLang 为 true 时，将按语言（中/英）路由到不同的模型目录。
	// 说明：这能在“只使用单一语言”时显著降低常驻内存（按需加载）。
	RouteByLang bool `yaml:"route_by_lang"`
	// ModelPathEN / ModelPathZH 为按语言路由时的模型路径（可为空；为空将尝试回退到 ModelPath 或默认路径）。
	ModelPathEN string `yaml:"model_path_en"`
	ModelPathZH string `yaml:"model_path_zh"`
	// MaxLoadedModels 控制最多同时常驻多少个 ONNX 模型（1=最低内存；2=切换更快）。
	// 仅在 RouteByLang=true 且 Engine=onnx 时生效。
	MaxLoadedModels int `yaml:"max_loaded_models"`
	// Entities 指定启用的实体类型（如 PERSON/ORG/LOCATION/DATE...）。空表示使用实现内默认集合。
	Entities []string `yaml:"entities"`
	// MinScore 为 ONNX/NLP 模型的置信度阈值（仅 onnx 引擎需要；0 表示使用默认值）。
	MinScore float64 `yaml:"min_score"`
}

// RuleListConfig 描述一个规则列表文件（逐行规则）。
type RuleListConfig struct {
	// ID 为稳定标识（管理端创建时生成）；可为空（将以 Path 作为展示名）。
	ID string `yaml:"id" json:"id"`
	// Name 为展示名（管理端可编辑）；可为空。
	Name string `yaml:"name" json:"name"`
	// Path 为规则文件路径（支持 ~ 前缀）；与 URL 二选一。
	Path string `yaml:"path" json:"path"`
	// URL 为远端订阅地址（http/https）；与 Path 二选一。
	URL string `yaml:"url" json:"url"`
	// SigURL 为远端订阅的“分离签名”地址（可选）；建议与 PubKey 配合使用（ed25519）。
	SigURL string `yaml:"sig_url" json:"sig_url"`
	// PubKey 为 ed25519 公钥（base64/hex）；用于校验 SigURL 提供的签名（可选）。
	PubKey string `yaml:"pubkey" json:"pubkey"`
	// SHA256 为内容哈希（hex，64 位）；用于固定版本校验（可选）。若希望自动更新，建议使用签名校验。
	SHA256 string `yaml:"sha256" json:"sha256"`
	// UpdateInterval 为订阅更新间隔（如 24h/6h）；仅 URL 模式生效。空值默认 24h。
	UpdateInterval string `yaml:"update_interval" json:"update_interval"`
	// AllowHTTP 为 true 时允许使用 http:// 订阅（不推荐；默认仅允许 https://）。
	AllowHTTP bool `yaml:"allow_http" json:"allow_http"`
	// Enabled 控制该规则列表是否参与匹配。
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Priority 控制该规则列表的优先级（1~99）；越大越优先保留。
	Priority int `yaml:"priority" json:"priority"`
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
	TTL                       string `yaml:"ttl"`
	MaxMappings               int    `yaml:"max_mappings"`
	WALEnabled                bool   `yaml:"wal_enabled"`
	WALPath                   string `yaml:"wal_path"`
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
		Keywords:  []KeywordPattern{},
		Regex:     []RegexPattern{},
		Builtin:   []string{},
		Exclude:   []string{},
		RuleLists: []RuleListConfig{},
		NLP: NLPConfig{
			Enabled:         false,
			Engine:          "heuristic",
			ModelPath:       "",
			RouteByLang:     false,
			ModelPathEN:     "",
			ModelPathZH:     "",
			MaxLoadedModels: 1,
			Entities:        []string{},
			MinScore:        0,
		},
	},
	Targets: []TargetConfig{
		{Host: "api.anthropic.com", Enabled: true},
		{Host: "api.openai.com", Enabled: true},
		{Host: "api2.cursor.sh", Enabled: true},
		{Host: "generativelanguage.googleapis.com", Enabled: true},
	},
	Session: SessionConfig{
		TTL:                       "1h",
		MaxMappings:               100000,
		WALEnabled:                true,
		WALPath:                   "~/.vibeguard/session.wal",
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

	// Patterns: rule_lists
	if len(cfg.Patterns.RuleLists) > 0 {
		out := make([]RuleListConfig, 0, len(cfg.Patterns.RuleLists))
		seen := make(map[string]struct{}, len(cfg.Patterns.RuleLists))
		for _, rl := range cfg.Patterns.RuleLists {
			path := strings.TrimSpace(rl.Path)
			url := strings.TrimSpace(rl.URL)
			if path == "" && url == "" {
				continue
			}
			id := SanitizePatternValue(rl.ID)
			name := SanitizePatternValue(rl.Name)
			sigURL := SanitizePatternValue(rl.SigURL)
			pubKey := SanitizePatternValue(rl.PubKey)
			sha256 := SanitizePatternValue(rl.SHA256)
			updateInterval := strings.TrimSpace(rl.UpdateInterval)
			allowHTTP := rl.AllowHTTP
			if url != "" && updateInterval == "" {
				updateInterval = "24h"
			}
			priority := rl.Priority
			if priority <= 0 {
				priority = 50
			}
			if priority > 99 {
				priority = 99
			}

			// 去重键：优先使用 ID；否则按 Path/URL 去重，避免重复加载造成困惑/性能浪费。
			key := id
			if key == "" {
				if path != "" {
					key = "path:" + path
				} else {
					key = "url:" + url
				}
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			out = append(out, RuleListConfig{
				ID:     id,
				Name:   name,
				Path:   path,
				URL:    url,
				SigURL: sigURL,
				PubKey: pubKey,
				SHA256: sha256,
				// 仅 URL 模式生效；Path 模式保留原值但不使用。
				UpdateInterval: updateInterval,
				AllowHTTP:      allowHTTP,
				Enabled:        rl.Enabled,
				Priority:       priority,
			})
		}
		cfg.Patterns.RuleLists = out
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

	// Patterns: nlp
	if eng := SanitizeNLPEngine(cfg.Patterns.NLP.Engine); eng != "" {
		cfg.Patterns.NLP.Engine = eng
	} else if strings.TrimSpace(cfg.Patterns.NLP.Engine) == "" {
		// 空值回退默认（避免配置文件缺失字段时出现空字符串）。
		cfg.Patterns.NLP.Engine = defaultConfig.Patterns.NLP.Engine
	} else {
		// 非法值回退到默认。
		cfg.Patterns.NLP.Engine = defaultConfig.Patterns.NLP.Engine
	}
	cfg.Patterns.NLP.ModelPath = strings.TrimSpace(cfg.Patterns.NLP.ModelPath)
	cfg.Patterns.NLP.ModelPathEN = strings.TrimSpace(cfg.Patterns.NLP.ModelPathEN)
	cfg.Patterns.NLP.ModelPathZH = strings.TrimSpace(cfg.Patterns.NLP.ModelPathZH)
	if cfg.Patterns.NLP.MaxLoadedModels <= 0 {
		cfg.Patterns.NLP.MaxLoadedModels = 1
	}
	if cfg.Patterns.NLP.MaxLoadedModels > 2 {
		cfg.Patterns.NLP.MaxLoadedModels = 2
	}
	if len(cfg.Patterns.NLP.Entities) > 0 {
		out := make([]string, 0, len(cfg.Patterns.NLP.Entities))
		for _, e := range cfg.Patterns.NLP.Entities {
			v := SanitizeCategory(e)
			if v == "" {
				continue
			}
			out = append(out, v)
		}
		cfg.Patterns.NLP.Entities = out
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

	// Merge rule lists (append, not replace)
	if len(project.Patterns.RuleLists) > 0 {
		result.Patterns.RuleLists = append(result.Patterns.RuleLists, project.Patterns.RuleLists...)
	}

	// NLP: project-level settings can enable and/or override entities.
	if project.Patterns.NLP.Enabled {
		result.Patterns.NLP.Enabled = true
	}
	if strings.TrimSpace(project.Patterns.NLP.Engine) != "" {
		result.Patterns.NLP.Engine = project.Patterns.NLP.Engine
	}
	if strings.TrimSpace(project.Patterns.NLP.ModelPath) != "" {
		result.Patterns.NLP.ModelPath = project.Patterns.NLP.ModelPath
	}
	if project.Patterns.NLP.RouteByLang {
		result.Patterns.NLP.RouteByLang = true
	}
	if strings.TrimSpace(project.Patterns.NLP.ModelPathEN) != "" {
		result.Patterns.NLP.ModelPathEN = project.Patterns.NLP.ModelPathEN
	}
	if strings.TrimSpace(project.Patterns.NLP.ModelPathZH) != "" {
		result.Patterns.NLP.ModelPathZH = project.Patterns.NLP.ModelPathZH
	}
	if project.Patterns.NLP.MaxLoadedModels > 0 {
		result.Patterns.NLP.MaxLoadedModels = project.Patterns.NLP.MaxLoadedModels
	}
	if len(project.Patterns.NLP.Entities) > 0 {
		// Entities 同样采用覆盖语义。
		result.Patterns.NLP.Entities = append([]string(nil), project.Patterns.NLP.Entities...)
	}
	if project.Patterns.NLP.MinScore != 0 {
		result.Patterns.NLP.MinScore = project.Patterns.NLP.MinScore
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
