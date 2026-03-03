package nlp

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
)

var (
	ErrInvalidEngine       = errors.New("invalid nlp engine")
	ErrOnnxNotAvailable    = errors.New("onnx nlp engine not available")
	ErrMissingOnnxModel    = errors.New("missing onnx model_path")
	ErrUnsupportedEntities = errors.New("unsupported entities")
)

type Options struct {
	Engine          string
	ModelPath       string
	RouteByLang     bool
	ModelPathEN     string
	ModelPathZH     string
	MaxLoadedModels int
	Entities        []string
	MinScore        float64
}

func isDir(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

func defaultOnnxModelPath() string {
	if p := strings.TrimSpace(os.Getenv("VIBEGUARD_ONNX_MODEL_PATH")); p != "" {
		return p
	}
	if h, err := os.UserHomeDir(); err == nil && strings.TrimSpace(h) != "" {
		p := filepath.Join(h, ".vibeguard", "models", "ner")
		if isDir(p) {
			return p
		}
	}
	if isDir(filepath.Join("models", "ner")) {
		return filepath.Join("models", "ner")
	}
	return ""
}

func defaultOnnxModelPathEN() string {
	if p := strings.TrimSpace(os.Getenv("VIBEGUARD_ONNX_MODEL_PATH_EN")); p != "" {
		return p
	}
	if h, err := os.UserHomeDir(); err == nil && strings.TrimSpace(h) != "" {
		// 优先尝试 ~/.vibeguard/models/ner/en
		p := filepath.Join(h, ".vibeguard", "models", "ner", "en")
		if isDir(p) {
			return p
		}
		// 其次尝试 ~/.vibeguard/models/ner_en
		p = filepath.Join(h, ".vibeguard", "models", "ner_en")
		if isDir(p) {
			return p
		}
	}
	// 项目内默认：models/ner/en
	if isDir(filepath.Join("models", "ner", "en")) {
		return filepath.Join("models", "ner", "en")
	}
	if isDir(filepath.Join("models", "ner_en")) {
		return filepath.Join("models", "ner_en")
	}
	return defaultOnnxModelPath()
}

func defaultOnnxModelPathZH() string {
	if p := strings.TrimSpace(os.Getenv("VIBEGUARD_ONNX_MODEL_PATH_ZH")); p != "" {
		return p
	}
	if h, err := os.UserHomeDir(); err == nil && strings.TrimSpace(h) != "" {
		// 优先尝试 ~/.vibeguard/models/ner/zh
		p := filepath.Join(h, ".vibeguard", "models", "ner", "zh")
		if isDir(p) {
			return p
		}
		// 其次尝试 ~/.vibeguard/models/ner_zh
		p = filepath.Join(h, ".vibeguard", "models", "ner_zh")
		if isDir(p) {
			return p
		}
	}
	// 项目内默认：models/ner/zh
	if isDir(filepath.Join("models", "ner", "zh")) {
		return filepath.Join("models", "ner", "zh")
	}
	if isDir(filepath.Join("models", "ner_zh")) {
		return filepath.Join("models", "ner_zh")
	}
	return ""
}

// SafeEntityNames 返回一组“相对低误报”的默认实体类型。
func SafeEntityNames() []string {
	// 默认启用常见三类实体。更细的控制可在管理页中勾选。
	return []string{"PERSON", "ORG", "LOCATION"}
}

func normalizeEngine(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "heuristic"
	}
	return s
}

func normalizeEntities(list []string) map[string]struct{} {
	if len(list) == 0 {
		list = SafeEntityNames()
	}
	out := make(map[string]struct{}, len(list))
	for _, v := range list {
		v = strings.ToUpper(strings.TrimSpace(v))
		if v == "" {
			continue
		}
		out[v] = struct{}{}
	}
	return out
}

// New returns a Recognizer for NLP-style entities.
// 默认使用 heuristic 引擎（无需额外依赖）。
func New(opts Options) (recognizer.Recognizer, error) {
	eng := normalizeEngine(opts.Engine)
	switch eng {
	case "heuristic":
		return newHeuristicRecognizer(opts), nil
	case "onnx":
		if !OnnxAvailable() {
			return nil, ErrOnnxNotAvailable
		}
		if opts.MaxLoadedModels <= 0 {
			opts.MaxLoadedModels = 1
		}
		if opts.MaxLoadedModels > 2 {
			opts.MaxLoadedModels = 2
		}

		if opts.RouteByLang {
			if strings.TrimSpace(opts.ModelPathEN) == "" {
				opts.ModelPathEN = defaultOnnxModelPathEN()
			}
			if strings.TrimSpace(opts.ModelPathZH) == "" {
				opts.ModelPathZH = defaultOnnxModelPathZH()
			}
			// 兼容旧字段：若仍为空，则回退到 ModelPath（作为 EN）。
			if strings.TrimSpace(opts.ModelPathEN) == "" {
				opts.ModelPathEN = strings.TrimSpace(opts.ModelPath)
			}
			if strings.TrimSpace(opts.ModelPathEN) == "" && strings.TrimSpace(opts.ModelPathZH) == "" {
				return nil, ErrMissingOnnxModel
			}
			return newOnnxRouterRecognizer(opts)
		}

		if strings.TrimSpace(opts.ModelPath) == "" {
			opts.ModelPath = defaultOnnxModelPath()
		}
		if strings.TrimSpace(opts.ModelPath) == "" {
			return nil, ErrMissingOnnxModel
		}
		return newOnnxRecognizer(opts)
	default:
		return nil, ErrInvalidEngine
	}
}
