//go:build onnx && cgo

package onnxruntime

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const ortLibEnvKey = "VIBEGUARD_ONNXRUNTIME_LIB"

func init() {
	// 若用户已显式指定，则不做任何自动探测。
	if strings.TrimSpace(os.Getenv(ortLibEnvKey)) != "" {
		return
	}
	if p := autoDetectOrtLibPath(); p != "" {
		_ = os.Setenv(ortLibEnvKey, p)
	}
}

func autoDetectOrtLibPath() string {
	switch runtime.GOOS {
	case "darwin":
		return autoDetectOrtLibPathDarwin()
	case "linux":
		return autoDetectOrtLibPathLinux()
	default:
		return ""
	}
}

func pickFirstExisting(paths []string) string {
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	return ""
}

func globFirst(patterns []string) string {
	var candidates []string
	for _, pat := range patterns {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		ms, _ := filepath.Glob(pat)
		for _, m := range ms {
			candidates = append(candidates, m)
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	sort.Strings(candidates)
	// 倾向选择“更具体/版本号更高”的文件名（排序后取最后一个）。
	for i := len(candidates) - 1; i >= 0; i-- {
		if fi, err := os.Stat(candidates[i]); err == nil && fi.Mode().IsRegular() {
			return candidates[i]
		}
	}
	return ""
}

func autoDetectOrtLibPathDarwin() string {
	// 1) Homebrew / 系统常见位置
	if p := globFirst([]string{
		"/opt/homebrew/lib/libonnxruntime*.dylib",
		"/usr/local/lib/libonnxruntime*.dylib",
		"/usr/lib/libonnxruntime*.dylib",
	}); p != "" {
		return p
	}

	home, _ := os.UserHomeDir()

	// 2) venv / conda（常见）
	if ve := strings.TrimSpace(os.Getenv("VIRTUAL_ENV")); ve != "" {
		if p := globFirst([]string{
			filepath.Join(ve, "lib", "python*", "site-packages", "onnxruntime", "capi", "libonnxruntime*.dylib"),
			filepath.Join(ve, "lib", "libonnxruntime*.dylib"),
		}); p != "" {
			return p
		}
	}
	if cp := strings.TrimSpace(os.Getenv("CONDA_PREFIX")); cp != "" {
		if p := globFirst([]string{
			filepath.Join(cp, "lib", "python*", "site-packages", "onnxruntime", "capi", "libonnxruntime*.dylib"),
			filepath.Join(cp, "lib", "libonnxruntime*.dylib"),
		}); p != "" {
			return p
		}
	}

	// 3) Homebrew Python site-packages（你当前环境就是这种路径）
	if p := globFirst([]string{
		"/opt/homebrew/lib/python*/site-packages/onnxruntime/capi/libonnxruntime*.dylib",
		"/usr/local/lib/python*/site-packages/onnxruntime/capi/libonnxruntime*.dylib",
	}); p != "" {
		return p
	}

	// 4) 用户级 Python site-packages
	if home != "" {
		if p := globFirst([]string{
			filepath.Join(home, "Library", "Python", "*", "lib", "python", "site-packages", "onnxruntime", "capi", "libonnxruntime*.dylib"),
		}); p != "" {
			return p
		}
	}

	return ""
}

func autoDetectOrtLibPathLinux() string {
	// 1) 系统常见位置
	if p := globFirst([]string{
		"/usr/lib*/libonnxruntime.so*",
		"/usr/local/lib*/libonnxruntime.so*",
	}); p != "" {
		return p
	}

	// 2) venv / conda
	if ve := strings.TrimSpace(os.Getenv("VIRTUAL_ENV")); ve != "" {
		if p := globFirst([]string{
			filepath.Join(ve, "lib", "python*", "site-packages", "onnxruntime", "capi", "libonnxruntime.so*"),
			filepath.Join(ve, "lib", "libonnxruntime.so*"),
		}); p != "" {
			return p
		}
	}
	if cp := strings.TrimSpace(os.Getenv("CONDA_PREFIX")); cp != "" {
		if p := globFirst([]string{
			filepath.Join(cp, "lib", "python*", "site-packages", "onnxruntime", "capi", "libonnxruntime.so*"),
			filepath.Join(cp, "lib", "libonnxruntime.so*"),
		}); p != "" {
			return p
		}
	}
	return ""
}
