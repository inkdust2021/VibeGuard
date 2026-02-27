package log

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Setup initializes the logger with file output
func Setup(logPath string, level string) error {
	logPath = ExpandPath(logPath)

	// Ensure log directory exists
	logDir := filepath.Dir(logPath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}

	// Open log file
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	// Parse log level
	var slogLevel slog.Level
	switch level {
	case "debug":
		slogLevel = slog.LevelDebug
	case "info":
		slogLevel = slog.LevelInfo
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	// Create handler that writes to both stderr and file
	handler := slog.NewTextHandler(io.MultiWriter(os.Stderr, logFile), &slog.HandlerOptions{
		Level: slogLevel,
	})

	slog.SetDefault(slog.New(handler))
	return nil
}

// SetFileOnly switches to file-only logging (no stderr)
func SetFileOnly(logPath string, level string) error {
	logPath = ExpandPath(logPath)

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	var slogLevel slog.Level
	switch level {
	case "debug":
		slogLevel = slog.LevelDebug
	case "info":
		slogLevel = slog.LevelInfo
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	handler := slog.NewTextHandler(logFile, &slog.HandlerOptions{
		Level: slogLevel,
	})

	slog.SetDefault(slog.New(handler))
	return nil
}

// ExpandPath 展开路径中的 "~/"（仅支持当前用户），避免把日志写到相对目录下的 "~" 文件夹。
func ExpandPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return path
	}
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return home
		}
		return path
	}
	if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, "~"+string(os.PathSeparator)) {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}
