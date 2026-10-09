package log

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/inkdust2021/vibeguard/internal/config"
)

// Setup initializes the logger with file output and default cleanup.
func Setup(logPath string, level string) error {
	_, err := SetupWithCleanup(logPath, level, config.NewManager().Get().Cleanup)
	return err
}

// SetupWithCleanup returns the file writer so runtime policy changes and shutdown can be managed.
func SetupWithCleanup(logPath, level string, cleanup config.CleanupConfig) (*fileWriter, error) {
	return setup(logPath, level, true, cleanup.Log)
}

// SetFileOnly switches to file-only logging (no stderr).
func SetFileOnly(logPath string, level string) error {
	_, err := setup(logPath, level, false, config.NewManager().Get().Cleanup.Log)
	return err
}

func setup(logPath, level string, stderr bool, cleanup config.LogCleanupConfig) (*fileWriter, error) {
	writer, err := newFileWriter(ExpandPath(logPath), cleanup)
	if err != nil {
		return nil, err
	}
	var slogLevel slog.Level
	switch level {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}
	var output io.Writer = writer
	if stderr {
		output = io.MultiWriter(os.Stderr, writer)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(output, &slog.HandlerOptions{Level: slogLevel})))
	return writer, nil
}

// ExpandPath expands "~/" in paths (current user only), avoiding writing logs into a literal "~" directory under a relative path.
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
