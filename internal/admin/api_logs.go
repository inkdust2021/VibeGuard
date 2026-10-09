package admin

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	vglog "github.com/inkdust2021/vibeguard/internal/log"
)

type LogsResponse struct {
	ConfiguredPath string   `json:"configured_path"`
	EffectivePath  string   `json:"effective_path"`
	Exists         bool     `json:"exists"`
	Lines          []string `json:"lines"`
	Warning        string   `json:"warning,omitempty"`
}

// handleLogs handles GET /manager/api/logs?tail=200
func (a *Admin) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tail := clampInt(queryInt(r, "tail", 200), 1, 2000)
	cfg := a.config.Get()

	configured := strings.TrimSpace(cfg.Log.File)
	effective, warning := resolveLogPath(configured)

	lines, err := tailFileLines(effective, tail)
	if err != nil {
		// File missing/unreadable: return an empty list and put the error into warning for UI display.
		slog.Debug("Read logs failed", "path", effective, "error", err)
		warning = strings.TrimSpace(strings.Join([]string{warning, err.Error()}, " "))
	}

	resp := LogsResponse{
		ConfiguredPath: configured,
		EffectivePath:  effective,
		Exists:         fileExists(effective),
		Lines:          lines,
		Warning:        warning,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleLogsStream handles GET /manager/api/logs/stream?tail=200
func (a *Admin) handleLogsStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	tail := clampInt(queryInt(r, "tail", 200), 1, 2000)
	cfg := a.config.Get()

	configured := strings.TrimSpace(cfg.Log.File)
	effective, warning := resolveLogPath(configured)

	send := func(event string, v any) bool {
		data, err := json.Marshal(v)
		if err != nil {
			return false
		}
		_, _ = w.Write([]byte("event: " + event + "\n"))
		_, _ = w.Write([]byte("data: " + string(data) + "\n\n"))
		flusher.Flush()
		return true
	}

	// Capture the initial file identity and offset before sending the snapshot.
	var pos int64
	var previous os.FileInfo
	if st, err := os.Stat(effective); err == nil {
		previous = st
		pos = st.Size()
	}

	// Initial tail.
	lines, err := tailFileLines(effective, tail)
	if err != nil {
		warning = strings.TrimSpace(strings.Join([]string{warning, err.Error()}, " "))
		lines = nil
	}
	_ = send("logs_init", LogsResponse{
		ConfiguredPath: configured,
		EffectivePath:  effective,
		Exists:         fileExists(effective),
		Lines:          lines,
		Warning:        warning,
	})

	// Follow mode: read newly appended content from the end of the file.
	var carry []byte

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			st, err := os.Stat(effective)
			if err != nil {
				continue
			}

			size := st.Size()
			if size < pos || (previous != nil && !os.SameFile(previous, st)) {
				// File truncated/rotated: restart from the beginning.
				pos = 0
				carry = carry[:0]
			}
			previous = st
			if size == pos {
				continue
			}

			const maxReadBytes int64 = 256 * 1024
			start := pos
			if size-start > maxReadBytes {
				// Too much change: only read the last chunk to avoid freezing the admin UI.
				start = size - maxReadBytes
			}

			b, err := readFileRange(effective, start, size)
			if err != nil || len(b) == 0 {
				pos = size
				continue
			}
			pos = size

			data := make([]byte, 0, len(carry)+len(b))
			data = append(data, carry...)
			data = append(data, b...)
			linesBytes, newCarry := splitCompleteLines(data)
			carry = newCarry

			lines := make([]string, 0, len(linesBytes))
			for _, ln := range linesBytes {
				ln = bytes.TrimSuffix(ln, []byte("\r"))
				if len(ln) == 0 {
					continue
				}
				lines = append(lines, string(ln))
			}
			if len(lines) == 0 {
				continue
			}

			_ = send("logs_append", map[string]any{
				"lines": lines,
			})
		}
	}
}

func resolveLogPath(configured string) (effective string, warning string) {
	if strings.TrimSpace(configured) == "" {
		// Default value (same as config default) to avoid confusing the UI with an empty path.
		configured = "~/.vibeguard/vibeguard.log"
	}

	expanded := vglog.ExpandPath(configured)
	if expanded != configured {
		if fileExists(expanded) {
			return expanded, ""
		}
		if fileExists(configured) {
			return configured, fmt.Sprintf("检测到日志路径未展开 ~：当前读取 %s（如需写入 %s，请重启服务）", configured, expanded)
		}
		return expanded, ""
	}
	return configured, ""
}

func readFileRange(path string, start, end int64) ([]byte, error) {
	if start < 0 {
		start = 0
	}
	if end < start {
		end = start
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	limit := end - start
	if limit <= 0 {
		return nil, nil
	}
	return io.ReadAll(io.LimitReader(f, limit))
}

func tailFileLines(path string, tail int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}

	size := st.Size()
	if size == 0 {
		return nil, nil
	}

	// Grow a window from the file end until we capture enough newlines or reach the beginning.
	var window int64 = 64 * 1024
	if window > size {
		window = size
	}

	var buf []byte
	for {
		start := size - window
		if start < 0 {
			start = 0
		}
		b, err := readFileRange(path, start, size)
		if err != nil {
			return nil, err
		}
		buf = b

		if countNewlines(buf) >= tail || start == 0 {
			break
		}
		window *= 2
		if window > size {
			window = size
		}
	}

	// Split by line via Scanner to avoid large temporary allocations from a full split.
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(buf))
	// Support long log lines.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		lines = append(lines, line)
	}
	if err := sc.Err(); err != nil {
		// Fallback to a simple split when Scanner fails.
		parts := bytes.Split(buf, []byte("\n"))
		lines = lines[:0]
		for _, p := range parts {
			p = bytes.TrimSuffix(p, []byte("\r"))
			if len(p) == 0 {
				continue
			}
			lines = append(lines, string(p))
		}
	}

	if len(lines) <= tail {
		return lines, nil
	}
	return lines[len(lines)-tail:], nil
}

func splitCompleteLines(data []byte) (lines [][]byte, carry []byte) {
	if len(data) == 0 {
		return nil, nil
	}

	parts := bytes.Split(data, []byte("\n"))
	if len(parts) == 0 {
		return nil, data
	}
	// If the last segment does not end with \n, keep it as carry.
	if len(data) > 0 && data[len(data)-1] != '\n' {
		carry = append([]byte(nil), parts[len(parts)-1]...)
		parts = parts[:len(parts)-1]
	}
	return parts, carry
}

func countNewlines(b []byte) int {
	return bytes.Count(b, []byte("\n"))
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func queryInt(r *http.Request, key string, def int) int {
	if r == nil {
		return def
	}
	v := strings.TrimSpace(r.URL.Query().Get(key))
	if v == "" {
		return def
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return i
}

func clampInt(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
