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
		// 文件不存在/不可读：返回空列表，并把错误放到 warning 里，便于前端提示。
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

	// 初始 tail
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

	// 进入 follow：从文件末尾开始读取新增内容
	var pos int64 = 0
	if st, err := os.Stat(effective); err == nil {
		pos = st.Size()
	}
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
			if size < pos {
				// 文件被截断/轮转：从头开始
				pos = 0
				carry = carry[:0]
			}
			if size == pos {
				continue
			}

			const maxReadBytes int64 = 256 * 1024
			start := pos
			if size-start > maxReadBytes {
				// 变更过大：只取最后一段，避免把管理页卡死
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
		// 默认值（和 config 默认一致），避免出现空路径导致前端不知所措
		configured = "~/.vibeguard/vibeguard.log"
	}

	expanded := vglog.ExpandPath(configured)
	if expanded != configured {
		// 优先使用“正确展开后的路径”；但为了兼容旧版本（未展开 ~ 导致写到相对路径），若展开路径不存在则回退。
		if fileExists(expanded) {
			return expanded, ""
		}
		if fileExists(configured) {
			return configured, fmt.Sprintf("检测到旧版未展开 ~ 的日志路径：当前读取 %s（建议升级后重启让日志写入 %s）", configured, expanded)
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

	// 从文件末尾开始逐步扩大读取窗口，直到捕获到足够的换行符或到达文件开头。
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

	// 用 Scanner 按行切分，避免一次性 split 造成大量临时对象
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(buf))
	// 适配较长日志行
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		lines = append(lines, line)
	}
	if err := sc.Err(); err != nil {
		// Scanner 失败时退化为简单 split
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
	// 如果最后一段不是以 \n 结尾，则作为 carry 保留
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
