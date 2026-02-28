package admin

import (
	"os"
	"strings"
)

func isLikelyContainerRuntime() bool {
	// 允许通过环境变量显式标记（便于自定义容器运行时/测试）。
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("VIBEGUARD_CONTAINER"))); v != "" {
		switch v {
		case "1", "true", "yes", "y", "on":
			return true
		case "0", "false", "no", "n", "off":
			return false
		}
	}

	// Docker 通常会注入该文件。
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	// Linux 容器常见：/proc/1/cgroup 里包含 docker/kubepods/containerd 等关键字。
	// 其他平台直接返回 false。
	if b, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := strings.ToLower(string(b))
		if strings.Contains(s, "docker") ||
			strings.Contains(s, "kubepods") ||
			strings.Contains(s, "containerd") ||
			strings.Contains(s, "podman") {
			return true
		}
	}

	return false
}
