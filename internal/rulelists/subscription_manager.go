package rulelists

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/inkdust2021/vibeguard/internal/config"
)

// SubscriptionManager 周期性拉取并校验规则订阅，并在内容更新后触发回调（通常用于热重载）。
type SubscriptionManager struct {
	cfg      *config.Manager
	onUpdate func()

	client *http.Client

	stop chan struct{}
	done chan struct{}
}

func NewSubscriptionManager(cfg *config.Manager, onUpdate func()) *SubscriptionManager {
	return &SubscriptionManager{
		cfg:      cfg,
		onUpdate: onUpdate,
		client:   &http.Client{Timeout: defaultSubscriptionTimeout},
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

func (m *SubscriptionManager) Start() {
	if m == nil {
		return
	}
	go m.loop()
}

func (m *SubscriptionManager) Stop() {
	if m == nil {
		return
	}
	select {
	case <-m.stop:
		// already closed
	default:
		close(m.stop)
	}
	<-m.done
}

func (m *SubscriptionManager) loop() {
	defer close(m.done)

	// 立即尝试同步一次（非阻塞主流程：失败只记录日志）。
	m.syncOnce(true)

	tk := time.NewTicker(5 * time.Minute)
	defer tk.Stop()

	for {
		select {
		case <-m.stop:
			return
		case <-tk.C:
			m.syncOnce(false)
		}
	}
}

func (m *SubscriptionManager) syncOnce(force bool) {
	if m == nil || m.cfg == nil {
		return
	}
	c := m.cfg.Get()
	now := time.Now()

	updatedAny := false
	for _, rl := range c.Patterns.RuleLists {
		if !rl.Enabled {
			continue
		}
		if strings.TrimSpace(rl.URL) == "" {
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), defaultSubscriptionTimeout)
		updated, _, err := SyncSubscriptionIfDue(ctx, rl, SyncSubscriptionOptions{
			Client: m.client,
			Force:  force,
			Now:    now,
		})
		cancel()

		if err != nil {
			slog.Warn("规则订阅同步失败", "error", err, "id", strings.TrimSpace(rl.ID), "url", strings.TrimSpace(rl.URL))
			continue
		}
		if updated {
			updatedAny = true
		}
	}

	if updatedAny && m.onUpdate != nil {
		m.onUpdate()
	}
}
