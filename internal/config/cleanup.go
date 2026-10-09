package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// CleanupConfig controls disk retention independently from the session mapping TTL.
type CleanupConfig struct {
	Log        LogCleanupConfig `yaml:"log" json:"log"`
	SessionWAL WALCleanupConfig `yaml:"session_wal" json:"session_wal"`
}

type WALCleanupConfig struct {
	// A pointer distinguishes an omitted project override from an explicit false.
	Enabled  *bool  `yaml:"enabled,omitempty" json:"enabled"`
	Interval string `yaml:"interval" json:"interval"`
}

type LogCleanupConfig struct {
	Enabled    *bool  `yaml:"enabled,omitempty" json:"enabled"`
	Interval   string `yaml:"interval" json:"interval"`
	MaxSizeMB  int    `yaml:"max_size_mb" json:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups" json:"max_backups"`
}

func (c LogCleanupConfig) IsEnabled() bool { return c.Enabled == nil || *c.Enabled }
func (c WALCleanupConfig) IsEnabled() bool { return c.Enabled == nil || *c.Enabled }

// ParseCleanupInterval accepts Go durations and whole-day durations, at least one minute.
func ParseCleanupInterval(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if strings.HasSuffix(value, "d") {
		days, err := strconv.ParseInt(strings.TrimSuffix(value, "d"), 10, 64)
		if err != nil || days <= 0 || days > int64((1<<63-1)/(24*time.Hour)) {
			return 0, fmt.Errorf("invalid cleanup interval %q", value)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil || d < time.Minute {
		return 0, fmt.Errorf("cleanup interval must be at least 1m: %q", value)
	}
	return d, nil
}

func normalizeCleanup(c *CleanupConfig) {
	if c.Log.Enabled == nil {
		enabled := true
		c.Log.Enabled = &enabled
	}
	if c.SessionWAL.Enabled == nil {
		enabled := true
		c.SessionWAL.Enabled = &enabled
	}
	c.Log.Interval = strings.TrimSpace(c.Log.Interval)
	c.SessionWAL.Interval = strings.TrimSpace(c.SessionWAL.Interval)
	if c.Log.Interval == "" {
		c.Log.Interval = "24h"
	}
	if c.SessionWAL.Interval == "" {
		c.SessionWAL.Interval = "1h"
	}
	if c.Log.MaxSizeMB == 0 {
		c.Log.MaxSizeMB = 10
	}
	if c.Log.MaxBackups == 0 {
		c.Log.MaxBackups = 3
	}
}

func (c CleanupConfig) Validate() error {
	if _, err := ParseCleanupInterval(c.Log.Interval); err != nil {
		return fmt.Errorf("cleanup.log.interval: %w", err)
	}
	if _, err := ParseCleanupInterval(c.SessionWAL.Interval); err != nil {
		return fmt.Errorf("cleanup.session_wal.interval: %w", err)
	}
	if c.Log.MaxSizeMB < 1 || c.Log.MaxSizeMB > 1024 {
		return fmt.Errorf("cleanup.log.max_size_mb must be between 1 and 1024")
	}
	if c.Log.MaxBackups < 1 || c.Log.MaxBackups > 100 {
		return fmt.Errorf("cleanup.log.max_backups must be between 1 and 100")
	}
	return nil
}

func mergeCleanup(global, project CleanupConfig) CleanupConfig {
	if project.Log.Enabled != nil {
		global.Log.Enabled = project.Log.Enabled
	}
	if project.Log.Interval != "" {
		global.Log.Interval = project.Log.Interval
	}
	if project.Log.MaxSizeMB != 0 {
		global.Log.MaxSizeMB = project.Log.MaxSizeMB
	}
	if project.Log.MaxBackups != 0 {
		global.Log.MaxBackups = project.Log.MaxBackups
	}
	if project.SessionWAL.Enabled != nil {
		global.SessionWAL.Enabled = project.SessionWAL.Enabled
	}
	if project.SessionWAL.Interval != "" {
		global.SessionWAL.Interval = project.SessionWAL.Interval
	}
	return global
}
