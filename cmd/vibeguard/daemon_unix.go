//go:build darwin || linux

package main

import (
	"os"
	"os/exec"
	"syscall"
)

// startDetachedProxyProcess 在后台拉起一个“前台运行模式”的子进程，并与当前终端会话脱离，
// 以避免终端关闭导致代理进程收到 SIGHUP 退出。
func startDetachedProxyProcess() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	c := exec.Command(exe, "start", "--foreground")
	c.Env = os.Environ()
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	// 关闭与当前终端的绑定：日志仍会写入配置中的 log.file；stdout/stderr 丢弃即可。
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err == nil {
		defer devNull.Close()
		c.Stdin = devNull
		c.Stdout = devNull
		c.Stderr = devNull
	}

	return c.Start()
}
