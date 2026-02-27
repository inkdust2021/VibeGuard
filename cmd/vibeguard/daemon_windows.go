//go:build windows

package main

import (
	"os"
	"os/exec"
	"syscall"
)

// startDetachedProxyProcess 在 Windows 上以“脱离控制台”的方式启动代理子进程。
func startDetachedProxyProcess() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	c := exec.Command(exe, "start", "--foreground")
	c.Env = os.Environ()

	// 让子进程独立运行，避免父进程退出或控制台关闭影响子进程。
	c.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | syscall.DETACHED_PROCESS,
		HideWindow:    true,
	}

	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err == nil {
		defer devNull.Close()
		c.Stdin = devNull
		c.Stdout = devNull
		c.Stderr = devNull
	}

	return c.Start()
}
