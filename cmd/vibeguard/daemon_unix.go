//go:build darwin || linux

package main

import (
	"os"
	"os/exec"
	"syscall"
)

func startDetachedProxyProcess() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	c := exec.Command(exe, "start", "--foreground")
	c.Env = os.Environ()
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err == nil {
		defer devNull.Close()
		c.Stdin = devNull
		c.Stdout = devNull
		c.Stderr = devNull
	}

	return c.Start()
}
