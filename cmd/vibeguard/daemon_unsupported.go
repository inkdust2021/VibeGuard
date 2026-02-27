//go:build !darwin && !linux && !windows

package main

import "fmt"

func startDetachedProxyProcess() error {
	return fmt.Errorf("background start is not supported on this platform")
}
