//go:build !windows

package core

import "os/exec"

// HideCmdWindow 非 Windows 平台无控制台窗口问题，空实现。
func HideCmdWindow(cmd *exec.Cmd) {}
