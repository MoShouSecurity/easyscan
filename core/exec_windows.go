//go:build windows

package core

import (
	"os/exec"
	"syscall"
)

// HideCmdWindow 隐藏子进程的控制台窗口。
// GUI 程序启动 nmap/git 等控制台子进程时，Windows 默认会弹出黑色终端窗口。
func HideCmdWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
