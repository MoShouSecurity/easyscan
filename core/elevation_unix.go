//go:build !windows

package core

import (
	"os"
	"os/exec"
)

// nmapSynElevation 判断 nmap SYN 半开扫描（-sS）的可用提权方式。
// 返回命令前缀与是否可用 SYN：
//   - 当前进程已是 root → 无前缀，直接 -sS
//   - sudo timestamp 缓存可用（sudo -n -v 静默验证）→ sudo -n 前缀，不弹授权框
//   - 否则不可用，调用方降级 -sT
func nmapSynElevation() (prefix []string, syn bool) {
	if isPrivileged() {
		return nil, true
	}
	if err := exec.Command("sudo", "-n", "-v").Run(); err == nil {
		return []string{"sudo", "-n"}, true
	}
	return nil, false
}

// isPrivileged 当前进程是否以 root 运行。
func isPrivileged() bool {
	return os.Geteuid() == 0
}
