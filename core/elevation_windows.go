//go:build windows

package core

import (
	"golang.org/x/sys/windows"
)

// nmapSynElevation 判断 nmap SYN 半开扫描（-sS）的可用提权方式。
// Windows 上 nmap -sS 需要管理员权限 + Npcap 驱动，当前进程为管理员则直接可用；
// 驱动缺失时 -sS 会在运行时失败，由调用方降级 -sT。
func nmapSynElevation() (prefix []string, syn bool) {
	if isPrivileged() {
		return nil, true
	}
	return nil, false
}

// isPrivileged 当前进程是否以管理员运行（检查 token 的 Administrators 组成员身份）。
func isPrivileged() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY, 2,
		windows.SECURITY_BUILTIN_DOMAIN_RID, windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)
	token := windows.GetCurrentProcessToken()
	defer token.Close()
	isMember, err := token.IsMember(sid)
	return err == nil && isMember
}
