//go:build !windows

package core

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// enumerateWithKsubdomainPrivileged 用提权机制重新执行当前二进制（--ksubdomain-enum helper 模式）
// 来枚举子域名。
//
// 优先使用 `sudo -n` 静默提权：依赖 sudo 的 timestamp 缓存（默认 5 分钟，可在 sudoers 的
// timestamp_timeout 调整），缓存期内不弹授权框。缓存过期后再用系统授权框（macOS osascript /
// Linux pkexec）重新授权。
func enumerateWithKsubdomainPrivileged(domain string) ([]string, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}

	// 1. 优先 sudo -n 静默提权（sudo timestamp 缓存期内不弹框）。
	if out, err := exec.Command("sudo", "-n", exe, "--ksubdomain-enum", domain).Output(); err == nil {
		return parseSubdomainOutput(out), nil
	}

	// 2. 缓存过期，用系统授权框重新授权。
	var out []byte
	switch runtime.GOOS {
	case "darwin":
		// osascript 弹管理员授权框，输入密码后以 root 执行，同时刷新 sudo timestamp。
		// with prompt 自定义授权框提示，说明提权是为了跑子域名爆破。
		// 转义反斜杠与引号：exe 路径可能含空格（app bundle 位于 /Applications 下），
		// domain 为用户输入，防 shell 断开与命令注入。
		exeQuoted := strings.ReplaceAll(strings.ReplaceAll(exe, `\`, `\\`), `"`, `\"`)
		domainQuoted := strings.ReplaceAll(strings.ReplaceAll(domain, `\`, `\\`), `"`, `\"`)
		script := fmt.Sprintf(`do shell script "%s --ksubdomain-enum %s" with prompt "Easy Scan 需要使用 ksubdomain 进行子域名无状态爆破，需要管理员权限" with administrator privileges`, exeQuoted, domainQuoted)
		out, err = exec.Command("osascript", "-e", script).Output()
	case "linux":
		// pkexec 弹 PolicyKit 授权框。
		out, err = exec.Command("pkexec", exe, "--ksubdomain-enum", domain).Output()
	default:
		return nil, fmt.Errorf("平台 %s 暂不支持 ksubdomain 提权", runtime.GOOS)
	}
	if err != nil {
		return nil, err
	}
	return parseSubdomainOutput(out), nil
}

// parseSubdomainOutput 解析 helper 模式输出的子域名（一行一个）。
// 非域名字面量的行（SDK 日志混入 stdout 的 [INFO] 等）直接丢弃。
func parseSubdomainOutput(out []byte) []string {
	subs := make([]string, 0)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if isSubdomainLine(line) {
			subs = append(subs, line)
		}
	}
	return subs
}
