// 输入校验：域名目标会进入提权子进程（sudo/osascript/pkexec/UAC）等
// 危险上下文，必须在入口层做严格白名单校验（CWE-78 命令注入防线）。
package core

import (
	"fmt"
	"strings"
)

// ValidateDomain 校验域名字面量：仅 [a-z0-9.-]（大小写不敏感），
// 逐标签 ≤63、总长 ≤253，禁止空标签与首尾的 . 或 -。
// 校验通过返回 nil，否则返回错误（调用方应拒绝执行扫描）。
func ValidateDomain(domain string) error {
	d := strings.ToLower(strings.TrimSpace(domain))
	if len(d) == 0 || len(d) > 253 {
		return fmt.Errorf("域名长度需在 1-253 之间")
	}
	if strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") ||
		strings.HasPrefix(d, "-") || strings.HasSuffix(d, "-") {
		return fmt.Errorf("域名不能以 . 或 - 开头/结尾")
	}
	for _, label := range strings.Split(d, ".") {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("域名标签长度需在 1-63 之间")
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("域名标签不能以 - 开头/结尾")
		}
		for _, c := range label {
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
				continue
			}
			return fmt.Errorf("域名含非法字符 %q（仅允许字母/数字/-/.）", c)
		}
	}
	return nil
}
