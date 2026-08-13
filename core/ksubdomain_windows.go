//go:build windows

package core

import (
	"context"
	"fmt"
)

// enumerateWithKsubdomain Windows 上 ksubdomain 依赖 Npcap 驱动与原始 socket 权限，
// 暂不支持交叉编译，返回错误触发纯 Go 字典爆破降级。
func enumerateWithKsubdomain(ctx context.Context, domain string) ([]string, error) {
	return nil, fmt.Errorf("ksubdomain 在 Windows 上暂不可用，已降级为纯 Go 字典爆破")
}

// EnumerateWithKsubdomain 导出 ksubdomain 枚举（Windows 上返回错误触发降级）。
func EnumerateWithKsubdomain(ctx context.Context, domain string) ([]string, error) {
	return enumerateWithKsubdomain(ctx, domain)
}

// GetFullSubdomainDict Windows 上无 ksubdomain 字典，返回 nil（用内置小字典兜底）。
func GetFullSubdomainDict() []string {
	return nil
}
