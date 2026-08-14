package core

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// enumerateSubdomains 合并被动收集（subfinder）与主动爆破（ksubdomain），
// ksubdomain 不可用（无权限/无网卡/Windows）时降级为纯 Go 字典爆破。
func enumerateSubdomains(ctx context.Context, domain string, opts ScanOptions) []string {
	seen := map[string]bool{}

	// 1. subfinder 被动收集（多公开数据源）。
	if subs, err := enumerateWithSubfinder(ctx, domain, opts.ProviderConfigPath); err == nil {
		for _, s := range subs {
			seen[s] = true
		}
	}

	// 2. ksubdomain 主动爆破：优先提权执行（弹授权框），失败再子进程隔离执行，最后降级纯 Go。
	// 库内直调有 SDK Fatalf（os.Exit）闪退风险，父进程内只走子进程隔离版本。
	enumerated := false
	if subs, err := enumerateWithKsubdomainPrivileged(domain); err == nil && len(subs) > 0 {
		for _, s := range subs {
			seen[s] = true
		}
		enumerated = true
	}
	if !enumerated {
		if subs, err := enumerateWithKsubdomainIsolated(ctx, domain); err == nil && len(subs) > 0 {
			for _, s := range subs {
				seen[s] = true
			}
			enumerated = true
		}
	}
	if !enumerated {
		// 纯 Go 兜底：优先用 ksubdomain 完整字典的前 10000 词（覆盖更广），
		// 提高并发、缩短超时以控制在可接受时间内。
		dict := subdomainDict
		if full := GetFullSubdomainDict(); len(full) > 0 {
			const maxDict = 10000
			if len(full) > maxDict {
				dict = full[:maxDict]
			} else {
				dict = full
			}
		}
		for _, s := range bruteSubdomains(ctx, domain, dict, 500, 2*time.Second) {
			seen[s] = true
		}
	}

	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	return out
}

// bruteSubdomains 字典爆破：对每个候选前缀做 DNS 解析，能解析到的即为存活子域名。
// 这是 ksubdomain 不可用（无权限/无网卡）时的纯 Go 兜底实现。
func bruteSubdomains(ctx context.Context, domain string, dict []string, limit int, timeout time.Duration) []string {
	if len(dict) == 0 {
		dict = subdomainDict
	}
	candidates := make([]string, 0, len(dict))
	for _, prefix := range dict {
		prefix = strings.TrimSpace(prefix)
		if prefix == "" {
			continue
		}
		candidates = append(candidates, fmt.Sprintf("%s.%s", prefix, domain))
	}
	resolved := resolveBatch(ctx, candidates, limit, timeout)
	out := make([]string, 0, len(resolved))
	for host := range resolved {
		out = append(out, host)
	}
	return out
}

// defaultHTTPClient 构造带超时的 HTTP 客户端。
func defaultHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}

// readBodyLimited 限制读取大小，避免超大响应耗尽内存。
func readBodyLimited(r io.Reader, limit int64) []byte {
	if limit <= 0 {
		limit = 1 << 20 // 1MB
	}
	b, _ := io.ReadAll(io.LimitReader(r, limit))
	return b
}
