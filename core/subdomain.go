package core

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// persistEnumerated 把枚举到的子域名入库（IP 可为空，DNS 阶段再补）。
// store 为 nil 时跳过（CLI 场景）；单条失败忽略，不阻断枚举流程。
func persistEnumerated(store *Store, domain, taskID, source string, hosts []string) {
	if store == nil {
		return
	}
	for _, host := range hosts {
		_ = store.UpsertSubdomain(Subdomain{
			ID:        newID(),
			Domain:    domain,
			Subdomain: host,
			Source:    source,
			TaskID:    taskID,
			CreatedAt: nowUnix(),
		})
	}
}

// enumerateSubdomains 合并 FOFA / subfinder 被动收集与 ksubdomain 主动爆破，
// ksubdomain 不可用（无权限/无网卡/Windows）时降级为纯 Go 字典爆破。
// 各源结果立即入库（子域名 tab 展示，含未解析出 IP 的记录）。
// FOFA 独立于爆破开关（被动查库）；subfinder/ksubdomain/纯 Go 跟随 SubdomainBrute。
func enumerateSubdomains(ctx context.Context, domain string, opts ScanOptions, store *Store, taskID string, report ProgressFunc) []string {
	seen := map[string]bool{}

	// 1. FOFA 被动收集（配置了 API key 才执行），子域名与 IP 直接入库；
	// 带端口线索的记录直接探测站点入库（进入后续指纹/截图流程）。
	if opts.FofaKey != "" {
		results, err := fofaSearch(ctx, domain, opts.FofaKey, opts.ProxyURL, fofaTimeout(opts.Timeout))
		if err != nil {
			if report != nil {
				report("子域名枚举", "FOFA 查询失败，降级继续: "+err.Error(), 5)
			}
		} else {
			for _, r := range results {
				seen[r.Host] = true
				if store != nil {
					_ = store.UpsertSubdomain(Subdomain{
						ID:        newID(),
						Domain:    domain,
						Subdomain: r.Host,
						IP:        r.IP,
						Source:    "fofa",
						TaskID:    taskID,
						CreatedAt: nowUnix(),
					})
					// FOFA 收录的端口在端口扫描模式之外也可能开放 Web 服务，
					// 直接用子域名做 Host 头探测 http/https，命中即入库站点（截图链）。
					if r.Port > 0 {
						for _, scheme := range []string{"http", "https"} {
							if site, ok := probeSite(ctx, r.IP, r.Port, scheme, r.Host, opts.Timeout); ok {
								site.TaskID = taskID
								_ = store.UpsertSite(site)
								break
							}
						}
					}
				}
			}
			if report != nil && len(results) > 0 {
				report("子域名枚举", fmt.Sprintf("FOFA 收集 %d 个子域名", len(results)), 5)
			}
		}
	}

	if opts.SubdomainBrute {
		// 2. subfinder 被动收集（多公开数据源，走代理）。
		if subs, err := enumerateWithSubfinder(ctx, domain, opts.ProviderConfigPath, opts.ProxyURL); err == nil {
			persistEnumerated(store, domain, taskID, "subfinder", subs)
			for _, s := range subs {
				seen[s] = true
			}
		}

		// 3. ksubdomain 主动爆破：优先提权执行（弹授权框），失败再子进程隔离执行，最后降级纯 Go。
		// 库内直调有 SDK Fatalf（os.Exit）闪退风险，父进程内只走子进程隔离版本。
		enumerated := false
		if subs, err := enumerateWithKsubdomainPrivileged(domain); err == nil && len(subs) > 0 {
			persistEnumerated(store, domain, taskID, "ksubdomain", subs)
			for _, s := range subs {
				seen[s] = true
			}
			enumerated = true
		}
		if !enumerated {
			if subs, err := enumerateWithKsubdomainIsolated(ctx, domain); err == nil && len(subs) > 0 {
				persistEnumerated(store, domain, taskID, "ksubdomain", subs)
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
			brute := bruteSubdomains(ctx, domain, dict, 500, 2*time.Second)
			persistEnumerated(store, domain, taskID, "brute", brute)
			for _, s := range brute {
				seen[s] = true
			}
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
