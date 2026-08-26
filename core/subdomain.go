package core

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// persistEnumerated 把枚举到的子域名入库（IP 可为空，DNS 阶段再补）。
// store 为 nil 时跳过（CLI 场景）；写入失败返回上层，避免任务完成但资产缺失。
func persistEnumerated(store *Store, domain, taskID, source string, hosts []string) error {
	if store == nil {
		return nil
	}
	for _, host := range hosts {
		if err := store.UpsertSubdomain(Subdomain{
			ID:        newID(),
			Domain:    domain,
			Subdomain: host,
			Source:    source,
			TaskID:    taskID,
			CreatedAt: nowUnix(),
		}); err != nil {
			return fmt.Errorf("保存 %s 子域名 %s: %w", source, host, err)
		}
	}
	return nil
}

// enumerateSubdomains 合并 FOFA / subfinder 被动收集与 ksubdomain 主动爆破，
// ksubdomain 不可用（无权限/无网卡/Windows）时降级为纯 Go 字典爆破。
// 各源结果去重后立即入库（子域名 tab 展示，含未解析出 IP 的记录）。
// FOFA 独立于爆破开关（被动查库）；subfinder/ksubdomain/纯 Go 跟随 SubdomainBrute。
// FOFA 站点探测与爆破并行执行（互不阻塞），探测结果与端口扫描发现的网页
// 统一走站点去重（URL 唯一）+ 截图链。
func enumerateSubdomains(ctx context.Context, domain string, opts ScanOptions, store *Store, taskID string, report ProgressFunc) ([]string, error) {
	seen := map[string]bool{}
	var fofaResults []fofaResult

	// 1. FOFA 查询与 subfinder 并行（两者都是网络往返，互不依赖）。
	// 结果经局部变量回传；errored 用于"任一源查询失败"标记（各自独立降级）。
	var fofaErrs []string
	var subErr error
	var wg sync.WaitGroup
	if opts.FofaKey != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, err := fofaSearch(ctx, domain, opts.FofaKey, opts.ProxyURL, fofaTimeout(opts.Timeout))
			if err != nil {
				fofaErrs = append(fofaErrs, err.Error())
				return
			}
			fofaResults = results
		}()
	}
	if opts.SubdomainBrute {
		wg.Add(1)
		go func() {
			defer wg.Done()
			subs, err := enumerateWithSubfinder(ctx, domain, opts.ProviderConfigPath, opts.ProxyURL)
			if err != nil {
				subErr = err
				return
			}
			if err := persistEnumerated(store, domain, taskID, "subfinder", subs); err != nil {
				subErr = err
				return
			}
			// 主流程在 wg.Wait 之后才读 seen，此处并发写与主流程无重叠。
			for _, s := range subs {
				seen[s] = true
			}
		}()
	}
	wg.Wait()

	// 1b. 合并 FOFA 结果（查询失败独立降级；入库失败中止）。
	if opts.FofaKey != "" {
		if len(fofaErrs) > 0 {
			if report != nil {
				report("子域名枚举", "FOFA 查询失败，降级继续: "+fofaErrs[0], 5)
			}
		} else {
			for _, r := range fofaResults {
				seen[r.Host] = true
				if store != nil {
					if err := store.UpsertSubdomain(Subdomain{
						ID:        newID(),
						Domain:    domain,
						Subdomain: r.Host,
						IP:        r.IP,
						Source:    "fofa",
						TaskID:    taskID,
						CreatedAt: nowUnix(),
					}); err != nil {
						return nil, fmt.Errorf("保存 FOFA 子域名 %s: %w", r.Host, err)
					}
				}
			}
			if report != nil && len(fofaResults) > 0 {
				report("子域名枚举", fmt.Sprintf("FOFA 收集 %d 个子域名", len(fofaResults)), 5)
			}
		}
	}
	// 1c. subfinder 失败/入库失败（与现状语义一致：失败中止枚举）。
	if opts.SubdomainBrute {
		if subErr != nil {
			return nil, fmt.Errorf("subfinder 收集失败: %w", subErr)
		}
		if report != nil {
			report("子域名枚举", "subfinder 完成后进入爆破阶段", 5)
		}
	}

	// 2. FOFA 站点探测与爆破并行（probe 不写 seen，无并发问题）。
	// probe 实际探测 FOFA 端口线索，确认后保存端口和站点，与爆破互不阻塞。
	var probeDone chan error
	if len(fofaResults) > 0 && store != nil {
		probeDone = make(chan error, 1)
		go func() {
			probeDone <- probeFofaSites(ctx, fofaResults, store, taskID, opts.Timeout)
		}()
	}
	waitProbe := func() error {
		if probeDone == nil {
			return nil
		}
		err := <-probeDone
		probeDone = nil
		return err
	}

	if opts.SubdomainBrute {
		// 3. ksubdomain 主动爆破：优先提权执行（弹授权框），失败再子进程隔离执行，最后降级纯 Go。
		// 库内直调有 SDK Fatalf（os.Exit）闪退风险，父进程内只走子进程隔离版本。
		enumerated := false
		if report != nil {
			report("子域名枚举", "ksubdomain 无状态爆破 ...", 8)
		}
		if subs, err := enumerateWithKsubdomainPrivileged(domain); err == nil && len(subs) > 0 {
			if err := persistEnumerated(store, domain, taskID, "ksubdomain", subs); err != nil {
				_ = waitProbe()
				return nil, err
			}
			for _, s := range subs {
				seen[s] = true
			}
			enumerated = true
		}
		if !enumerated {
			if subs, err := enumerateWithKsubdomainIsolated(ctx, domain); err == nil && len(subs) > 0 {
				if err := persistEnumerated(store, domain, taskID, "ksubdomain", subs); err != nil {
					_ = waitProbe()
					return nil, err
				}
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
			if err := persistEnumerated(store, domain, taskID, "brute", brute); err != nil {
				_ = waitProbe()
				return nil, err
			}
			for _, s := range brute {
				seen[s] = true
			}
		}
	}

	if probeDone != nil {
		if err := waitProbe(); err != nil {
			return nil, err
		}
	}

	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	return out, nil
}

// probeFofaSites 并发探测 FOFA 带端口线索的站点（http/https，Host 头=子域名），
// 实际 HTTP(S) 探测成功才保存端口和站点，不能把未验证的搜索线索当成开放端口。
// 限并发 20，避免大量结果时打满网络；与爆破并行调用，互不阻塞。
func probeFofaSites(ctx context.Context, results []fofaResult, store *Store, taskID string, timeout time.Duration) error {
	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup
	var firstErr error
	var errOnce sync.Once
	for _, r := range results {
		if r.Port <= 0 {
			continue
		}
		wg.Add(1)
		go func(r fofaResult) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			for _, scheme := range fofaWebSchemes(r.Port) {
				if ctx.Err() != nil {
					return
				}
				if site, ok := probeSite(ctx, r.IP, r.Port, scheme, r.Host, timeout); ok {
					site.TaskID = taskID
					service := "http"
					if strings.HasPrefix(site.URL, "https://") {
						service = "https"
					}
					// 先落盘端口；站点写入失败也不能丢失已经确认的 TCP 结果。
					if err := store.UpsertPort(Port{
						ID: newID(), IP: site.IP, Port: site.Port, Protocol: "tcp",
						Service: service, Title: site.Title, Confidence: ConfidencePureGo,
						TaskID: taskID, CreatedAt: site.CreatedAt,
					}); err != nil {
						errOnce.Do(func() { firstErr = fmt.Errorf("保存 FOFA 确认端口 %s:%d: %w", site.IP, site.Port, err) })
						return
					}
					if err := store.UpsertSite(site); err != nil {
						errOnce.Do(func() { firstErr = fmt.Errorf("保存 FOFA 站点 %s: %w", site.URL, err) })
					}
					return
				}
			}
		}(r)
	}
	wg.Wait()
	return firstErr
}

// fofaWebSchemes 返回 FOFA 端口线索的协议探测顺序。常见 TLS 端口必须优先 HTTPS，
// 避免同时接受明文 HTTP 的 443 端口先被记录为 http://host:443；未知端口仍保留
// HTTP/HTTPS 双探测，以免遗漏部署在非标准端口上的 Web 服务。
func fofaWebSchemes(port int) []string {
	if schemes := webSchemes(port, ""); len(schemes) > 0 {
		return schemes
	}
	return []string{"http", "https"}
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

// readBodyLimited 限制读取大小，避免超大响应耗尽内存。
// 返回读取错误（截断响应调用方应视为不完整，不参与精确匹配）。
func readBodyLimited(r io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = 1 << 20 // 1MB
	}
	return io.ReadAll(io.LimitReader(r, limit))
}
