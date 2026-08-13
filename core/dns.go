package core

import (
	"context"
	"net"
	"sync"
	"time"
)

// resolveHost 解析域名 A 记录，返回去重后的 IPv4/IPv6 列表（空表示解析失败）。
func resolveHost(ctx context.Context, host string, timeout time.Duration) []string {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupHost(cctx, host)
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

// resolveBatch 并发解析一组主机，返回 host -> IP 列表。并发度由 limit 控制。
func resolveBatch(ctx context.Context, hosts []string, limit int, timeout time.Duration) map[string][]string {
	if limit <= 0 {
		limit = 100
	}
	result := make(map[string][]string, len(hosts))

	type job struct {
		host string
	}
	type res struct {
		host string
		ips  []string
	}

	jobs := make(chan job)
	results := make(chan res, len(hosts))

	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for j := range jobs {
			results <- res{j.host, resolveHost(ctx, j.host, timeout)}
		}
	}

	n := limit
	if n > len(hosts) {
		n = len(hosts)
	}
	wg.Add(n)
	for i := 0; i < n; i++ {
		go worker()
	}

	go func() {
		for _, h := range hosts {
			jobs <- job{h}
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	for r := range results {
		if len(r.ips) > 0 {
			result[r.host] = r.ips
		}
	}
	return result
}
