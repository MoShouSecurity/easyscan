package core

import (
	"context"
	"testing"
	"time"
)

// TestBruteSubdomainsFallback 验证纯 Go 字典爆破兜底能发现常见子域名。
// 只测单个 www 候选，避免大量并发 DNS 查询压力导致的间歇性失败。
func TestBruteSubdomainsFallback(t *testing.T) {
	ctx := context.Background()
	results := bruteSubdomains(ctx, "example.com", []string{"www"}, 5, 8*time.Second)
	t.Logf("纯 Go 爆破结果 (%d): %v", len(results), results)
	if len(results) == 0 {
		t.Fatalf("纯 Go 爆破未发现 www.example.com")
	}
}
