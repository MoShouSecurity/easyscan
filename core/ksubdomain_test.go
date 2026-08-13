package core

import (
	"context"
	"testing"
	"time"
)

// TestBruteSubdomainsFallback 验证纯 Go 字典爆破兜底能发现常见子域名。
func TestBruteSubdomainsFallback(t *testing.T) {
	ctx := context.Background()
	results := bruteSubdomains(ctx, "example.com", subdomainDict, 100, 5*time.Second)
	t.Logf("纯 Go 爆破结果 (%d): %v", len(results), results)
	if len(results) == 0 {
		t.Fatalf("纯 Go 爆破未发现任何子域名（预期至少 www.example.com）")
	}
}
