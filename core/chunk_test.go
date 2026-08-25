package core

import (
	"strconv"
	"testing"
)

func itoa(i int) string { return strconv.Itoa(i) }

// TestChunkIPs 验证 nmap 目标分批：批数、边界、空输入、部分批。
func TestChunkIPs(t *testing.T) {
	// 空输入。
	if got := chunkIPs(nil, 256); len(got) != 0 {
		t.Fatalf("chunkIPs(nil) = %v; want 空", got)
	}
	if got := chunkIPs([]string{}, 256); len(got) != 0 {
		t.Fatalf("chunkIPs(空) = %v; want 空", got)
	}

	// 恰好整除：512 条 → 2 批。
	ips := make([]string, 512)
	for i := range ips {
		ips[i] = "10.0.0." + itoa(i)
	}
	got := chunkIPs(ips, 256)
	if len(got) != 2 || len(got[0]) != 256 || len(got[1]) != 256 {
		t.Fatalf("chunkIPs(512, 256) = %d 批 %d/%d; want 2/256/256", len(got), len(got[0]), len(got[1]))
	}

	// 非整批：513 条 → 3 批（256/256/1）。
	ips = append(ips, "10.0.0.999")
	got = chunkIPs(ips, 256)
	if len(got) != 3 || len(got[0]) != 256 || len(got[1]) != 256 || len(got[2]) != 1 {
		t.Fatalf("chunkIPs(513, 256) = %d 批 %v; want 3 批（256/256/1）", len(got), len(got))
	}

	// 单条。
	got = chunkIPs([]string{"1.2.3.4"}, 256)
	if len(got) != 1 || got[0][0] != "1.2.3.4" {
		t.Fatalf("chunkIPs(单条) = %v", got)
	}

	// 非法 size 回退默认（常量 256）。
	got = chunkIPs(make([]string, 257), 0)
	if len(got) != 2 {
		t.Fatalf("chunkIPs(257, 0) = %d 批; want 2（默认 256）", len(got))
	}

	// 内容与顺序不变。
	ips = []string{"a", "b", "c", "d", "e"}
	got = chunkIPs(ips, 2)
	if len(got) != 3 || got[0][0] != "a" || got[2][0] != "e" {
		t.Fatalf("chunkIPs 顺序/内容错误: %v", got)
	}
}
