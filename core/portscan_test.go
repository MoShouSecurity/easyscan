package core

import (
	"context"
	"net"
	"testing"
	"time"
)

// listenFreePort 在 127.0.0.1 上监听一个随机空闲端口。
func listenFreePort(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen 127.0.0.1:0: %v", err)
	}
	return ln
}

// closedPort 返回一个刚释放的空闲端口（无服务监听，连接会立即被拒绝）。
func closedPort(t *testing.T) int {
	t.Helper()
	ln := listenFreePort(t)
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// TestPingSweepPortsAlive 验证 TCP 探测能识别真实存活主机（监听探测端口即视为存活）。
func TestPingSweepPortsAlive(t *testing.T) {
	ctx := context.Background()
	ln := listenFreePort(t)
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	alive := pingSweepPorts(ctx, []string{"127.0.0.1"}, []int{port}, 4, time.Second)
	if len(alive) != 1 || alive[0] != "127.0.0.1" {
		t.Fatalf("pingSweepPorts = %v; want [127.0.0.1]", alive)
	}
}

// TestPingSweepPortsDead 验证探测端口全不可达的 IP 不会被判为存活（网段扫描收录不存在 IP 的回归测试）。
func TestPingSweepPortsDead(t *testing.T) {
	ctx := context.Background()
	port := closedPort(t)

	alive := pingSweepPorts(ctx, []string{"127.0.0.1"}, []int{port}, 4, time.Second)
	if len(alive) != 0 {
		t.Fatalf("pingSweepPorts = %v; want 空列表（端口全关的 IP 不应判为存活）", alive)
	}
}

// TestProbePorts 验证单主机探测：任一端口开放即存活，全关则不存活。
func TestProbePorts(t *testing.T) {
	ctx := context.Background()

	ln := listenFreePort(t)
	openPort := ln.Addr().(*net.TCPAddr).Port
	deadPort := closedPort(t)
	defer ln.Close()

	if !probePorts(ctx, "127.0.0.1", []int{deadPort, openPort}, time.Second) {
		t.Fatal("probePorts: 存在开放端口时应判为存活")
	}
	if probePorts(ctx, "127.0.0.1", []int{deadPort}, time.Second) {
		t.Fatal("probePorts: 端口全关时应判为不存活")
	}
}

// TestScanPortRetryOpen 验证重试探测能检出本地开放端口。
func TestScanPortRetryOpen(t *testing.T) {
	ctx := context.Background()
	ln := listenFreePort(t)
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	if !scanPortRetry(ctx, "127.0.0.1", port, 200*time.Millisecond, 2) {
		t.Fatal("scanPortRetry 应检出本地开放端口")
	}
}

// TestScanPortRetryClosed 验证重试探测不会把已关闭端口判为开放，且重试耗时有界。
func TestScanPortRetryClosed(t *testing.T) {
	ctx := context.Background()
	port := closedPort(t)

	start := time.Now()
	if scanPortRetry(ctx, "127.0.0.1", port, 50*time.Millisecond, 2) {
		t.Fatal("scanPortRetry 不应把已关闭端口判为开放")
	}
	// 3 次探测（1 初始 + 2 重试），超时递增 50/75/112ms，总耗时不应远超上限。
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("scanPortRetry 耗时 %v，重试超时未按预期收敛", elapsed)
	}
}

// TestScanPortRetryCtxCancel 已取消的 ctx 应立即停止重试。
func TestScanPortRetryCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if scanPortRetry(ctx, "127.0.0.1", 1, 50*time.Millisecond, 2) {
		t.Fatal("已取消的 ctx 不应检出端口")
	}
}

// TestMeasureRTT 验证 RTT 测量：本地 loopback 应测得正耗时，空端口列表返回 0。
func TestMeasureRTT(t *testing.T) {
	ctx := context.Background()
	ln := listenFreePort(t)
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	rtt := measureRTT(ctx, "127.0.0.1", []int{port}, 500*time.Millisecond)
	if rtt <= 0 || rtt > 500*time.Millisecond {
		t.Fatalf("measureRTT = %v; want (0, 500ms]", rtt)
	}

	if rtt := measureRTT(ctx, "127.0.0.1", nil, 100*time.Millisecond); rtt != 0 {
		t.Fatalf("measureRTT(空端口) = %v; want 0", rtt)
	}
}

// TestScanIPPorts 验证并发扫描只检出开放端口（动态超时 + 重试路径）。
func TestScanIPPorts(t *testing.T) {
	ctx := context.Background()
	ln := listenFreePort(t)
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	dead := closedPort(t)

	open := scanIPPorts(ctx, "127.0.0.1", []int{port, dead}, 10, 200*time.Millisecond)
	if len(open) != 1 || open[0] != port {
		t.Fatalf("scanIPPorts = %v; want [%d]", open, port)
	}
}
