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
