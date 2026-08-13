package core

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// scanPort 对单个 IP:port 做 TCP connect 探测，返回是否开放。
func scanPort(ctx context.Context, ip string, port int, timeout time.Duration) bool {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// scanIPPorts 并发扫描指定 IP 的端口列表，返回开放端口。
func scanIPPorts(ctx context.Context, ip string, ports []int, limit int, timeout time.Duration) []int {
	if limit <= 0 {
		limit = 500
	}
	var open []int
	var mu sync.Mutex

	jobs := make(chan int)
	var wg sync.WaitGroup
	n := limit
	if n > len(ports) {
		n = len(ports)
	}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				if scanPort(ctx, ip, p, timeout) {
					mu.Lock()
					open = append(open, p)
					mu.Unlock()
				}
			}
		}()
	}
	for _, p := range ports {
		jobs <- p
	}
	close(jobs)
	wg.Wait()
	return open
}

// hostProbePorts 存活探测端口：TCP connect 探测这些常见端口，任一成功即视为存活。
// 覆盖 SSH/HTTP/HTTPS/SMB/RDP/常见 Web 端口，思路与 nmap -sn 的 TCP 探测一致，且无需特权。
var hostProbePorts = []int{22, 80, 443, 445, 3389, 8080}

// probePorts 依次 TCP connect 探测端口列表，任一开放即视为存活。
func probePorts(ctx context.Context, ip string, ports []int, timeout time.Duration) bool {
	for _, p := range ports {
		if ctx.Err() != nil {
			return false
		}
		if scanPort(ctx, ip, p, timeout) {
			return true
		}
	}
	return false
}

// probeHostAlive 依次 TCP connect 探测常见端口，任一开放即视为存活。
func probeHostAlive(ctx context.Context, ip string, timeout time.Duration) bool {
	return probePorts(ctx, ip, hostProbePorts, timeout)
}

// pingSweepGo 纯 Go TCP 存活探测（无 nmap 时的兜底），返回存活 IP 列表。
func pingSweepGo(ctx context.Context, ips []string, concurrency int, timeout time.Duration) []string {
	return pingSweepPorts(ctx, ips, hostProbePorts, concurrency, timeout)
}

// pingSweepPorts 并发对每个 IP 探测指定端口，任一端口连通即视为存活。
func pingSweepPorts(ctx context.Context, ips []string, ports []int, concurrency int, timeout time.Duration) []string {
	if concurrency <= 0 {
		concurrency = 500
	}
	var alive []string
	var mu sync.Mutex

	jobs := make(chan string)
	var wg sync.WaitGroup
	n := concurrency
	if n > len(ips) {
		n = len(ips)
	}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				if probePorts(ctx, ip, ports, timeout) {
					mu.Lock()
					alive = append(alive, ip)
					mu.Unlock()
				}
			}
		}()
	}
	for _, ip := range ips {
		jobs <- ip
	}
	close(jobs)
	wg.Wait()
	return alive
}

// grabBanner 连接开放端口，尝试读取一段 banner 用于服务识别。
func grabBanner(ctx context.Context, ip string, port int, timeout time.Duration) (service, banner string) {
	service = commonServices[port]

	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return service, ""
	}
	defer conn.Close()

	// 读取前最多 256 字节作为 banner。
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n > 0 {
		banner = string(buf[:n])
	}
	if service == "" && banner != "" {
		service = guessServiceFromBanner(banner)
	}
	return service, banner
}

// guessServiceFromBanner 依据 banner 关键字粗略猜测服务名。
func guessServiceFromBanner(b string) string {
	lower := strings.ToLower(b)
	switch {
	case strings.Contains(b, "SSH-"):
		return "ssh"
	case strings.Contains(lower, "http/"), strings.Contains(lower, "html"), strings.Contains(lower, "<title"):
		return "http"
	case strings.Contains(lower, "esmtp"):
		return "smtp"
	case strings.Contains(b, "220") && strings.Contains(lower, "ftp"):
		return "ftp"
	case strings.HasPrefix(b, "+OK"):
		return "pop3"
	case strings.HasPrefix(b, "* OK"):
		return "imap"
	case strings.Contains(lower, "redis"):
		return "redis"
	case strings.Contains(lower, "mysql"):
		return "mysql"
	case strings.Contains(lower, "postgresql"):
		return "postgresql"
	case strings.Contains(lower, "mongodb"):
		return "mongodb"
	default:
		return "unknown"
	}
}
