package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
)

// MasscanScanner 封装 masscan 调用，用于纯 ICMP echo 存活探测。
type MasscanScanner struct {
	binary string
	rate   int // 发包速率（包/秒）
}

// NewMasscanScanner 创建 masscan 扫描器，binary 为空时自动探测。
func NewMasscanScanner(binary string) *MasscanScanner {
	if binary == "" {
		binary = findMasscan()
	}
	return &MasscanScanner{binary: binary, rate: 1000}
}

// Available 返回 masscan 是否可用。
func (m *MasscanScanner) Available() bool { return m.binary != "" }

// findMasscan 查找 masscan 二进制：先查 PATH，再探测各平台常见安装位置。
// GUI 应用从 Finder/桌面启动时 PATH 不含 Homebrew 目录，需显式探测。
func findMasscan() string {
	if p, err := exec.LookPath("masscan"); err == nil {
		return p
	}
	for _, p := range []string{
		"/opt/homebrew/bin/masscan", // Apple Silicon Homebrew
		"/usr/local/bin/masscan",    // Intel Homebrew
		"/opt/local/bin/masscan",    // MacPorts
	} {
		if fileExists(p) {
			return p
		}
	}
	return ""
}

// PingScan 用 masscan 纯 ICMP echo 探测（--ping）主机存活，返回存活 IP 列表。
// 目标为原始 IP/CIDR 条目（不展开，避免大网段展开成海量参数）。
// 探测失败（驱动缺失 / 无权限 / 非零退出）时返回错误，由调用方降级。
func (m *MasscanScanner) PingScan(ctx context.Context, targets []string) ([]string, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	targs, cleanup, err := targetListArgs(targets)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// --ping 纯 ICMP echo（此前误用 nmap 语法 -PE，masscan 直接报 unsupported
	// option 退出，探测从未真正执行）；--retries 3 减少丢包漏报；
	// --wait 5 收尾等待：局域网设备（WiFi 节能唤醒/ARP 慢）响应常超 2s，
	// 等待过短会随机漏报导致每次扫描结果不同（5s 是准确性与耗时的折中）。
	args := []string{"--ping", "--rate", fmt.Sprintf("%d", m.rate), "--retries", "3", "--wait", "5", "-oJ", "-"}
	args = append(args, targs...)

	out, err := m.run(ctx, args...)
	if err != nil {
		return nil, err
	}
	return parseMasscanJSON(out)
}

func (m *MasscanScanner) run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, m.binary, args...)
	HideCmdWindow(cmd)
	return cmd.Output()
}

// ipRegex 兜底提取 masscan 输出中的 ip 字段。
var ipRegex = regexp.MustCompile(`"ip"\s*:\s*"([^"]+)"`)

// parseMasscanJSON 解析 masscan -oJ 输出，返回去重后的存活 IP 列表。
// 兼容 JSON 数组、逐行 JSON 对象、带前缀噪音三种形态，最后用正则兜底；
// 全部失败时返回错误（触发调用方降级）。
func parseMasscanJSON(data []byte) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(ip string) {
		ip = strings.TrimSpace(ip)
		if net.ParseIP(ip) != nil && !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}

	// 1. JSON 数组（容忍 stdout 上前缀噪音，如 [WARNING] 行）。
	text := bytes.TrimSpace(data)
	if i := bytes.IndexByte(text, '['); i >= 0 {
		text = text[i:]
	}
	var hosts []struct {
		IP string `json:"ip"`
	}
	if err := json.Unmarshal(text, &hosts); err == nil {
		for _, h := range hosts {
			add(h.IP)
		}
		if len(out) > 0 {
			return out, nil
		}
	}

	// 2. 逐行 JSON 对象。
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var h struct {
			IP string `json:"ip"`
		}
		if err := dec.Decode(&h); err != nil {
			break
		}
		add(h.IP)
	}
	if len(out) > 0 {
		return out, nil
	}

	// 3. 正则兜底。
	for _, m := range ipRegex.FindAllSubmatch(data, -1) {
		add(string(m[1]))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("解析 masscan 输出失败，未找到存活 IP")
	}
	return out, nil
}
