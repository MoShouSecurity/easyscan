package core

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// NmapScanner 封装 nmap 调用，用于端口扫描与服务/版本识别。
type NmapScanner struct {
	binary string
}

// NewNmapScanner 创建 nmap 扫描器，binary 为空时自动探测。
func NewNmapScanner(binary string) *NmapScanner {
	if binary == "" {
		binary = findNmap()
	}
	return &NmapScanner{binary: binary}
}

// Available 返回 nmap 是否可用。
func (n *NmapScanner) Available() bool { return n.binary != "" }

// findNmap 查找 nmap 二进制：先查 PATH，再探测各平台常见安装位置。
// GUI 应用从 Finder/桌面启动时 PATH 不含 Homebrew 目录，需显式探测（brew 安装场景）。
func findNmap() string {
	if p, err := exec.LookPath("nmap"); err == nil {
		return p
	}
	for _, p := range []string{
		"/opt/homebrew/bin/nmap", // Apple Silicon Homebrew
		"/usr/local/bin/nmap",    // Intel Homebrew / 系统
		"/opt/local/bin/nmap",    // MacPorts
		"/usr/bin/nmap",          // macOS 系统自带
	} {
		if fileExists(p) {
			return p
		}
	}
	if runtime.GOOS == "windows" {
		for _, p := range []string{
			`C:\Program Files (x86)\Nmap\nmap.exe`,
			`C:\Program Files\Nmap\nmap.exe`,
			filepath.Join(os.Getenv("LOCALAPPDATA"), "Nmap", "nmap.exe"),
		} {
			if fileExists(p) {
				return p
			}
		}
	}
	return ""
}

// fileExists 判断路径是否存在且为文件。
func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// DetectNmapPath 探测 nmap 可执行文件路径。
func DetectNmapPath() string {
	return findNmap()
}

// DetectMasscanPath 探测 masscan 可执行文件路径。
func DetectMasscanPath() string {
	return findMasscan()
}

// maxNmapArgTargets 直接作为命令行参数传给 nmap 的最大目标数。
// Windows 命令行总长限制 32767 字符，按最坏情况每个目标 16 字符（含空格）
// 留足余量取 1024；超出则改用 -iL 临时文件传入。
const maxNmapArgTargets = 1024

// targetListArgs 生成 nmap/masscan 的目标参数。目标较少时直接传参；
// 目标较多时写入临时文件并用 -iL 传入，返回的 cleanup 负责删除临时文件。
func targetListArgs(targets []string) (args []string, cleanup func(), err error) {
	if len(targets) <= maxNmapArgTargets {
		return targets, func() {}, nil
	}
	f, err := os.CreateTemp("", "easyscan-nmap-*.txt")
	if err != nil {
		return nil, nil, fmt.Errorf("创建 nmap 目标临时文件: %w", err)
	}
	cleanup = func() {
		f.Close()
		os.Remove(f.Name())
	}
	for _, t := range targets {
		if _, err := fmt.Fprintln(f, t); err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("写入 nmap 目标临时文件: %w", err)
		}
	}
	return []string{"-iL", f.Name()}, cleanup, nil
}

// nmapPortArgs 根据端口模式生成 nmap 的端口参数。custom 模式透传用户端口规范（范围语法）。
// 未知模式默认 top100，与纯 Go 路径 portList 的默认值一致（结果可比）。
func nmapPortArgs(mode, spec string) []string {
	switch mode {
	case "top100":
		return []string{"--top-ports", "100"}
	case "top1000":
		return []string{"--top-ports", "1000"}
	case "all":
		return []string{"-p", "1-65535"}
	case "custom":
		return []string{"-p", spec}
	case "test":
		return []string{"-p", "22,80,443,3389,445,8080"}
	default:
		return []string{"--top-ports", "100"}
	}
}

// PingSweep 用 nmap -sn -PE 做 ICMP echo 存活探测，返回存活 IP 列表。
// -PE 发送 ICMP echo request；局域网目标 nmap 自动用 ARP 解析 MAC（不禁用——
// 禁用 ARP 会导致局域网 ICMP 探测大量随机漏报，每次扫描结果不稳定）。
// 探测失败或未发现存活主机时返回空列表，由调用方降级。
func (n *NmapScanner) PingSweep(ctx context.Context, targets []string) []string {
	if len(targets) == 0 {
		return nil
	}
	targs, cleanup, err := targetListArgs(targets)
	if err != nil {
		return nil
	}
	defer cleanup()
	args := append([]string{"-sn", "-PE", "-T4"}, targs...)
	out, err := n.run(ctx, nil, args...)
	if err != nil || len(out) == 0 {
		return nil
	}
	var alive []string
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "Nmap scan report for") {
			continue
		}
		if ip := parseNmapReportIP(line); ip != "" {
			alive = append(alive, ip)
		}
	}
	return alive
}

// parseNmapReportIP 从 "Nmap scan report for ..." 行中提取 IP。
// 兼容 "Nmap scan report for 1.2.3.4" 与 "Nmap scan report for hostname (1.2.3.4)" 两种格式。
func parseNmapReportIP(line string) string {
	ip := strings.TrimSpace(strings.TrimPrefix(line, "Nmap scan report for"))
	if i := strings.Index(ip, " ("); i > 0 {
		ip = ip[i+2:]
		if j := strings.Index(ip, ")"); j > 0 {
			ip = ip[:j]
		}
	} else if i := strings.Index(ip, " "); i > 0 {
		ip = ip[:i] // 去掉主机名，只留 IP
	}
	if net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}

// Scan 对目标执行端口扫描 + 服务/版本识别，返回解析后的主机结果。
// -Pn 跳过主机发现：前面已单独做过 IP 存活确认，且禁 ping 的主机也能扫到。
// 扫描方式优先 SYN 半开（-sS，更快更准确）：当前进程有特权或 sudo 缓存可用时直接使用；
// 不可用或 -sS 运行失败（如 Windows 缺 Npcap 驱动）时降级 TCP connect（-sT）。
// portSpec 仅在 custom 模式使用（端口范围语法，如 1-1000,8080）。
func (n *NmapScanner) Scan(ctx context.Context, targets []string, portMode, portSpec string) ([]NmapHost, error) {
	targs, cleanup, err := targetListArgs(targets)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// --host-timeout 仅作单主机兜底上限（防异常挂死，正常主机远达不到），
	// 不限制探测重试：丢包链路上 nmap 默认重试（10 次）是准确性的保障。
	args := []string{"-sT", "-sV", "-Pn", "--open", "-T4", "--host-timeout", "300s"}
	args = append(args, nmapPortArgs(portMode, portSpec)...)
	args = append(args, "-oX", "-")
	args = append(args, targs...)

	syn := false
	prefix, canSyn := nmapSynElevation()
	if canSyn {
		synArgs := append([]string{"-sS"}, args[1:]...)
		if out, err := n.run(ctx, prefix, synArgs...); err == nil {
			return n.parseHosts(out, true)
		}
		// -sS 运行失败（驱动缺失 / 权限不足），降级 -sT 无提权重试。
	}

	out, err := n.run(ctx, nil, args...)
	if err != nil {
		return nil, err
	}
	return n.parseHosts(out, syn)
}

// parseHosts 解析 nmap XML 输出并标注扫描方式。
func (n *NmapScanner) parseHosts(out []byte, syn bool) ([]NmapHost, error) {
	hosts, err := parseNmapXML(out)
	if err != nil {
		return nil, err
	}
	for i := range hosts {
		hosts[i].Syn = syn
	}
	return hosts, nil
}

func (n *NmapScanner) run(ctx context.Context, prefix []string, args ...string) ([]byte, error) {
	full := append(append([]string{}, prefix...), n.binary)
	full = append(full, args...)
	cmd := exec.CommandContext(ctx, full[0], full[1:]...)
	HideCmdWindow(cmd)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		// 附上 stderr 摘要（权限/参数错误等诊断信息，此前用户只看到 exit status 1）。
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			if len(msg) > 300 {
				msg = msg[:300]
			}
			return nil, fmt.Errorf("%w: %s", err, msg)
		}
		return nil, err
	}
	return out, nil
}

// ---- nmap XML 解析 ----

// NmapHost 解析后的 nmap 主机结果。
type NmapHost struct {
	IP    string
	Syn   bool // 是否由 SYN 半开扫描（-sS）发现
	Ports []NmapPortResult
}

// NmapPortResult 解析后的 nmap 端口结果。
type NmapPortResult struct {
	Port     int
	Protocol string
	Service  string // 服务名，如 http/mysql/smb/ftp
	Product  string // 产品名，如 nginx/MySQL
	Version  string // 版本号
	Title    string // http-title 脚本输出
}

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddress `xml:"address"`
	Ports     nmapPorts     `xml:"ports"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string       `xml:"protocol,attr"`
	PortID   int          `xml:"portid,attr"`
	State    nmapState    `xml:"state"`
	Service  nmapService  `xml:"service"`
	Scripts  []nmapScript `xml:"script"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

type nmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

func parseNmapXML(data []byte) ([]NmapHost, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, err
	}
	var hosts []NmapHost
	for _, h := range run.Hosts {
		host := NmapHost{}
		for _, a := range h.Addresses {
			if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
				host.IP = a.Addr
				break
			}
		}
		if host.IP == "" {
			continue
		}
		for _, p := range h.Ports.Ports {
			if p.State.State != "open" {
				continue
			}
			pr := NmapPortResult{
				Port:     p.PortID,
				Protocol: p.Protocol,
				Service:  p.Service.Name,
				Product:  p.Service.Product,
				Version:  p.Service.Version,
			}
			for _, s := range p.Scripts {
				if s.ID == "http-title" {
					pr.Title = strings.TrimSpace(s.Output)
				}
			}
			host.Ports = append(host.Ports, pr)
		}
		hosts = append(hosts, host)
	}
	return hosts, nil
}
