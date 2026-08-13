package core

import (
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"os/exec"
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

// findNmap 查找 nmap 二进制。
func findNmap() string {
	if p, err := exec.LookPath("nmap"); err == nil {
		return p
	}
	return ""
}

// DetectNmapPath 探测 nmap 可执行文件路径。
func DetectNmapPath() string {
	return findNmap()
}

// DetectMasscanPath 探测 masscan 可执行文件路径。
func DetectMasscanPath() string {
	if p, err := exec.LookPath("masscan"); err == nil {
		return p
	}
	return ""
}

// maxNmapArgTargets 直接作为命令行参数传给 nmap 的最大目标数。
// Windows 命令行总长限制 32767 字符，按最坏情况每个目标 16 字符（含空格）
// 留足余量取 1024；超出则改用 -iL 临时文件传入。
const maxNmapArgTargets = 1024

// nmapTargetArgs 生成 nmap 的目标参数。目标较少时直接传参；
// 目标较多时写入临时文件并用 -iL 传入，返回的 cleanup 负责删除临时文件。
func nmapTargetArgs(targets []string) (args []string, cleanup func(), err error) {
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

// nmapPortArgs 根据端口模式生成 nmap 的端口参数。
func nmapPortArgs(mode string) []string {
	switch mode {
	case "top100":
		return []string{"--top-ports", "100"}
	case "top1000":
		return []string{"--top-ports", "1000"}
	case "all":
		return []string{"-p", "1-65535"}
	default: // test
		return []string{"-p", "22,80,8080,3389,445"}
	}
}

// PingSweep 用 nmap -sn 做主机存活探测，返回存活 IP 列表。
// -sn 会综合 ICMP echo + TCP SYN(80/443) + ARP 探测，即使禁 ping 也能发现存活主机。
// 探测失败或未发现存活主机时返回空列表，由调用方降级为纯 Go TCP 探测，
// 避免把网段内不存在的 IP 全部当成存活。
func (n *NmapScanner) PingSweep(ctx context.Context, targets []string) []string {
	if len(targets) == 0 {
		return nil
	}
	targs, cleanup, err := nmapTargetArgs(targets)
	if err != nil {
		return nil
	}
	defer cleanup()
	args := append([]string{"-sn", "-T4"}, targs...)
	out, err := n.run(ctx, args...)
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
func (n *NmapScanner) Scan(ctx context.Context, targets []string, portMode string) ([]NmapHost, error) {
	targs, cleanup, err := nmapTargetArgs(targets)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	args := []string{"-sT", "-sV", "-Pn", "--open", "-T4"}
	args = append(args, nmapPortArgs(portMode)...)
	args = append(args, "-oX", "-")
	args = append(args, targs...)

	out, err := n.run(ctx, args...)
	if err != nil {
		return nil, err
	}
	return parseNmapXML(out)
}

func (n *NmapScanner) run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, n.binary, args...)
	HideCmdWindow(cmd)
	return cmd.Output()
}

// ---- nmap XML 解析 ----

// NmapHost 解析后的 nmap 主机结果。
type NmapHost struct {
	IP    string
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
