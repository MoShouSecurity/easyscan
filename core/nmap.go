package core

import (
	"context"
	"encoding/xml"
	"net"
	"os/exec"
	"strings"
)

// NmapScanner 封装 nmap 调用，用于端口扫描与服务/版本识别。
type NmapScanner struct {
	binary string
}

// NewNmapScanner 检测 nmap 并创建扫描器。
func NewNmapScanner() *NmapScanner {
	return &NmapScanner{binary: findNmap()}
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
func (n *NmapScanner) PingSweep(ctx context.Context, targets []string) []string {
	if len(targets) == 0 {
		return nil
	}
	args := append([]string{"-sn", "-T4"}, targets...)
	out, err := n.run(ctx, args...)
	if err != nil || len(out) == 0 {
		return targets // 探测失败则回退原列表
	}
	var alive []string
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "Nmap scan report for") {
			continue
		}
		ip := strings.TrimSpace(strings.TrimPrefix(line, "Nmap scan report for"))
		if i := strings.Index(ip, " "); i > 0 {
			ip = ip[:i] // 去掉主机名，只留 IP
		}
		if net.ParseIP(ip) != nil {
			alive = append(alive, ip)
		}
	}
	if len(alive) == 0 {
		return targets
	}
	return alive
}

// Scan 对目标执行端口扫描 + 服务/版本识别，返回解析后的主机结果。
// -Pn 跳过主机发现：前面已单独做过 IP 存活确认，且禁 ping 的主机也能扫到。
func (n *NmapScanner) Scan(ctx context.Context, targets []string, portMode string) ([]NmapHost, error) {
	args := []string{"-sT", "-sV", "-Pn", "--open", "-T4"}
	args = append(args, nmapPortArgs(portMode)...)
	args = append(args, "-oX", "-")
	args = append(args, targets...)

	out, err := n.run(ctx, args...)
	if err != nil {
		return nil, err
	}
	return parseNmapXML(out)
}

func (n *NmapScanner) run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, n.binary, args...)
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
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
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
