// Package-level ksubdomain 无状态爆破集成（三端共用）。
// Windows 上 gopacket/pcap 通过纯 Go 方式动态加载 Npcap DLL（运行时需安装 Npcap 驱动），
// macOS/Linux 使用 libpcap（CGO）。运行权限不足或驱动缺失时由调用方降级为纯 Go 字典爆破。
package core

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	ksubdomain "github.com/boy-hack/ksubdomain/v2/pkg/core"
	"github.com/boy-hack/ksubdomain/v2/pkg/core/options"
	"github.com/boy-hack/ksubdomain/v2/pkg/device"
	"github.com/boy-hack/ksubdomain/v2/pkg/runner"
	"github.com/boy-hack/ksubdomain/v2/pkg/runner/outputter"
	"github.com/boy-hack/ksubdomain/v2/pkg/runner/processbar"
	"github.com/boy-hack/ksubdomain/v2/pkg/runner/result"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// subdomainCollector 实现 ksubdomain 的 outputter.Output，收集爆破结果。
type subdomainCollector struct {
	mu      sync.Mutex
	domains []string
}

func (c *subdomainCollector) WriteDomainResult(r result.Result) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.domains = append(c.domains, r.Subdomain)
	return nil
}

func (c *subdomainCollector) Close() error { return nil }

// EnumerateWithKsubdomain 导出 ksubdomain 枚举（供 CLI helper 模式与提权调用）。
func EnumerateWithKsubdomain(ctx context.Context, domain string) ([]string, error) {
	return enumerateWithKsubdomain(ctx, domain)
}

// ksubdomainConfigFile 返回 ksubdomain 网卡配置（ksubdomain.yaml）的稳定路径：
// 应用配置目录（如 ~/Library/Application Support/EasyScan），与 cwd 无关。
// GUI 从 Finder 启动时 cwd=/，读不到 cwd 下的配置会走 30 秒网卡自动识别
// （且识别失败 SDK 直接 Fatalf 杀进程）；配置落盘到稳定路径后二次扫描直接命中。
func ksubdomainConfigFile() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return "ksubdomain.yaml"
	}
	return filepath.Join(dir, "EasyScan", "ksubdomain.yaml")
}

// enumerateWithKsubdomainIsolated 以子进程（--ksubdomain-enum helper 模式）执行 ksubdomain 枚举。
// SDK 内部多处 gologger.Fatalf 会直接 os.Exit(1)（网卡/DNS 识别失败等），
// 库内直调会杀死 GUI 进程且 recover 无法拦截；子进程隔离后崩溃只影响 helper，
// 父进程收到非零退出码即可优雅降级为纯 Go 字典爆破。
func enumerateWithKsubdomainIsolated(ctx context.Context, domain string) ([]string, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, exe, "--ksubdomain-enum", domain)
	HideCmdWindow(cmd)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return parseSubdomainOutput(out), nil
}

// GetFullSubdomainDict 返回 ksubdomain 内置完整字典（约 10 万词）。
func GetFullSubdomainDict() []string {
	return ksubdomain.GetDefaultSubdomainData()
}

// testKsubdomainSpeed 测试网卡最大发包速度，返回每秒包数（pps）。
// 参考 ksubdomain 的 test 命令：设置错误 dstmac，让包经过网卡但发不出去，测网卡发包能力。
func testKsubdomainSpeed(ether *device.EtherTable) (int64, error) {
	testEther := *ether
	testEther.DstMac = device.SelfMac(net.HardwareAddr{0x5c, 0xc9, 0x09, 0x33, 0x34, 0x80})

	handle, err := device.PcapInit(testEther.Device)
	if err != nil {
		return 0, err
	}
	defer handle.Close()

	dstIP := net.ParseIP("1.1.1.2").To4()
	eth := &layers.Ethernet{
		SrcMAC:       testEther.SrcMac.HardwareAddr(),
		DstMAC:       testEther.DstMac.HardwareAddr(),
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      255,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    testEther.SrcIp,
		DstIP:    dstIP,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(5555),
		DstPort: layers.UDPPort(53),
	}
	_ = udp.SetNetworkLayerForChecksum(ip)
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}

	dns := &layers.DNS{
		ID:      0x2021,
		QDCount: 1,
		RD:      true,
		Questions: []layers.DNSQuestion{
			{Name: []byte("www.hacking8.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
		},
	}

	var index int64
	start := time.Now()
	for time.Since(start) < 5*time.Second {
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, dns); err != nil {
			continue
		}
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			if !strings.Contains(err.Error(), "No buffer space available") {
				return 0, err
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		index++
	}
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		return 0, fmt.Errorf("测速时间异常")
	}
	return int64(float64(index) / elapsed), nil
}

// enumerateWithKsubdomain 用 ksubdomain 无状态爆破枚举子域名。
// 注意：本函数在 helper 子进程内执行（父进程通过 enumerateWithKsubdomainIsolated /
// 提权机制调用），SDK 内部 Fatalf（os.Exit）风险被进程隔离。
func enumerateWithKsubdomain(ctx context.Context, domain string) ([]string, error) {
	// 固定网卡配置路径（应用配置目录）：GUI 从 Finder 启动时 cwd=/，
	// 默认在 cwd 找 ksubdomain.yaml 会落空并触发 30 秒网卡自动识别。
	// 无条件设置：首次识别成功后 saveConfig 会落盘到该路径，二次扫描直接命中。
	cfgFile := ksubdomainConfigFile()
	_ = os.MkdirAll(filepath.Dir(cfgFile), 0o755)
	_ = os.Setenv("ksubdomain-config", cfgFile)
	resolvers := options.GetResolvers(nil)
	ether := options.GetDeviceConfig(resolvers)

	// 先测网卡速度，用测速结果的 80% 作为爆破速率。
	rate := int64(0)
	if pps, err := testKsubdomainSpeed(ether); err == nil && pps > 0 {
		rate = pps * 80 / 100
	}
	if rate <= 0 {
		rate = options.Band2Rate("5m")
	}

	dict := ksubdomain.GetDefaultSubdomainData()
	render := make(chan string, 4096)
	go func() {
		defer close(render)
		for _, sub := range dict {
			select {
			case <-ctx.Done():
				return
			case render <- sub + "." + domain:
			}
		}
	}()

	col := &subdomainCollector{domains: make([]string, 0, 4096)}

	opt := &options.Options{
		Rate:       rate,
		Domain:     render,
		Resolvers:  resolvers,
		TimeOut:    6,
		Retry:      3,
		Method:     options.VerifyType,
		Writer:     []outputter.Output{col},
		ProcessBar: &processbar.ScreenProcess{Silent: true},
	}
	opt.Check()
	opt.EtherInfo = ether

	r, err := runner.New(opt)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	r.RunEnumeration(ctx)
	return col.domains, nil
}
