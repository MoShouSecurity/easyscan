// 端口扫描基准对比：以 nmap 为基准（ground truth），量化纯 Go 降级路径的
// 召回率与误报率，用于验证扫描准确性与调优。
package core

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// PortBenchResult 单端口（ip:port）两种扫描方式的检出对比。
type PortBenchResult struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Nmap    bool   `json:"nmap"`              // nmap 检出
	PureGo  bool   `json:"pure_go"`           // 纯 Go 检出
	Product string `json:"product,omitempty"` // nmap 识别的产品
	Version string `json:"version,omitempty"` // nmap 识别的版本
}

// BenchmarkReport 一次基准对比的完整报告。
type BenchmarkReport struct {
	Target   string            `json:"target"`
	PortMode string            `json:"port_mode"`
	Ports    int               `json:"ports_scanned"`
	NmapOpen int               `json:"nmap_open"`
	GoOpen   int               `json:"pure_go_open"`
	Common   int               `json:"common_open"`
	NmapOnly int               `json:"nmap_only"`    // 纯 Go 漏报数
	GoOnly   int               `json:"pure_go_only"` // 纯 Go 误报数
	Recall   float64           `json:"recall"`       // 纯 Go 召回率 = common / nmap_open
	FalsePos float64           `json:"false_positive_rate"`
	NmapTime time.Duration     `json:"nmap_duration_ns"`
	GoTime   time.Duration     `json:"pure_go_duration_ns"`
	Details  []PortBenchResult `json:"details"`
}

// RunPortBenchmark 对目标执行 nmap 与纯 Go 两种扫描并对比结果。
// 不依赖数据库，nmap 不可用时返回错误（无基准无法对比）。
func RunPortBenchmark(ctx context.Context, target, portMode, portSpec string, opts ScanOptions) (*BenchmarkReport, error) {
	ips, err := expandTarget(target)
	if err != nil {
		return nil, err
	}
	nmapTargets, _ := splitTargets(target)
	ports := portList(portMode, portSpec)
	if len(ports) == 0 {
		return nil, fmt.Errorf("无效的端口模式或规范: %s %s", portMode, portSpec)
	}

	rep := &BenchmarkReport{
		Target:   target,
		PortMode: portMode,
		Ports:    len(ports),
		Details:  make([]PortBenchResult, 0),
	}

	// 1. nmap 基准扫描（服务/版本识别）。
	nmap := NewNmapScanner(opts.NmapPath)
	if !nmap.Available() {
		return nil, fmt.Errorf("未找到 nmap，无法建立基准")
	}
	nmapSet := map[string]NmapPortResult{} // "ip:port" -> nmap 结果
	start := time.Now()
	hosts, err := nmap.Scan(ctx, nmapTargets, portMode, portSpec)
	rep.NmapTime = time.Since(start)
	if err != nil {
		return nil, fmt.Errorf("nmap 扫描失败: %w", err)
	}
	for _, h := range hosts {
		for _, p := range h.Ports {
			nmapSet[fmt.Sprintf("%s:%d", h.IP, p.Port)] = p
		}
	}

	// 2. 纯 Go 扫描（同一端口列表、同一超时/并发参数）。
	goSet := map[string]bool{}
	start = time.Now()
	for _, ip := range ips {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		for _, p := range scanIPPorts(ctx, ip, ports, opts.Concurrency, opts.Timeout) {
			goSet[fmt.Sprintf("%s:%d", ip, p)] = true
		}
	}
	rep.GoTime = time.Since(start)

	// 3. 汇总对比。
	keys := make([]string, 0, len(nmapSet)+len(goSet))
	seen := map[string]bool{}
	for k := range nmapSet {
		keys, seen[k] = append(keys, k), true
	}
	for k := range goSet {
		if !seen[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		ip, portStr, _ := strings.Cut(k, ":")
		port, _ := strconv.Atoi(portStr)
		d := PortBenchResult{IP: ip, Port: port, PureGo: goSet[k]}
		if r, ok := nmapSet[k]; ok {
			d.Nmap = true
			d.Product, d.Version = r.Product, r.Version
		}
		rep.Details = append(rep.Details, d)
	}
	rep.NmapOpen = len(nmapSet)
	rep.GoOpen = len(goSet)
	for _, d := range rep.Details {
		switch {
		case d.Nmap && d.PureGo:
			rep.Common++
		case d.Nmap && !d.PureGo:
			rep.NmapOnly++
		case !d.Nmap && d.PureGo:
			rep.GoOnly++
		}
	}
	if rep.NmapOpen > 0 {
		rep.Recall = float64(rep.Common) / float64(rep.NmapOpen)
	}
	if rep.GoOpen > 0 {
		rep.FalsePos = float64(rep.GoOnly) / float64(rep.GoOpen)
	}
	return rep, nil
}
