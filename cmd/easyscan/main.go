// Command easyscan 是 EasyScan 引擎的 CLI 入口，用于独立运行与验证侦察流程。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"easyscan/core"
)

func main() {
	var (
		target   = flag.String("target", "", "目标域名或 IP/网段，如 example.com 或 1.2.3.0/24")
		typ      = flag.String("type", "domain", "任务类型: domain / ip")
		ports    = flag.String("ports", "top100", "端口模式: test / top100 / top1000 / all")
		db       = flag.String("db", "easyscan.db", "SQLite 数据库路径")
		noBrute  = flag.Bool("no-brute", false, "关闭子域名字典爆破")
		noShot   = flag.Bool("no-shot", false, "关闭站点截图")
		shotDir  = flag.String("shot-dir", "screenshots", "截图保存目录")
		bench    = flag.Bool("bench", false, "端口扫描基准对比（nmap vs 纯 Go），不写库")
		jsonOut  = flag.Bool("json", false, "benchmark 输出 JSON（供脚本消费）")
		fofaKey  = flag.String("fofa-key", "", "FOFA API key（子域名收集，留空跳过）")
		proxy    = flag.String("proxy", "", "HTTP 代理（FOFA/subfinder 出站请求），如 http://127.0.0.1:7890")
		fileLeak = flag.Bool("file-leak", false, "开启文件泄漏扫描")
		leakDict = flag.String("leak-dict", "", "文件泄漏字典文件（每行：路径 [类型]）")
		dirScan  = flag.Bool("dir-scan", false, "开启 Web 路径发现（目录/路由/文件）")
		dirDict  = flag.String("dir-dict", "", "路径发现字典文件（路径后可附类型）")
		pathMode = flag.String("path-mode", core.PathScanModeQuick, "路径扫描强度: quick / deep")
	)
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "用法: easyscan -target example.com [-type domain] [-ports top100]")
		flag.Usage()
		os.Exit(2)
	}
	if err := core.ValidatePathScanMode(*pathMode); err != nil {
		fmt.Fprintf(os.Stderr, "路径扫描强度无效: %v\n", err)
		os.Exit(2)
	}

	if *bench {
		opts := core.DefaultScanOptions()
		opts.PortMode = *ports
		report, err := core.RunPortBenchmark(context.Background(), *target, *ports, "", opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "基准对比失败: %v\n", err)
			os.Exit(1)
		}
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(report); err != nil {
				fmt.Fprintf(os.Stderr, "输出 JSON 失败: %v\n", err)
				os.Exit(1)
			}
			return
		}
		printBenchmark(report)
		return
	}

	store, err := core.OpenStore(*db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "打开数据库失败: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	opts := core.DefaultScanOptions()
	opts.PortMode = *ports
	opts.SubdomainBrute = !*noBrute
	opts.Screenshot = !*noShot
	opts.ScreenshotDir = *shotDir
	opts.FofaKey = *fofaKey
	opts.ProxyURL = *proxy
	opts.FileLeak = *fileLeak
	opts.LeakDictPath = *leakDict
	opts.DirectoryScan = *dirScan
	opts.DirectoryDictPath = *dirDict
	opts.PathScanMode = *pathMode

	engine := core.NewEngine(store, opts)
	ctx := context.Background()

	fmt.Printf("=== Easy Scan 侦察目标: %s (类型: %s, 端口: %s) ===\n\n", *target, *typ, *ports)

	var taskType core.TaskType = core.TaskDomain
	if *typ == "ip" {
		taskType = core.TaskIP
	}

	err = engine.ScanTarget(ctx, *target, taskType, "", "", func(stage, detail string, progress int) {
		fmt.Printf("  [%3d%%] %s: %s\n", progress, stage, detail)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "扫描失败: %v\n", err)
		os.Exit(1)
	}

	printSummary(store, *target, taskType)
}

// printBenchmark 输出基准对比的人类可读摘要。
func printBenchmark(r *core.BenchmarkReport) {
	fmt.Printf("=== 端口扫描基准对比: %s (%s, %d 端口) ===\n\n", r.Target, r.PortMode, r.Ports)
	fmt.Printf("nmap   : 开放端口 %4d, 耗时 %v\n", r.NmapOpen, r.NmapTime.Round(time.Millisecond))
	fmt.Printf("纯 Go : 开放端口 %4d, 耗时 %v\n", r.GoOpen, r.GoTime.Round(time.Millisecond))
	fmt.Printf("\n共同检出  : %d\n", r.Common)
	fmt.Printf("nmap 独有 : %d  (纯 Go 漏报)\n", r.NmapOnly)
	fmt.Printf("纯 Go 独有: %d  (纯 Go 误报)\n", r.GoOnly)
	fmt.Printf("召回率    : %.1f%%  (纯 Go 相对 nmap)\n", r.Recall*100)
	fmt.Printf("误报率    : %.1f%%\n", r.FalsePos*100)

	var miss, fp []core.PortBenchResult
	for _, d := range r.Details {
		if d.Nmap && !d.PureGo {
			miss = append(miss, d)
		} else if !d.Nmap && d.PureGo {
			fp = append(fp, d)
		}
	}
	if len(miss) > 0 {
		fmt.Println("\n--- nmap 独有端口（纯 Go 漏报）---")
		for _, d := range miss {
			pv := ""
			if d.Product != "" {
				pv = fmt.Sprintf("  [%s %s]", d.Product, d.Version)
			}
			fmt.Printf("  %s:%d%s\n", d.IP, d.Port, pv)
		}
	}
	if len(fp) > 0 {
		fmt.Println("\n--- 纯 Go 独有端口（疑似误报）---")
		for _, d := range fp {
			fmt.Printf("  %s:%d\n", d.IP, d.Port)
		}
	}
}

func printSummary(store *core.Store, target string, typ core.TaskType) {
	fmt.Println("\n=== 侦察结果 ===")

	if typ == core.TaskDomain {
		if n, err := store.SubdomainCount(target); err == nil {
			fmt.Printf("存活子域名: %d\n", n)
		}
		subs, _ := store.ListSubdomains(target, 50)
		for _, s := range subs {
			fmt.Printf("  %-40s -> %s\n", s.Subdomain, s.IP)
		}
	}

	if n, err := store.PortCount(); err == nil {
		fmt.Printf("\n开放端口: %d\n", n)
	}
	ports, _ := store.ListPorts(100)
	for _, p := range ports {
		title := p.Title
		if title == "" {
			title = strings.TrimSpace(p.Banner)
		}
		if len(title) > 60 {
			title = title[:60]
		}
		fmt.Printf("  %-16s %-6d %-14s %s\n", p.IP, p.Port, p.Service, title)
	}

	sites, _ := store.ListSites(100)
	if len(sites) > 0 {
		fmt.Printf("\nWeb 站点指纹: %d\n", len(sites))
		for _, s := range sites {
			shot := ""
			if s.Screenshot != "" {
				shot = " (截图: " + s.Screenshot + ")"
			}
			fmt.Printf("  %-40s [%s] %s%s\n", s.URL, s.Fingerprint, s.Title, shot)
		}
	}

	leaks, _ := store.ListLeaksByTask("", 100, 0)
	if len(leaks) > 0 {
		fmt.Printf("\n文件泄漏: %d\n", len(leaks))
		for _, leak := range leaks {
			fmt.Printf("  %-6d %-12s %s\n", leak.StatusCode, leak.Type, leak.URL)
		}
	}

	directories, _ := store.ListDirectoriesByTask("", 200, 0)
	if len(directories) > 0 {
		fmt.Printf("\n路径发现: %d\n", len(directories))
		for _, directory := range directories {
			fmt.Printf("  %-6d %-10s %-8d %s\n", directory.StatusCode, directory.Kind, directory.ContentLength, directory.URL)
		}
	}
}
