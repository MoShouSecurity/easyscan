// Command easyscan 是 EasyScan 引擎的 CLI 入口，用于独立运行与验证侦察流程。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"easyscan/core"
)

func main() {
	var (
		target  = flag.String("target", "", "目标域名或 IP/网段，如 example.com 或 1.2.3.0/24")
		typ     = flag.String("type", "domain", "任务类型: domain / ip")
		ports   = flag.String("ports", "top100", "端口模式: test / top100 / top1000 / all")
		db      = flag.String("db", "easyscan.db", "SQLite 数据库路径")
		noBrute = flag.Bool("no-brute", false, "关闭子域名字典爆破")
		noShot  = flag.Bool("no-shot", false, "关闭站点截图")
		shotDir = flag.String("shot-dir", "screenshots", "截图保存目录")
	)
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "用法: easyscan -target example.com [-type domain] [-ports top100]")
		flag.Usage()
		os.Exit(2)
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
}
