package core

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// Engine 侦察引擎：编排子域名枚举 → DNS 解析 → 端口扫描 → 指纹识别 → 泄漏/POC/截图 的完整闭环。
type Engine struct {
	store *Store
	opts  ScanOptions
}

// NewEngine 构造侦察引擎。
func NewEngine(store *Store, opts ScanOptions) *Engine {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 100
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	return &Engine{store: store, opts: opts}
}

// ProgressFunc 进度回调，用于实时上报（GUI / CLI）。progress 为 0-100 的百分比。
type ProgressFunc func(stage string, detail string, progress int)

// 扫描阶段（用于分阶段断点续扫）。
const (
	StageSubdomain   = "subdomain"   // 子域名枚举
	StageDNS         = "dns"         // DNS 解析
	StagePortScan    = "portscan"    // 端口扫描
	StagePostProcess = "postprocess" // 附加模块
)

// stageIndex 返回阶段序号，用于比较（恢复时跳过已完成阶段）。
func stageIndex(stage string) int {
	switch stage {
	case StageSubdomain:
		return 1
	case StageDNS:
		return 2
	case StagePortScan:
		return 3
	case StagePostProcess:
		return 4
	default:
		return 0
	}
}

// updateStage 记录任务当前阶段（持久化，用于断点续扫）。
func (e *Engine) updateStage(taskID, stage string) {
	if taskID == "" {
		return
	}
	_ = e.store.UpdateTaskStage(taskID, stage)
}

// ScanTarget 按目标类型分发到域名或 IP 侦察流程。
// taskID 为空表示不关联任务（如 CLI）。startStage 用于断点续扫，空则从头执行。
func (e *Engine) ScanTarget(ctx context.Context, target string, typ TaskType, taskID string, startStage string, progress ProgressFunc) error {
	switch typ {
	case TaskIP:
		return e.ScanIPs(ctx, target, taskID, startStage, progress)
	default:
		return e.ScanDomain(ctx, target, taskID, startStage, progress)
	}
}

// ScanDomain 执行域名侦察完整流程。startStage 用于断点续扫，空则从头执行。
func (e *Engine) ScanDomain(ctx context.Context, domain string, taskID string, startStage string, progress ProgressFunc) error {
	domain = strings.TrimSpace(strings.ToLower(domain))
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimSuffix(domain, "/")
	if domain == "" {
		return fmt.Errorf("目标域名不能为空")
	}

	report := func(stage, detail string, pct int) {
		if progress != nil {
			progress(stage, detail, pct)
		}
	}

	// 1. 记录根域名（总是执行）。
	if err := e.store.UpsertDomain(Domain{ID: newID(), Domain: domain, Source: "manual", CreatedAt: nowUnix()}); err != nil {
		return err
	}
	report("初始化", "记录根域名", 2)

	subs := map[string]bool{domain: true}

	// 2. 子域名枚举（断点续扫时跳过，从数据库恢复）。
	if stageIndex(startStage) <= stageIndex(StageSubdomain) {
		e.updateStage(taskID, StageSubdomain)
		if e.opts.SubdomainBrute {
			report("子域名枚举", "无状态爆破 ...", 5)
			for _, s := range enumerateSubdomains(ctx, domain, e.opts) {
				subs[s] = true
			}
		}
		report("子域名枚举", fmt.Sprintf("共发现 %d 个子域名", len(subs)), 20)
	} else {
		saved, _ := e.store.ListSubdomains(domain, 0)
		for _, sd := range saved {
			subs[sd.Subdomain] = true
		}
	}

	if ctx.Err() != nil {
		return ctx.Err() // 被暂停取消
	}

	all := keysOf(subs)
	sort.Strings(all)

	// 3. DNS 解析（断点续扫时跳过，从数据库恢复 IP）。
	ipHosts := map[string][]string{} // ip -> 关联域名
	if stageIndex(startStage) <= stageIndex(StageDNS) {
		e.updateStage(taskID, StageDNS)
		report("DNS 解析", "解析 A 记录 ...", 22)
		resolved := resolveBatch(ctx, all, e.opts.Concurrency, e.opts.Timeout)
		for _, host := range all {
			ips := resolved[host]
			if len(ips) == 0 {
				continue
			}
			sd := Subdomain{
				ID:        newID(),
				Domain:    domain,
				Subdomain: host,
				IP:        ips[0],
				Source:    "resolved",
				TaskID:    taskID,
				CreatedAt: nowUnix(),
			}
			_ = e.store.UpsertSubdomain(sd)
			for _, ip := range ips {
				ipHosts[ip] = appendUnique(ipHosts[ip], host)
			}
		}
		report("DNS 解析", fmt.Sprintf("解析到 %d 个存活子域名 / %d 个独立 IP", len(resolved), len(keysOfSlice(ipHosts))), 30)
	} else {
		saved, _ := e.store.ListSubdomains(domain, 0)
		for _, sd := range saved {
			if sd.IP != "" {
				ipHosts[sd.IP] = appendUnique(ipHosts[sd.IP], sd.Subdomain)
			}
		}
	}

	if ctx.Err() != nil {
		return ctx.Err() // 被暂停取消
	}

	ips := keysOfSlice(ipHosts)
	sort.Strings(ips)

	// 4. 端口扫描 + 服务识别 + 指纹。（断点续扫时跳过，从数据库恢复站点）
	var sites []Site
	if stageIndex(startStage) <= stageIndex(StagePortScan) {
		e.updateStage(taskID, StagePortScan)
		sites = e.scanPortsAndSites(ctx, ips, nil, ipHosts, taskID, report, 30, 60)
	} else {
		sites, _ = e.store.ListSitesByTask(taskID, 0)
	}

	if ctx.Err() != nil {
		return ctx.Err() // 被暂停取消
	}

	// 5. 附加模块：文件泄漏 / POC / 截图。
	if stageIndex(startStage) <= stageIndex(StagePostProcess) {
		e.updateStage(taskID, StagePostProcess)
		e.postProcess(ctx, sites, taskID, report, 90)
	}

	return nil
}

// ScanIPs 对 IP 或 CIDR 网段执行端口扫描流程。startStage 用于断点续扫。
func (e *Engine) ScanIPs(ctx context.Context, target string, taskID string, startStage string, progress ProgressFunc) error {
	ips, err := expandTarget(target)
	if err != nil {
		return err
	}
	// nmap 直接接收原始 IP/CIDR 条目，避免展开成大量参数（Windows 命令行长度限制）。
	nmapTargets, _ := splitTargets(target)
	report := func(stage, detail string, pct int) {
		if progress != nil {
			progress(stage, detail, pct)
		}
	}

	var sites []Site
	if stageIndex(startStage) <= stageIndex(StagePortScan) {
		e.updateStage(taskID, StagePortScan)
		report("端口扫描", fmt.Sprintf("目标 %d 个 IP (模式: %s) ...", len(ips), e.opts.PortMode), 1)
		sites = e.scanPortsAndSites(ctx, ips, nmapTargets, nil, taskID, report, 0, 90)
	} else {
		sites, _ = e.store.ListSitesByTask(taskID, 0)
	}

	if ctx.Err() != nil {
		return ctx.Err() // 被暂停取消
	}

	if stageIndex(startStage) <= stageIndex(StagePostProcess) {
		e.updateStage(taskID, StagePostProcess)
		e.postProcess(ctx, sites, taskID, report, 90)
	}
	return nil
}

// scanPortsAndSites 对一组 IP 做 IP 存活确认 + 端口扫描 + 服务识别 + 指纹，返回去重后的站点列表。
// nmapTargets 为 nmap 使用的原始目标条目（支持 CIDR，避免展开成大量参数）；为空则退回 ips。
// base/span 为进度区间（如 base=30, span=60 表示进度从 30% 推进到 90%）。
// 优先用 nmap（-sn 存活确认 + -sV 服务/版本识别），不可用/失败时降级纯 Go 扫描。
func (e *Engine) scanPortsAndSites(ctx context.Context, ips []string, nmapTargets []string, ipHosts map[string][]string, taskID string, report ProgressFunc, base int, span int) []Site {
	siteMap := map[string]Site{}
	nmap := NewNmapScanner(e.opts.NmapPath)
	nmapT := nmapTargets
	if len(nmapT) == 0 {
		nmapT = ips
	}

	// 1. IP 存活确认（nmap -sn 综合 ICMP/TCP/ARP 探测，无 nmap 时降级纯 Go TCP 探测）。
	// alive 决定扫描范围；confirmed 记录确认存活的 IP（探测命中或发现开放端口），
	// 只有 confirmed 才入库「IP存活」，避免把网段内不存在的 IP 大量收录。
	alive := ips
	confirmed := map[string]bool{}
	discovered := false // 是否已通过探测获得存活结果
	if e.opts.NoPing {
		report("IP存活确认", "目标禁 ping，跳过存活确认直接扫描", base)
	} else {
		// 存活探测降级链：masscan 纯 ICMP → nmap 纯 ICMP（-sn -PE）→ 纯 Go TCP。
		// masscan/nmap 探测失败（无二进制 / 无权限 / 驱动缺失）或未发现存活时继续降级，
		// 避免把网段内不存在的 IP 全部当成存活；同时保证探测方式缺失不影响任务。
		if m := NewMasscanScanner(e.opts.MasscanPath); m.Available() {
			report("IP存活确认", fmt.Sprintf("masscan ICMP 探测 %d 个 IP ...", len(ips)), base)
			hit, err := m.PingScan(ctx, nmapT)
			if err != nil {
				report("IP存活确认", "masscan 探测失败，降级 nmap: "+err.Error(), base)
			} else if len(hit) > 0 {
				alive, discovered = hit, true
				report("IP存活确认", fmt.Sprintf("masscan 确认 %d/%d 个 IP 存活", len(hit), len(ips)), base+span/10)
			} else {
				report("IP存活确认", "masscan 未发现存活主机，降级 nmap", base)
			}
		}
		if !discovered && nmap.Available() {
			report("IP存活确认", fmt.Sprintf("nmap ICMP 探测 %d 个 IP ...", len(ips)), base)
			hit := nmap.PingSweep(ctx, nmapT)
			report("IP存活确认", fmt.Sprintf("nmap 确认 %d/%d 个 IP 存活", len(hit), len(ips)), base+span/10)
			if len(hit) > 0 {
				alive, discovered = hit, true
			}
		}
		if !discovered {
			report("IP存活确认", fmt.Sprintf("纯 Go TCP 探测 %d 个 IP ...", len(ips)), base)
			probeTO := e.opts.Timeout
			if probeTO > 2*time.Second {
				probeTO = 2 * time.Second
			}
			alive = pingSweepGo(ctx, ips, e.opts.Concurrency, probeTO)
			discovered = true
			report("IP存活确认", fmt.Sprintf("TCP 探测确认 %d/%d 个 IP 存活", len(alive), len(ips)), base+span/10)
		}
		for _, ip := range alive {
			confirmed[ip] = true
		}
		if len(alive) == 0 && len(ips) <= 256 {
			// 目标较少时失败开放：探测无结果仍扫描全部，避免漏掉不响应探测的 IP。
			// 注意不影响 confirmed，未确认的 IP 不会入库。
			alive = ips
			report("IP存活确认", "未确认到存活主机，目标较少，仍扫描全部", base)
		}
	}

	// recordAlive 确认存活 IP 入库（即使无开放端口也记录，详情页「IP存活」显示）。
	recordAlive := func(ip string) {
		if confirmed[ip] {
			return
		}
		confirmed[ip] = true
		_ = e.store.UpsertIP(IP{
			ID:        newID(),
			IP:        ip,
			TaskID:    taskID,
			CreatedAt: nowUnix(),
		})
	}
	for ip := range confirmed {
		recordAlive(ip)
	}

	// 2. nmap 端口扫描 + 服务/版本识别。
	if nmap.Available() {
		report("端口扫描", fmt.Sprintf("nmap 服务识别 %d 个存活 IP (模式: %s) ...", len(alive), e.opts.PortMode), base+span/10)
		hosts, err := nmap.Scan(ctx, alive, e.opts.PortMode, e.opts.PortSpec)
		if err == nil {
			for _, h := range hosts {
				if len(h.Ports) > 0 {
					recordAlive(h.IP)
				}
				hostname := ""
				if ipHosts != nil {
					if hs := ipHosts[h.IP]; len(hs) > 0 {
						hostname = hs[0]
					}
				}
				for _, p := range h.Ports {
					rec := Port{
						ID:        newID(),
						IP:        h.IP,
						Port:      p.Port,
						Protocol:  p.Protocol,
						Service:   p.Service,
						Product:   p.Product,
						Version:   p.Version,
						Title:     p.Title,
						TaskID:    taskID,
						CreatedAt: nowUnix(),
					}
					// Web 站点走指纹流程，获取标题与 CMS。
					if site, ok := probeWebSite(ctx, h.IP, p.Port, p.Service, hostname, e.opts.Timeout); ok {
						site.TaskID = taskID
						rec.Title = site.Title
						siteMap[site.URL] = site
						_ = e.store.UpsertSite(site)
					}
					_ = e.store.UpsertPort(rec)
				}
			}
			report("端口扫描", fmt.Sprintf("nmap 扫描完成，识别 %d 个 IP", len(hosts)), base+span)
			return mapToSites(siteMap)
		}
		report("端口扫描", "nmap 扫描失败，降级纯 Go 扫描: "+err.Error(), base+span/10)
	}

	// 3. 纯 Go fallback。
	ports := portList(e.opts.PortMode, e.opts.PortSpec)
	for i, ip := range alive {
		hostname := ""
		if ipHosts != nil {
			if hs := ipHosts[ip]; len(hs) > 0 {
				hostname = hs[0]
			}
		}
		open := scanIPPorts(ctx, ip, ports, e.opts.Concurrency, e.opts.Timeout)
		if len(open) > 0 {
			recordAlive(ip)
		}
		for _, p := range open {
			service, banner := grabBanner(ctx, ip, p, e.opts.Timeout)
			rec := Port{
				ID:        newID(),
				IP:        ip,
				Port:      p,
				Protocol:  "tcp",
				Service:   service,
				Banner:    strings.TrimSpace(banner),
				TaskID:    taskID,
				CreatedAt: nowUnix(),
			}
			if site, ok := probeWebSite(ctx, ip, p, service, hostname, e.opts.Timeout); ok {
				site.TaskID = taskID
				rec.Title = site.Title
				siteMap[site.URL] = site
				_ = e.store.UpsertSite(site)
			}
			_ = e.store.UpsertPort(rec)
		}
		pct := base
		if len(alive) > 0 {
			pct = base + (i+1)*span/len(alive)
		}
		report("端口扫描", fmt.Sprintf("[%d/%d] %s 开放 %d 端口", i+1, len(alive), ip, len(open)), pct)
	}

	return mapToSites(siteMap)
}

func mapToSites(siteMap map[string]Site) []Site {
	sites := make([]Site, 0, len(siteMap))
	for _, s := range siteMap {
		sites = append(sites, s)
	}
	return sites
}

// postProcess 执行文件泄漏 / POC / 截图等附加模块。base 为起始进度（百分比）。
func (e *Engine) postProcess(ctx context.Context, sites []Site, taskID string, report ProgressFunc, base int) {
	if len(sites) == 0 {
		return
	}
	pct := base

	if e.opts.FileLeak {
		report("文件泄漏检测", fmt.Sprintf("探测 %d 个站点", len(sites)), pct)
		rules := leakRules
		if e.opts.LeakDictPath != "" {
			if custom, err := loadLeakDict(e.opts.LeakDictPath); err == nil && len(custom) > 0 {
				rules = custom
				report("文件泄漏检测", fmt.Sprintf("加载自定义字典 %d 条", len(custom)), pct)
			} else if err != nil {
				report("文件泄漏检测", "加载自定义字典失败，改用内置字典: "+err.Error(), pct)
			}
		}
		for _, site := range sites {
			for _, leak := range detectLeaks(ctx, site, taskID, e.opts.Timeout, rules) {
				_ = e.store.UpsertLeak(leak)
			}
		}
		pct += 3
		report("文件泄漏检测", "完成", pct)
	}
	if e.opts.Nuclei {
		report("POC 检测", fmt.Sprintf("检测 %d 个站点", len(sites)), pct)
		for _, site := range sites {
			for _, leak := range runNuclei(ctx, site, taskID, e.opts.Timeout) {
				_ = e.store.UpsertLeak(leak)
			}
		}
		// 自定义 nuclei 模板目录。
		if e.opts.NucleiTemplatesDir != "" {
			if templates, err := loadNucleiTemplates(e.opts.NucleiTemplatesDir); err == nil && len(templates) > 0 {
				report("POC 检测", fmt.Sprintf("加载 %d 个自定义模板", len(templates)), pct)
				for _, site := range sites {
					for _, leak := range runNucleiYAML(ctx, site, taskID, templates, e.opts.Timeout) {
						_ = e.store.UpsertLeak(leak)
					}
				}
			} else if err != nil {
				report("POC 检测", "加载模板目录失败: "+err.Error(), pct)
			}
		}
		pct += 3
		report("POC 检测", "完成", pct)
	}
	if e.opts.Screenshot {
		report("站点截图", fmt.Sprintf("截图 %d 个站点", len(sites)), pct)
		shot, err := NewScreenshotter(e.opts.ChromePath, e.opts.ScreenshotDir)
		if err != nil {
			report("站点截图", "截图器初始化失败: "+err.Error(), pct)
			return
		}
		defer shot.Close()
		for _, site := range sites {
			saved := false
			for _, u := range ScreenshotCandidates(site.URL) {
				if path, err := shot.Capture(u); err == nil {
					_ = e.store.SetSiteScreenshot(site.URL, path)
					saved = true
					break
				}
			}
			if !saved {
				report("站点截图", fmt.Sprintf("截图失败 %s", site.URL), pct)
			}
		}
		pct += 3
		report("站点截图", "完成", pct)
	}
}

// probeWebSite 判断端口是否为 Web 服务并探测指纹；非 Web 返回 ok=false。
func probeWebSite(ctx context.Context, ip string, port int, service string, hostname string, timeout time.Duration) (Site, bool) {
	schemes := webSchemes(port, service)
	for _, scheme := range schemes {
		if site, ok := probeSite(ctx, ip, port, scheme, hostname, timeout); ok {
			return site, true
		}
	}
	return Site{}, false
}

// webSchemes 依据端口/服务确定要尝试的协议。
func webSchemes(port int, service string) []string {
	switch {
	case service == "https", port == 443, port == 8443, port == 9443:
		return []string{"https"}
	case service == "http":
		return []string{"http"}
	case isWebPort(port):
		return []string{"http", "https"}
	default:
		return nil
	}
}

func isWebPort(port int) bool {
	switch port {
	case 80, 81, 300, 443, 800, 808, 3000, 5000, 7001, 8000, 8001, 8008, 8009, 8080,
		8081, 8082, 8088, 8090, 8181, 8443, 8888, 9000, 9080, 9090, 9100, 9200, 9443:
		return true
	default:
		return false
	}
}

// IsIPTarget 判断目标是否为 IP 或 CIDR 网段。
func IsIPTarget(target string) bool {
	t := strings.TrimSpace(target)
	if net.ParseIP(t) != nil {
		return true
	}
	if _, _, err := net.ParseCIDR(t); err == nil {
		return true
	}
	return false
}

// splitTargets 拆分并校验目标字符串，返回去重后的 IP/CIDR 条目（保持原样，供 nmap 使用）。
// 支持逗号、空格、换行、分号分隔的多个 IP 或网段。
func splitTargets(target string) ([]string, error) {
	parts := strings.FieldsFunc(target, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == ';' || r == '\r'
	})
	var out []string
	seen := map[string]bool{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if net.ParseIP(part) == nil {
			if _, _, err := net.ParseCIDR(part); err != nil {
				return nil, fmt.Errorf("无效的 IP 或网段: %s", part)
			}
		}
		if !seen[part] {
			seen[part] = true
			out = append(out, part)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("无效的 IP 或网段: %s", target)
	}
	return out, nil
}

// expandTarget 将单个或多个 IP/CIDR 展开为 IP 列表（纯 Go 扫描使用）。
func expandTarget(target string) ([]string, error) {
	parts, err := splitTargets(target)
	if err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	for _, part := range parts {
		if ip := net.ParseIP(part); ip != nil {
			s := ip.String()
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
			continue
		}
		_, ipnet, _ := net.ParseCIDR(part)
		for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
			s := ip.String()
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out, nil
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func keysOfSlice(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
