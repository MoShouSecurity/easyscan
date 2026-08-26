package core

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
	opts.PathScanMode = normalizePathScanMode(opts.PathScanMode)
	if ValidatePathScanMode(opts.PathScanMode) != nil {
		opts.PathScanMode = PathScanModeQuick
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
func (e *Engine) updateStage(taskID, stage string) error {
	if taskID == "" {
		return nil
	}
	if err := e.store.UpdateTaskStage(taskID, stage); err != nil {
		return fmt.Errorf("记录扫描阶段 %s: %w", stage, err)
	}
	return nil
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
	if err := ValidateDomain(domain); err != nil {
		return fmt.Errorf("目标域名非法: %w", err) // 拒绝进入提权子进程等危险上下文
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
	// FOFA 独立于爆破开关：关爆破但配置了 FOFA key 时仍执行被动收集。
	if stageIndex(startStage) <= stageIndex(StageSubdomain) {
		if err := e.updateStage(taskID, StageSubdomain); err != nil {
			return err
		}
		if e.opts.SubdomainBrute || e.opts.FofaKey != "" {
			report("子域名枚举", "无状态爆破 ...", 5)
			discovered, err := enumerateSubdomains(ctx, domain, e.opts, e.store, taskID, report)
			if err != nil {
				return err
			}
			for _, s := range discovered {
				subs[s] = true
			}
		}
		report("子域名枚举", fmt.Sprintf("共发现 %d 个子域名", len(subs)), 20)
	} else {
		saved, err := e.taskSubdomains(taskID, domain)
		if err != nil {
			return err
		}
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
		if err := e.updateStage(taskID, StageDNS); err != nil {
			return err
		}
		report("DNS 解析", "解析 A 记录 ...", 22)
		resolved := resolveBatch(ctx, all, e.opts.Concurrency, e.opts.Timeout)
		// 枚举阶段入库的历史 IP（FOFA 收录等）：子域名已不解析时兜底进扫描，
		// 解析成功时也一并纳入（失效 IP 由端口扫描前的存活探测拦截）。
		historical := map[string][]string{}
		saved, err := e.store.ListSubdomains(domain, -1)
		if err != nil {
			return fmt.Errorf("读取历史子域名: %w", err)
		}
		for _, sd := range saved {
			if sd.IP != "" {
				historical[sd.Subdomain] = appendUnique(historical[sd.Subdomain], sd.IP)
			}
		}
		for _, host := range all {
			ips := resolved[host]
			for _, hip := range historical[host] {
				ips = appendUnique(ips, hip)
			}
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
			if err := e.store.UpsertSubdomain(sd); err != nil {
				return fmt.Errorf("保存子域名 %s: %w", host, err)
			}
			for _, ip := range ips {
				ipHosts[ip] = appendUnique(ipHosts[ip], host)
			}
		}
		report("DNS 解析", fmt.Sprintf("解析到 %d 个存活子域名 / %d 个独立 IP", len(resolved), len(keysOfSlice(ipHosts))), 30)
	} else {
		saved, err := e.taskSubdomains(taskID, domain)
		if err != nil {
			return err
		}
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
	var err error
	if stageIndex(startStage) <= stageIndex(StagePortScan) {
		if err := e.updateStage(taskID, StagePortScan); err != nil {
			return err
		}
		sites, err = e.scanPortsAndSites(ctx, ips, nil, ipHosts, taskID, report, 30, 60)
		if err != nil {
			return err
		}
	} else {
		sites, err = e.store.ListSitesByTask(taskID, -1, 0)
		if err != nil {
			return fmt.Errorf("恢复任务站点: %w", err)
		}
	}

	if ctx.Err() != nil {
		return ctx.Err() // 被暂停取消
	}

	// 5. 附加模块：文件泄漏 / POC / 截图。
	if stageIndex(startStage) <= stageIndex(StagePostProcess) {
		if err := e.updateStage(taskID, StagePostProcess); err != nil {
			return err
		}
		if err := e.postProcess(ctx, sites, taskID, report, 90); err != nil {
			return err
		}
	}

	return nil
}

// taskSubdomains 优先恢复当前任务的数据；旧数据库中任务关联可能为空，
// 此时回退到该根域名的最新全局记录，保证升级后的旧任务仍可恢复。
func (e *Engine) taskSubdomains(taskID, domain string) ([]Subdomain, error) {
	if taskID != "" {
		saved, err := e.store.ListSubdomainsByTask(taskID, -1, 0)
		if err != nil {
			return nil, fmt.Errorf("恢复任务子域名: %w", err)
		}
		if len(saved) > 0 {
			return saved, nil
		}
	}
	saved, err := e.store.ListSubdomains(domain, -1)
	if err != nil {
		return nil, fmt.Errorf("恢复域名资产: %w", err)
	}
	return saved, nil
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
		if err := e.updateStage(taskID, StagePortScan); err != nil {
			return err
		}
		report("端口扫描", fmt.Sprintf("目标 %d 个 IP (模式: %s) ...", len(ips), e.opts.PortMode), 1)
		sites, err = e.scanPortsAndSites(ctx, ips, nmapTargets, nil, taskID, report, 0, 90)
		if err != nil {
			return err
		}
	} else {
		sites, err = e.store.ListSitesByTask(taskID, -1, 0)
		if err != nil {
			return fmt.Errorf("恢复任务站点: %w", err)
		}
	}

	if ctx.Err() != nil {
		return ctx.Err() // 被暂停取消
	}

	if stageIndex(startStage) <= stageIndex(StagePostProcess) {
		if err := e.updateStage(taskID, StagePostProcess); err != nil {
			return err
		}
		if err := e.postProcess(ctx, sites, taskID, report, 90); err != nil {
			return err
		}
	}
	return nil
}

// scanPortsAndSites 对一组 IP 做 IP 存活确认 + 端口扫描 + 服务识别 + 指纹，返回去重后的站点列表。
// nmapTargets 为 nmap 使用的原始目标条目（支持 CIDR，避免展开成大量参数）；为空则退回 ips。
// base/span 为进度区间（如 base=30, span=60 表示进度从 30% 推进到 90%）。
// 优先用 nmap（-sn 存活确认 + -sV 服务/版本识别），不可用/失败时降级纯 Go 扫描。
func (e *Engine) scanPortsAndSites(ctx context.Context, ips []string, nmapTargets []string, ipHosts map[string][]string, taskID string, report ProgressFunc, base int, span int) ([]Site, error) {
	siteMap := map[string]Site{}
	// 合并任务已有站点（如 FOFA 端口线索在枚举阶段直接探测入库的），
	// 保证它们进入后续泄漏/POC/截图等附加流程。
	if taskID != "" {
		saved, err := e.store.ListSitesByTask(taskID, -1, 0)
		if err != nil {
			return nil, fmt.Errorf("读取已有站点: %w", err)
		}
		for _, s := range saved {
			siteMap[s.URL] = s
		}
	}
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
	recorded := map[string]bool{}
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
	recordAlive := func(ip string) error {
		if recorded[ip] {
			return nil
		}
		confirmed[ip] = true
		if err := e.store.UpsertIP(IP{
			ID:        newID(),
			IP:        ip,
			TaskID:    taskID,
			CreatedAt: nowUnix(),
		}); err != nil {
			return fmt.Errorf("保存存活 IP %s: %w", ip, err)
		}
		recorded[ip] = true
		return nil
	}
	for ip := range confirmed {
		if err := recordAlive(ip); err != nil {
			return nil, err
		}
	}

	// 2. nmap 端口扫描 + 服务/版本识别（存活 IP 分批，进度按批推进；
	// 单批失败该批降级纯 Go，其余批继续 nmap）。
	if nmap.Available() {
		batches := chunkIPs(alive, nmapBatchSize)
		var pureGoIPs []string
		var resMu sync.Mutex
		syn := false
		for bi, batch := range batches {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			report("端口扫描",
				fmt.Sprintf("nmap 服务识别 批次 %d/%d（%d 个 IP, 模式: %s）...", bi+1, len(batches), len(batch), e.opts.PortMode),
				base+span/10)
			hosts, err := nmap.Scan(ctx, batch, e.opts.PortMode, e.opts.PortSpec)
			if err != nil {
				report("端口扫描", fmt.Sprintf("nmap 批次 %d/%d 失败，该批降级纯 Go: %s", bi+1, len(batches), err.Error()), base+span/10)
				pureGoIPs = append(pureGoIPs, batch...)
				continue
			}
			for _, h := range hosts {
				if h.Syn {
					syn = true
					break
				}
			}
			if err := e.processNmapBatch(ctx, hosts, ipHosts, taskID, siteMap, recordAlive, &resMu); err != nil {
				return nil, err
			}
			// 进度按批单调推进（nmap 阶段 base+span/10 → base+span*9/10）。
			pct := base + span/10 + (span*4/5)*(bi+1)/len(batches)
			report("端口扫描", fmt.Sprintf("nmap 批次 %d/%d 完成", bi+1, len(batches)), pct)
		}
		// 失败批的纯 Go 兜底（复用同套处理，进度推进到 base+span）。
		if len(pureGoIPs) > 0 {
			ports := portList(e.opts.PortMode, e.opts.PortSpec)
			report("端口扫描", fmt.Sprintf("纯 Go 兜底 %d 个 IP ...", len(pureGoIPs)), base+span*9/10)
			for i, ip := range pureGoIPs {
				open, err := e.processPureGoIP(ctx, ip, ipHosts, taskID, siteMap, recordAlive, ports)
				if err != nil {
					return nil, err
				}
				pct := base + span*9/10 + span*(i+1)/len(pureGoIPs)/10
				if pct > base+span {
					pct = base + span
				}
				report("端口扫描", fmt.Sprintf("[%d/%d] %s 开放 %d 端口", i+1, len(pureGoIPs), ip, open), pct)
			}
		}
		mode := "TCP connect"
		if syn {
			mode = "SYN 半开"
		}
		report("端口扫描", fmt.Sprintf("nmap %s 扫描完成（%d 批）", mode, len(batches)), base+span)
		return mapToSites(siteMap), nil
	}

	// 3. 纯 Go fallback（nmap 不可用：逐 IP 扫描，进度线性推进）。
	ports := portList(e.opts.PortMode, e.opts.PortSpec)
	for i, ip := range alive {
		open, err := e.processPureGoIP(ctx, ip, ipHosts, taskID, siteMap, recordAlive, ports)
		if err != nil {
			return nil, err
		}
		pct := base
		if len(alive) > 0 {
			pct = base + (i+1)*span/len(alive)
		}
		report("端口扫描", fmt.Sprintf("[%d/%d] %s 开放 %d 端口", i+1, len(alive), ip, open), pct)
	}

	return mapToSites(siteMap), nil
}

// processPureGoIP 纯 Go 扫描单个 IP（端口扫描 + banner + Web 指纹 + 落库），
// 返回开放端口数。供无 nmap 整体兜底与 nmap 单批失败兜底两处复用。
func (e *Engine) processPureGoIP(ctx context.Context, ip string, ipHosts map[string][]string, taskID string, siteMap map[string]Site, recordAlive func(string) error, ports []int) (int, error) {
	hostname := ""
	if ipHosts != nil {
		if hs := ipHosts[ip]; len(hs) > 0 {
			hostname = hs[0]
		}
	}
	open := scanIPPorts(ctx, ip, ports, e.opts.Concurrency, e.opts.Timeout)
	if len(open) > 0 {
		if err := recordAlive(ip); err != nil {
			return 0, err
		}
	}
	// 扫描已确认的端口先全部落盘，不能被后续 banner / HTTP 超时阻塞。
	records := make([]Port, 0, len(open))
	for _, p := range open {
		rec := Port{
			ID:         newID(),
			IP:         ip,
			Port:       p,
			Protocol:   "tcp",
			Confidence: ConfidencePureGo,
			TaskID:     taskID,
			CreatedAt:  nowUnix(),
		}
		if err := e.store.UpsertPort(rec); err != nil {
			return len(open), fmt.Errorf("保存端口 %s:%d: %w", rec.IP, rec.Port, err)
		}
		records = append(records, rec)
	}
	for _, rec := range records {
		if err := ctx.Err(); err != nil {
			return len(open), err
		}
		service, banner := grabBanner(ctx, ip, rec.Port, e.opts.Timeout)
		rec.Service, rec.Banner = service, strings.TrimSpace(banner)
		if err := e.store.UpsertPort(rec); err != nil {
			return len(open), fmt.Errorf("保存端口指纹 %s:%d: %w", rec.IP, rec.Port, err)
		}
		if site, ok := probeWebSite(ctx, ip, rec.Port, service, hostname, e.opts.Timeout); ok {
			site.TaskID = taskID
			rec.Title = site.Title
			if err := e.store.UpsertPort(rec); err != nil {
				return len(open), fmt.Errorf("保存端口标题 %s:%d: %w", rec.IP, rec.Port, err)
			}
			if err := e.store.UpsertSite(site); err != nil {
				return len(open), fmt.Errorf("保存站点 %s: %w", site.URL, err)
			}
			siteMap[site.URL] = site
		}
	}
	return len(open), ctx.Err()
}

// nmapBatchSize nmap 目标分批大小（< maxNmapArgTargets 1024，不触发 -iL）。
const nmapBatchSize = 256

// chunkIPs 顺序切分 IP 列表为 size 大小的批次（不改变集合内容与顺序）。
func chunkIPs(ips []string, size int) [][]string {
	if size <= 0 {
		size = nmapBatchSize
	}
	var out [][]string
	for i := 0; i < len(ips); i += size {
		end := i + size
		if end > len(ips) {
			end = len(ips)
		}
		out = append(out, ips[i:end])
	}
	return out
}

func mapToSites(siteMap map[string]Site) []Site {
	sites := make([]Site, 0, len(siteMap))
	for _, s := range siteMap {
		sites = append(sites, s)
	}
	return sites
}

// postProcess 执行文件泄漏、路径发现、POC 和截图等附加模块。base 为起始进度（百分比）。
// postSiteConcurrency postProcess 站点级并发度（泄漏/目录模块，单站内另有 50 并发）。
const postSiteConcurrency = 4

// nmapHostConcurrency nmap 结果的 Web 指纹补全并发度。
const nmapHostConcurrency = 20

// nmapPortRecord 将已确认的 nmap 结果转为端口记录，不进行任何网络请求。
func nmapPortRecord(host NmapHost, p NmapPortResult, taskID string) Port {
	confidence := ConfidenceNmap
	if host.Syn {
		confidence = ConfidenceSyn
	} else if p.Product != "" || p.Version != "" {
		confidence = ConfidenceNmapV
	}
	return Port{
		ID: newID(), IP: host.IP, Port: p.Port, Protocol: p.Protocol,
		Service: p.Service, Product: p.Product, Version: p.Version, Title: p.Title,
		Confidence: confidence, TaskID: taskID, CreatedAt: nowUnix(),
	}
}

// processNmapBatch 先保存本批已确认的全部端口，再并发补全 Web 指纹。
// 即使补全被暂停或失败，已收到的扫描结果也保留。首个写入错误取消 worker
// 和任务投递，避免 worker 全部退出后生产者永久阻塞。
func (e *Engine) processNmapBatch(ctx context.Context, hosts []NmapHost, ipHosts map[string][]string, taskID string, siteMap map[string]Site, recordAlive func(string) error, resMu *sync.Mutex) error {
	if len(hosts) == 0 {
		return nil
	}
	// 此阶段无网络等待；取消只中止补全，不丢弃 nmap 已返回的结果。
	for _, h := range hosts {
		if len(h.Ports) == 0 {
			continue
		}
		if err := recordAlive(h.IP); err != nil {
			return err
		}
		for _, p := range h.Ports {
			rec := nmapPortRecord(h, p, taskID)
			if err := e.store.UpsertPort(rec); err != nil {
				return fmt.Errorf("保存端口 %s:%d: %w", rec.IP, rec.Port, err)
			}
		}
	}

	probeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan NmapHost, nmapHostConcurrency)
	var wg sync.WaitGroup
	var firstErr error
	var errOnce sync.Once
	fail := func(err error) {
		errOnce.Do(func() {
			firstErr = err
			cancel()
		})
	}

	for i := 0; i < nmapHostConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range jobs {
				if probeCtx.Err() != nil {
					return
				}
				hostname := ""
				if ipHosts != nil {
					if hs := ipHosts[h.IP]; len(hs) > 0 {
						hostname = hs[0]
					}
				}
				for _, p := range h.Ports {
					if probeCtx.Err() != nil {
						return
					}
					site, ok := probeWebSite(probeCtx, h.IP, p.Port, p.Service, hostname, e.opts.Timeout)
					if !ok {
						continue
					}
					site.TaskID = taskID
					rec := nmapPortRecord(h, p, taskID)
					rec.Title = site.Title
					if err := e.store.UpsertPort(rec); err != nil {
						fail(fmt.Errorf("保存端口标题 %s:%d: %w", rec.IP, rec.Port, err))
						return
					}
					if err := e.store.UpsertSite(site); err != nil {
						fail(fmt.Errorf("保存站点 %s: %w", site.URL, err))
						return
					}
					resMu.Lock()
					siteMap[site.URL] = site
					resMu.Unlock()
				}
			}
		}()
	}
sendLoop:
	for _, h := range hosts {
		select {
		case jobs <- h:
		case <-probeCtx.Done():
			break sendLoop
		}
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	return ctx.Err()
}

func (e *Engine) postProcess(ctx context.Context, sites []Site, taskID string, report ProgressFunc, base int) error {
	if len(sites) == 0 {
		return nil
	}
	for _, site := range sites {
		if _, err := newSiteScope(site); err != nil {
			return fmt.Errorf("站点扫描范围无效: %w", err)
		}
	}
	pct := base
	pathModeLabel := "快速"
	if e.opts.PathScanMode == PathScanModeDeep {
		pathModeLabel = "深度"
	}

	if e.opts.FileLeak {
		var rules []leakRule // nil 表示流式使用内置压缩字典。
		if e.opts.LeakDictPath != "" {
			if custom, err := loadLeakDict(e.opts.LeakDictPath); err == nil && len(custom) > 0 {
				rules = custom
				report("文件泄漏检测", fmt.Sprintf("加载自定义字典 %d 条", len(custom)), pct)
			} else if err != nil {
				report("文件泄漏检测", "加载自定义字典失败，改用内置字典: "+err.Error(), pct)
			}
		}
		source, requestBudget := leakProbeSourceForMode(rules, e.opts.PathScanMode)
		leakModeLabel := pathModeLabel
		if rules != nil {
			leakModeLabel = "自定义字典"
		}
		report("文件泄漏检测", fmt.Sprintf("%s：探测 %d 个站点，每站路径预算 %d 条", leakModeLabel, len(sites), requestBudget), pct)
		// 站点级并发（sem=4）：单站内 50 并发 worker 池保持不变；
		// 首个站点错误经 errOnce 温和中止（已启动站点跑完）。
		sem := make(chan struct{}, postSiteConcurrency)
		var wg sync.WaitGroup
		var firstErr error
		var errOnce sync.Once
		var done int32
		for _, site := range sites {
			site := site
			wg.Add(1)
			go func() {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()
				saved := 0
				err := detectLeaksEach(ctx, site, taskID, e.opts.Timeout, e.opts.Concurrency, source, func(leak Leak) error {
					if err := e.store.UpsertLeak(leak); err != nil {
						return fmt.Errorf("保存泄漏结果 %s: %w", leak.URL, err)
					}
					saved++
					return nil
				})
				if err != nil {
					errOnce.Do(func() { firstErr = fmt.Errorf("文件泄漏检测 %s: %w", site.URL, err) })
					return
				}
				n := atomic.AddInt32(&done, 1)
				report("文件泄漏检测", fmt.Sprintf("[%d/%d] %s，命中 %d 条", n, len(sites), site.URL, saved), pct)
			}()
		}
		wg.Wait()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if firstErr != nil {
			return firstErr
		}
		pct += 3
		report("文件泄漏检测", "完成", pct)
	}
	if e.opts.DirectoryScan {
		var probes []pathProbe // nil 表示流式使用内置压缩字典。
		if e.opts.DirectoryDictPath != "" {
			if custom, err := loadDirectoryDict(e.opts.DirectoryDictPath); err == nil {
				probes = custom
				report("路径发现", fmt.Sprintf("加载自定义字典 %d 条", len(custom)), pct)
			} else {
				report("路径发现", "加载自定义字典失败，改用内置字典: "+err.Error(), pct)
			}
		}
		source, requestBudget := directoryProbeSourceForMode(probes, e.opts.PathScanMode)
		directoryModeLabel := pathModeLabel
		if probes != nil {
			directoryModeLabel = "自定义字典"
		}
		report("路径发现", fmt.Sprintf("%s：探测 %d 个站点，每站路径预算 %d 条", directoryModeLabel, len(sites), requestBudget), pct)
		// 站点级并发（sem=4，同文件泄漏）：单站内 worker 池不变。
		sem := make(chan struct{}, postSiteConcurrency)
		var wg sync.WaitGroup
		var firstErr error
		var errOnce sync.Once
		var done int32
		for _, site := range sites {
			site := site
			wg.Add(1)
			go func() {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()
				saved := 0
				err := detectDirectoriesEach(ctx, site, taskID, e.opts.Timeout, e.opts.Concurrency, source, func(result DirectoryResult) error {
					if err := e.store.UpsertDirectory(result); err != nil {
						return fmt.Errorf("保存路径结果 %s: %w", result.URL, err)
					}
					saved++
					return nil
				})
				if err != nil {
					errOnce.Do(func() { firstErr = fmt.Errorf("路径发现 %s: %w", site.URL, err) })
					return
				}
				n := atomic.AddInt32(&done, 1)
				report("路径发现", fmt.Sprintf("[%d/%d] %s，命中 %d 条", n, len(sites), site.URL, saved), pct)
			}()
		}
		wg.Wait()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if firstErr != nil {
			return firstErr
		}
		pct += 3
		report("路径发现", "完成", pct)
	}
	if e.opts.Nuclei {
		report("POC 检测", fmt.Sprintf("检测 %d 个站点", len(sites)), pct)
		// 自定义模板一次加载（共享给所有站点），加载失败降级内置。
		var yamlTpls []NucleiTemplate
		if e.opts.NucleiTemplatesDir != "" {
			if tpls, err := loadNucleiTemplates(e.opts.NucleiTemplatesDir); err == nil && len(tpls) > 0 {
				yamlTpls = tpls
				report("POC 检测", fmt.Sprintf("加载 %d 个自定义模板", len(tpls)), pct)
			} else if err != nil {
				report("POC 检测", "加载模板目录失败: "+err.Error(), pct)
			}
		}
		// 站点级并发（sem=10）：原三重串行（站点×模板×路径）改为站点间并行，
		// 模板/路径循环在站点 goroutine 内保持原顺序；首个写库错误温和中止。
		const nucleiConcurrentSites = 10
		sem := make(chan struct{}, nucleiConcurrentSites)
		var wg sync.WaitGroup
		var firstErr error
		var errOnce sync.Once
		var done int32
		for _, site := range sites {
			site := site
			wg.Add(1)
			go func() {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()
				for _, leak := range runNuclei(ctx, site, taskID, e.opts.Timeout) {
					if err := e.store.UpsertLeak(leak); err != nil {
						errOnce.Do(func() { firstErr = fmt.Errorf("保存 POC 结果 %s: %w", leak.URL, err) })
						return
					}
				}
				for _, leak := range runNucleiYAML(ctx, site, taskID, yamlTpls, e.opts.Timeout) {
					if err := e.store.UpsertLeak(leak); err != nil {
						errOnce.Do(func() { firstErr = fmt.Errorf("保存自定义 POC 结果 %s: %w", leak.URL, err) })
						return
					}
				}
				atomic.AddInt32(&done, 1)
			}()
		}
		wg.Wait()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if firstErr != nil {
			return firstErr
		}
		pct += 3
		report("POC 检测", "完成", pct)
	}
	if e.opts.Screenshot {
		report("站点截图", fmt.Sprintf("截图 %d 个站点", len(sites)), pct)
		groups, err := groupScreenshotSites(sites)
		if err != nil {
			return fmt.Errorf("构造截图范围: %w", err)
		}
		for _, group := range groups {
			shot, err := NewScopedScreenshotterContext(ctx, e.opts.ChromePath, e.opts.ScreenshotDir, group)
			if err != nil {
				return fmt.Errorf("截图器初始化失败: %w", err)
			}
			// 组内站点并发（Capture 内部 sem=3 限流）：单站失败仅标记不中断，
			// 首个写库错误经 errOnce 捕获（保持"保存失败中止"语义）。
			var wg sync.WaitGroup
			var firstErr error
			var errOnce sync.Once
			var done int32
			for _, site := range group {
				site := site
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer func() {
						if r := recover(); r != nil {
							errOnce.Do(func() { firstErr = fmt.Errorf("截图任务异常: %v", r) })
						}
					}()
					saved := false
					for _, u := range ScreenshotCandidates(site.URL) {
						if ctx.Err() != nil {
							return
						}
						if path, err := shot.Capture(u); err == nil {
							if err := e.store.SetSiteScreenshot(taskID, site.URL, path); err != nil {
								errOnce.Do(func() { firstErr = fmt.Errorf("保存站点截图路径 %s: %w", site.URL, err) })
								return
							}
							saved = true
							break
						}
					}
					n := atomic.AddInt32(&done, 1)
					if !saved {
						report("站点截图", fmt.Sprintf("截图失败 %s", site.URL), pct)
					} else {
						report("站点截图", fmt.Sprintf("[%d/%d] 已截 %s", n, len(group), site.URL), pct)
					}
				}()
			}
			wg.Wait()
			if ctx.Err() != nil {
				shot.Close()
				return ctx.Err()
			}
			if firstErr != nil {
				shot.Close()
				return firstErr
			}
			shot.Close()
		}
		pct += 3
		report("站点截图", "完成", pct)
	}
	return nil
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
// 443 等 TLS 端口 https 优先（服务识别误判为 http 也先试 https，失败再回退明文 http）。
func webSchemes(port int, service string) []string {
	switch {
	case port == 443 || port == 8443 || port == 9443:
		return []string{"https", "http"}
	case service == "https":
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
	_, err := splitTargets(target)
	return err == nil
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

// maxExpandTargetIPs 单任务展开的 IP 数上限（/16 网段），
// 防 /8 等超大网段一次物化上千万 IP 造成自拒绝服务。
const maxExpandTargetIPs = 65536

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
				if len(out) > maxExpandTargetIPs {
					return nil, fmt.Errorf("目标展开超过 %d 个 IP，请拆分网段或缩小范围", maxExpandTargetIPs)
				}
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
