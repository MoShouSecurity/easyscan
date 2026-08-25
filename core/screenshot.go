package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/security"
	"github.com/chromedp/chromedp"
)

// 截图并发与等待参数：单浏览器多 tab 并发（sem 限额），
// 静默窗口/sleep 从 800/600ms 放宽——SPA 等满 12s 上限不变，准确性与速度平衡。
const (
	screenshotMaxConcurrent = 3
	screenshotQuietWindow   = 500 * time.Millisecond
	screenshotPostSleep     = 300 * time.Millisecond
)

// Screenshotter 基于 chromedp 无头浏览器对站点首页截图，复用单一浏览器实例。
// 并发安全：Capture 通过 sem（信号量）限流，多 tab 在共享浏览器进程内并行；
// allowedHosts（host-resolver-rules）与 dir 全程只读，并发读安全。
type Screenshotter struct {
	ctx          context.Context
	allocCancel  context.CancelFunc
	ctxCancel    context.CancelFunc
	dir          string
	sem          chan struct{}     // 并发截图配额（默认 3）
	allowedHosts map[string]string // hostname -> 扫描阶段确认的固定 IP
}

// NewScreenshotter 构造截图器。chromePath 为空时由 chromedp 自动探测 Chrome。
func NewScreenshotter(chromePath, dir string) (*Screenshotter, error) {
	return NewScreenshotterContext(context.Background(), chromePath, dir)
}

// NewScreenshotterContext 构造可随父任务取消的截图器。
func NewScreenshotterContext(parent context.Context, chromePath, dir string) (*Screenshotter, error) {
	return newScreenshotterContext(parent, chromePath, dir, nil)
}

// NewScopedScreenshotterContext 构造绑定到当前任务已发现站点集合的截图器。
// Chrome 的 DNS 解析被固定到各 Site.IP，集合外的子资源和重定向都会被拦截。
func NewScopedScreenshotterContext(parent context.Context, chromePath, dir string, sites []Site) (*Screenshotter, error) {
	allowedHosts := make(map[string]string, len(sites))
	for _, site := range sites {
		scope, err := newSiteScope(site)
		if err != nil {
			return nil, err
		}
		if existing, exists := allowedHosts[scope.hostname]; exists && existing != scope.ip {
			return nil, fmt.Errorf("主机 %s 同时关联多个 IP，需分组截图", scope.hostname)
		}
		allowedHosts[scope.hostname] = scope.ip
	}
	if len(allowedHosts) == 0 {
		return nil, fmt.Errorf("没有可截图的有效站点")
	}
	return newScreenshotterContext(parent, chromePath, dir, allowedHosts)
}

// groupScreenshotSites 把同一 hostname 的不同 IP 拆到不同浏览器组，
// 避免 host-resolver-rules 把其中一个站点错误映射到另一个 IP。
func groupScreenshotSites(sites []Site) ([][]Site, error) {
	var groups [][]Site
	groupHosts := make([]map[string]string, 0)
	for _, site := range sites {
		scope, err := newSiteScope(site)
		if err != nil {
			return nil, err
		}
		placed := false
		for i, hosts := range groupHosts {
			if ip, exists := hosts[scope.hostname]; exists && ip != scope.ip {
				continue
			}
			groups[i] = append(groups[i], site)
			hosts[scope.hostname] = scope.ip
			placed = true
			break
		}
		if !placed {
			groups = append(groups, []Site{site})
			groupHosts = append(groupHosts, map[string]string{scope.hostname: scope.ip})
		}
	}
	return groups, nil
}

func newScreenshotterContext(parent context.Context, chromePath, dir string, allowedHosts map[string]string) (*Screenshotter, error) {
	if parent == nil {
		parent = context.Background()
	}
	opts := []chromedp.ExecAllocatorOption{
		// headless=new：Chromium 新版无头模式，完全离屏渲染。
		// 进程不触碰屏幕采集 API（CGWindowList/CGDisplay 等），不触发
		// macOS 屏幕录制（TCC）权限弹窗——与 Goby（Electron capturePage）同理。
		chromedp.Flag("headless", "new"),
		chromedp.NoSandbox,
		chromedp.DisableGPU,
		chromedp.WindowSize(1366, 768),
		chromedp.Flag("ignore-certificate-errors", true),
		// 参考 Goby 的 chromedp 配置，避免 headless Chrome 共享内存不足导致截图失败。
		chromedp.Flag("disable-dev-shm-usage", true),
	}
	if len(allowedHosts) > 0 {
		hosts := make([]string, 0, len(allowedHosts))
		for host := range allowedHosts {
			hosts = append(hosts, host)
		}
		sort.Strings(hosts)
		var rules []string
		for _, host := range hosts {
			if net.ParseIP(host) != nil {
				continue
			}
			ip := allowedHosts[host]
			if strings.Contains(ip, ":") {
				ip = "[" + ip + "]"
			}
			rules = append(rules, fmt.Sprintf("MAP %s %s", host, ip))
		}
		if len(rules) > 0 {
			opts = append(opts, chromedp.Flag("host-resolver-rules", strings.Join(rules, ", ")))
		}
	}
	if chromePath != "" {
		opts = append([]chromedp.ExecAllocatorOption{chromedp.ExecPath(chromePath)}, opts...)
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(parent, opts...)
	ctx, ctxCancel := chromedp.NewContext(allocCtx)

	if err := os.MkdirAll(dir, 0o755); err != nil {
		ctxCancel()
		allocCancel()
		return nil, err
	}
	return &Screenshotter{
		ctx:          ctx,
		allocCancel:  allocCancel,
		ctxCancel:    ctxCancel,
		dir:          dir,
		sem:          make(chan struct{}, screenshotMaxConcurrent),
		allowedHosts: allowedHosts,
	}, nil
}

// Capture 对 URL 截图并保存，返回文件路径。并发安全：sem 限流（默认 3）。
func (s *Screenshotter) Capture(url string) (string, error) {
	s.sem <- struct{}{}
	defer func() { <-s.sem }()
	if len(s.allowedHosts) > 0 && !s.allows(url) {
		return "", fmt.Errorf("拒绝截图扫描范围外地址 %q", url)
	}

	name := hashURL(url) + ".png"
	path := filepath.Join(s.dir, name)
	if _, err := os.Stat(path); err == nil {
		return path, nil // 已截图则直接复用
	}

	// 每次截图用独立的新 tab，避免连续导航的重定向失败污染 tab 状态。
	tabCtx, tabCancel := chromedp.NewContext(s.ctx)
	defer tabCancel()

	var buf []byte
	cctx, cancel := context.WithTimeout(tabCtx, 30*time.Second)
	defer cancel()

	// 网络静默状态：导航前注册监听，记录最近一次网络活动时间，
	// 供 waitNetworkIdle 判定 SPA 异步加载是否结束。
	var mu sync.Mutex
	lastActive := time.Now()
	markActive := func() {
		mu.Lock()
		lastActive = time.Now()
		mu.Unlock()
	}
	listen := chromedp.ActionFunc(func(ctx context.Context) error {
		chromedp.ListenTarget(ctx, func(ev interface{}) {
			switch e := ev.(type) {
			case *fetch.EventRequestPaused:
				allowed := len(s.allowedHosts) == 0 || s.allows(e.Request.URL) || isBrowserLocalURL(e.Request.URL)
				go func() {
					if allowed {
						_ = fetch.ContinueRequest(e.RequestID).Do(ctx)
						return
					}
					_ = fetch.FailRequest(e.RequestID, network.ErrorReasonBlockedByClient).Do(ctx)
				}()
			case *network.EventRequestWillBeSent,
				*network.EventResponseReceived,
				*network.EventLoadingFinished,
				*network.EventLoadingFailed:
				markActive()
			}
		})
		return nil
	})
	actions := []chromedp.Action{
		// 忽略 SSL 证书错误（自签名/过期证书的站点也能截图）。
		chromedp.ActionFunc(func(ctx context.Context) error {
			return security.SetIgnoreCertificateErrors(true).Do(ctx)
		}),
		listen,
	}
	if len(s.allowedHosts) > 0 {
		actions = append(actions, fetch.Enable().WithPatterns([]*fetch.RequestPattern{{URLPattern: "*", RequestStage: fetch.RequestStageRequest}}))
	}
	actions = append(actions,
		chromedp.Navigate(url),
		chromedp.ActionFunc(func(ctx context.Context) error {
			return waitNetworkIdle(ctx, &mu, &lastActive, 12*time.Second, screenshotQuietWindow)
		}),
		chromedp.Sleep(screenshotPostSleep),
		chromedp.CaptureScreenshot(&buf),
	)

	if err := chromedp.Run(cctx, actions...); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func (s *Screenshotter) allows(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.User != nil || !isHTTPScheme(u.Scheme) {
		return false
	}
	_, ok := s.allowedHosts[normalizeHTTPHost(u.Hostname())]
	return ok
}

func isBrowserLocalURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "about", "blob", "data":
		return true
	default:
		return false
	}
}

// Close 释放浏览器资源。
func (s *Screenshotter) Close() {
	s.ctxCancel()
	s.allocCancel()
}

func hashURL(u string) string {
	h := sha256.Sum256([]byte(u))
	return hex.EncodeToString(h[:])[:16]
}

// waitNetworkIdle 等待网络静默（静默窗口 quiet 内无新请求），最多等 maxWait。
// lastActive 由调用方在导航前注册的网络事件监听持续更新。
// 到达 maxWait 仍未静默也不报错（继续截图），由外层 context 超时兜底。
func waitNetworkIdle(ctx context.Context, mu *sync.Mutex, lastActive *time.Time, maxWait, quiet time.Duration) error {
	deadline := time.Now().Add(maxWait)
	for {
		mu.Lock()
		idle := time.Since(*lastActive) >= quiet
		mu.Unlock()
		if idle || time.Now().After(deadline) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// DetectChromePath 探测本机 Chrome/Chromium/Edge 可执行文件路径，找不到返回空串。
func DetectChromePath() string {
	var candidates []string
	switch runtime.GOOS {
	case "darwin":
		candidates = []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
		}
	case "windows":
		candidates = []string{
			os.Getenv("LOCALAPPDATA") + `\Google\Chrome\Application\chrome.exe`,
			os.Getenv("PROGRAMFILES") + `\Google\Chrome\Application\chrome.exe`,
			os.Getenv("PROGRAMFILES(X86)") + `\Google\Chrome\Application\chrome.exe`,
			os.Getenv("PROGRAMFILES") + `\Microsoft\Edge\Application\msedge.exe`,
		}
	default: // linux
		candidates = []string{
			"/usr/bin/google-chrome",
			"/usr/bin/google-chrome-stable",
			"/usr/bin/chromium",
			"/usr/bin/chromium-browser",
			"/snap/bin/chromium",
		}
	}
	for _, p := range candidates {
		if p != "" {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return ""
}

// ScreenshotCandidates 返回截图的候选 URL（按顺序逐个尝试，直到成功）。
// 规避 chromedp 对重定向导航（http→https、去默认端口）触发 context canceled 的问题。
func ScreenshotCandidates(u string) []string {
	var out []string
	add := func(s string) {
		for _, x := range out {
			if x == s {
				return
			}
		}
		out = append(out, s)
	}

	// 443 端口的 http URL：https 变体优先（TLS 端口应直接截 https 的图）。
	if strings.HasPrefix(u, "http://") && strings.Contains(u, ":443/") {
		add(strings.Replace(u, "http://", "https://", 1))
	}
	add(u)

	// 去掉默认端口（:80 / :443）。
	if strings.HasPrefix(u, "http://") && strings.Contains(u, ":80/") {
		add(strings.Replace(u, ":80/", "/", 1))
	}
	if strings.HasPrefix(u, "https://") && strings.Contains(u, ":443/") {
		add(strings.Replace(u, ":443/", "/", 1))
	}

	// http → https（去掉 80 端口）。
	if strings.HasPrefix(u, "http://") {
		add(httpsVariant(u))
	}

	return out
}

// httpsVariant 将 http URL 转为 https（去掉默认 80 端口）。
func httpsVariant(u string) string {
	rest := strings.TrimPrefix(u, "http://")
	if strings.HasSuffix(rest, ":80/") {
		rest = strings.TrimSuffix(rest, ":80/") + "/"
	}
	return "https://" + rest
}
