package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
)

// Screenshotter 基于 chromedp 无头浏览器对站点首页截图，复用单一浏览器实例。
type Screenshotter struct {
	ctx         context.Context
	allocCancel context.CancelFunc
	ctxCancel   context.CancelFunc
	dir         string
	mu          sync.Mutex
}

// NewScreenshotter 构造截图器。chromePath 为空时由 chromedp 自动探测 Chrome。
func NewScreenshotter(chromePath, dir string) (*Screenshotter, error) {
	// CGPreflightScreenCaptureAccess 在 macOS 13+ 有误报（已授权也可能返回 false），
	// 因此不据此阻断截图，仅打印提示；真正失败会在 Capture 时暴露。
	if !hasScreenCapturePermission() {
		println("提示: 屏幕录制权限预检未通过，若截图失败请到 系统设置 → 隐私与安全性 → 屏幕录制 中授权")
	}

	opts := []chromedp.ExecAllocatorOption{
		chromedp.Headless,
		chromedp.NoSandbox,
		chromedp.DisableGPU,
		chromedp.WindowSize(1366, 768),
		chromedp.Flag("ignore-certificate-errors", true),
		// 参考 Goby 的 chromedp 配置，避免 headless Chrome 共享内存不足导致截图失败。
		chromedp.Flag("disable-dev-shm-usage", true),
	}
	if chromePath != "" {
		opts = append([]chromedp.ExecAllocatorOption{chromedp.ExecPath(chromePath)}, opts...)
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, ctxCancel := chromedp.NewContext(allocCtx)

	if err := os.MkdirAll(dir, 0o755); err != nil {
		ctxCancel()
		allocCancel()
		return nil, err
	}
	return &Screenshotter{ctx: ctx, allocCancel: allocCancel, ctxCancel: ctxCancel, dir: dir}, nil
}

// Capture 对 URL 截图并保存，返回文件路径。
func (s *Screenshotter) Capture(url string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	name := hashURL(url) + ".png"
	path := filepath.Join(s.dir, name)
	if _, err := os.Stat(path); err == nil {
		return path, nil // 已截图则直接复用
	}

	// 每次截图用独立的新 tab，避免连续导航的重定向失败污染 tab 状态。
	tabCtx, tabCancel := chromedp.NewContext(s.ctx)
	defer tabCancel()

	var buf []byte
	cctx, cancel := context.WithTimeout(tabCtx, 25*time.Second)
	defer cancel()
	if err := chromedp.Run(cctx,
		chromedp.Navigate(url),
		chromedp.Sleep(1500*time.Millisecond),
		chromedp.CaptureScreenshot(&buf),
	); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		return "", err
	}
	return path, nil
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
