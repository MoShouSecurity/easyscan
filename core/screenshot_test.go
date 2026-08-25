package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// TestWebSchemes443First 443 等 TLS 端口 https 优先（即使服务被误判为 http）。
func TestWebSchemes443First(t *testing.T) {
	cases := []struct {
		port    int
		service string
		want    string // 期望的第一个 scheme
	}{
		{443, "http", "https"},  // nmap 误判 http 也先试 https
		{443, "https", "https"}, // 正常
		{8443, "", "https"},     // 空服务按端口
		{80, "http", "http"},    // 常规 http
		{8080, "", "http"},      // web 端口默认先 http
		{22, "ssh", ""},         // 非 web 端口无 scheme
	}
	for _, c := range cases {
		got := webSchemes(c.port, c.service)
		if c.want == "" {
			if got != nil {
				t.Errorf("webSchemes(%d, %q) = %v; want nil", c.port, c.service, got)
			}
			continue
		}
		if len(got) == 0 || got[0] != c.want {
			t.Errorf("webSchemes(%d, %q) = %v; want 首个 %s", c.port, c.service, got, c.want)
		}
	}
}

// TestScreenshotCandidatesHTTPS443First http 的 443 端口 URL，https 变体必须排第一。
func TestScreenshotCandidatesHTTPS443First(t *testing.T) {
	got := ScreenshotCandidates("http://10.0.0.5:443/")
	if len(got) == 0 || got[0] != "https://10.0.0.5:443/" {
		t.Fatalf("ScreenshotCandidates(http://10.0.0.5:443/) = %v; want https 变体优先", got)
	}
	// 常规 http URL 仍以原样优先。
	got = ScreenshotCandidates("http://10.0.0.5/")
	if len(got) == 0 || got[0] != "http://10.0.0.5/" {
		t.Fatalf("ScreenshotCandidates(http://10.0.0.5/) = %v; want 原样优先", got)
	}
}

// TestScreenshotCapture 诊断 chromedp 是否能找到 Chrome 并截图。
func TestScreenshotCapture(t *testing.T) {
	dir := t.TempDir()
	shot, err := NewScreenshotter("", dir)
	if err != nil {
		t.Fatalf("NewScreenshotter: %v", err)
	}
	defer shot.Close()

	path, err := shot.Capture("data:text/html,<html><body><h1>hello</h1></body></html>")
	if err != nil {
		t.Fatalf("Capture 失败: %v", err)
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("截图文件不存在: %v", statErr)
	}
	t.Logf("截图成功: %s", path)
}

// TestScreenshotPostProcess 验证 postProcess 的截图能生成文件并存入数据库。
func TestScreenshotPostProcess(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><head><title>Test</title></head><body>hi</body></html>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	store, err := OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	opts := DefaultScanOptions()
	opts.Screenshot = true
	opts.ScreenshotDir = t.TempDir()

	engine := NewEngine(store, opts)

	site := Site{ID: newID(), IP: "127.0.0.1", Port: 80, URL: srv.URL, Title: "Test", TaskID: "t1", CreatedAt: nowUnix()}
	if err := store.UpsertSite(site); err != nil {
		t.Fatal(err)
	}

	engine.postProcess(context.Background(), []Site{site}, "t1", func(stage, detail string, pct int) {}, 90)

	sites, _ := store.ListSitesByTask("t1", 0, 0)
	if len(sites) == 0 || sites[0].Screenshot == "" {
		t.Fatalf("截图未存入数据库: %+v", sites)
	}
	t.Logf("截图路径已存入: %s", sites[0].Screenshot)
}

// TestScreenshotMulti 诊断连续截图是否间歇性失败（tab 状态污染）。
func TestScreenshotMulti(t *testing.T) {
	dir := t.TempDir()
	shot, err := NewScreenshotter("", dir)
	if err != nil {
		t.Fatal(err)
	}
	defer shot.Close()

	urls := []string{
		"https://example.com/",
		"https://example.com/",
		"https://example.com/",
	}
	for i, u := range urls {
		path, err := shot.Capture(u)
		t.Logf("第%d次 %s -> err=%v", i+1, u, err)
		_ = path
	}
}
