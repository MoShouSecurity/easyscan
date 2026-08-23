package core

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProbeSiteBlocksCrossHostRedirect(t *testing.T) {
	var escaped atomic.Int32
	offScope := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escaped.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer offScope.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, offScope.URL+"/internal", http.StatusFound)
	}))
	defer target.Close()
	port := serverPort(t, target.URL)

	site, ok := probeSite(context.Background(), "127.0.0.1", port, "http", "target.example", 2*time.Second)
	if !ok {
		t.Fatal("目标的原始重定向响应应仍被识别为站点")
	}
	if escaped.Load() != 0 {
		t.Fatalf("跨主机重定向被访问 %d 次", escaped.Load())
	}
	if !strings.Contains(site.URL, "target.example") {
		t.Fatalf("site.URL = %q; want target.example origin", site.URL)
	}
}

func TestProbeSiteStoresOriginAfterPathRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusFound)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<title>Login</title>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	site, ok := probeSite(context.Background(), u.Hostname(), serverPort(t, srv.URL), "http", "", 2*time.Second)
	if !ok {
		t.Fatal("同主机路径重定向探测失败")
	}
	if site.URL != srv.URL+"/" {
		t.Fatalf("site.URL = %q; want origin %q", site.URL, srv.URL+"/")
	}
}

func TestSiteScopePinsHostnameToDiscoveredIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("pinned"))
	}))
	defer srv.Close()
	port := serverPort(t, srv.URL)
	scope, err := newSiteScope(Site{IP: "127.0.0.1", URL: "http://does-not-resolve.invalid:" + portString(port) + "/"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := scope.client(2*time.Second, 0).Get(scope.baseURL)
	if err != nil {
		t.Fatalf("固定 IP 请求失败: %v", err)
	}
	resp.Body.Close()
}

func TestDetectLeaksRejectsSoft404(t *testing.T) {
	page := strings.Repeat("generic single-page application not found ", 20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(page))
	}))
	defer srv.Close()

	leaks := detectLeaks(context.Background(), Site{URL: srv.URL}, "task", 2*time.Second, leakRules)
	if len(leaks) != 0 {
		t.Fatalf("软 404 不应产生泄漏结果: %+v", leaks)
	}
}

func TestNucleiTemplateRejectsCrossOriginAbsoluteURL(t *testing.T) {
	var escaped atomic.Int32
	offScope := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escaped.Add(1)
		w.Write([]byte("matched"))
	}))
	defer offScope.Close()
	target := httptest.NewServer(http.NotFoundHandler())
	defer target.Close()

	templates := []NucleiTemplate{{
		ID: "cross-origin",
		Requests: []NucleiRequest{{
			Method: http.MethodGet,
			Path:   StringOrList{offScope.URL + "/metadata"},
			Matchers: []NucleiMatcher{{
				Type:  "word",
				Words: []string{"matched"},
			}},
		}},
	}}
	if got := runNucleiYAML(context.Background(), Site{URL: target.URL}, "task", templates, 2*time.Second); len(got) != 0 {
		t.Fatalf("跨 origin 模板不应命中: %+v", got)
	}
	if escaped.Load() != 0 {
		t.Fatalf("跨 origin 模板发出了 %d 次请求", escaped.Load())
	}
}

func TestTaskParamsNeverExposeOrPersistSecrets(t *testing.T) {
	store, err := OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	opts := DefaultScanOptions()
	opts.FofaKey = "fofa-secret"
	opts.ProxyURL = "http://user:proxy-secret@127.0.0.1:7890"
	scheduler := NewScheduler(store, opts)
	task, err := scheduler.Submit("127.0.0.1", TaskIP, opts)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := store.GetTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored.Params, "fofa-secret") || strings.Contains(stored.Params, "proxy-secret") {
		t.Fatalf("任务参数仍包含凭据: %s", stored.Params)
	}
	publicJSON, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(publicJSON), "params") {
		t.Fatalf("任务 JSON 仍暴露 params: %s", publicJSON)
	}
}

func TestScopedScreenshotRejectsUnknownHostBeforeNavigation(t *testing.T) {
	shot, err := NewScopedScreenshotterContext(context.Background(), "", t.TempDir(), []Site{{
		IP:  "127.0.0.1",
		URL: "http://target.example/",
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer shot.Close()
	if _, err := shot.Capture("http://127.0.0.1/internal"); err == nil {
		t.Fatal("截图器接受了任务范围外主机")
	}
}

func TestScreenshotGroupsSplitSameHostDifferentIPs(t *testing.T) {
	groups, err := groupScreenshotSites([]Site{
		{IP: "192.0.2.10", URL: "https://multi.example/"},
		{IP: "192.0.2.11", URL: "https://multi.example:8443/"},
		{IP: "192.0.2.12", URL: "https://other.example/"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 {
		t.Fatalf("截图分组数 = %d; want 2", len(groups))
	}
}

func TestPipelineReturnsStoreErrors(t *testing.T) {
	store, err := OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(store, DefaultScanOptions())
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := engine.updateStage("task", StagePortScan); err == nil {
		t.Fatal("数据库关闭后更新阶段应返回错误")
	}
	if _, err := engine.scanPortsAndSites(context.Background(), nil, nil, nil, "task", nil, 0, 90); err == nil {
		t.Fatal("数据库关闭后扫描流水线应返回错误")
	}
}

func TestStoreMigrationRedactsLegacyTaskSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	task := &Task{ID: newID(), Target: "example.com", Type: TaskDomain, Status: TaskPaused, Params: `{"port_mode":"test","fofa_key":"legacy-key","proxy_url":"http://u:p@proxy"}`, CreatedAt: nowUnix()}
	if err := store.CreateTask(task); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	stored, err := store.GetTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored.Params, "legacy-key") || strings.Contains(stored.Params, "proxy") {
		t.Fatalf("旧任务凭据未清理: %s", stored.Params)
	}
	if !strings.Contains(stored.Params, "port_mode") {
		t.Fatalf("非敏感任务参数被意外删除: %s", stored.Params)
	}
}

func serverPort(t *testing.T, rawURL string) int {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func portString(port int) string { return strconv.Itoa(port) }
