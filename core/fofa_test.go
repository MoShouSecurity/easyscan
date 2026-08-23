package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestFofaFilterResults 过滤逻辑 table-driven 测试。
func TestFofaFilterResults(t *testing.T) {
	cases := []struct {
		name     string
		rows     [][]string
		want     int
		first    string // 期望第一条 host（无则为空）
		wantPort int    // 期望第一条 port（-1 表示不校验）
	}{
		{"正常子域名", [][]string{{"api.example.com", "1.2.3.4"}}, 1, "api.example.com", -1},
		{"根域名本身", [][]string{{"example.com", "1.2.3.4"}}, 1, "example.com", -1},
		{"大小写加尾点归一化", [][]string{{"Www.Example.COM.", "1.2.3.4"}}, 1, "www.example.com", -1},
		{"裸 IP host 丢弃", [][]string{{"1.2.3.4", "5.6.7.8"}}, 0, "", -1},
		{"前缀绕过丢弃", [][]string{{"sub.example.com.evil.com", "1.2.3.4"}}, 0, "", -1},
		{"无关域名丢弃", [][]string{{"other.com", "1.2.3.4"}}, 0, "", -1},
		{"空 host 丢弃", [][]string{{"", "1.2.3.4"}}, 0, "", -1},
		{"空 IP 丢弃", [][]string{{"a.example.com", ""}}, 0, "", -1},
		{"非法 IP 丢弃", [][]string{{"a.example.com", "not-an-ip"}}, 0, "", -1},
		{"带端口 IP 丢弃", [][]string{{"a.example.com", "1.2.3.4:8080"}}, 0, "", -1},
		{"重复 host 保留首条", [][]string{{"a.example.com", "1.1.1.1"}, {"a.example.com", "2.2.2.2"}}, 1, "a.example.com", -1},
		{"合法端口保留", [][]string{{"a.example.com", "1.1.1.1", "8080"}}, 1, "a.example.com", 8080},
		{"非法端口置零", [][]string{{"a.example.com", "1.1.1.1", "not-a-port"}}, 1, "a.example.com", 0},
		{"无端口列", [][]string{{"a.example.com", "1.1.1.1"}}, 1, "a.example.com", 0},
		{"URL形态剥scheme", [][]string{{"https://gwq.example.com", "1.1.1.1"}}, 1, "gwq.example.com", 0},
		{"URL形态剥路径", [][]string{{"http://a.example.com/login", "1.1.1.1"}}, 1, "a.example.com", 0},
		{"域名带端口剥端口", [][]string{{"a.example.com:8443", "1.1.1.1"}}, 1, "a.example.com", 0},
		{"URL形态同域名归并", [][]string{{"https://a.example.com", "1.1.1.1"}, {"a.example.com", "2.2.2.2"}}, 1, "a.example.com", 0},
		{"列不足丢弃", [][]string{{"x"}}, 0, "", -1},
		{"混合行", [][]string{
			{"ok.example.com", "1.1.1.1"},
			{"bad.evil.com", "2.2.2.2"},
			{"", "3.3.3.3"},
		}, 1, "ok.example.com", -1},
	}
	for _, c := range cases {
		got := fofaFilterResults("example.com", c.rows)
		if len(got) != c.want {
			t.Errorf("%s: 结果数 = %d; want %d (%+v)", c.name, len(got), c.want, got)
			continue
		}
		if c.first != "" && (len(got) == 0 || got[0].Host != c.first) {
			t.Errorf("%s: 首条 = %+v; want host %s", c.name, got, c.first)
		}
		if c.wantPort >= 0 && (len(got) == 0 || got[0].Port != c.wantPort) {
			t.Errorf("%s: 首条 port = %+v; want %d", c.name, got, c.wantPort)
		}
	}
}

// startFofaMock 起一个 FOFA API mock server，返回 handler 与请求计数。
func startFofaMock(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestFofaSearchOK(t *testing.T) {
	srv, hits := startFofaMock(t, func(w http.ResponseWriter, r *http.Request) {
		// 断言请求参数。
		if got := r.URL.Query().Get("key"); got != "test-key" {
			t.Errorf("key = %q; want test-key", got)
		}
		decoded, err := base64.StdEncoding.DecodeString(r.URL.Query().Get("qbase64"))
		if err != nil || string(decoded) != `domain="example.com"` {
			t.Errorf("qbase64 解码 = %q err=%v; want domain=\"example.com\"", decoded, err)
		}
		if got := r.URL.Query().Get("fields"); got != "host,ip,port" {
			t.Errorf("fields = %q; want host,ip,port", got)
		}
		if got := r.URL.Query().Get("size"); got != "10000" {
			t.Errorf("size = %q; want 10000", got)
		}
		if got := r.URL.Query().Get("page"); got != "1" {
			t.Errorf("page = %q; want 1", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":false,"size":2,"results":[["a.example.com","1.1.1.1","8080"],["1.2.3.4","5.6.7.8","80"]]}`))
	})

	// 直连 mock（proxyURL 传空）。
	results, err := fofaSearchImpl(context.Background(), "example.com", "test-key", "", 10*time.Second, srv.URL+"/api/v1/search/all")
	if err != nil {
		t.Fatalf("fofaSearch: %v", err)
	}
	_ = hits
	if len(results) != 1 || results[0].Host != "a.example.com" || results[0].IP != "1.1.1.1" || results[0].Port != 8080 {
		t.Fatalf("results = %+v; want 仅 a.example.com（裸 IP 行被过滤，port=8080）", results)
	}
}

func TestFofaSearchEmptyKey(t *testing.T) {
	srv, hits := startFofaMock(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("空 key 不应发请求")
	})
	results, err := fofaSearchImpl(context.Background(), "example.com", "", "", 5*time.Second, srv.URL+"/api/v1/search/all")
	if err != nil || results != nil {
		t.Fatalf("空 key 应返回 nil,nil; got %+v err=%v", results, err)
	}
	if atomic.LoadInt32(hits) != 0 {
		t.Fatal("空 key 发出了请求")
	}
}

func TestFofaSearchAPIError(t *testing.T) {
	srv, _ := startFofaMock(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"error":true,"errmsg":"余额不足"}`))
	})
	_, err := fofaSearchImpl(context.Background(), "example.com", "k", "", 5*time.Second, srv.URL+"/api/v1/search/all")
	if err == nil || !strings.Contains(err.Error(), "余额不足") {
		t.Fatalf("err = %v; want 包含「余额不足」", err)
	}
}

func TestFofaSearchHTTPError(t *testing.T) {
	srv, _ := startFofaMock(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte("boom"))
	})
	if _, err := fofaSearchImpl(context.Background(), "example.com", "k", "", 5*time.Second, srv.URL+"/api/v1/search/all"); err == nil {
		t.Fatal("HTTP 500 应返回错误")
	}
}

func TestFofaSearchProxy(t *testing.T) {
	// 假代理 server：收到请求后返回合法 FOFA JSON（模拟转发）。
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": false, "size": 1,
			"results": [][]string{{"api.example.com", "9.9.9.9"}},
		})
	}))
	defer proxySrv.Close()

	// 直连的 mock 不应收到任何请求。
	srv, hits := startFofaMock(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("请求应走代理而非直连")
	})

	results, err := fofaSearchImpl(context.Background(), "example.com", "k", proxySrv.URL, 5*time.Second, srv.URL+"/api/v1/search/all")
	if err != nil {
		t.Fatalf("fofaSearch(proxy): %v", err)
	}
	if len(results) != 1 || results[0].IP != "9.9.9.9" {
		t.Fatalf("results = %+v", results)
	}
	if atomic.LoadInt32(hits) != 0 {
		t.Fatal("直连 mock 收到了请求")
	}
}

func TestFofaTimeout(t *testing.T) {
	if got := fofaTimeout(5 * time.Second); got != 15*time.Second {
		t.Errorf("fofaTimeout(5s) = %v; want 15s", got)
	}
	if got := fofaTimeout(30 * time.Second); got != 30*time.Second {
		t.Errorf("fofaTimeout(30s) = %v; want 30s", got)
	}
}

// TestPersistEnumerated 验证枚举入库：首次写入、任务隔离、无 IP 入库、nil store 防御。
func TestPersistEnumerated(t *testing.T) {
	s, err := OpenStore("")
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer s.Close()
	const taskID = "task-fofa"
	const domain = "example.com"

	// 首次入库（无 IP）。
	persistEnumerated(s, domain, taskID, "subfinder", []string{"a.example.com", "b.example.com"})
	subs, err := s.ListSubdomains(domain, 0)
	if err != nil || len(subs) != 2 {
		t.Fatalf("ListSubdomains = %d err=%v; want 2", len(subs), err)
	}
	got := subs[0]
	if got.Source != "subfinder" || got.IP != "" || got.TaskID != taskID {
		t.Fatalf("入库记录 = %+v; want source=subfinder ip=空 task=task-fofa", got)
	}

	// 另一任务写入同一子域名时，两份任务结果必须各自保留。
	_ = s.UpsertSubdomain(Subdomain{ID: newID(), Domain: domain, Subdomain: "a.example.com", IP: "1.2.3.4", Source: "resolved", TaskID: "task-other", CreatedAt: nowUnix()})
	original, err := s.ListSubdomainsByTask(taskID, 0)
	if err != nil || len(original) != 2 {
		t.Fatalf("原任务记录 = %+v err=%v", original, err)
	}
	for _, sd := range original {
		if sd.Subdomain == "a.example.com" && (sd.Source != "subfinder" || sd.IP != "" || sd.TaskID != taskID) {
			t.Fatalf("另一任务覆盖了原任务记录: %+v", sd)
		}
	}
	other, err := s.ListSubdomainsByTask("task-other", 0)
	if err != nil || len(other) != 1 || other[0].IP != "1.2.3.4" || other[0].Source != "resolved" {
		t.Fatalf("另一任务记录 = %+v err=%v", other, err)
	}

	// nil store 防御（不 panic）。
	persistEnumerated(nil, domain, taskID, "x", []string{"c.example.com"})
}
