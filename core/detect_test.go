package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestDetectLeaksAndNuclei 用本地 HTTP 服务器验证泄漏检测与 POC 检测能正确命中。
func TestDetectLeaksAndNuclei(t *testing.T) {
	mux := http.NewServeMux()
	// 模拟 Git 源码泄露。
	mux.HandleFunc("/.git/config", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("[core]\n\trepositoryformatversion = 0\n"))
	})
	// 模拟 SpringBoot Actuator 未授权。
	mux.HandleFunc("/actuator/env", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"propertySources":[{"name":"systemProperties"}]}`))
	})
	// 其它路径返回 404。
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	site := Site{URL: srv.URL}
	ctx := context.Background()
	timeout := 2 * time.Second

	leaks := detectLeaks(ctx, site, "task1", timeout, leakRules)
	if !hasLeakType(leaks, "git") {
		t.Fatalf("文件泄漏检测未命中 .git/config: %+v", leaks)
	}

	pocs := runNuclei(ctx, site, "task1", timeout)
	if !hasLeakType(pocs, "nuclei:SpringBoot Actuator 未授权访问") {
		t.Fatalf("POC 检测未命中 actuator: %+v", pocs)
	}
}

func hasLeakType(leaks []Leak, typ string) bool {
	for _, l := range leaks {
		if l.Type == typ {
			return true
		}
	}
	return false
}
