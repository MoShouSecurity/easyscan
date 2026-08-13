package core

import (
	"net/http"
	"strings"
	"testing"
)

func TestOpenStoreAndRoundtrip(t *testing.T) {
	s, err := OpenStore("")
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer s.Close()

	d := Domain{ID: newID(), Domain: "example.com", Source: "manual", CreatedAt: nowUnix()}
	if err := s.UpsertDomain(d); err != nil {
		t.Fatalf("UpsertDomain: %v", err)
	}

	sd := Subdomain{ID: newID(), Domain: "example.com", Subdomain: "www.example.com", IP: "1.2.3.4", Source: "crtsh", CreatedAt: nowUnix()}
	if err := s.UpsertSubdomain(sd); err != nil {
		t.Fatalf("UpsertSubdomain: %v", err)
	}

	// 重复插入应幂等，不报错。
	if err := s.UpsertSubdomain(sd); err != nil {
		t.Fatalf("UpsertSubdomain (dup): %v", err)
	}

	n, err := s.SubdomainCount("example.com")
	if err != nil || n != 1 {
		t.Fatalf("SubdomainCount = %d, err=%v; want 1", n, err)
	}

	subs, err := s.ListSubdomains("example.com", 10)
	if err != nil || len(subs) != 1 {
		t.Fatalf("ListSubdomains len=%d, err=%v; want 1", len(subs), err)
	}
	if subs[0].Subdomain != "www.example.com" || subs[0].IP != "1.2.3.4" {
		t.Fatalf("unexpected subdomain: %+v", subs[0])
	}

	p := Port{ID: newID(), IP: "1.2.3.4", Port: 443, Protocol: "tcp", Service: "https", CreatedAt: nowUnix()}
	if err := s.UpsertPort(p); err != nil {
		t.Fatalf("UpsertPort: %v", err)
	}
	if n, _ := s.PortCount(); n != 1 {
		t.Fatalf("PortCount = %d; want 1", n)
	}

	site := Site{ID: newID(), IP: "1.2.3.4", Port: 443, URL: "https://1.2.3.4/", Title: "Example", Server: "nginx", Fingerprint: "Nginx", CreatedAt: nowUnix()}
	if err := s.UpsertSite(site); err != nil {
		t.Fatalf("UpsertSite: %v", err)
	}

	// 任务创建与更新。
	task := &Task{ID: newID(), Target: "example.com", Type: TaskDomain, Status: TaskPending, CreatedAt: nowUnix()}
	if err := s.CreateTask(task); err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	task.Status = TaskFinished
	task.Progress = 100
	if err := s.UpdateTask(task); err != nil {
		t.Fatalf("UpdateTask: %v", err)
	}
	got, err := s.GetTask(task.ID)
	if err != nil || got.Status != TaskFinished || got.Progress != 100 {
		t.Fatalf("GetTask = %+v err=%v", got, err)
	}
}

func TestPortList(t *testing.T) {
	cases := map[string]int{
		"test":    5,
		"top100":  100,
		"top1000": 996,
		"all":     65535,
	}
	for mode, want := range cases {
		got := portList(mode)
		if len(got) != want {
			t.Errorf("portList(%s) = %d ports; want %d", mode, len(got), want)
		}
	}
}

func TestExpandTarget(t *testing.T) {
	ips, err := expandTarget("1.2.3.4")
	if err != nil || len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Fatalf("expandTarget(single) = %v err=%v", ips, err)
	}

	ips, err = expandTarget("10.0.0.0/30")
	if err != nil || len(ips) != 4 {
		t.Fatalf("expandTarget(/30) = %v err=%v; want 4 IPs", ips, err)
	}

	if _, err := expandTarget("not-an-ip"); err == nil {
		t.Fatal("expandTarget(invalid) should error")
	}

	// 多个 IP/CIDR 合并展开。
	ips, err = expandTarget("1.2.3.4, 5.6.7.0/30")
	if err != nil || len(ips) != 5 {
		t.Fatalf("expandTarget(multi) = %v err=%v; want 5 IPs", ips, err)
	}
}

func TestIsIPTarget(t *testing.T) {
	cases := map[string]bool{
		"1.2.3.4":         true,
		"10.0.0.0/24":     true,
		"2001:db8::1":     true,
		"example.com":     false,
		"www.example.com": false,
		"example.com/24":  false,
	}
	for target, want := range cases {
		if got := IsIPTarget(target); got != want {
			t.Errorf("IsIPTarget(%q) = %v; want %v", target, got, want)
		}
	}
}

func TestGuessServiceFromBanner(t *testing.T) {
	cases := map[string]string{
		"SSH-2.0-OpenSSH_8.9": "ssh",
		"HTTP/1.1 400 Bad Request\r\n": "http",
		"+OK Hello":            "pop3",
		"220 smtp.example ESMTP": "smtp",
	}
	for banner, want := range cases {
		if got := guessServiceFromBanner(banner); got != want {
			t.Errorf("guessServiceFromBanner(%q) = %q; want %q", banner, got, want)
		}
	}
}

func TestMatchFingerprint(t *testing.T) {
	body := []byte(`<html><head><title>My Blog</title></head><body><script src="/wp-content/themes/x"></script></body></html>`)
	h := http.Header{}
	h.Set("Server", "nginx")
	got := matchFingerprint(body, h)
	if !strings.Contains(got, "Nginx") || !strings.Contains(got, "WordPress") {
		t.Fatalf("matchFingerprint = %q; want Nginx + WordPress", got)
	}
}

func TestTitleExtract(t *testing.T) {
	body := []byte("<html><head><TITLE>Example &amp; Domain</TITLE></head></html>")
	m := titleRe.FindSubmatch(body)
	if len(m) < 2 {
		t.Fatal("title not matched")
	}
	got := strings.TrimSpace(string(m[1]))
	if got != "Example &amp; Domain" {
		t.Fatalf("title = %q", got)
	}
}

func TestTaskFilterAndSearch(t *testing.T) {
	s, err := OpenStore("")
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer s.Close()

	const taskA = "taskA"
	const taskB = "taskB"

	// 两个任务各写一条端口与站点。
	if err := s.UpsertPort(Port{ID: newID(), IP: "10.0.0.1", Port: 80, Protocol: "tcp", Service: "http", TaskID: taskA, CreatedAt: nowUnix()}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertPort(Port{ID: newID(), IP: "10.0.0.2", Port: 443, Protocol: "tcp", Service: "https", TaskID: taskB, CreatedAt: nowUnix()}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSite(Site{ID: newID(), IP: "10.0.0.1", Port: 80, URL: "http://api.example.com/", Title: "API Admin", TaskID: taskA, CreatedAt: nowUnix()}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertLeak(Leak{ID: newID(), TaskID: taskA, URL: "http://api.example.com/.git/config", Path: "/.git/config", Type: "git", StatusCode: 200, CreatedAt: nowUnix()}); err != nil {
		t.Fatal(err)
	}

	// 按任务过滤。
	portsA, _ := s.ListPortsByTask(taskA, 0)
	if len(portsA) != 1 || portsA[0].IP != "10.0.0.1" {
		t.Fatalf("ListPortsByTask(taskA) = %+v", portsA)
	}
	leaksA, _ := s.ListLeaksByTask(taskA, 0)
	if len(leaksA) != 1 || leaksA[0].Type != "git" {
		t.Fatalf("ListLeaksByTask(taskA) = %+v", leaksA)
	}

	// 搜索命中站点标题。
	res, _ := s.Search("API Admin", 10)
	found := false
	for _, r := range res {
		if r.Type == "site" && r.Value == "http://api.example.com/" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Search 未命中站点: %+v", res)
	}

	// 删除任务，验证关联资产一并删除。
	if err := s.DeleteTask(taskA); err != nil {
		t.Fatalf("DeleteTask: %v", err)
	}
	if ports, _ := s.ListPortsByTask(taskA, 0); len(ports) != 0 {
		t.Fatalf("删除后端口仍存在: %+v", ports)
	}
	if leaks, _ := s.ListLeaksByTask(taskA, 0); len(leaks) != 0 {
		t.Fatalf("删除后泄漏仍存在: %+v", leaks)
	}
}
