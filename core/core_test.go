package core

import (
	"context"
	"database/sql"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
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
		"test":    6,
		"top100":  100,
		"top1000": 996,
		"all":     65535,
	}
	for mode, want := range cases {
		got := portList(mode, "")
		if len(got) != want {
			t.Errorf("portList(%s) = %d ports; want %d", mode, len(got), want)
		}
	}
	// 自定义端口：去重 + 排序。
	got := portList("custom", "9000-9002,80,1-3,80")
	if len(got) != 7 {
		t.Fatalf("portList(custom) = %d ports; want 7", len(got))
	}
	if got[0] != 1 || got[6] != 9002 {
		t.Fatalf("portList(custom) 内容/排序错误: %v", got)
	}
	// 自定义端口非法规范返回 nil。
	if got := portList("custom", "abc"); got != nil {
		t.Fatalf("portList(custom, invalid) = %v; want nil", got)
	}
}

func TestParsePortSpec(t *testing.T) {
	// 合法：范围 + 单端口 + 多分隔符。
	ports, err := ParsePortSpec("1-3, 8080;9000-9001")
	if err != nil {
		t.Fatalf("ParsePortSpec: %v", err)
	}
	if len(ports) != 6 || ports[0] != 1 || ports[3] != 8080 || ports[5] != 9001 {
		t.Fatalf("ParsePortSpec = %v; want [1 2 3 8080 9000 9001]", ports)
	}
	// 非法输入。
	for _, bad := range []string{"", "abc", "1-", "-1", "0", "70000", "10-5", "-"} {
		if _, err := ParsePortSpec(bad); err == nil {
			t.Errorf("ParsePortSpec(%q) 应报错", bad)
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

func TestSplitTargets(t *testing.T) {
	// CIDR 保持原样（供 nmap 直接使用，避免展开成大量参数）。
	parts, err := splitTargets("10.10.0.0/16")
	if err != nil || len(parts) != 1 || parts[0] != "10.10.0.0/16" {
		t.Fatalf("splitTargets(cidr) = %v err=%v; want [10.10.0.0/16]", parts, err)
	}

	// 混合 IP/CIDR 拆分去重。
	parts, err = splitTargets("1.2.3.4, 5.6.7.0/30;1.2.3.4 2001:db8::1")
	if err != nil || len(parts) != 3 {
		t.Fatalf("splitTargets(multi) = %v err=%v; want 3 条", parts, err)
	}

	if _, err := splitTargets("not-an-ip"); err == nil {
		t.Fatal("splitTargets(invalid) should error")
	}
}

func TestIsIPTarget(t *testing.T) {
	cases := map[string]bool{
		"1.2.3.4":         true,
		"10.0.0.0/24":     true,
		"2001:db8::1":     true,
		"1.2.3.4,5.6.7.8": true,
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
		"SSH-2.0-OpenSSH_8.9":          "ssh",
		"HTTP/1.1 400 Bad Request\r\n": "http",
		"+OK Hello":                    "pop3",
		"220 smtp.example ESMTP":       "smtp",
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
	if err := s.UpsertDirectory(DirectoryResult{ID: newID(), TaskID: taskA, URL: "http://api.example.com/admin", Path: "/admin", StatusCode: 403, ContentLength: 13, ContentType: "text/html", CreatedAt: nowUnix()}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertIP(IP{ID: newID(), IP: "10.0.0.1", TaskID: taskA, CreatedAt: nowUnix()}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSubdomain(Subdomain{ID: newID(), Domain: "example.com", Subdomain: "api.example.com", IP: "10.0.0.1", Source: "fofa", TaskID: taskA, CreatedAt: nowUnix()}); err != nil {
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
	directoriesA, _ := s.ListDirectoriesByTask(taskA, 0)
	if len(directoriesA) != 1 || directoriesA[0].Path != "/admin" || directoriesA[0].ContentLength != 13 {
		t.Fatalf("ListDirectoriesByTask(taskA) = %+v", directoriesA)
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
	res, _ = s.Search("/admin", 10)
	found = false
	for _, r := range res {
		if r.Type == "directory" && r.Value == "http://api.example.com/admin" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Search 未命中目录: %+v", res)
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
	if directories, _ := s.ListDirectoriesByTask(taskA, 0); len(directories) != 0 {
		t.Fatalf("删除后目录仍存在: %+v", directories)
	}
	if ips, _ := s.ListIPsByTask(taskA, 0); len(ips) != 0 {
		t.Fatalf("删除后存活 IP 仍存在: %+v", ips)
	}
	if subs, _ := s.ListSubdomainsByTask(taskA, 0); len(subs) != 0 {
		t.Fatalf("删除后子域名仍存在: %+v", subs)
	}
	if _, err := s.GetTask(taskA); err == nil {
		t.Fatal("删除后任务仍存在")
	}
}

func TestTaskAssetsRemainIsolated(t *testing.T) {
	s, err := OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	const taskA = "task-a"
	const taskB = "task-b"
	now := nowUnix()
	for _, taskID := range []string{taskA, taskB} {
		if err := s.CreateTask(&Task{ID: taskID, Target: "example.com", Type: TaskDomain, Status: TaskFinished, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
		if err := s.UpsertSubdomain(Subdomain{ID: newID(), Domain: "example.com", Subdomain: "www.example.com", IP: "192.0.2.1", TaskID: taskID, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
		if err := s.UpsertIP(IP{ID: newID(), IP: "192.0.2.1", TaskID: taskID, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
		if err := s.UpsertPort(Port{ID: newID(), IP: "192.0.2.1", Port: 443, Protocol: "tcp", Service: "https", TaskID: taskID, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
		if err := s.UpsertSite(Site{ID: newID(), IP: "192.0.2.1", Port: 443, URL: "https://www.example.com:443/", TaskID: taskID, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}

	for _, taskID := range []string{taskA, taskB} {
		ports, err := s.ListPortsByTask(taskID, 0)
		if err != nil || len(ports) != 1 {
			t.Fatalf("ListPortsByTask(%s) = %+v, err=%v", taskID, ports, err)
		}
	}
	if count, err := s.PortCount(); err != nil || count != 1 {
		t.Fatalf("global PortCount = %d, err=%v; want deduplicated count 1", count, err)
	}

	if err := s.DeleteTask(taskB); err != nil {
		t.Fatal(err)
	}
	ports, err := s.ListPortsByTask(taskA, 0)
	if err != nil || len(ports) != 1 {
		t.Fatalf("deleting task B damaged task A: ports=%+v err=%v", ports, err)
	}
	sites, err := s.ListSitesByTask(taskA, 0)
	if err != nil || len(sites) != 1 {
		t.Fatalf("deleting task B damaged task A: sites=%+v err=%v", sites, err)
	}
}

func TestLegacyStoreMigratesTaskScopedAssets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE ports (
		id TEXT PRIMARY KEY, ip TEXT NOT NULL, port INTEGER NOT NULL,
		protocol TEXT DEFAULT 'tcp', service TEXT DEFAULT '', banner TEXT DEFAULT '',
		title TEXT DEFAULT '', created_at INTEGER NOT NULL,
		UNIQUE(ip, port, protocol)
	)`)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := OpenStore(path)
	if err != nil {
		t.Fatalf("OpenStore legacy migration: %v", err)
	}
	defer s.Close()
	for _, taskID := range []string{"old-task", "new-task"} {
		if err := s.UpsertPort(Port{ID: newID(), IP: "192.0.2.2", Port: 80, Protocol: "tcp", TaskID: taskID, CreatedAt: nowUnix()}); err != nil {
			t.Fatalf("UpsertPort after migration: %v", err)
		}
	}
	for _, taskID := range []string{"old-task", "new-task"} {
		ports, err := s.ListPortsByTask(taskID, 0)
		if err != nil || len(ports) != 1 {
			t.Fatalf("migrated task %s ports=%+v err=%v", taskID, ports, err)
		}
	}
}

func TestTaskStateUpdatePreservesStageAndPause(t *testing.T) {
	s, err := OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	task := &Task{ID: "task-state", Target: "example.com", Type: TaskDomain, Status: TaskRunning, CreatedAt: nowUnix()}
	if err := s.CreateTask(task); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateTaskStage(task.ID, StageDNS); err != nil {
		t.Fatal(err)
	}
	task.Message = "DNS 解析: 处理中"
	if updated, err := s.UpdateTaskIfStatus(task, TaskRunning); err != nil || !updated {
		t.Fatalf("UpdateTaskIfStatus updated=%v err=%v", updated, err)
	}
	paused, err := s.PauseTask(task.ID, "已暂停")
	if err != nil || !paused {
		t.Fatalf("PauseTask paused=%v err=%v", paused, err)
	}
	task.Status = TaskFinished
	if updated, err := s.UpdateTaskIfStatus(task, TaskRunning); err != nil || updated {
		t.Fatalf("finished update must not overwrite paused: updated=%v err=%v", updated, err)
	}
	got, err := s.GetTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != TaskPaused || got.Stage != StageDNS {
		t.Fatalf("task state=%s stage=%s; want paused/%s", got.Status, got.Stage, StageDNS)
	}
}

func TestConfirmedAliveIPIsPersistedWithoutOpenScanPort(t *testing.T) {
	probeListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local listener unavailable: %v", err)
	}
	defer probeListener.Close()
	probePort := probeListener.Addr().(*net.TCPAddr).Port

	closedListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local listener unavailable: %v", err)
	}
	closedPort := closedListener.Addr().(*net.TCPAddr).Port
	closedListener.Close()

	oldProbePorts := hostProbePorts
	hostProbePorts = []int{probePort}
	defer func() { hostProbePorts = oldProbePorts }()

	s, err := OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	engine := NewEngine(s, ScanOptions{
		PortMode:    "custom",
		PortSpec:    strconv.Itoa(closedPort),
		NmapPath:    filepath.Join(t.TempDir(), "missing-nmap"),
		MasscanPath: filepath.Join(t.TempDir(), "missing-masscan"),
		Concurrency: 1,
		Timeout:     100 * time.Millisecond,
	})
	engine.scanPortsAndSites(context.Background(), []string{"127.0.0.1"}, nil, nil, "alive-task", func(string, string, int) {}, 0, 90)
	ips, err := s.ListIPsByTask("alive-task", 0)
	if err != nil || len(ips) != 1 || ips[0].IP != "127.0.0.1" {
		t.Fatalf("confirmed alive IPs=%+v err=%v; want 127.0.0.1", ips, err)
	}
	ports, err := s.ListPortsByTask("alive-task", 0)
	if err != nil || len(ports) != 0 {
		t.Fatalf("closed scan port unexpectedly persisted: %+v err=%v", ports, err)
	}
}
