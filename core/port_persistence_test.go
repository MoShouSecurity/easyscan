package core

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func portTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func taskPorts(t *testing.T, s *Store, taskID string) []Port {
	t.Helper()
	ports, err := s.ListPortsByTask(taskID, -1, 0)
	if err != nil {
		t.Fatal(err)
	}
	return ports
}

func TestFofaProbePersistsConfirmedPorts(t *testing.T) {
	s := portTestStore(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<title>Confirmed site</title>"))
	}))
	defer srv.Close()
	port := serverPort(t, srv.URL)
	result := fofaResult{Host: "fixture.invalid", IP: "127.0.0.1", Port: port}
	// 重复线索及不同虚拟主机不能产生重复端口；不同任务必须各自保留。
	for _, taskID := range []string{"task-a", "task-b"} {
		other := result
		other.Host = "other.invalid"
		if err := probeFofaSites(context.Background(), []fofaResult{result, result, other}, s, taskID, time.Second); err != nil {
			t.Fatal(err)
		}
		ports := taskPorts(t, s, taskID)
		if len(ports) != 1 {
			t.Fatalf("%s: ports=%d; want 1", taskID, len(ports))
		}
		p := ports[0]
		if p.Port != port || p.Protocol != "tcp" || p.Service != "http" || p.Title != "Confirmed site" || p.Confidence != ConfidencePureGo {
			t.Fatalf("unexpected confirmed port: %+v", p)
		}
	}
}

func TestFofaProbeDoesNotPersistUnconfirmedPorts(t *testing.T) {
	s := portTestStore(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	port := serverPort(t, srv.URL)
	srv.Close()
	if err := probeFofaSites(context.Background(), []fofaResult{{Host: "fixture.invalid", IP: "127.0.0.1", Port: port}}, s, "task", 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if ports := taskPorts(t, s, "task"); len(ports) != 0 {
		t.Fatalf("unconfirmed ports persisted: %+v", ports)
	}
}

func TestUpsertPortPreservesEnrichment(t *testing.T) {
	s := portTestStore(t)
	p := Port{ID: newID(), IP: "127.0.0.1", Port: 443, Protocol: "tcp", TaskID: "task", Service: "https", Product: "nginx", Version: "1.2", Banner: "server banner", Title: "existing title", Confidence: ConfidenceNmapV, CreatedAt: nowUnix()}
	if err := s.UpsertPort(p); err != nil {
		t.Fatal(err)
	}
	// 先写基础发现、后补指纹时，空字段不能抹除已有结果。
	if err := s.UpsertPort(Port{ID: newID(), IP: p.IP, Port: p.Port, Protocol: p.Protocol, TaskID: p.TaskID, Confidence: ConfidencePureGo, CreatedAt: nowUnix()}); err != nil {
		t.Fatal(err)
	}
	got := taskPorts(t, s, p.TaskID)[0]
	if got != p {
		t.Fatalf("basic discovery erased enrichment: got %+v; want %+v", got, p)
	}
	if err := s.UpsertPort(Port{ID: newID(), IP: p.IP, Port: p.Port, Protocol: p.Protocol, TaskID: p.TaskID, Service: "http", Title: "new title", Confidence: ConfidencePureGo}); err != nil {
		t.Fatal(err)
	}
	got = taskPorts(t, s, p.TaskID)[0]
	if got.Service != "https" || got.Product != p.Product || got.Version != p.Version || got.Confidence != p.Confidence || got.Title != "new title" {
		t.Fatalf("lower-confidence probe replaced service details: %+v", got)
	}
}

func TestNmapPortsPersistBeforeWebProbe(t *testing.T) {
	for _, cancelProbe := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "cancel"}[cancelProbe], func(t *testing.T) {
			s := portTestStore(t)
			entered, release := make(chan struct{}), make(chan struct{})
			var enterOnce, releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				enterOnce.Do(func() { close(entered) })
				select {
				case <-release:
					_, _ = w.Write([]byte("<title>Enriched title</title>"))
				case <-r.Context().Done():
				}
			}))
			defer srv.Close()
			defer unblock()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			port := serverPort(t, srv.URL)
			e := NewEngine(s, ScanOptions{Timeout: 5 * time.Second})
			hosts := []NmapHost{{IP: "127.0.0.1", Ports: []NmapPortResult{
				{Port: 22, Protocol: "tcp", Service: "ssh"},
				{Port: port, Protocol: "tcp", Service: "http", Product: "fixture", Version: "1"},
			}}}
			done := make(chan error, 1)
			go func() {
				done <- e.processNmapBatch(ctx, hosts, nil, "task", map[string]Site{}, func(string) error { return nil }, &sync.Mutex{})
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("HTTP probe did not start")
			}
			before := len(taskPorts(t, s, "task"))
			if cancelProbe {
				cancel()
			} else {
				unblock()
			}
			select {
			case err := <-done:
				if cancelProbe && !errors.Is(err, context.Canceled) || !cancelProbe && err != nil {
					t.Fatalf("unexpected result: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("processing did not finish")
			}
			ports := taskPorts(t, s, "task")
			if before != 2 || len(ports) != 2 {
				t.Fatalf("ports before probe=%d, after=%d; want 2,2", before, len(ports))
			}
			if !cancelProbe {
				for _, p := range ports {
					if p.Port == port && (p.Title != "Enriched title" || p.Product != "fixture" || p.Version != "1") {
						t.Fatalf("enrichment missing: %+v", p)
					}
				}
			}
		})
	}
}

func TestNmapStoreFailureReturnsWithoutDeadlock(t *testing.T) {
	s := portTestStore(t)
	e := NewEngine(s, ScanOptions{})
	want := errors.New("fixture storage failure")
	hosts := make([]NmapHost, nmapHostConcurrency*3)
	for i := range hosts {
		hosts[i] = NmapHost{IP: "127.0.0.1", Ports: []NmapPortResult{{Port: 22, Protocol: "tcp", Service: "ssh"}}}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- e.processNmapBatch(ctx, hosts, nil, "task", map[string]Site{}, func(string) error { return want }, &sync.Mutex{})
	}()
	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Fatalf("got %v; want %v", err, want)
		}
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("storage failure left producer blocked")
	}
}

func TestSiteWriteFailureKeepsConfirmedPort(t *testing.T) {
	for _, source := range []string{"fofa", "nmap"} {
		t.Run(source, func(t *testing.T) {
			s := portTestStore(t)
			_, err := s.db.Exec(`CREATE TRIGGER reject_site BEFORE INSERT ON sites BEGIN SELECT RAISE(FAIL, 'fixture site failure'); END`)
			if err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("<title>Confirmed</title>"))
			}))
			defer srv.Close()
			port := serverPort(t, srv.URL)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if source == "fofa" {
				err = probeFofaSites(ctx, []fofaResult{{IP: "127.0.0.1", Port: port}}, s, "task", time.Second)
			} else {
				hosts := make([]NmapHost, nmapHostConcurrency*3)
				for i := range hosts {
					hosts[i] = NmapHost{IP: "127.0.0.1", Ports: []NmapPortResult{{Port: port, Protocol: "tcp", Service: "http"}}}
				}
				err = NewEngine(s, ScanOptions{Timeout: time.Second}).processNmapBatch(ctx, hosts, nil, "task", map[string]Site{}, func(string) error { return nil }, &sync.Mutex{})
			}
			if err == nil {
				t.Fatal("site write failure was swallowed")
			}
			if ctx.Err() != nil {
				t.Fatal("write failure did not stop workers before deadline")
			}
			if ports := taskPorts(t, s, "task"); len(ports) != 1 {
				t.Fatalf("confirmed port lost after site error: %+v", ports)
			}
		})
	}
}

func TestNmapCancellationRetainsReceivedBatch(t *testing.T) {
	s := portTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	hosts := make([]NmapHost, nmapHostConcurrency*3)
	for i := range hosts {
		hosts[i] = NmapHost{IP: "127.0.0.1", Ports: []NmapPortResult{{Port: 10000 + i, Protocol: "tcp", Service: "ssh"}}}
	}
	err := NewEngine(s, ScanOptions{}).processNmapBatch(ctx, hosts, nil, "task", map[string]Site{}, func(string) error { return nil }, &sync.Mutex{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v; want canceled", err)
	}
	if ports := taskPorts(t, s, "task"); len(ports) != len(hosts) {
		t.Fatalf("received results lost on cancellation: got %d; want %d", len(ports), len(hosts))
	}
}

func TestPureGoPortsPersistBeforeBanner(t *testing.T) {
	s := portTestStore(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	serverDone := make(chan error, 1)
	go func() {
		// 第一次连接确认端口，第二次连接等待 banner。
		for i := 0; i < 2; i++ {
			conn, err := ln.Accept()
			if err != nil {
				serverDone <- err
				return
			}
			if i == 1 {
				close(entered)
				<-release
				_, _ = conn.Write([]byte("SSH-2.0-fixture\r\n"))
			}
			_ = conn.Close()
		}
		serverDone <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := NewEngine(s, ScanOptions{Timeout: time.Second}).processPureGoIP(ctx, "127.0.0.1", nil, "task", map[string]Site{}, func(string) error { return nil }, []int{port})
		done <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("banner probe did not start")
	}
	before := len(taskPorts(t, s, "task"))
	unblock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	ports := taskPorts(t, s, "task")
	if before != 1 || len(ports) != 1 || ports[0].Service != "ssh" || ports[0].Banner != "SSH-2.0-fixture" {
		t.Fatalf("before=%d; after=%+v", before, ports)
	}
}
