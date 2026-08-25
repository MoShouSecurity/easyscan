package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoadPathDictionaryNormalizesAndDeduplicates(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "dirs.txt")
	content := "\ufeff# comment\nadmin\n/admin/\n/api/v1\n\n"
	if err := os.WriteFile(filePath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	items, err := loadPathDictionary(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"/admin", "/api/v1"}; !reflect.DeepEqual(items, want) {
		t.Fatalf("items = %#v, want %#v", items, want)
	}
}

func TestLoadPathDictionaryRejectsExternalURL(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "dirs.txt")
	if err := os.WriteFile(filePath, []byte("/admin\nhttps://outside.example/internal\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPathDictionary(filePath); err == nil || !strings.Contains(err.Error(), "第 2 行") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNormalizeScanPathRejectsTraversal(t *testing.T) {
	for _, input := range []string{"../admin", "/a/../admin", "/%2e%2e/admin"} {
		if _, err := normalizeScanPath(input); err == nil {
			t.Errorf("normalizeScanPath(%q) accepted traversal", input)
		}
	}
}

func TestNormalizeScanPathRejectsUnsafeDecodedCharacters(t *testing.T) {
	for _, input := range []string{"/admin%20panel", "/%00", "/api%0d%0aheader", "/%23", "/%3fadmin", "/%25"} {
		if _, err := normalizeScanPath(input); err == nil {
			t.Errorf("normalizeScanPath(%q) accepted unsafe decoded characters", input)
		}
	}
}

func TestLoadDirectoryDictReadsOptionalKind(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "paths.txt")
	content := "/admin directory\n/api/v1 route\n/app.js file\n"
	if err := os.WriteFile(filePath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	probes, err := loadDirectoryDict(filePath)
	if err != nil {
		t.Fatal(err)
	}
	want := []pathProbe{{path: "/admin", kind: "directory"}, {path: "/api/v1", kind: "route"}, {path: "/app.js", kind: "file"}}
	if !reflect.DeepEqual(probes, want) {
		t.Fatalf("probes = %#v, want %#v", probes, want)
	}
}

func TestBuiltinDirectoryDictionaryIsNormalizedAndUnique(t *testing.T) {
	counts := map[string]int{}
	previous := ""
	err := forEachBuiltinPathProbe(func(probe pathProbe) bool {
		if previous != "" && probe.path <= previous {
			t.Fatalf("builtin paths are not strictly sorted: %q after %q", probe.path, previous)
		}
		previous = probe.path
		counts[probe.kind]++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if counts["directory"] != builtinDirectoryCount || counts["route"] != builtinRouteCount || counts["file"] != builtinFileCount {
		t.Fatalf("unexpected builtin kind counts: %#v", counts)
	}
}

func TestBuiltinLeakDictionaryIsNormalizedAndUnique(t *testing.T) {
	count := 0
	previous := ""
	err := forEachBuiltinLeakRule(func(rule leakRule) bool {
		if previous != "" && rule.Path <= previous {
			t.Fatalf("builtin leak paths are not strictly sorted: %q after %q", rule.Path, previous)
		}
		previous = rule.Path
		count++
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != builtinLeakRuleCount {
		t.Fatalf("builtin leak dictionary has %d entries, want %d", count, builtinLeakRuleCount)
	}
}

func TestPathScanModesUseBoundedSources(t *testing.T) {
	if got := DefaultScanOptions().PathScanMode; got != PathScanModeQuick {
		t.Fatalf("default path scan mode = %q, want %q", got, PathScanModeQuick)
	}

	leakSource, leakBudget := leakProbeSourceForMode(nil, PathScanModeQuick)
	quickLeakCount := 0
	leakPaths := make(map[string]struct{}, quickPathProbeBudget)
	if err := leakSource(func(probe pathProbe) bool {
		if quickLeakCount < len(quickLeakRules) && probe.path != quickLeakRules[quickLeakCount].Path {
			t.Fatalf("quick leak priority[%d] = %q, want %q", quickLeakCount, probe.path, quickLeakRules[quickLeakCount].Path)
		}
		if _, exists := leakPaths[probe.path]; exists {
			t.Fatalf("duplicate quick leak path: %q", probe.path)
		}
		leakPaths[probe.path] = struct{}{}
		quickLeakCount++
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if quickLeakCount != quickPathProbeBudget || leakBudget != quickPathProbeBudget {
		t.Fatalf("quick leak count=%d budget=%d want=%d", quickLeakCount, leakBudget, quickPathProbeBudget)
	}

	directorySource, directoryBudget := directoryProbeSourceForMode(nil, PathScanModeQuick)
	quickDirectoryCount := 0
	directoryPaths := make(map[string]struct{}, quickPathProbeBudget)
	if err := directorySource(func(probe pathProbe) bool {
		if quickDirectoryCount < len(quickDirectoryProbes) && probe != quickDirectoryProbes[quickDirectoryCount] {
			t.Fatalf("quick directory priority[%d] = %+v, want %+v", quickDirectoryCount, probe, quickDirectoryProbes[quickDirectoryCount])
		}
		if _, exists := directoryPaths[probe.path]; exists {
			t.Fatalf("duplicate quick directory path: %q", probe.path)
		}
		directoryPaths[probe.path] = struct{}{}
		quickDirectoryCount++
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if quickDirectoryCount != quickPathProbeBudget || directoryBudget != quickPathProbeBudget {
		t.Fatalf("quick directory count=%d budget=%d want=%d", quickDirectoryCount, directoryBudget, quickPathProbeBudget)
	}

	_, deepLeakBudget := leakProbeSourceForMode(nil, PathScanModeDeep)
	_, deepDirectoryBudget := directoryProbeSourceForMode(nil, PathScanModeDeep)
	if deepLeakBudget != builtinLeakRuleCount || deepDirectoryBudget != builtinPathCount {
		t.Fatalf("deep budgets leak=%d directory=%d", deepLeakBudget, deepDirectoryBudget)
	}
}

func TestPrioritizedSamplePathProbeSourceIsStableAndDistributed(t *testing.T) {
	priority := func(yield func(pathProbe) bool) error {
		yield(pathProbe{path: "/p5", kind: "route"})
		return nil
	}
	full := func(yield func(pathProbe) bool) error {
		for i := 0; i < 10; i++ {
			if !yield(pathProbe{path: fmt.Sprintf("/p%d", i), kind: "route"}) {
				return nil
			}
		}
		return nil
	}
	source := prioritizedSamplePathProbeSource(priority, full, 10, 5)
	var got []string
	if err := source(func(probe pathProbe) bool {
		got = append(got, probe.path)
		return true
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{"/p5", "/p2", "/p4", "/p7", "/p9"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sampled paths = %#v, want %#v", got, want)
	}
}

func TestPrioritizedSamplePathProbeSourceRejectsShortFullSource(t *testing.T) {
	priority := func(yield func(pathProbe) bool) error {
		yield(pathProbe{path: "/priority", kind: "route"})
		return nil
	}
	shortFull := func(yield func(pathProbe) bool) error {
		yield(pathProbe{path: "/only-one", kind: "route"})
		return nil
	}
	err := prioritizedSamplePathProbeSource(priority, shortFull, 10, 5)(func(pathProbe) bool { return true })
	if err == nil || !strings.Contains(err.Error(), "期望 5 条") {
		t.Fatalf("unexpected short source error: %v", err)
	}
}

func TestPrioritizedSamplePathProbeSourceSupportsConcurrentReuse(t *testing.T) {
	priority := func(yield func(pathProbe) bool) error {
		yield(pathProbe{path: "/priority", kind: "route"})
		return nil
	}
	full := func(yield func(pathProbe) bool) error {
		for i := 0; i < 100; i++ {
			if !yield(pathProbe{path: fmt.Sprintf("/item-%03d", i), kind: "route"}) {
				return nil
			}
		}
		return nil
	}
	source := prioritizedSamplePathProbeSource(priority, full, 100, 30)
	var workers sync.WaitGroup
	errors := make(chan error, 8)
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			count := 0
			err := source(func(pathProbe) bool {
				count++
				return true
			})
			if err != nil {
				errors <- err
				return
			}
			if count != 30 {
				errors <- fmt.Errorf("sample count = %d, want 30", count)
			}
		}()
	}
	workers.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}

func TestLimitPathProbeSourceCapsDictionary(t *testing.T) {
	source := limitPathProbeSource(func(yield func(pathProbe) bool) error {
		for i := 0; i < 5; i++ {
			if !yield(pathProbe{path: "/item", kind: "route"}) {
				return nil
			}
		}
		return nil
	}, 2)
	count := 0
	if err := source(func(pathProbe) bool {
		count++
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("bounded source yielded %d probes, want 2", count)
	}
}

func TestDetectDirectoriesFiltersSoft404AndKeepsUsefulStatuses(t *testing.T) {
	soft404 := strings.Repeat("generic not found ", 20)
	mux := http.NewServeMux()
	mux.HandleFunc("/admin", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("access denied"))
	})
	mux.HandleFunc("/api", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/ghost", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(soft404))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(soft404))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	probes := []pathProbe{{path: "/ghost", kind: "route"}, {path: "/api", kind: "route"}, {path: "/admin", kind: "directory"}}
	results, err := detectDirectories(context.Background(), Site{URL: server.URL}, "task", 2*time.Second, 4, probes)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %+v, want /admin and /api", results)
	}
	if results[0].Path != "/admin" || results[0].StatusCode != http.StatusForbidden {
		t.Fatalf("first result = %+v", results[0])
	}
	if results[0].Kind != "directory" || results[1].Kind != "route" {
		t.Fatalf("result kinds = %+v", results)
	}
	if results[1].Path != "/api" || results[1].ContentType != "application/json" {
		t.Fatalf("second result = %+v", results[1])
	}
}

func TestSoft404DoesNotHideDifferentSmallResponse(t *testing.T) {
	baseline := soft404Baseline{status: http.StatusOK, contentType: "text/plain", body: []byte("not found")}
	response := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/plain"}}}
	if baseline.matches(response, []byte("api ready")) {
		t.Fatal("different small response was classified as soft 404")
	}
}

func TestPathScanHonorsCancelledContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results, err := detectDirectories(ctx, Site{URL: server.URL}, "task", time.Second, 2, []pathProbe{{path: "/admin", kind: "directory"}})
	if !errors.Is(err, context.Canceled) || len(results) != 0 {
		t.Fatalf("cancelled scan returned results=%+v err=%v", results, err)
	}
}

func TestPathScanStreamsHitsBeforeSourceCompletes(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/first", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("first")) })
	mux.HandleFunc("/second", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("second")) })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	server := httptest.NewServer(mux)
	defer server.Close()

	firstPersisted := make(chan struct{})
	source := func(yield func(pathProbe) bool) error {
		if !yield(pathProbe{path: "/first", kind: "route"}) {
			return nil
		}
		select {
		case <-firstPersisted:
		case <-time.After(2 * time.Second):
			return errors.New("first hit was not delivered incrementally")
		}
		yield(pathProbe{path: "/second", kind: "route"})
		return nil
	}

	paths := make([]string, 0, 2)
	err := scanPathSourceEach(context.Background(), Site{URL: server.URL}, 2*time.Second, 1, source, func(status int) bool {
		return status == http.StatusOK
	}, func(hit pathHit) error {
		paths = append(paths, hit.path)
		if hit.path == "/first" {
			close(firstPersisted)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"/first", "/second"}; !reflect.DeepEqual(paths, want) {
		t.Fatalf("streamed paths = %#v, want %#v", paths, want)
	}
}

func TestPathScanRecoversWorkerPanicAndWritesLog(t *testing.T) {
	logDir := t.TempDir()
	SetCrashLogDir(logDir)
	defer SetCrashLogDir("")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/panic" {
			_, _ = w.Write([]byte("ok"))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	err := scanPathSourceEach(context.Background(), Site{URL: server.URL}, 2*time.Second, 1, func(yield func(pathProbe) bool) error {
		yield(pathProbe{path: "/panic", kind: "route"})
		return nil
	}, func(int) bool {
		panic("path-scan-test-panic")
	}, func(pathHit) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "路径扫描工作协程") {
		t.Fatalf("unexpected panic recovery error: %v", err)
	}
	logPath := filepath.Join(logDir, "crash.log")
	data, readErr := os.ReadFile(logPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Contains(data, []byte("path-scan-test-panic")) || !bytes.Contains(data, []byte("goroutine")) {
		t.Fatalf("crash log missing panic or stack: %s", data)
	}
	info, statErr := os.Stat(logPath)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("crash log mode = %o, want 600", info.Mode().Perm())
	}
}

func TestPathScanClientConnectionLimits(t *testing.T) {
	scope, err := newSiteScope(Site{IP: "127.0.0.1", URL: "http://example.invalid:8080"})
	if err != nil {
		t.Fatal(err)
	}
	client := scope.clientWithConnectionLimit(3*time.Second, 0, 7)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T", client.Transport)
	}
	if transport.MaxConnsPerHost != 7 || transport.MaxIdleConnsPerHost != 7 || transport.MaxIdleConns != 7 {
		t.Fatalf("unexpected connection limits: %+v", transport)
	}
	if transport.ResponseHeaderTimeout != 3*time.Second || transport.TLSHandshakeTimeout != 3*time.Second {
		t.Fatalf("unexpected transport timeouts: %+v", transport)
	}
}

func TestPathScanCapsConcurrentRequests(t *testing.T) {
	var active int64
	var maximum int64
	var requests int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requests, 1)
		current := atomic.AddInt64(&active, 1)
		defer atomic.AddInt64(&active, -1)
		for {
			previous := atomic.LoadInt64(&maximum)
			if current <= previous || atomic.CompareAndSwapInt64(&maximum, previous, current) {
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
		http.NotFound(w, r)
	}))
	defer server.Close()

	const probes = 500
	err := scanPathSourceEach(context.Background(), Site{URL: server.URL}, 2*time.Second, 500, func(yield func(pathProbe) bool) error {
		for i := 0; i < probes; i++ {
			if !yield(pathProbe{path: "/missing", kind: "route"}) {
				return nil
			}
		}
		return nil
	}, func(status int) bool { return status == http.StatusOK }, func(pathHit) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&requests); got != probes+1 {
		t.Fatalf("request count = %d, want %d including baseline", got, probes+1)
	}
	if got := atomic.LoadInt64(&maximum); got > maxPathConcurrency {
		t.Fatalf("maximum concurrent requests = %d, cap = %d", got, maxPathConcurrency)
	}
}

func TestPostProcessPersistsLeakAndDirectoryHitsIncrementally(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.git/config", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("[core]\nrepositoryformatversion = 0"))
	})
	mux.HandleFunc("/admin", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("access denied"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	server := httptest.NewServer(mux)
	defer server.Close()

	store, err := OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	leakDictPath := filepath.Join(t.TempDir(), "leaks.txt")
	if err := os.WriteFile(leakDictPath, []byte("/.git/config git [core]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	directoryDictPath := filepath.Join(t.TempDir(), "paths.txt")
	if err := os.WriteFile(directoryDictPath, []byte("/admin directory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(store, ScanOptions{
		FileLeak:          true,
		DirectoryScan:     true,
		PathScanMode:      PathScanModeQuick,
		LeakDictPath:      leakDictPath,
		DirectoryDictPath: directoryDictPath,
		Concurrency:       100,
		Timeout:           2 * time.Second,
	})
	if err := engine.postProcess(context.Background(), []Site{{URL: server.URL}}, "task", func(string, string, int) {}, 90); err != nil {
		t.Fatal(err)
	}
	leaks, err := store.ListLeaksByTask("task", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaks) != 1 || leaks[0].Path != "/.git/config" {
		t.Fatalf("persisted leaks = %+v", leaks)
	}
	directories, err := store.ListDirectoriesByTask("task", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(directories) != 1 || directories[0].Path != "/admin" {
		t.Fatalf("persisted directories = %+v", directories)
	}
}
