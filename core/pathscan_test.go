package core

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
