package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	cfg := DefaultConfig()
	cfg.FileLeak.DictPath = "/tmp/my-leak-dict.txt"
	cfg.Directory.DictPath = "/tmp/my-directory-dict.txt"
	cfg.Nuclei.TemplatesDir = "/tmp/my-templates"
	cfg.Scan.Concurrency = 250
	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if loaded.FileLeak.DictPath != "/tmp/my-leak-dict.txt" {
		t.Fatalf("DictPath = %q", loaded.FileLeak.DictPath)
	}
	if loaded.Directory.DictPath != "/tmp/my-directory-dict.txt" {
		t.Fatalf("Directory.DictPath = %q", loaded.Directory.DictPath)
	}
	if loaded.Nuclei.TemplatesDir != "/tmp/my-templates" {
		t.Fatalf("TemplatesDir = %q", loaded.Nuclei.TemplatesDir)
	}
	if loaded.Scan.Concurrency != 250 {
		t.Fatalf("Concurrency = %d", loaded.Scan.Concurrency)
	}

	// 不存在的文件返回默认配置。
	def, err := LoadConfig(filepath.Join(dir, "nope.yaml"))
	if err != nil || def.Scan.Concurrency != 100 {
		t.Fatalf("LoadConfig(nonexistent) = %+v err=%v", def, err)
	}
}

func TestConfigValidationAndPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("config permissions = %o; want 600", info.Mode().Perm())
	}

	invalid := []Config{DefaultConfig(), DefaultConfig(), DefaultConfig(), DefaultConfig()}
	invalid[0].Scan.Concurrency = 0
	invalid[1].Scan.Concurrency = MaxScanConcurrency + 1
	invalid[2].Scan.DefaultPortMode = "unknown"
	invalid[3].Proxy.HTTPURL = "file:///tmp/proxy"
	for i, candidate := range invalid {
		if err := candidate.Validate(); err == nil {
			t.Errorf("invalid config %d passed validation", i)
		}
	}
}

func TestLoadLeakDict(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dict.txt")
	content := "# 自定义泄漏字典\n/.git/config git [core]\n/.env\n/backup.zip backup\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	rules, err := loadLeakDict(path)
	if err != nil {
		t.Fatalf("loadLeakDict: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("len(rules) = %d; want 3", len(rules))
	}
	if rules[0].Type != "git" || rules[1].Type != "env" || rules[2].Type != "backup" {
		t.Fatalf("rules = %+v", rules)
	}
	if rules[0].Sig != "[core]" {
		t.Fatalf("signature = %q; want [core]", rules[0].Sig)
	}
	if got := inferLeakType("/index.php"); got == "phpinfo" {
		t.Fatalf("ordinary PHP file inferred as phpinfo: %q", got)
	}
}

func TestLoadLeakDictRejectsExternalURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dict.txt")
	if err := os.WriteFile(path, []byte("https://outside.example/.env env\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLeakDict(path); err == nil {
		t.Fatal("外部 URL 不应作为文件泄漏路径")
	}
}

func TestNucleiYAMLTemplates(t *testing.T) {
	// 构造一个 nuclei 风格 YAML 模板。
	dir := t.TempDir()
	tpl := `id: test-actuator
info:
  name: "Test Actuator Exposure"
  severity: medium
requests:
  - method: GET
    path:
      - "{{BaseURL}}/actuator/env"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "propertySources"
        part: body
`
	if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(tpl), 0o644); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/actuator/env", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"propertySources":[{"name":"x"}]}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	templates, err := loadNucleiTemplates(dir)
	if err != nil || len(templates) != 1 {
		t.Fatalf("loadNucleiTemplates = %d err=%v", len(templates), err)
	}

	leaks := runNucleiYAML(context.Background(), Site{URL: srv.URL}, "task1", templates, 2*time.Second)
	if !hasLeakType(leaks, "nuclei:Test Actuator Exposure") {
		t.Fatalf("自定义 nuclei 模板未命中: %+v", leaks)
	}
}
