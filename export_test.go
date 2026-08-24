package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"easyscan/core"

	"github.com/xuri/excelize/v2"
)

const exportTestTaskID = "0123456789abcdef0123456789abcdef"

func newExportTestApp(t *testing.T) *App {
	t.Helper()
	store, err := core.OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	task := core.Task{
		ID: exportTestTaskID, Target: "example.com", Type: core.TaskDomain,
		Status: core.TaskFinished, Progress: 100, Stage: "done", Params: `{"secret":"not-exported"}`,
		CreatedAt: 1_700_000_000, FinishedAt: 1_700_000_100,
	}
	if err := store.CreateTask(&task); err != nil {
		t.Fatal(err)
	}
	assets := []func() error{
		func() error {
			return store.UpsertSubdomain(core.Subdomain{ID: strings.Repeat("1", 32), Domain: "example.com", Subdomain: "www.example.com", IP: "192.0.2.10", Source: "subfinder", TaskID: exportTestTaskID, CreatedAt: 1_700_000_001})
		},
		func() error {
			return store.UpsertIP(core.IP{ID: strings.Repeat("2", 32), IP: "192.0.2.10", Domain: "www.example.com", TaskID: exportTestTaskID, CreatedAt: 1_700_000_002})
		},
		func() error {
			return store.UpsertPort(core.Port{ID: strings.Repeat("3", 32), IP: "192.0.2.10", Port: 443, Protocol: "tcp", Service: "https", Product: "nginx", Version: "1.25.4", Banner: "=1+1", Title: "TLS", Confidence: 90, TaskID: exportTestTaskID, CreatedAt: 1_700_000_003})
		},
		func() error {
			return store.UpsertSite(core.Site{ID: strings.Repeat("4", 32), IP: "192.0.2.10", Port: 443, URL: "https://www.example.com", Title: "=HYPERLINK(\"https://invalid\")", StatusCode: 200, Server: "nginx", Fingerprint: "WordPress", Screenshot: "/tmp/site.png", TaskID: exportTestTaskID, CreatedAt: 1_700_000_004})
		},
		func() error {
			return store.UpsertLeak(core.Leak{ID: strings.Repeat("5", 32), URL: "https://www.example.com/.env", Path: "/.env", Type: "env", StatusCode: 200, TaskID: exportTestTaskID, CreatedAt: 1_700_000_005})
		},
		func() error {
			return store.UpsertDirectory(core.DirectoryResult{ID: strings.Repeat("6", 32), URL: "https://www.example.com/admin", Path: "/admin", StatusCode: 403, ContentLength: 128, ContentType: "text/html", TaskID: exportTestTaskID, CreatedAt: 1_700_000_006})
		},
	}
	for _, insert := range assets {
		if err := insert(); err != nil {
			t.Fatal(err)
		}
	}
	return &App{store: store, configDir: t.TempDir()}
}

func TestExportTaskCSVIncludesAllAssetFields(t *testing.T) {
	app := newExportTestApp(t)
	path, err := app.ExportTask(exportTestTaskID)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Ext(path) != ".csv" {
		t.Fatalf("extension = %q", filepath.Ext(path))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %o", info.Mode().Perm())
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(content, []byte("\xEF\xBB\xBF")) {
		t.Fatal("CSV missing UTF-8 BOM")
	}
	reader := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(content, []byte("\xEF\xBB\xBF"))))
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 7 {
		t.Fatalf("rows = %d, want header + 6 assets", len(rows))
	}
	headers := strings.Join(rows[0], ",")
	for _, header := range []string{"产品", "版本", "Banner", "置信度", "指纹", "截图路径", "目录路径", "响应长度"} {
		if !strings.Contains(headers, header) {
			t.Errorf("missing header %q", header)
		}
	}
	all := strings.Join(flattenRows(rows), "\n")
	for _, expected := range []string{"存活IP", "nginx", "1.25.4", "WordPress", "目录", "/admin", "128", "'=1+1", "'=HYPERLINK"} {
		if !strings.Contains(all, expected) {
			t.Errorf("CSV missing %q", expected)
		}
	}
}

func TestExportTaskJSONFiltersAssetTypes(t *testing.T) {
	app := newExportTestApp(t)
	path, err := app.ExportTaskWithOptions(ExportRequest{
		TaskID: exportTestTaskID, Format: "JSON", AssetTypes: []string{exportSites, exportPorts, exportPorts},
	})
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(content, &result); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"ports", "sites"} {
		if _, ok := result[key]; !ok {
			t.Errorf("selected key %q missing", key)
		}
	}
	for _, key := range []string{"subdomains", "ips", "leaks", "directories"} {
		if _, ok := result[key]; ok {
			t.Errorf("unselected key %q exported", key)
		}
	}
	if bytes.Contains(content, []byte("not-exported")) || bytes.Contains(content, []byte("params")) {
		t.Fatal("internal task params leaked into JSON")
	}
	if !bytes.Contains(content, []byte(`"product": "nginx"`)) || !bytes.Contains(content, []byte(`"version": "1.25.4"`)) || !bytes.Contains(content, []byte(`"fingerprint": "WordPress"`)) {
		t.Fatal("JSON missing complete port or fingerprint fields")
	}
}

func TestExportTaskXLSXCreatesFilteredStyledSheets(t *testing.T) {
	app := newExportTestApp(t)
	path, err := app.ExportTaskWithOptions(ExportRequest{
		TaskID: exportTestTaskID, Format: "xlsx", AssetTypes: []string{exportPorts, exportSites},
	})
	if err != nil {
		t.Fatal(err)
	}
	book, err := excelize.OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer book.Close()
	if got, want := book.GetSheetList(), []string{"任务概览", "端口", "站点"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("sheets = %#v, want %#v", got, want)
	}
	if value, err := book.GetCellValue("端口", "H2"); err != nil || value != "1.25.4" {
		t.Fatalf("port version = %q, err = %v", value, err)
	}
	if value, err := book.GetCellValue("站点", "I2"); err != nil || value != "WordPress" {
		t.Fatalf("site fingerprint = %q, err = %v", value, err)
	}
	if formula, err := book.GetCellFormula("站点", "F2"); err != nil || formula != "" {
		t.Fatalf("untrusted title became formula %q, err = %v", formula, err)
	}
	if value, err := book.GetCellValue("站点", "F2"); err != nil || !strings.HasPrefix(value, "=HYPERLINK") {
		t.Fatalf("untrusted title not preserved as text: %q, err = %v", value, err)
	}
	styleID, err := book.GetCellStyle("端口", "A1")
	if err != nil || styleID == 0 {
		t.Fatalf("header style missing: id=%d err=%v", styleID, err)
	}
	style, err := book.GetStyle(styleID)
	if err != nil || style.Font == nil || style.Font.Family != "Arial" || !style.Font.Bold {
		t.Fatalf("header typography invalid: style=%#v err=%v", style, err)
	}
}

func TestExportTaskRejectsInvalidInput(t *testing.T) {
	app := newExportTestApp(t)
	tests := []ExportRequest{
		{TaskID: "../escape", Format: "csv"},
		{TaskID: exportTestTaskID, Format: "xml"},
		{TaskID: exportTestTaskID, Format: "json", AssetTypes: []string{"unknown"}},
		{TaskID: strings.Repeat("f", 32), Format: "csv"},
	}
	for _, req := range tests {
		if _, err := app.ExportTaskWithOptions(req); err == nil {
			t.Errorf("request %#v unexpectedly succeeded", req)
		}
	}
}

func TestExportTaskDoesNotOverwritePreviousExport(t *testing.T) {
	app := newExportTestApp(t)
	first, err := app.ExportTask(exportTestTaskID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := app.ExportTask(exportTestTaskID)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("repeated export reused path %q", first)
	}
	for _, path := range []string{first, second} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("export %q missing: %v", path, err)
		}
	}
}

func flattenRows(rows [][]string) []string {
	var result []string
	for _, row := range rows {
		result = append(result, row...)
	}
	return result
}
