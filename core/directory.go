package core

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

//go:embed dicts/paths.tsv.gz
var builtinPathDictionary []byte

const (
	builtinPathCount      = 3378432
	builtinDirectoryCount = 101928
	builtinRouteCount     = 757859
	builtinFileCount      = 2518645
)

var validPathKinds = map[string]bool{
	"directory": true,
	"route":     true,
	"file":      true,
}

// quickDirectoryProbes 是快速模式优先探测的常见入口；随后从完整路径字典均匀补足 3 万条。
var quickDirectoryProbes = []pathProbe{
	{path: "/admin", kind: "directory"},
	{path: "/administrator", kind: "directory"},
	{path: "/manage", kind: "directory"},
	{path: "/management", kind: "directory"},
	{path: "/manager", kind: "directory"},
	{path: "/manager/html", kind: "route"},
	{path: "/console", kind: "route"},
	{path: "/login", kind: "route"},
	{path: "/signin", kind: "route"},
	{path: "/register", kind: "route"},
	{path: "/dashboard", kind: "route"},
	{path: "/portal", kind: "directory"},
	{path: "/api", kind: "route"},
	{path: "/api/v1", kind: "route"},
	{path: "/api/v2", kind: "route"},
	{path: "/graphql", kind: "route"},
	{path: "/graphiql", kind: "route"},
	{path: "/swagger", kind: "directory"},
	{path: "/swagger-ui", kind: "directory"},
	{path: "/swagger-ui.html", kind: "file"},
	{path: "/swagger/index.html", kind: "file"},
	{path: "/api-docs", kind: "route"},
	{path: "/v2/api-docs", kind: "route"},
	{path: "/v3/api-docs", kind: "route"},
	{path: "/openapi.json", kind: "file"},
	{path: "/actuator", kind: "route"},
	{path: "/actuator/health", kind: "route"},
	{path: "/actuator/env", kind: "route"},
	{path: "/actuator/mappings", kind: "route"},
	{path: "/actuator/metrics", kind: "route"},
	{path: "/health", kind: "route"},
	{path: "/healthz", kind: "route"},
	{path: "/status", kind: "route"},
	{path: "/metrics", kind: "route"},
	{path: "/debug", kind: "directory"},
	{path: "/debug/pprof", kind: "route"},
	{path: "/server-status", kind: "route"},
	{path: "/server-info", kind: "route"},
	{path: "/phpmyadmin", kind: "directory"},
	{path: "/pma", kind: "directory"},
	{path: "/wp-admin", kind: "directory"},
	{path: "/wp-login.php", kind: "file"},
	{path: "/jenkins", kind: "directory"},
	{path: "/gitlab", kind: "directory"},
	{path: "/jmx-console", kind: "route"},
	{path: "/web-console", kind: "route"},
	{path: "/solr", kind: "directory"},
	{path: "/kibana", kind: "directory"},
	{path: "/grafana", kind: "directory"},
	{path: "/prometheus", kind: "directory"},
	{path: "/uploads", kind: "directory"},
	{path: "/upload", kind: "directory"},
	{path: "/files", kind: "directory"},
	{path: "/download", kind: "directory"},
	{path: "/static", kind: "directory"},
	{path: "/assets", kind: "directory"},
	{path: "/public", kind: "directory"},
	{path: "/backup", kind: "directory"},
	{path: "/backups", kind: "directory"},
	{path: "/config", kind: "directory"},
	{path: "/docs", kind: "directory"},
	{path: "/test", kind: "directory"},
	{path: "/dev", kind: "directory"},
	{path: "/robots.txt", kind: "file"},
	{path: "/sitemap.xml", kind: "file"},
	{path: "/security.txt", kind: "file"},
	{path: "/.well-known/security.txt", kind: "file"},
}

// loadDirectoryDict 加载自定义路径发现字典。格式为 `路径 [directory|route|file]`。
func loadDirectoryDict(filePath string) ([]pathProbe, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxPathDictionarySize {
		return nil, fmt.Errorf("字典必须是普通文件且不超过 %d 字节", maxPathDictionarySize)
	}
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	seen := make(map[string]bool)
	probes := make([]pathProbe, 0)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), maxPathDictionarySize)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "\ufeff"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		normalized, err := normalizeScanPath(fields[0])
		if err != nil {
			return nil, fmt.Errorf("字典第 %d 行: %w", lineNumber, err)
		}
		if seen[normalized] {
			continue
		}
		kind := "route"
		if len(fields) >= 2 {
			kind = strings.ToLower(fields[1])
			if !validPathKinds[kind] {
				return nil, fmt.Errorf("字典第 %d 行: 未知路径类型 %q", lineNumber, fields[1])
			}
		}
		seen[normalized] = true
		probes = append(probes, pathProbe{path: normalized, kind: kind})
		if len(probes) > maxPathDictionaryRows {
			return nil, fmt.Errorf("字典条目超过 %d 条", maxPathDictionaryRows)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取字典: %w", err)
	}
	if len(probes) == 0 {
		return nil, fmt.Errorf("字典没有有效路径")
	}
	return probes, nil
}

func detectDirectories(ctx context.Context, site Site, taskID string, timeout time.Duration, concurrency int, probes []pathProbe) ([]DirectoryResult, error) {
	results := make([]DirectoryResult, 0)
	err := detectDirectoriesEach(ctx, site, taskID, timeout, concurrency, directoryProbeSource(probes), func(result DirectoryResult) error {
		results = append(results, result)
		return nil
	})
	sort.Slice(results, func(i, j int) bool { return results[i].URL < results[j].URL })
	return results, err
}

func detectDirectoriesEach(ctx context.Context, site Site, taskID string, timeout time.Duration, concurrency int, source pathProbeSource, onResult func(DirectoryResult) error) error {
	if onResult == nil {
		return fmt.Errorf("路径结果处理器为空")
	}
	accept := func(status int) bool {
		switch status {
		case http.StatusOK, http.StatusNoContent,
			http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect,
			http.StatusUnauthorized, http.StatusForbidden:
			return true
		default:
			return false
		}
	}
	return scanPathSourceEach(ctx, site, timeout, concurrency, source, accept, func(hit pathHit) error {
		return onResult(DirectoryResult{
			ID:            newID(),
			TaskID:        taskID,
			URL:           hit.url,
			Path:          hit.path,
			Kind:          hit.kind,
			StatusCode:    hit.statusCode,
			ContentLength: hit.contentLength,
			ContentType:   hit.contentType,
			CreatedAt:     nowUnix(),
		})
	})
}

func directoryProbeSourceForMode(probes []pathProbe, mode string) (pathProbeSource, int) {
	if probes != nil {
		return limitPathProbeSource(directoryProbeSource(probes), len(probes)), len(probes)
	}
	if normalizePathScanMode(mode) == PathScanModeDeep {
		return limitPathProbeSource(directoryProbeSource(nil), builtinPathCount), builtinPathCount
	}
	return prioritizedSamplePathProbeSource(
		directoryProbeSource(quickDirectoryProbes),
		directoryProbeSource(nil),
		builtinPathCount,
		quickPathProbeBudget,
	), quickPathProbeBudget
}

// directoryProbeSource 中 probes 为 nil 时流式解压内置字典；非 nil 时使用自定义字典。
func directoryProbeSource(probes []pathProbe) pathProbeSource {
	return func(yield func(pathProbe) bool) error {
		if probes != nil {
			for _, probe := range probes {
				if !yield(probe) {
					return nil
				}
			}
			return nil
		}
		return forEachBuiltinPathProbe(yield)
	}
}

func forEachBuiltinPathProbe(yield func(pathProbe) bool) error {
	reader, err := gzip.NewReader(bytes.NewReader(builtinPathDictionary))
	if err != nil {
		return fmt.Errorf("打开内置路径字典: %w", err)
	}
	defer reader.Close()

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), maxPathDictionarySize)
	count := 0
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) != 2 || !validPathKinds[fields[1]] {
			return fmt.Errorf("内置路径字典第 %d 行格式无效", count+1)
		}
		normalized, err := normalizeScanPath(fields[0])
		if err != nil || normalized != fields[0] {
			return fmt.Errorf("内置路径字典第 %d 行路径无效: %q", count+1, fields[0])
		}
		count++
		if !yield(pathProbe{path: normalized, kind: fields[1]}) {
			return nil
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if count != builtinPathCount {
		return fmt.Errorf("内置路径字典条目数为 %d，期望 %d", count, builtinPathCount)
	}
	return nil
}
