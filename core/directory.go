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
	hits, err := scanPathSource(ctx, site, timeout, concurrency, directoryProbeSource(probes), accept)
	if err != nil {
		return nil, err
	}
	results := make([]DirectoryResult, 0, len(hits))
	for _, hit := range hits {
		results = append(results, DirectoryResult{
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
	}
	return results, nil
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
