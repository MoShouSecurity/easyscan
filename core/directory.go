package core

import (
	"context"
	_ "embed"
	"net/http"
	"strings"
	"time"
)

//go:embed dicts/directories.txt
var builtinDirectoryDictionary string

// directoryPaths 从单一内置字典生成，启动时完成格式校验、归一化和去重。
var directoryPaths = mustLoadBuiltinDirectoryPaths()

func mustLoadBuiltinDirectoryPaths() []string {
	paths, err := parsePathDictionary(strings.NewReader(builtinDirectoryDictionary))
	if err != nil {
		panic("内置目录字典无效: " + err.Error())
	}
	return paths
}

func loadDirectoryDict(filePath string) ([]string, error) {
	return loadPathDictionary(filePath)
}

func detectDirectories(ctx context.Context, site Site, taskID string, timeout time.Duration, concurrency int, paths []string) []DirectoryResult {
	probes := make([]pathProbe, 0, len(paths))
	for _, item := range paths {
		normalized, err := normalizeScanPath(item)
		if err != nil {
			continue
		}
		probes = append(probes, pathProbe{path: normalized, kind: "directory"})
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
	hits := scanPaths(ctx, site, timeout, concurrency, probes, accept)
	results := make([]DirectoryResult, 0, len(hits))
	for _, hit := range hits {
		results = append(results, DirectoryResult{
			ID:            newID(),
			TaskID:        taskID,
			URL:           hit.url,
			Path:          hit.path,
			StatusCode:    hit.statusCode,
			ContentLength: hit.contentLength,
			ContentType:   hit.contentType,
			CreatedAt:     nowUnix(),
		})
	}
	return results
}
