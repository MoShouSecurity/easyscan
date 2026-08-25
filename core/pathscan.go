package core

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxPathDictionarySize = 4 << 20
	maxPathDictionaryRows = 10000
	maxPathResponseSize   = 256 << 10
	maxPathConcurrency    = 50
)

// pathProbe 描述一次同源 HTTP 路径探测。signature 为空时依靠软 404 基线过滤误报。
type pathProbe struct {
	path      string
	kind      string
	signature string
}

type pathHit struct {
	url           string
	path          string
	kind          string
	statusCode    int
	contentLength int64
	contentType   string
}

// pathProbeSource 按需产生探测项。返回错误表示字典损坏或读取失败。
type pathProbeSource func(yield func(pathProbe) bool) error

// limitPathProbeSource 为单站探测设置硬性请求预算，防止损坏或意外扩张的字典无限产出。
func limitPathProbeSource(source pathProbeSource, limit int) pathProbeSource {
	return func(yield func(pathProbe) bool) error {
		if source == nil || limit < 1 {
			return fmt.Errorf("路径探测源为空或请求预算无效")
		}
		count := 0
		return source(func(probe pathProbe) bool {
			if count >= limit {
				return false
			}
			count++
			return yield(probe)
		})
	}
}

// scanPaths 并发探测一个站点下的路径。请求始终固定到发现阶段确认的 IP，且不跟随重定向。
func scanPaths(ctx context.Context, site Site, timeout time.Duration, concurrency int, probes []pathProbe, accept func(int) bool) ([]pathHit, error) {
	if len(probes) == 0 {
		return nil, nil
	}
	return scanPathSource(ctx, site, timeout, concurrency, func(yield func(pathProbe) bool) error {
		for _, probe := range probes {
			if !yield(probe) {
				return nil
			}
		}
		return nil
	}, accept)
}

// scanPathSource 流式消费探测路径，并为需要一次性结果的调用方收集命中项。
func scanPathSource(ctx context.Context, site Site, timeout time.Duration, concurrency int, source pathProbeSource, accept func(int) bool) ([]pathHit, error) {
	results := make([]pathHit, 0)
	err := scanPathSourceEach(ctx, site, timeout, concurrency, source, accept, func(hit pathHit) error {
		results = append(results, hit)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(results, func(i, j int) bool { return results[i].url < results[j].url })
	return results, nil
}

// scanPathSourceEach 逐条交付命中结果，避免深度扫描把全部结果滞留在内存中。
// 字典生产协程和每个探测 worker 都独立捕获 panic，单个异常只会终止当前任务。
func scanPathSourceEach(ctx context.Context, site Site, timeout time.Duration, concurrency int, source pathProbeSource, accept func(int) bool, onHit func(pathHit) error) error {
	scope, err := newSiteScope(site)
	if err != nil {
		return fmt.Errorf("初始化站点扫描范围: %w", err)
	}
	if source == nil || accept == nil || onHit == nil {
		return fmt.Errorf("路径探测源、状态码过滤器或结果处理器为空")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > maxPathConcurrency {
		concurrency = maxPathConcurrency
	}
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	client := scope.clientWithConnectionLimit(timeout, 0, concurrency)
	defer client.CloseIdleConnections()
	base := strings.TrimSuffix(scope.baseURL, "/")
	baseline := fetchSoft404Baseline(scanCtx, client, base)
	if err := scanCtx.Err(); err != nil {
		return err
	}

	jobs := make(chan pathProbe)
	hits := make(chan pathHit)
	workerErrors := make(chan error, concurrency+1)
	var producers sync.WaitGroup
	reportError := func(err error) {
		if err == nil {
			return
		}
		workerErrors <- err
		cancel()
	}

	for i := 0; i < concurrency; i++ {
		producers.Add(1)
		go func() {
			defer producers.Done()
			defer func() {
				if recovered := recover(); recovered != nil {
					reportError(recoveredPanicError("路径扫描工作协程", recovered))
				}
			}()
			for {
				var probe pathProbe
				var ok bool
				select {
				case <-scanCtx.Done():
					return
				case probe, ok = <-jobs:
					if !ok {
						return
					}
				}
				hit, ok := probePath(scanCtx, client, base, baseline, probe, accept)
				if !ok {
					continue
				}
				select {
				case hits <- hit:
				case <-scanCtx.Done():
					return
				}
			}
		}()
	}

	producers.Add(1)
	go func() {
		defer producers.Done()
		defer close(jobs)
		defer func() {
			if recovered := recover(); recovered != nil {
				reportError(recoveredPanicError("路径字典读取协程", recovered))
			}
		}()
		if err := source(func(probe pathProbe) bool {
			select {
			case jobs <- probe:
				return true
			case <-scanCtx.Done():
				return false
			}
		}); err != nil {
			reportError(fmt.Errorf("读取路径字典: %w", err))
		}
	}()
	go func() {
		producers.Wait()
		close(hits)
		close(workerErrors)
	}()

	var firstErr error
	for hits != nil || workerErrors != nil {
		select {
		case hit, ok := <-hits:
			if !ok {
				hits = nil
				continue
			}
			if firstErr == nil {
				if err := onHit(hit); err != nil {
					firstErr = err
					cancel()
				}
			}
		case err, ok := <-workerErrors:
			if !ok {
				workerErrors = nil
				continue
			}
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return firstErr
}

func probePath(ctx context.Context, client *http.Client, base string, baseline soft404Baseline, probe pathProbe, accept func(int) bool) (pathHit, bool) {
	target := base + probe.path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return pathHit{}, false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (EasyScan)")
	resp, err := client.Do(req)
	if err != nil {
		return pathHit{}, false
	}
	body, readErr := readBodyLimited(resp.Body, maxPathResponseSize)
	closeErr := resp.Body.Close()
	if readErr != nil || closeErr != nil || !accept(resp.StatusCode) {
		return pathHit{}, false
	}
	if baseline.matches(resp, body) {
		return pathHit{}, false
	}
	if probe.signature != "" && !bytes.Contains(bytes.ToLower(body), bytes.ToLower([]byte(probe.signature))) {
		return pathHit{}, false
	}
	return pathHit{
		url:           target,
		path:          probe.path,
		kind:          probe.kind,
		statusCode:    resp.StatusCode,
		contentLength: int64(len(body)),
		contentType:   normalizedContentType(resp.Header.Get("Content-Type")),
	}, true
}

// loadPathDictionary 读取一行一个路径的 UTF-8 文本字典，并限制文件大小和条目数。
func loadPathDictionary(filePath string) ([]string, error) {
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
	return parsePathDictionary(file)
}

func parsePathDictionary(reader io.Reader) ([]string, error) {
	seen := make(map[string]bool)
	items := make([]string, 0)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), maxPathDictionarySize)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "\ufeff"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		item, err := normalizeScanPath(line)
		if err != nil {
			return nil, fmt.Errorf("字典第 %d 行: %w", lineNumber, err)
		}
		if seen[item] {
			continue
		}
		seen[item] = true
		items = append(items, item)
		if len(items) > maxPathDictionaryRows {
			return nil, fmt.Errorf("字典条目超过 %d 条", maxPathDictionaryRows)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取字典: %w", err)
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("字典没有有效路径")
	}
	return items, nil
}

func normalizeScanPath(raw string) (string, error) {
	if strings.ContainsAny(raw, "\x00\r\n\t ") {
		return "", fmt.Errorf("路径不能包含空白或控制字符")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("只允许不含查询参数的站内路径: %q", raw)
	}
	if strings.ContainsAny(parsed.Path, "\x00\r\n\t ?#%") {
		return "", fmt.Errorf("解码后的路径包含不安全字符")
	}
	for _, segment := range strings.Split(parsed.Path, "/") {
		if segment == ".." {
			return "", fmt.Errorf("路径不能包含上级目录: %q", raw)
		}
	}
	cleaned := path.Clean("/" + strings.TrimPrefix(parsed.Path, "/"))
	if cleaned == "/" {
		return "", fmt.Errorf("路径无效: %q", raw)
	}
	if len(cleaned) > 2048 {
		return "", fmt.Errorf("路径超过 2048 字符")
	}
	return cleaned, nil
}

type soft404Baseline struct {
	status      int
	contentType string
	body        []byte
}

func fetchSoft404Baseline(ctx context.Context, client *http.Client, base string) soft404Baseline {
	target := base + "/.easyscan-not-found-" + newID()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return soft404Baseline{}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (EasyScan)")
	resp, err := client.Do(req)
	if err != nil {
		return soft404Baseline{}
	}
	defer resp.Body.Close()
	body, _ := readBodyLimited(resp.Body, maxPathResponseSize)
	return soft404Baseline{
		status:      resp.StatusCode,
		contentType: normalizedContentType(resp.Header.Get("Content-Type")),
		body:        body,
	}
}

func (b soft404Baseline) matches(resp *http.Response, body []byte) bool {
	if b.status == 0 || b.status != resp.StatusCode {
		return false
	}
	if bytes.Equal(bytes.TrimSpace(b.body), bytes.TrimSpace(body)) {
		return true
	}
	if b.contentType == "" || b.contentType != normalizedContentType(resp.Header.Get("Content-Type")) {
		return false
	}
	// 短响应只做精确比较，不能仅因长度接近就把真实的小文件或 JSON 接口当成软 404。
	if len(b.body) < 512 || len(body) < 512 || !isTextContentType(b.contentType) {
		return false
	}
	delta := len(b.body) - len(body)
	if delta < 0 {
		delta = -delta
	}
	tolerance := len(b.body) / 20
	if tolerance < 64 {
		tolerance = 64
	}
	if delta > tolerance {
		return false
	}
	const sampleSize = 128
	return bytes.Equal(b.body[:sampleSize], body[:sampleSize]) &&
		bytes.Equal(b.body[len(b.body)-sampleSize:], body[len(body)-sampleSize:])
}

func normalizedContentType(value string) string {
	if i := strings.IndexByte(value, ';'); i >= 0 {
		value = value[:i]
	}
	return strings.ToLower(strings.TrimSpace(value))
}

func isTextContentType(value string) bool {
	return strings.HasPrefix(value, "text/") || strings.Contains(value, "json") || strings.Contains(value, "xml")
}
