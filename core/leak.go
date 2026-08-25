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

// leakRule 敏感文件/信息泄漏探测规则。
// Sig 为响应体命中签名（不区分大小写），空则依靠状态码和软 404 基线判断。
type leakRule struct {
	Path string
	Type string
	Sig  string
}

//go:embed dicts/leaks.tsv.gz
var builtinLeakDictionary []byte

const builtinLeakRuleCount = 153737

// quickLeakRules 保留最常见且高价值的敏感文件，作为默认扫描集合。
var quickLeakRules = []leakRule{
	{Path: "/.git/config", Type: "git", Sig: "[core]"},
	{Path: "/.git/HEAD", Type: "git", Sig: "ref:"},
	{Path: "/.gitignore", Type: "git"},
	{Path: "/.svn/entries", Type: "svn", Sig: "dir"},
	{Path: "/.svn/wc.db", Type: "svn"},
	{Path: "/.env", Type: "env"},
	{Path: "/.env.local", Type: "env"},
	{Path: "/.DS_Store", Type: "ds_store"},
	{Path: "/.idea/workspace.xml", Type: "idea", Sig: "project"},
	{Path: "/.vscode/settings.json", Type: "vscode"},
	{Path: "/.htaccess", Type: "htaccess"},
	{Path: "/.htpasswd", Type: "htpasswd"},
	{Path: "/WEB-INF/web.xml", Type: "java", Sig: "web-app"},
	{Path: "/WEB-INF/classes/application.properties", Type: "java", Sig: "="},
	{Path: "/phpinfo.php", Type: "phpinfo", Sig: "php version"},
	{Path: "/info.php", Type: "phpinfo", Sig: "php version"},
	{Path: "/composer.json", Type: "composer", Sig: "require"},
	{Path: "/package.json", Type: "node", Sig: "\"name\""},
	{Path: "/package-lock.json", Type: "node", Sig: "\"lockfileVersion\""},
	{Path: "/docker-compose.yml", Type: "docker", Sig: "services:"},
	{Path: "/Dockerfile", Type: "docker", Sig: "FROM"},
	{Path: "/backup.zip", Type: "backup"},
	{Path: "/backup.tar.gz", Type: "backup"},
	{Path: "/backup.sql", Type: "backup"},
	{Path: "/www.zip", Type: "backup"},
	{Path: "/wwwroot.zip", Type: "backup"},
	{Path: "/db.sql", Type: "backup"},
	{Path: "/database.sql", Type: "backup"},
	{Path: "/config.php.bak", Type: "backup"},
	{Path: "/web.config", Type: "iis", Sig: "configuration"},
	{Path: "/robots.txt", Type: "robots"},
	{Path: "/crossdomain.xml", Type: "crossdomain", Sig: "cross-domain-policy"},
	{Path: "/sitemap.xml", Type: "sitemap", Sig: "urlset"},
}

// loadLeakDict 从字典文件加载泄漏规则。格式：`路径 [类型] [响应签名]`。
func loadLeakDict(path string) ([]leakRule, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxPathDictionarySize {
		return nil, fmt.Errorf("字典必须是普通文件且不超过 %d 字节", maxPathDictionarySize)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	rules := make([]leakRule, 0)
	seen := make(map[string]bool)
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
		seen[normalized] = true
		rule := leakRule{Path: normalized, Type: inferLeakType(normalized)}
		if len(fields) >= 2 {
			rule.Type = strings.ToLower(fields[1])
		}
		if len(fields) >= 3 {
			rule.Sig = strings.Join(fields[2:], " ")
		}
		if rule.Type == "" || len(rule.Type) > 64 || len(rule.Sig) > 256 {
			return nil, fmt.Errorf("字典第 %d 行: 类型或响应签名无效", lineNumber)
		}
		rules = append(rules, rule)
		if len(rules) > maxPathDictionaryRows {
			return nil, fmt.Errorf("字典条目超过 %d 条", maxPathDictionaryRows)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取字典: %w", err)
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("字典没有有效路径")
	}
	return rules, nil
}

// inferLeakType 依据路径特征推断泄漏类型，不把普通 PHP 文件归类为 phpinfo。
func inferLeakType(path string) string {
	p := strings.ToLower(path)
	switch {
	case strings.Contains(p, "/.git/") || strings.HasSuffix(p, "/.gitignore"):
		return "git"
	case strings.Contains(p, "/.svn/"):
		return "svn"
	case strings.Contains(p, "/.hg/"):
		return "hg"
	case strings.Contains(p, "/.env"):
		return "env"
	case strings.Contains(p, "phpinfo") || strings.HasSuffix(p, "/info.php"):
		return "phpinfo"
	case strings.Contains(p, "credential") || strings.Contains(p, "passwd") || strings.Contains(p, "password") || strings.Contains(p, "secret"):
		return "credential"
	case strings.Contains(p, "backup") || strings.HasSuffix(p, ".zip") || strings.HasSuffix(p, ".tar") ||
		strings.HasSuffix(p, ".gz") || strings.HasSuffix(p, ".bak"):
		return "backup"
	case strings.HasSuffix(p, ".sql") || strings.HasSuffix(p, ".db") || strings.HasSuffix(p, ".sqlite"):
		return "database"
	case strings.Contains(p, "config") || strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".properties"):
		return "config"
	default:
		return "misc"
	}
}

// detectLeaks 对一个站点流式探测敏感文件，rules 为 nil 时使用内置压缩字典。
func detectLeaks(ctx context.Context, site Site, taskID string, timeout time.Duration, concurrency int, rules []leakRule) ([]Leak, error) {
	out := make([]Leak, 0)
	err := detectLeaksEach(ctx, site, taskID, timeout, concurrency, leakProbeSource(rules), func(leak Leak) error {
		out = append(out, leak)
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out, err
}

func detectLeaksEach(ctx context.Context, site Site, taskID string, timeout time.Duration, concurrency int, source pathProbeSource, onLeak func(Leak) error) error {
	if onLeak == nil {
		return fmt.Errorf("泄漏结果处理器为空")
	}
	return scanPathSourceEach(ctx, site, timeout, concurrency, source, func(status int) bool {
		return status == http.StatusOK
	}, func(hit pathHit) error {
		if hit.contentLength == 0 {
			return nil
		}
		return onLeak(Leak{
			ID:         newID(),
			TaskID:     taskID,
			URL:        hit.url,
			Path:       hit.path,
			Type:       hit.kind,
			StatusCode: hit.statusCode,
			CreatedAt:  nowUnix(),
		})
	})
}

func leakProbeSourceForMode(rules []leakRule, mode string) (pathProbeSource, int) {
	if rules != nil {
		return limitPathProbeSource(leakProbeSource(rules), len(rules)), len(rules)
	}
	if normalizePathScanMode(mode) == PathScanModeDeep {
		return limitPathProbeSource(leakProbeSource(nil), builtinLeakRuleCount), builtinLeakRuleCount
	}
	return limitPathProbeSource(leakProbeSource(quickLeakRules), len(quickLeakRules)), len(quickLeakRules)
}

func leakProbeSource(rules []leakRule) pathProbeSource {
	return func(yield func(pathProbe) bool) error {
		if rules != nil {
			for _, rule := range rules {
				normalized, err := normalizeScanPath(rule.Path)
				if err != nil {
					return err
				}
				if !yield(pathProbe{path: normalized, kind: rule.Type, signature: rule.Sig}) {
					return nil
				}
			}
			return nil
		}
		return forEachBuiltinLeakRule(func(rule leakRule) bool {
			return yield(pathProbe{path: rule.Path, kind: rule.Type, signature: rule.Sig})
		})
	}
}

func forEachBuiltinLeakRule(yield func(leakRule) bool) error {
	reader, err := gzip.NewReader(bytes.NewReader(builtinLeakDictionary))
	if err != nil {
		return fmt.Errorf("打开内置泄漏字典: %w", err)
	}
	defer reader.Close()

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), maxPathDictionarySize)
	count := 0
	for scanner.Scan() {
		fields := strings.SplitN(scanner.Text(), "\t", 3)
		if len(fields) != 3 || fields[1] == "" {
			return fmt.Errorf("内置泄漏字典第 %d 行格式无效", count+1)
		}
		normalized, err := normalizeScanPath(fields[0])
		if err != nil || normalized != fields[0] {
			return fmt.Errorf("内置泄漏字典第 %d 行路径无效: %q", count+1, fields[0])
		}
		count++
		if !yield(leakRule{Path: normalized, Type: fields[1], Sig: fields[2]}) {
			return nil
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if count != builtinLeakRuleCount {
		return fmt.Errorf("内置泄漏字典条目数为 %d，期望 %d", count, builtinLeakRuleCount)
	}
	return nil
}
