package core

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// leakRule 敏感文件/信息泄漏探测规则。
// Sig 为响应体命中签名（小写匹配），空则仅需状态码 200。
type leakRule struct {
	Path string
	Type string
	Sig  string
}

// leakRules 内置文件泄漏字典。
var leakRules = []leakRule{
	{"/.git/config", "git", "[core]"},
	{"/.git/HEAD", "git", "ref:"},
	{"/.gitignore", "git", ""},
	{"/.svn/entries", "svn", "dir"},
	{"/.svn/wc.db", "svn", ""},
	{"/.env", "env", ""},
	{"/.env.local", "env", ""},
	{"/.DS_Store", "ds_store", ""},
	{"/.idea/workspace.xml", "idea", "project"},
	{"/.vscode/settings.json", "vscode", ""},
	{"/.htaccess", "htaccess", ""},
	{"/.htpasswd", "htpasswd", ""},
	{"/WEB-INF/web.xml", "java", "web-app"},
	{"/WEB-INF/classes/application.properties", "java", "="},
	{"/phpinfo.php", "phpinfo", "php version"},
	{"/info.php", "phpinfo", "php version"},
	{"/composer.json", "composer", "require"},
	{"/package.json", "node", "\"name\""},
	{"/package-lock.json", "node", "\"lockfileVersion\""},
	{"/docker-compose.yml", "docker", "services:"},
	{"/Dockerfile", "docker", "FROM"},
	{"/backup.zip", "backup", ""},
	{"/backup.tar.gz", "backup", ""},
	{"/backup.sql", "backup", ""},
	{"/www.zip", "backup", ""},
	{"/wwwroot.zip", "backup", ""},
	{"/db.sql", "backup", ""},
	{"/database.sql", "backup", ""},
	{"/config.php.bak", "backup", ""},
	{"/web.config", "iis", "configuration"},
	{"/robots.txt", "robots", ""},
	{"/crossdomain.xml", "crossdomain", "cross-domain-policy"},
	{"/sitemap.xml", "sitemap", "urlset"},
}

// loadLeakDict 从字典文件加载泄漏规则。格式：每行 `路径 [类型]`，# 开头为注释，空行忽略。
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
		if len(fields) == 0 {
			continue
		}
		normalized, err := normalizeScanPath(fields[0])
		if err != nil {
			return nil, fmt.Errorf("字典第 %d 行: %w", lineNumber, err)
		}
		if seen[normalized] {
			continue
		}
		seen[normalized] = true
		rule := leakRule{Path: normalized}
		if len(fields) >= 2 {
			rule.Type = fields[1]
		} else {
			rule.Type = inferLeakType(normalized)
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

// inferLeakType 依据路径关键字自动推断泄露类型。
func inferLeakType(path string) string {
	p := strings.ToLower(path)
	switch {
	case strings.Contains(p, ".git"):
		return "git"
	case strings.Contains(p, ".svn"):
		return "svn"
	case strings.Contains(p, ".env"):
		return "env"
	case strings.Contains(p, "backup"), strings.HasSuffix(p, ".zip"), strings.HasSuffix(p, ".tar"),
		strings.HasSuffix(p, ".gz"), strings.HasSuffix(p, ".sql"), strings.HasSuffix(p, ".bak"):
		return "backup"
	case strings.Contains(p, "phpinfo"), strings.HasSuffix(p, ".php"):
		return "phpinfo"
	case strings.Contains(p, "actuator"):
		return "spring"
	case strings.Contains(p, "swagger"), strings.Contains(p, "api-docs"):
		return "swagger"
	default:
		return "misc"
	}
}

// detectLeaks 对一个站点探测敏感文件/信息泄漏，返回命中的泄漏记录。
func detectLeaks(ctx context.Context, site Site, taskID string, timeout time.Duration, concurrency int, rules []leakRule) []Leak {
	probes := make([]pathProbe, 0, len(rules))
	for _, r := range rules {
		path, err := normalizeScanPath(r.Path)
		if err != nil {
			continue
		}
		probes = append(probes, pathProbe{path: path, kind: r.Type, signature: r.Sig})
	}
	hits := scanPaths(ctx, site, timeout, concurrency, probes, func(status int) bool {
		return status == http.StatusOK
	})
	out := make([]Leak, 0, len(hits))
	for _, hit := range hits {
		if hit.contentLength == 0 {
			continue
		}
		out = append(out, Leak{
			ID:         newID(),
			TaskID:     taskID,
			URL:        hit.url,
			Path:       hit.path,
			Type:       hit.kind,
			StatusCode: hit.statusCode,
			CreatedAt:  nowUnix(),
		})
	}
	return out
}
