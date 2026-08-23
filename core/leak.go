package core

import (
	"bytes"
	"context"
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
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rules []leakRule
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		rule := leakRule{Path: fields[0]}
		if len(fields) >= 2 {
			rule.Type = fields[1]
		} else {
			rule.Type = inferLeakType(fields[0])
		}
		rules = append(rules, rule)
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
func detectLeaks(ctx context.Context, site Site, taskID string, timeout time.Duration, rules []leakRule) []Leak {
	scope, err := newSiteScope(site)
	if err != nil {
		return nil
	}
	client := scope.client(timeout, 0)
	base := strings.TrimSuffix(scope.baseURL, "/")
	baseline := fetchSoft404Baseline(ctx, client, base)

	var out []Leak
	for _, r := range rules {
		url := base + r.Path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (EasyScan)")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}
		body, _ := readBodyLimited(resp.Body, 256<<10)
		resp.Body.Close()

		lower := strings.ToLower(string(body))
		if r.Sig != "" && !strings.Contains(lower, strings.ToLower(r.Sig)) {
			continue
		}
		if r.Sig == "" {
			// 空签名规则必须区别于随机不存在路径；SPA/catch-all 的统一 200 页面不算泄漏。
			if len(body) < 64 || baseline.matches(resp, body) {
				continue
			}
		}
		out = append(out, Leak{
			ID:         newID(),
			TaskID:     taskID,
			URL:        url,
			Path:       r.Path,
			Type:       r.Type,
			StatusCode: resp.StatusCode,
			CreatedAt:  nowUnix(),
		})
	}
	return out
}

type soft404Baseline struct {
	status      int
	contentType string
	body        []byte
}

func fetchSoft404Baseline(ctx context.Context, client *http.Client, base string) soft404Baseline {
	url := base + "/.easyscan-not-found-" + newID()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return soft404Baseline{}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (EasyScan)")
	resp, err := client.Do(req)
	if err != nil {
		return soft404Baseline{}
	}
	defer resp.Body.Close()
	body, _ := readBodyLimited(resp.Body, 256<<10)
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
	delta := len(b.body) - len(body)
	if delta < 0 {
		delta = -delta
	}
	tolerance := len(b.body) / 20 // 允许软 404 中时间戳、nonce 等造成约 5% 波动。
	if tolerance < 64 {
		tolerance = 64
	}
	return delta <= tolerance
}

func normalizedContentType(value string) string {
	if i := strings.IndexByte(value, ';'); i >= 0 {
		value = value[:i]
	}
	return strings.ToLower(strings.TrimSpace(value))
}
