package core

import (
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
	client := defaultHTTPClient(timeout)
	// 泄漏探测不跟随重定向，避免命中自定义 404 跳转页造成误报。
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	base := strings.TrimSuffix(site.URL, "/")

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
		// 空签名规则（.DS_Store/.env 等仅判断 200）在 SPA/软 404 站点任意路径
		// 都返回 200，会产生成片误报；要求响应体有实际内容（≥64 字节）抑制。
		if r.Sig == "" && len(body) < 64 {
			continue
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
