package core

import (
	"context"
	"html"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// fpRule Web 指纹规则：命中 body 中任一关键字即判定为对应指纹。
type fpRule struct {
	Name     string
	Keywords []string
}

// fingerprintRules 内置指纹规则（CMS / 框架 / 中间件常见特征）。
var fingerprintRules = []fpRule{
	{"WordPress", []string{"wp-content", "wp-includes", "wp-login.php", "name=\"generator\" content=\"WordPress"}},
	{"ThinkPHP", []string{"ThinkPHP", "thinkphp"}},
	{"phpMyAdmin", []string{"phpMyAdmin", "pma_navigation"}},
	{"Jenkins", []string{"Jenkins", "jenkins", "X-Jenkins"}},
	{"GitLab", []string{"GitLab", "gitlab"}},
	{"Discuz", []string{"Discuz", "discuz"}},
	{"DedeCMS", []string{"dedecms", "DedeCMS", "power by dedecms"}},
	{"帝国CMS", []string{"帝国CMS", "EmpireCMS", "e:loop"}},
	{"Spring Boot", []string{"Whitelabel Error Page"}},
	{"Apache Tomcat", []string{"Apache Tomcat", "jakarta"}},
	{"Apache Shiro", []string{"rememberMe=deleteMe", "org.apache.shiro"}},
	{"Nginx", []string{"nginx"}},
	{"宝塔面板", []string{"宝塔", "bt.cn"}},
	{"phpStudy", []string{"phpstudy"}},
	{"若依", []string{"若依", "ruoyi"}},
	{"Swagger UI", []string{"Swagger UI", "swagger-ui"}},
	{"Kibana", []string{"kibana"}},
	{"Grafana", []string{"grafana", "Grafana"}},
	{"Jira", []string{"jira", "JIRA"}},
	{"Confluence", []string{"confluence", "Confluence"}},
	{"Weblogic", []string{"Weblogic", "weblogic"}},
	{"Jboss", []string{"jboss", "Jboss"}},
	{"Struts2", []string{"struts", "actionErrors"}},
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// probeSite 探测一个 HTTP(S) 站点，提取标题、Server 头、识别指纹。
// scheme 为 "http" 或 "https"。hostname 为关联域名（虚拟主机/SNI），为空则直接用 IP。
// 返回结果；若非 HTTP 服务则返回 ok=false。
func probeSite(ctx context.Context, ip string, port int, scheme string, hostname string, timeout time.Duration) (Site, bool) {
	host := ip
	if hostname != "" {
		host = hostname
	}
	// IPv6 地址需 [::1]:80 形式，net.JoinHostPort 统一处理（防非法 URL 静默失败）。
	url := scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port)) + "/"
	scope, err := newSiteScope(Site{IP: ip, URL: url})
	if err != nil {
		return Site{}, false
	}
	// 请求固定到已发现 IP；只允许同主机重定向，避免目标把扫描器带到本机或内网。
	client := scope.client(timeout, 5)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Site{}, false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (EasyScan)")

	resp, err := client.Do(req)
	if err != nil {
		return Site{}, false
	}
	defer resp.Body.Close()

	// 只记录最终站点的 origin，后续规则路径不能拼到 /login 等重定向路径之后。
	if resp.Request != nil && resp.Request.URL != nil {
		url = httpOrigin(resp.Request.URL)
	}

	body, _ := readBodyLimited(resp.Body, 1<<20) // 读取失败视为无内容，指纹匹配自然落空
	site := Site{
		ID:         newID(),
		IP:         ip,
		Port:       port,
		URL:        url,
		StatusCode: resp.StatusCode,
		Server:     resp.Header.Get("Server"),
		CreatedAt:  nowUnix(),
	}

	if m := titleRe.FindSubmatch(body); len(m) >= 2 {
		site.Title = strings.TrimSpace(html.UnescapeString(string(m[1])))
	}

	fp := matchFingerprint(body, resp.Header)
	if fp == "" {
		fp = resp.Header.Get("X-Powered-By")
	}
	site.Fingerprint = fp

	return site, true
}

// matchFingerprint 依据响应体与头部匹配指纹，命中多个用逗号连接。
func matchFingerprint(body []byte, header http.Header) string {
	lower := strings.ToLower(string(body))
	server := strings.ToLower(header.Get("Server"))
	powered := strings.ToLower(header.Get("X-Powered-By"))

	var hits []string
	add := func(name string) {
		for _, h := range hits {
			if h == name {
				return
			}
		}
		hits = append(hits, name)
	}

	// 头部指纹优先级高。
	if strings.Contains(server, "nginx") {
		add("Nginx")
	}
	if strings.Contains(server, "apache") {
		add("Apache")
	}
	if strings.Contains(server, "iis") || strings.Contains(server, "microsoft") {
		add("IIS")
	}
	if strings.Contains(powered, "php") {
		add("PHP")
	}
	if strings.Contains(powered, "asp.net") {
		add("ASP.NET")
	}

	for _, rule := range fingerprintRules {
		for _, kw := range rule.Keywords {
			if kw != "" && strings.Contains(lower, strings.ToLower(kw)) {
				add(rule.Name)
				break
			}
		}
	}
	return strings.Join(hits, ",")
}
