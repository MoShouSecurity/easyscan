package core

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ---- 内置 POC 模板（轻量，无外部依赖） ----

// pocTemplate 内置 POC 检测模板。
type pocTemplate struct {
	Name  string
	Paths []string
	Sig   string
}

// pocTemplates 内置检测模板，可继续扩展。
var pocTemplates = []pocTemplate{
	{Name: "SpringBoot Actuator 未授权访问", Paths: []string{"/actuator/env", "/actuator/configprops", "/actuator/heapdump"}, Sig: "propertySources"},
	{Name: "Swagger API 文档泄露", Paths: []string{"/v2/api-docs", "/v3/api-docs", "/swagger-ui.html"}, Sig: "swagger"},
	{Name: "phpinfo 信息泄露", Paths: []string{"/phpinfo.php", "/info.php", "/test.php"}, Sig: "php version"},
	{Name: "Druid 监控未授权访问", Paths: []string{"/druid/index.html", "/druid/login.html"}, Sig: "druid"},
	{Name: "Weblogic 控制台泄露", Paths: []string{"/console/login/LoginForm.jsp"}, Sig: "weblogic"},
	{Name: "ThinkPHP 远程代码执行特征", Paths: []string{"/index.php?s=/index/\\think\\app/invokefunction"}, Sig: "thinkphp"},
	{Name: "Git 源码泄露", Paths: []string{"/.git/config", "/.git/HEAD"}, Sig: "[core]"},
}

// runNuclei 对站点执行内置 POC 检测，命中结果以 leak 记录形式返回。
func runNuclei(ctx context.Context, site Site, taskID string, timeout time.Duration) []Leak {
	client := defaultHTTPClient(timeout)
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	base := strings.TrimSuffix(site.URL, "/")

	var out []Leak
	for _, tpl := range pocTemplates {
		for _, p := range tpl.Paths {
			url := base + p
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (EasyScan)")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body := readBodyLimited(resp.Body, 256<<10)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				continue
			}
			lower := strings.ToLower(string(body))
			if tpl.Sig != "" && !strings.Contains(lower, strings.ToLower(tpl.Sig)) {
				continue
			}
			out = append(out, Leak{
				ID:         newID(),
				TaskID:     taskID,
				URL:        url,
				Path:       p,
				Type:       "nuclei:" + tpl.Name,
				StatusCode: resp.StatusCode,
				CreatedAt:  nowUnix(),
			})
		}
	}
	return out
}

// ---- 自定义 nuclei 模板（YAML） ----

// StringOrList 兼容 nuclei YAML 中 path 字段既可为字符串也可为列表。
type StringOrList []string

// UnmarshalYAML 实现 yaml.Unmarshaler，支持标量与序列两种写法。
func (s *StringOrList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		*s = []string{node.Value}
	case yaml.SequenceNode:
		items := make([]string, 0, len(node.Content))
		for _, n := range node.Content {
			items = append(items, n.Value)
		}
		*s = items
	default:
		return fmt.Errorf("path 字段需为字符串或列表")
	}
	return nil
}

// NucleiMatcher 模板匹配器。
type NucleiMatcher struct {
	Type      string   `yaml:"type"`
	Words     []string `yaml:"words"`
	Regex     []string `yaml:"regex"`
	Status    []int    `yaml:"status"`
	Part      string   `yaml:"part"`
	Condition string   `yaml:"condition"`
}

// NucleiRequest 模板 HTTP 请求。
type NucleiRequest struct {
	Method            string          `yaml:"method"`
	Path              StringOrList    `yaml:"path"`
	Raw               StringOrList    `yaml:"raw"`
	MatchersCondition string          `yaml:"matchers-condition"`
	Matchers          []NucleiMatcher `yaml:"matchers"`
}

// NucleiTemplate 解析后的 nuclei HTTP 模板（子集）。
type NucleiTemplate struct {
	ID   string `yaml:"id"`
	Info struct {
		Name     string `yaml:"name"`
		Severity string `yaml:"severity"`
	} `yaml:"info"`
	Requests []NucleiRequest `yaml:"requests"`
}

// loadNucleiTemplates 递归扫描目录，解析所有 .yaml/.yml 模板。
func loadNucleiTemplates(dir string) ([]NucleiTemplate, error) {
	var templates []NucleiTemplate
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // 忽略单个文件读取错误
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var t NucleiTemplate
		if err := yaml.Unmarshal(data, &t); err != nil {
			return nil // 跳过无法解析的模板
		}
		if t.ID != "" && len(t.Requests) > 0 {
			templates = append(templates, t)
		}
		return nil
	})
	return templates, err
}

// runNucleiYAML 对站点执行自定义 nuclei 模板，命中以 leak 记录返回。
func runNucleiYAML(ctx context.Context, site Site, taskID string, templates []NucleiTemplate, timeout time.Duration) []Leak {
	base := strings.TrimSuffix(site.URL, "/")
	var out []Leak
	for _, tpl := range templates {
		if url, ok := matchNucleiTemplate(ctx, tpl, base, timeout); ok {
			name := tpl.Info.Name
			if name == "" {
				name = tpl.ID
			}
			out = append(out, Leak{
				ID:         newID(),
				TaskID:     taskID,
				URL:        url,
				Path:       firstPath(tpl),
				Type:       "nuclei:" + name,
				StatusCode: 200,
				CreatedAt:  nowUnix(),
			})
		}
	}
	return out
}

func firstPath(t NucleiTemplate) string {
	for _, r := range t.Requests {
		if len(r.Path) > 0 {
			return r.Path[0]
		}
	}
	return ""
}

// matchNucleiTemplate 执行单个模板，命中返回命中的 URL。
func matchNucleiTemplate(ctx context.Context, tpl NucleiTemplate, base string, timeout time.Duration) (string, bool) {
	client := defaultHTTPClient(timeout)
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	for _, req := range tpl.Requests {
		method := strings.ToUpper(req.Method)
		if method == "" {
			method = http.MethodGet
		}
		for _, p := range req.Path {
			url := expandPath(p, base)
			if url == "" {
				continue
			}
			httpReq, err := http.NewRequestWithContext(ctx, method, url, nil)
			if err != nil {
				continue
			}
			httpReq.Header.Set("User-Agent", "Mozilla/5.0 (EasyScan)")
			resp, err := client.Do(httpReq)
			if err != nil {
				continue
			}
			body := readBodyLimited(resp.Body, 512<<10)
			resp.Body.Close()
			if evalMatchers(req, resp, body) {
				return url, true
			}
		}
	}
	return "", false
}

// expandPath 替换模板变量（MVP 支持 {{BaseURL}} 与 {{RootURL}}）。
func expandPath(p, base string) string {
	p = strings.ReplaceAll(p, "{{BaseURL}}", base)
	p = strings.ReplaceAll(p, "{{RootURL}}", base)
	p = strings.ReplaceAll(p, "{{Hostname}}", strings.TrimPrefix(strings.TrimPrefix(base, "http://"), "https://"))
	if !strings.HasPrefix(p, "http") {
		return ""
	}
	return p
}

// evalMatchers 依据 matchers-condition 与每个 matcher 判定是否命中。
func evalMatchers(req NucleiRequest, resp *http.Response, body []byte) bool {
	if len(req.Matchers) == 0 {
		return resp.StatusCode == http.StatusOK
	}
	cond := req.MatchersCondition
	if cond == "" {
		cond = "or"
	}
	results := make([]bool, len(req.Matchers))
	for i, m := range req.Matchers {
		results[i] = matchOne(m, resp, body)
	}
	if cond == "and" {
		for _, r := range results {
			if !r {
				return false
			}
		}
		return len(results) > 0
	}
	for _, r := range results {
		if r {
			return true
		}
	}
	return false
}

func matchOne(m NucleiMatcher, resp *http.Response, body []byte) bool {
	target := body
	if m.Part == "header" {
		target = headerBytes(resp)
	}
	lower := strings.ToLower(string(target))

	switch m.Type {
	case "status":
		for _, s := range m.Status {
			if resp.StatusCode == s {
				return true
			}
		}
		return false
	case "word":
		cond := m.Condition
		if cond == "" {
			cond = "or"
		}
		hits := 0
		for _, w := range m.Words {
			if w != "" && strings.Contains(lower, strings.ToLower(w)) {
				hits++
			}
		}
		if cond == "and" {
			return hits == len(m.Words) && hits > 0
		}
		return hits > 0
	case "regex":
		for _, re := range m.Regex {
			if matched, _ := regexp.MatchString(re, string(target)); matched {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func headerBytes(resp *http.Response) []byte {
	var b strings.Builder
	for k, vs := range resp.Header {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(strings.Join(vs, ", "))
		b.WriteString("\n")
	}
	return []byte(b.String())
}

// DownloadNucleiTemplates 从官方仓库下载（git clone）nuclei 模板库到 destDir。
func DownloadNucleiTemplates(destDir, repo string) error {
	if repo == "" {
		repo = DefaultConfig().Nuclei.TemplatesRepo
	}
	if _, err := os.Stat(filepath.Join(destDir, ".git")); err == nil {
		// 已存在，执行 pull 更新。
		cmd := exec.Command("git", "-C", destDir, "pull", "--depth", "1")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	if err := os.MkdirAll(filepath.Dir(destDir), 0o755); err != nil {
		return err
	}
	cmd := exec.Command("git", "clone", "--depth", "1", repo, destDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
