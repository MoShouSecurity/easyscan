// FOFA 资产搜索引擎集成（https://fofa.info/api）：以 domain="x.com" 查询
// 目标域名的全部资产记录，提取子域名与对应 IP 作为子域名收集源之一。
package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// fofaAPIPageSize 单页查询条数。FOFA 普通会员单页上限 10000 条；
// 子域名收集场景取第一页即可（超出部分由 subfinder/ksubdomain 补足，翻页烧配额）。
const fofaAPIPageSize = 10000

// fofaMinTimeout FOFA 查询的最小超时（大查询响应慢，不随任务探测超时缩得太短）。
const fofaMinTimeout = 15 * time.Second

// fofaResult FOFA 查询结果条目。
type fofaResult struct {
	Host string
	IP   string
	Port int // FOFA 收录的端口（0 表示无端口线索）
}

// fofaResponse FOFA API 响应结构（仅取需要的字段）。
type fofaResponse struct {
	Error   bool       `json:"error"`
	ErrMsg  string     `json:"errmsg"`
	Results [][]string `json:"results"`
}

// fofaTimeout 返回 FOFA 请求超时：任务探测超时与 15s 最小值取大。
func fofaTimeout(optsTimeout time.Duration) time.Duration {
	if optsTimeout < fofaMinTimeout {
		return fofaMinTimeout
	}
	return optsTimeout
}

// fofaSearch 调用 FOFA API 查询目标域名的子域名资产。
// query 语法：domain="example.com"（qbase64 编码后传入），fields 取 host,ip。
// proxyURL 非空时出站请求走 HTTP 代理（如 http://127.0.0.1:7890）。
func fofaSearch(ctx context.Context, domain, apiKey, proxyURL string, timeout time.Duration) ([]fofaResult, error) {
	return fofaSearchImpl(ctx, domain, apiKey, proxyURL, timeout, "https://fofa.info/api/v1/search/all")
}

// fofaSearchImpl 与 fofaSearch 相同，apiURL 由调用方指定（测试注入 mock server）。
func fofaSearchImpl(ctx context.Context, domain, apiKey, proxyURL string, timeout time.Duration, apiURL string) ([]fofaResult, error) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, nil // 未配置 key，静默跳过
	}
	query := fmt.Sprintf(`domain="%s"`, domain)
	params := url.Values{
		"key":     {apiKey},
		"qbase64": {base64.StdEncoding.EncodeToString([]byte(query))},
		"fields":  {"host,ip,port"},
		"size":    {fmt.Sprintf("%d", fofaAPIPageSize)},
		"page":    {"1"},
	}
	apiURL += "?" + params.Encode()

	transport := &http.Transport{}
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("无效的代理地址 %q: %w", proxyURL, err)
		}
		transport.Proxy = http.ProxyURL(u)
	}
	client := &http.Client{Transport: transport, Timeout: timeout}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "EasyScan/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("FOFA HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var body fofaResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&body); err != nil {
		return nil, fmt.Errorf("解析 FOFA 响应失败: %w", err)
	}
	if body.Error {
		msg := strings.TrimSpace(body.ErrMsg)
		if msg == "" {
			msg = "未知错误（可能配额不足）"
		}
		return nil, fmt.Errorf("FOFA API 错误: %s", msg)
	}
	return fofaFilterResults(domain, body.Results), nil
}

// fofaFilterResults 过滤 FOFA 原始结果行（纯函数，便于单测）：
//   - host 归一化（去空格/小写/去尾点），丢弃空值、裸 IP 与目标域之外的记录
//     （domain= 语法会带回 example.com.evil.com 这类前缀绕过结果）
//   - IP 必须为合法地址（丢弃空值、ip:port 形态）
//   - port 为 1-65535 时保留（供站点直接探测），否则置 0
//   - 同一 host 多行时保留第一条有效记录
func fofaFilterResults(domain string, rows [][]string) []fofaResult {
	out := make([]fofaResult, 0)
	seen := map[string]bool{}
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(row[0])), ".")
		if host == "" || net.ParseIP(host) != nil {
			continue // 空 host 或裸 IP 记录
		}
		if host != domain && !strings.HasSuffix(host, "."+domain) {
			continue // 目标域之外的记录（防前缀绕过）
		}
		ip := strings.TrimSpace(row[1])
		if net.ParseIP(ip) == nil {
			continue // 空或非法 IP（含 ip:port 形态）
		}
		port := 0
		if len(row) >= 3 {
			if p, err := strconv.Atoi(strings.TrimSpace(row[2])); err == nil && p > 0 && p <= 65535 {
				port = p
			}
		}
		if seen[host] {
			continue
		}
		seen[host] = true
		out = append(out, fofaResult{Host: host, IP: ip, Port: port})
	}
	return out
}
