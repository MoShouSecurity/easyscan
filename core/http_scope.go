package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// siteScope 把站点后续 HTTP 请求固定到发现阶段确认的 IP，并限制为同一主机。
// 这样既保留域名 Host/SNI，又避免重定向和 DNS 重绑定把扫描带到未授权目标。
type siteScope struct {
	ip       string
	hostname string
	baseURL  string
}

func newSiteScope(site Site) (siteScope, error) {
	u, err := url.Parse(site.URL)
	if err != nil || u.Host == "" || u.User != nil || !isHTTPScheme(u.Scheme) {
		return siteScope{}, fmt.Errorf("站点 URL 无效: %q", site.URL)
	}
	hostname := normalizeHTTPHost(u.Hostname())
	if hostname == "" {
		return siteScope{}, fmt.Errorf("站点 URL 缺少主机: %q", site.URL)
	}
	ip := strings.TrimSpace(site.IP)
	if ip == "" && net.ParseIP(hostname) != nil {
		ip = hostname
	}
	if net.ParseIP(ip) == nil {
		return siteScope{}, fmt.Errorf("站点缺少有效的固定 IP: %q", site.IP)
	}
	return siteScope{
		ip:       ip,
		hostname: hostname,
		baseURL:  httpOrigin(u),
	}, nil
}

func (s siteScope) client(timeout time.Duration, maxRedirects int) *http.Client {
	return s.clientWithConnectionLimit(timeout, maxRedirects, 16)
}

// clientWithConnectionLimit 创建连接数有上限、可复用空闲连接的同源客户端。
func (s siteScope) clientWithConnectionLimit(timeout time.Duration, maxRedirects, maxConnections int) *http.Client {
	if maxConnections < 1 {
		maxConnections = 1
	}
	transport := &http.Transport{
		MaxIdleConns:          maxConnections,
		MaxIdleConnsPerHost:   maxConnections,
		MaxConnsPerHost:       maxConnections,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: time.Second,
		// 扫描器需要兼容自签名和过期证书；连接仍由固定 IP 和主机范围约束保护。
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, //nolint:gosec
		},
	}
	if net.ParseIP(s.hostname) == nil {
		transport.TLSClientConfig.ServerName = s.hostname
	}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("解析请求地址 %q: %w", addr, err)
		}
		if normalizeHTTPHost(host) != s.hostname {
			return nil, fmt.Errorf("拒绝访问扫描范围外主机 %q", host)
		}
		d := net.Dialer{Timeout: timeout}
		return d.DialContext(ctx, network, net.JoinHostPort(s.ip, port))
	}

	client := &http.Client{Transport: transport, Timeout: timeout}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if maxRedirects <= 0 {
			return http.ErrUseLastResponse
		}
		if len(via) >= maxRedirects {
			return http.ErrUseLastResponse
		}
		if !isHTTPScheme(req.URL.Scheme) || normalizeHTTPHost(req.URL.Hostname()) != s.hostname {
			// 保留原始 3xx 响应用于指纹记录，但绝不发送范围外请求。
			return http.ErrUseLastResponse
		}
		return nil
	}
	return client
}

func (s siteScope) allows(rawURL string) bool {
	u, err := url.Parse(rawURL)
	return err == nil && u.User == nil && isHTTPScheme(u.Scheme) && normalizeHTTPHost(u.Hostname()) == s.hostname
}

func (s siteScope) allowsOrigin(rawURL string) bool {
	u, err := url.Parse(rawURL)
	base, baseErr := url.Parse(s.baseURL)
	return err == nil && baseErr == nil && u.User == nil && isHTTPScheme(u.Scheme) &&
		strings.EqualFold(httpOrigin(u), httpOrigin(base))
}

func httpOrigin(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	host := u.Host
	if (scheme == "http" && u.Port() == "80") || (scheme == "https" && u.Port() == "443") {
		host = u.Hostname()
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	}
	return (&url.URL{Scheme: scheme, Host: host, Path: "/"}).String()
}

func normalizeHTTPHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func isHTTPScheme(scheme string) bool {
	return strings.EqualFold(scheme, "http") || strings.EqualFold(scheme, "https")
}
