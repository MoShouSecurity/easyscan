package core

import (
	"context"
	"os"
	"strings"

	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"gopkg.in/yaml.v3"
)

// GenerateSubfinderProviderConfig 生成 subfinder 的 provider-config.yaml 模板，
// 列出所有需要 API key 的数据源（key 留空），供用户自行填写。
func GenerateSubfinderProviderConfig(path string) error {
	sources := make(map[string][]string)
	for _, source := range passive.AllSources {
		keyReq := source.KeyRequirement()
		if keyReq == subscraping.RequiredKey || keyReq == subscraping.OptionalKey {
			sources[strings.ToLower(source.Name())] = []string{}
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return yaml.NewEncoder(f).Encode(sources)
}

// enumerateWithSubfinder 用 subfinder 被动收集子域名（多公开数据源）。
// providerConfig 为 subfinder 的 provider-config.yaml 路径，空则用默认位置。
// proxyURL 非空时被动收集出站请求走 HTTP 代理（空串=直连）。
func enumerateWithSubfinder(ctx context.Context, domain string, providerConfig, proxyURL string) ([]string, error) {
	options := &runner.Options{
		Silent:         true,
		Timeout:        30,
		Threads:        10,
		ProviderConfig: providerConfig,
		Proxy:          proxyURL,
	}
	r, err := runner.NewRunner(options)
	if err != nil {
		return nil, err
	}

	results, err := r.EnumerateSingleDomainWithCtx(ctx, domain, nil)
	if err != nil {
		return nil, err
	}

	out := make([]string, 0, len(results))
	for sub := range results {
		out = append(out, sub)
	}
	return out, nil
}
