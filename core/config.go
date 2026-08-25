package core

import (
	"fmt"
	"net/url"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	MaxScanConcurrency = 2000
	MaxScanTimeoutSec  = 300
	PathScanModeQuick  = "quick"
	PathScanModeDeep   = "deep"
)

// ScanOptions 描述一次侦察任务的策略参数。
type ScanOptions struct {
	// PortMode 端口扫描模式：test / top100 / top1000 / all / custom。
	PortMode string `json:"port_mode"`
	// PortSpec 自定义端口规范（范围语法，如 1-1000,8080），仅 PortMode=custom 时生效。
	PortSpec string `json:"port_spec"`
	// NoPing 目标禁 ping 时勾选，跳过存活确认直接用 nmap -Pn 扫描所有 IP。
	NoPing bool `json:"no_ping"`
	// SubdomainBrute 是否开启子域名字典爆破（ksubdomain 无状态爆破）。
	SubdomainBrute bool `json:"subdomain_brute"`
	// Nuclei 是否执行 POC 检测。
	Nuclei bool `json:"nuclei"`
	// FileLeak 是否执行敏感文件/信息泄漏检测。
	FileLeak bool `json:"file_leak"`
	// DirectoryScan 是否执行 Web 路径发现。字段名为兼容旧版保留。
	DirectoryScan bool `json:"directory_scan"`
	// PathScanMode 路径扫描强度：quick 每类约 3 万条，deep 使用完整内置字典。
	PathScanMode string `json:"path_scan_mode"`
	// Screenshot 是否对站点首页截图。
	Screenshot bool `json:"screenshot"`
	// ScreenshotDir 截图保存目录。
	ScreenshotDir string `json:"screenshot_dir"`
	// ChromePath 截图用 Chrome 可执行文件路径（空则自动探测）。
	ChromePath string `json:"chrome_path"`
	// NmapPath nmap 可执行文件路径（空则自动探测）。
	NmapPath string `json:"nmap_path"`
	// MasscanPath masscan 可执行文件路径（空则自动探测）。
	MasscanPath string `json:"masscan_path"`
	// LeakDictPath 文件泄漏自定义字典文件（空则用内置字典）。
	LeakDictPath string `json:"leak_dict_path"`
	// DirectoryDictPath 路径发现自定义字典文件（空则用内置字典）。
	DirectoryDictPath string `json:"directory_dict_path"`
	// NucleiTemplatesDir 自定义 nuclei 模板目录（空则用内置模板）。
	NucleiTemplatesDir string `json:"nuclei_templates_dir"`
	// ProviderConfigPath subfinder 的 provider-config.yaml 路径（空则用默认位置）。
	ProviderConfigPath string `json:"provider_config_path"`
	// FofaKey FOFA API key（空则跳过 FOFA 子域名收集）。
	FofaKey string `json:"fofa_key,omitempty"`
	// ProxyURL 出站 HTTP 代理（FOFA / subfinder 被动收集使用），如 http://127.0.0.1:7890。
	ProxyURL string `json:"proxy_url,omitempty"`
	// Concurrency 并发度（0 表示使用默认值）。
	Concurrency int `json:"concurrency"`
	// Timeout 单次网络探测超时（0 表示默认值），序列化为纳秒以便任务参数往返。
	Timeout time.Duration `json:"timeout_ns"`
}

// DefaultScanOptions 返回默认任务策略。
func DefaultScanOptions() ScanOptions {
	return ScanOptions{
		PortMode:       "top100",
		SubdomainBrute: true,
		Nuclei:         false,
		FileLeak:       false,
		PathScanMode:   PathScanModeQuick,
		Screenshot:     true,
		Concurrency:    100,
		Timeout:        5 * time.Second,
	}
}

// ValidatePathScanMode 校验路径扫描强度。空值仅用于兼容旧任务，由执行层按 quick 处理。
func ValidatePathScanMode(mode string) error {
	switch mode {
	case PathScanModeQuick, PathScanModeDeep:
		return nil
	default:
		return fmt.Errorf("路径扫描强度仅支持 %q 或 %q", PathScanModeQuick, PathScanModeDeep)
	}
}

func normalizePathScanMode(mode string) string {
	if mode == "" {
		return PathScanModeQuick
	}
	return mode
}

// Config 全局配置文件结构（config.yaml）。
type Config struct {
	Scan       ScanConfig        `yaml:"scan" json:"scan"`
	FileLeak   FileLeakConfig    `yaml:"file_leak" json:"file_leak"`
	Directory  DirectoryConfig   `yaml:"directory" json:"directory"`
	Nuclei     NucleiConfig      `yaml:"nuclei" json:"nuclei"`
	Subfinder  SubfinderConfig   `yaml:"subfinder" json:"subfinder"`
	Fofa       FofaConfig        `yaml:"fofa" json:"fofa"`
	Screenshot ScreenshotConfig  `yaml:"screenshot" json:"screenshot"`
	Proxy      ProxyConfig       `yaml:"proxy" json:"proxy"`
	APIKeys    map[string]string `yaml:"api_keys" json:"api_keys"`
}

// ScanConfig 扫描通用参数。
type ScanConfig struct {
	Concurrency        int    `yaml:"concurrency" json:"concurrency"`
	TimeoutSec         int    `yaml:"timeout_sec" json:"timeout_sec"`
	DefaultPortMode    string `yaml:"default_port_mode" json:"default_port_mode"`
	DefaultPortSpec    string `yaml:"default_port_spec" json:"default_port_spec"`     // 默认自定义端口，仅模式为 custom 时生效
	NmapPath           string `yaml:"nmap_path" json:"nmap_path"`                     // nmap 路径，空则自动探测
	MasscanPath        string `yaml:"masscan_path" json:"masscan_path"`               // masscan 路径，空则自动探测
	MaxConcurrentTasks int    `yaml:"max_concurrent_tasks" json:"max_concurrent_tasks"` // 最大并发任务数，0 用默认 4（1-16）
}

// FileLeakConfig 文件泄漏检测配置。
type FileLeakConfig struct {
	DictPath string `yaml:"dict_path" json:"dict_path"` // 自定义字典文件，空则用内置
}

// DirectoryConfig 路径发现配置。名称为兼容已有配置文件保留。
type DirectoryConfig struct {
	DictPath string `yaml:"dict_path" json:"dict_path"` // 一行一个站内路径，空则用内置字典
}

// NucleiConfig nuclei POC 检测配置。
type NucleiConfig struct {
	TemplatesDir  string `yaml:"templates_dir" json:"templates_dir"`   // 自定义模板目录
	AutoDownload  bool   `yaml:"auto_download" json:"auto_download"`   // 是否自动下载官方模板库
	TemplatesRepo string `yaml:"templates_repo" json:"templates_repo"` // 官方模板库 git 地址
}

// SubfinderConfig subfinder 被动子域名收集配置。
type SubfinderConfig struct {
	ProviderConfig string `yaml:"provider_config" json:"provider_config"` // provider-config.yaml 路径，空则用默认
}

// FofaConfig FOFA 资产搜索引擎配置（https://fofa.info/api）。
type FofaConfig struct {
	APIKey string `yaml:"api_key" json:"api_key"` // FOFA API key，空则不启用 FOFA 收集
}

// ScreenshotConfig 截图配置。
type ScreenshotConfig struct {
	ChromePath string `yaml:"chrome_path" json:"chrome_path"` // 自定义 Chrome 路径
}

// ProxyConfig 代理配置。
type ProxyConfig struct {
	HTTPURL string `yaml:"http_url" json:"http_url"`
}

// DefaultConfig 返回默认全局配置。
func DefaultConfig() Config {
	return Config{
		Scan: ScanConfig{
			Concurrency:        100,
			TimeoutSec:         5,
			DefaultPortMode:    "top1000",
			MaxConcurrentTasks: 4,
		},
		Nuclei: NucleiConfig{
			TemplatesRepo: "https://github.com/projectdiscovery/nuclei-templates.git",
		},
		APIKeys: map[string]string{},
	}
}

// LoadConfig 从 YAML 文件加载配置；文件不存在时返回默认配置。
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("读取配置: %w", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("解析配置: %w", err)
	}
	if cfg.Nuclei.TemplatesRepo == "" {
		cfg.Nuclei.TemplatesRepo = DefaultConfig().Nuclei.TemplatesRepo
	}
	if err := cfg.Validate(); err != nil {
		return DefaultConfig(), fmt.Errorf("校验配置: %w", err)
	}
	return cfg, nil
}

// Save 将配置写入 YAML 文件。
func (c Config) Save(path string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	data, err := yaml.Marshal(&c)
	if err != nil {
		return err
	}
	// 0o600：配置文件含 FOFA key 等敏感信息，仅本人可读写。
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	// os.WriteFile 的 mode 不会收紧已存在文件的权限，需显式 chmod。
	return os.Chmod(path, 0o600)
}

// Validate 校验来自配置文件和前端桥接的参数，防止异常并发/超时造成资源耗尽。
func (c Config) Validate() error {
	if c.Scan.Concurrency < 1 || c.Scan.Concurrency > MaxScanConcurrency {
		return fmt.Errorf("并发度需在 1-%d 之间", MaxScanConcurrency)
	}
	if c.Scan.MaxConcurrentTasks < 1 || c.Scan.MaxConcurrentTasks > 16 {
		return fmt.Errorf("最大并发任务数需在 1-16 之间")
	}
	if c.Scan.TimeoutSec < 1 || c.Scan.TimeoutSec > MaxScanTimeoutSec {
		return fmt.Errorf("超时需在 1-%d 秒之间", MaxScanTimeoutSec)
	}
	if err := ValidatePortMode(c.Scan.DefaultPortMode); err != nil {
		return err
	}
	if c.Scan.DefaultPortMode == "custom" {
		if _, err := ParsePortSpec(c.Scan.DefaultPortSpec); err != nil {
			return fmt.Errorf("默认自定义端口无效: %w", err)
		}
	}
	if c.Proxy.HTTPURL != "" {
		u, err := url.Parse(c.Proxy.HTTPURL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("HTTP 代理地址无效: %q", c.Proxy.HTTPURL)
		}
	}
	return nil
}

// ToOptions 将全局配置的默认参数合入任务策略。
func (c Config) ToOptions() ScanOptions {
	opts := DefaultScanOptions()
	if c.Scan.Concurrency > 0 {
		opts.Concurrency = c.Scan.Concurrency
	}
	if c.Scan.TimeoutSec > 0 {
		opts.Timeout = time.Duration(c.Scan.TimeoutSec) * time.Second
	}
	if c.Scan.DefaultPortMode != "" {
		opts.PortMode = c.Scan.DefaultPortMode
	}
	opts.PortSpec = c.Scan.DefaultPortSpec
	opts.LeakDictPath = c.FileLeak.DictPath
	opts.DirectoryDictPath = c.Directory.DictPath
	opts.NucleiTemplatesDir = c.Nuclei.TemplatesDir
	opts.ProviderConfigPath = c.Subfinder.ProviderConfig
	opts.FofaKey = c.Fofa.APIKey
	opts.ProxyURL = c.Proxy.HTTPURL
	opts.ChromePath = c.Screenshot.ChromePath
	opts.NmapPath = c.Scan.NmapPath
	opts.MasscanPath = c.Scan.MasscanPath
	return opts
}
