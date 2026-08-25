package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"easyscan/core"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// hexIDRegexp 任务/资产 ID 格式：32 位小写 hex（core.newID 生成）。
// 用于外部输入 ID 的白名单校验（防路径穿越等）。
var hexIDRegexp = regexp.MustCompile(`^[0-9a-f]{32}$`)

// App 是暴露给前端的后端桥接层，封装核心引擎的启动、任务提交与资产查询。
type App struct {
	ctx        context.Context
	store      *core.Store
	sched      *core.Scheduler
	configDir  string
	configPath string
	configMu   sync.RWMutex
	config     core.Config
	forceClose atomic.Bool
}

// NewApp 构造 App（尚未初始化 store，等待 OnStartup）。
func NewApp() *App { return &App{} }

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		if err != nil {
			println("resolve config dir:", err.Error())
		} else {
			println("resolve config dir: empty path")
		}
		return
	}
	dir = filepath.Join(dir, "EasyScan")
	a.configDir = dir
	if err := os.MkdirAll(dir, 0o700); err != nil {
		println("create config dir:", err.Error())
		return
	}
	core.SetCrashLogDir(dir)
	dbPath := filepath.Join(dir, "easyscan.db")

	// 加载配置（不存在则写入默认配置）。
	a.configPath = filepath.Join(dir, "config.yaml")
	cfg, err := core.LoadConfig(a.configPath)
	if err != nil {
		println("load config:", err.Error())
		cfg = core.DefaultConfig()
	}
	if _, statErr := os.Stat(a.configPath); os.IsNotExist(statErr) {
		if err := cfg.Save(a.configPath); err != nil {
			println("save default config:", err.Error())
			return
		}
	}
	a.configMu.Lock()
	a.config = cfg
	a.configMu.Unlock()

	store, err := core.OpenStore(dbPath)
	if err != nil {
		println("open store:", err.Error())
		return
	}
	a.store = store
	// 上次异常退出遗留的任务标记为 paused（可恢复），防永久 running。
	if err := store.MarkInterruptedTasks(); err != nil {
		println("mark interrupted tasks:", err.Error())
	}
	a.sched = core.NewScheduler(store, cfg.ToOptions())
	a.sched.Start(2)
}

func (a *App) shutdown(_ context.Context) {
	if a.sched != nil {
		a.sched.Stop()
	}
	if a.store != nil {
		_ = a.store.Close()
	}
}

// beforeClose 窗口关闭前回调：有运行中任务时阻止关闭并提醒前端。
func (a *App) beforeClose(ctx context.Context) bool {
	if a.forceClose.Load() {
		return false
	}
	if a.hasRunningTasks() {
		wruntime.EventsEmit(ctx, "close:confirm")
		return true // 阻止关闭
	}
	return false
}

func (a *App) hasRunningTasks() bool {
	if a.store == nil {
		return false
	}
	tasks, err := a.store.ListTasks(200)
	if err != nil {
		return false
	}
	for _, t := range tasks {
		if t.Status == core.TaskRunning || t.Status == core.TaskPending {
			return true
		}
	}
	return false
}

// ForceClose 用户确认关闭后调用，标记允许退出。
func (a *App) ForceClose() {
	a.forceClose.Store(true)
}

// ScanRequest 新建任务的请求参数。
type ScanRequest struct {
	Target     string `json:"target"`
	Type       string `json:"type"`      // domain / ip
	PortMode   string `json:"port_mode"` // test / top100 / top1000 / all / custom
	PortSpec   string `json:"port_spec"` // 自定义端口（范围语法），仅 custom 模式生效
	Brute      bool   `json:"brute"`
	NoPing     bool   `json:"no_ping"`
	Nuclei     bool   `json:"nuclei"`
	FileLeak   bool   `json:"file_leak"`
	Directory  bool   `json:"directory_scan"`
	PathMode   string `json:"path_scan_mode"`
	Screenshot bool   `json:"screenshot"`
}

// StartScan 提交侦察任务，立即返回任务 ID（异步执行）。
func (a *App) StartScan(req ScanRequest) (string, error) {
	if a.sched == nil {
		return "", fmt.Errorf("调度器未初始化")
	}
	opts := a.currentConfig().ToOptions()
	if req.PortMode != "" {
		opts.PortMode = req.PortMode
	}
	if err := core.ValidatePortMode(opts.PortMode); err != nil {
		return "", err
	}
	// 仅非空时覆盖：保留配置里的 DefaultPortSpec 默认值。
	if req.PortSpec != "" {
		opts.PortSpec = req.PortSpec
	}
	if opts.PortMode == "custom" {
		if _, err := core.ParsePortSpec(opts.PortSpec); err != nil {
			return "", fmt.Errorf("自定义端口无效: %w", err)
		}
	}
	opts.SubdomainBrute = req.Brute
	opts.NoPing = req.NoPing
	opts.Nuclei = req.Nuclei
	opts.FileLeak = req.FileLeak
	opts.DirectoryScan = req.Directory
	opts.PathScanMode = req.PathMode
	if opts.PathScanMode == "" {
		opts.PathScanMode = core.PathScanModeQuick
	}
	if err := core.ValidatePathScanMode(opts.PathScanMode); err != nil {
		return "", err
	}
	opts.Screenshot = req.Screenshot
	if req.Screenshot {
		opts.ScreenshotDir = filepath.Join(a.configDir, "screenshots")
	}

	typ := core.TaskDomain
	switch req.Type {
	case "ip":
		typ = core.TaskIP
	case "domain":
		typ = core.TaskDomain
	default:
		// 未指定或为空时自动判断。
		if core.IsIPTarget(req.Target) {
			typ = core.TaskIP
		}
	}

	// 域名目标强制白名单校验：会进入提权子进程（sudo/osascript 等），
	// 未经校验的用户输入存在命令注入风险（S-01），入口层拦截。
	if typ == core.TaskDomain {
		clean := strings.TrimSpace(strings.ToLower(req.Target))
		clean = strings.TrimPrefix(clean, "http://")
		clean = strings.TrimPrefix(clean, "https://")
		clean = strings.TrimSuffix(clean, "/")
		if err := core.ValidateDomain(clean); err != nil {
			return "", fmt.Errorf("目标域名非法: %w", err)
		}
	} else if !core.IsIPTarget(req.Target) {
		return "", fmt.Errorf("目标 IP 或网段非法")
	}

	task, err := a.sched.Submit(req.Target, typ, opts)
	if err != nil {
		return "", err
	}
	return task.ID, nil
}

// ---- 任务 ----

func (a *App) ListTasks() ([]core.Task, error) {
	if a.store == nil {
		return nil, fmt.Errorf("存储未初始化")
	}
	// 每页最多 50 条（UI 表格容器带垂直滚动条查看）
	return a.store.ListTasks(50)
}

func (a *App) GetTask(id string) (core.Task, error) {
	if a.store == nil {
		return core.Task{}, fmt.Errorf("存储未初始化")
	}
	t, err := a.store.GetTask(id)
	if err != nil {
		return core.Task{}, err
	}
	return *t, nil
}

// DeleteTask 删除任务及其专属资产。
func (a *App) DeleteTask(id string) error {
	if a.store == nil {
		return fmt.Errorf("存储未初始化")
	}
	if a.sched != nil && a.sched.IsTaskActive(id) {
		return fmt.Errorf("任务仍在运行或停止中，请先暂停并稍后重试")
	}
	if _, err := a.store.GetTask(id); err != nil {
		return fmt.Errorf("任务不存在: %w", err)
	}
	return a.store.DeleteTask(id)
}

// RescanTask 用旧任务的参数重新提交一个扫描任务，返回新任务 ID。
func (a *App) RescanTask(id string) (string, error) {
	if a.sched == nil {
		return "", fmt.Errorf("调度器未初始化")
	}
	t, err := a.store.GetTask(id)
	if err != nil {
		return "", err
	}
	cfg := a.currentConfig()
	opts := cfg.ToOptions()
	if t.Params != "" {
		if err := json.Unmarshal([]byte(t.Params), &opts); err != nil {
			return "", fmt.Errorf("旧任务参数损坏: %w", err)
		}
	}
	if opts.PathScanMode == "" {
		opts.PathScanMode = core.PathScanModeQuick
	}
	// 旧任务的 params 快照可能不含最新配置，覆盖为当前值（防旧 key 复活/丢失）。
	opts.FofaKey = cfg.Fofa.APIKey
	opts.ProxyURL = cfg.Proxy.HTTPURL
	task, err := a.sched.Submit(t.Target, t.Type, opts)
	if err != nil {
		return "", err
	}
	return task.ID, nil
}

// PauseTask 中止任务（暂停扫描）。
func (a *App) PauseTask(id string) error {
	if a.sched == nil {
		return fmt.Errorf("调度器未初始化")
	}
	a.sched.CancelTask(id)
	paused, err := a.store.PauseTask(id, "已暂停")
	if err != nil {
		return err
	}
	if !paused {
		t, getErr := a.store.GetTask(id)
		if getErr != nil {
			return getErr
		}
		return fmt.Errorf("任务不可暂停（当前状态: %s）", t.Status)
	}
	return nil
}

// ResumeTask 恢复暂停的任务（复用原参数继续扫描）。
func (a *App) ResumeTask(id string) error {
	if a.sched == nil {
		return fmt.Errorf("调度器未初始化")
	}
	t, err := a.store.GetTask(id)
	if err != nil {
		return err
	}
	return a.sched.Resume(t)
}

// ---- 资产全局查询 ----

func (a *App) ListDomains() ([]core.Domain, error) {
	if a.store == nil {
		return nil, fmt.Errorf("存储未初始化")
	}
	return a.store.ListDomains(0)
}

func (a *App) ListSubdomains(domain string) ([]core.Subdomain, error) {
	if a.store == nil {
		return nil, fmt.Errorf("存储未初始化")
	}
	return a.store.ListSubdomains(domain, 0)
}

func (a *App) ListPorts() ([]core.Port, error) {
	if a.store == nil {
		return nil, fmt.Errorf("存储未初始化")
	}
	return a.store.ListPorts(0)
}

func (a *App) ListSites() ([]core.Site, error) {
	if a.store == nil {
		return nil, fmt.Errorf("存储未初始化")
	}
	return a.store.ListSites(0)
}

// ---- 任务详情查询 ----

func (a *App) ListPortsByTask(taskID string) ([]core.Port, error) {
	if a.store == nil {
		return nil, fmt.Errorf("存储未初始化")
	}
	return a.store.ListPortsByTask(taskID, 50)
}

func (a *App) ListSitesByTask(taskID string) ([]core.Site, error) {
	if a.store == nil {
		return nil, fmt.Errorf("存储未初始化")
	}
	return a.store.ListSitesByTask(taskID, 50)
}

func (a *App) ListLeaksByTask(taskID string) ([]core.Leak, error) {
	if a.store == nil {
		return nil, fmt.Errorf("存储未初始化")
	}
	return a.store.ListLeaksByTask(taskID, 50)
}

func (a *App) ListDirectoriesByTask(taskID string) ([]core.DirectoryResult, error) {
	if a.store == nil {
		return nil, fmt.Errorf("存储未初始化")
	}
	return a.store.ListDirectoriesByTask(taskID, 50)
}

func (a *App) ListSubdomainsByTask(taskID string) ([]core.Subdomain, error) {
	if a.store == nil {
		return nil, fmt.Errorf("存储未初始化")
	}
	return a.store.ListSubdomainsByTask(taskID, 50)
}

// ListIPsByTask 返回任务发现的存活 IP（含无开放端口的）。
func (a *App) ListIPsByTask(taskID string) ([]core.IP, error) {
	if a.store == nil {
		return nil, fmt.Errorf("存储未初始化")
	}
	return a.store.ListIPsByTask(taskID, 50)
}

// ---- 搜索 ----

func (a *App) Search(query string) ([]core.SearchResult, error) {
	if a.store == nil {
		return nil, fmt.Errorf("存储未初始化")
	}
	return a.store.Search(query, 50)
}

// ---- 配置 ----

// GetConfig 返回当前全局配置。
func (a *App) GetConfig() (core.Config, error) {
	return a.currentConfig(), nil
}

func (a *App) currentConfig() core.Config {
	a.configMu.RLock()
	defer a.configMu.RUnlock()
	return a.config
}

// SaveConfig 保存配置到配置文件。
func (a *App) SaveConfig(cfg core.Config) error {
	if err := cfg.Save(a.configPath); err != nil {
		return err
	}
	a.configMu.Lock()
	a.config = cfg
	a.configMu.Unlock()
	if a.sched != nil {
		a.sched.UpdateOptions(cfg.ToOptions())
	}
	return nil
}

// ConfigPath 返回配置文件完整路径（供前端展示/用户手动编辑）。
func (a *App) ConfigPath() string {
	return a.configPath
}

// DownloadNucleiTemplates 下载官方 nuclei 模板库并更新配置中的模板目录。
func (a *App) DownloadNucleiTemplates() (string, error) {
	dest := filepath.Join(a.configDir, "nuclei-templates")
	cfg := a.currentConfig()
	if err := core.DownloadNucleiTemplates(dest, cfg.Nuclei.TemplatesRepo); err != nil {
		return "", err
	}
	cfg.Nuclei.TemplatesDir = dest
	if err := cfg.Save(a.configPath); err != nil {
		return "", fmt.Errorf("模板已下载，但保存配置失败: %w", err)
	}
	a.configMu.Lock()
	a.config = cfg
	a.configMu.Unlock()
	if a.sched != nil {
		a.sched.UpdateOptions(cfg.ToOptions())
	}
	return dest, nil
}

// OpenSubfinderProviderConfig 生成（如不存在）并用系统默认编辑器打开 subfinder provider-config 文件。
func (a *App) OpenSubfinderProviderConfig() (string, error) {
	cfg := a.currentConfig()
	path := cfg.Subfinder.ProviderConfig
	if path == "" {
		path = filepath.Join(a.configDir, "provider-config.yaml")
		cfg.Subfinder.ProviderConfig = path
		if err := cfg.Save(a.configPath); err != nil {
			return "", err
		}
		a.configMu.Lock()
		a.config = cfg
		a.configMu.Unlock()
		if a.sched != nil {
			a.sched.UpdateOptions(cfg.ToOptions())
		}
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := core.GenerateSubfinderProviderConfig(path); err != nil {
			return "", err
		}
	}
	return path, openFile(path)
}

// DetectChromePath 探测本机 Chrome 可执行文件路径。
func (a *App) DetectChromePath() string {
	return core.DetectChromePath()
}

// DetectNmapPath 探测本机 nmap 可执行文件路径。
func (a *App) DetectNmapPath() string {
	return core.DetectNmapPath()
}

// DetectMasscanPath 探测本机 masscan 可执行文件路径。
func (a *App) DetectMasscanPath() string {
	return core.DetectMasscanPath()
}

// openFile 用系统默认程序打开文件。
func openFile(path string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", path)
	case "windows":
		// 不经 cmd /c start，避免配置路径中的 shell 元字符被 cmd.exe 解释。
		cmd = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", path)
		core.HideCmdWindow(cmd)
	default:
		cmd = exec.Command("xdg-open", path)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	// 异步回收进程，避免僵尸进程（open/xdg-open 启动后即分离）。
	go func() { _ = cmd.Wait() }()
	return nil
}

// ---- 截图 ----

// GetScreenshot 读取截图文件并返回 base64（供前端 data URL 展示）。
// 仅允许读取截图目录（configDir/screenshots）子树内的文件，防任意本地文件读取。
func (a *App) GetScreenshot(path string) (string, error) {
	shotDir := filepath.Join(a.configDir, "screenshots")
	if !pathWithin(shotDir, path) {
		return "", fmt.Errorf("非法的截图路径")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// pathWithin 校验 path 位于 dir 子树内（EvalSymlinks 防符号链接逃逸）。
func pathWithin(dir, path string) bool {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	resolvedDir, err := filepath.EvalSymlinks(absDir)
	if err != nil {
		resolvedDir = absDir // 目录不存在时退回绝对路径比较
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	resolvedPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		resolvedPath = absPath
	}
	rel, err := filepath.Rel(resolvedDir, resolvedPath)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}
