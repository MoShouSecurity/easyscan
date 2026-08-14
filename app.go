package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"easyscan/core"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App 是暴露给前端的后端桥接层，封装核心引擎的启动、任务提交与资产查询。
type App struct {
	ctx        context.Context
	store      *core.Store
	sched      *core.Scheduler
	configDir  string
	configPath string
	config     core.Config
	forceClose bool
}

// NewApp 构造 App（尚未初始化 store，等待 OnStartup）。
func NewApp() *App { return &App{} }

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		dir = "."
	}
	dir = filepath.Join(dir, "EasyScan")
	a.configDir = dir
	_ = os.MkdirAll(dir, 0o755)
	dbPath := filepath.Join(dir, "easyscan.db")

	// 加载配置（不存在则写入默认配置）。
	a.configPath = filepath.Join(dir, "config.yaml")
	cfg, err := core.LoadConfig(a.configPath)
	if err != nil {
		println("load config:", err.Error())
		cfg = core.DefaultConfig()
	}
	if _, statErr := os.Stat(a.configPath); os.IsNotExist(statErr) {
		_ = cfg.Save(a.configPath)
	}
	a.config = cfg

	store, err := core.OpenStore(dbPath)
	if err != nil {
		println("open store:", err.Error())
		return
	}
	a.store = store
	a.sched = core.NewScheduler(store, a.config.ToOptions(), 2)
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
	if a.forceClose {
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
	a.forceClose = true
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
	Screenshot bool   `json:"screenshot"`
}

// StartScan 提交侦察任务，立即返回任务 ID（异步执行）。
func (a *App) StartScan(req ScanRequest) (string, error) {
	if a.sched == nil {
		return "", fmt.Errorf("调度器未初始化")
	}
	opts := a.config.ToOptions()
	if req.PortMode != "" {
		opts.PortMode = req.PortMode
	}
	opts.PortSpec = req.PortSpec
	if opts.PortMode == "custom" {
		if _, err := core.ParsePortSpec(req.PortSpec); err != nil {
			return "", fmt.Errorf("自定义端口无效: %w", err)
		}
	}
	opts.SubdomainBrute = req.Brute
	opts.NoPing = req.NoPing
	opts.Nuclei = req.Nuclei
	opts.FileLeak = req.FileLeak
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

	task, err := a.sched.Submit(req.Target, typ, opts)
	if err != nil {
		return "", err
	}
	return task.ID, nil
}

// ---- 任务 ----

func (a *App) ListTasks() ([]core.Task, error) {
	if a.store == nil {
		return nil, nil
	}
	return a.store.ListTasks(200)
}

func (a *App) GetTask(id string) (core.Task, error) {
	if a.store == nil {
		return core.Task{}, nil
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
	opts := a.config.ToOptions()
	if t.Params != "" {
		_ = json.Unmarshal([]byte(t.Params), &opts)
	}
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
	t, err := a.store.GetTask(id)
	if err != nil {
		return err
	}
	t.Status = core.TaskPaused
	t.Message = "已暂停"
	return a.store.UpdateTask(t)
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
	t.Status = core.TaskPending
	t.Message = "恢复中"
	if err := a.store.UpdateTask(t); err != nil {
		return err
	}
	a.sched.Resume(t)
	return nil
}

// ---- 资产全局查询 ----

func (a *App) ListDomains() ([]core.Domain, error) {
	if a.store == nil {
		return nil, nil
	}
	return a.store.ListDomains(0)
}

func (a *App) ListSubdomains(domain string) ([]core.Subdomain, error) {
	if a.store == nil {
		return nil, nil
	}
	return a.store.ListSubdomains(domain, 0)
}

func (a *App) ListPorts() ([]core.Port, error) {
	if a.store == nil {
		return nil, nil
	}
	return a.store.ListPorts(0)
}

func (a *App) ListSites() ([]core.Site, error) {
	if a.store == nil {
		return nil, nil
	}
	return a.store.ListSites(0)
}

// ---- 任务详情查询 ----

func (a *App) ListPortsByTask(taskID string) ([]core.Port, error) {
	if a.store == nil {
		return nil, nil
	}
	return a.store.ListPortsByTask(taskID, 0)
}

func (a *App) ListSitesByTask(taskID string) ([]core.Site, error) {
	if a.store == nil {
		return nil, nil
	}
	return a.store.ListSitesByTask(taskID, 0)
}

func (a *App) ListLeaksByTask(taskID string) ([]core.Leak, error) {
	if a.store == nil {
		return nil, nil
	}
	return a.store.ListLeaksByTask(taskID, 0)
}

func (a *App) ListSubdomainsByTask(taskID string) ([]core.Subdomain, error) {
	if a.store == nil {
		return nil, nil
	}
	return a.store.ListSubdomainsByTask(taskID, 0)
}

// ListIPsByTask 返回任务发现的存活 IP（含无开放端口的）。
func (a *App) ListIPsByTask(taskID string) ([]core.IP, error) {
	if a.store == nil {
		return nil, nil
	}
	return a.store.ListIPsByTask(taskID, 0)
}

// ---- 搜索 ----

func (a *App) Search(query string) ([]core.SearchResult, error) {
	if a.store == nil {
		return nil, nil
	}
	return a.store.Search(query, 0)
}

// ---- 配置 ----

// GetConfig 返回当前全局配置。
func (a *App) GetConfig() (core.Config, error) {
	return a.config, nil
}

// SaveConfig 保存配置到配置文件。
func (a *App) SaveConfig(cfg core.Config) error {
	if err := cfg.Save(a.configPath); err != nil {
		return err
	}
	a.config = cfg
	return nil
}

// ConfigPath 返回配置文件完整路径（供前端展示/用户手动编辑）。
func (a *App) ConfigPath() string {
	return a.configPath
}

// DownloadNucleiTemplates 下载官方 nuclei 模板库并更新配置中的模板目录。
func (a *App) DownloadNucleiTemplates() (string, error) {
	dest := filepath.Join(a.configDir, "nuclei-templates")
	if err := core.DownloadNucleiTemplates(dest, a.config.Nuclei.TemplatesRepo); err != nil {
		return "", err
	}
	a.config.Nuclei.TemplatesDir = dest
	_ = a.config.Save(a.configPath)
	return dest, nil
}

// OpenSubfinderProviderConfig 生成（如不存在）并用系统默认编辑器打开 subfinder provider-config 文件。
func (a *App) OpenSubfinderProviderConfig() (string, error) {
	path := a.config.Subfinder.ProviderConfig
	if path == "" {
		path = filepath.Join(a.configDir, "provider-config.yaml")
		a.config.Subfinder.ProviderConfig = path
		_ = a.config.Save(a.configPath)
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
		cmd = exec.Command("cmd", "/c", "start", "", path)
		core.HideCmdWindow(cmd) // 只隐藏 cmd 窗口本身，start 打开的目标程序正常显示
	default:
		cmd = exec.Command("xdg-open", path)
	}
	return cmd.Start()
}

// ---- 截图 ----

// GetScreenshot 读取截图文件并返回 base64（供前端 data URL 展示）。
func (a *App) GetScreenshot(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// ---- 导出 ----

// ExportTask 将任务资产导出为 CSV 文件，返回文件路径。
func (a *App) ExportTask(taskID string) (string, error) {
	if a.store == nil {
		return "", fmt.Errorf("存储未初始化")
	}
	subs, _ := a.store.ListSubdomainsByTask(taskID, 0)
	ports, _ := a.store.ListPortsByTask(taskID, 0)
	sites, _ := a.store.ListSitesByTask(taskID, 0)
	leaks, _ := a.store.ListLeaksByTask(taskID, 0)

	var buf bytes.Buffer
	buf.WriteString("\uFEFF") // BOM，保证 Excel 正确识别中文
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"类型", "值1", "值2", "值3"})
	for _, s := range subs {
		_ = w.Write([]string{"子域名", s.Subdomain, s.IP, s.Source})
	}
	for _, p := range ports {
		_ = w.Write([]string{"端口", p.IP, fmt.Sprintf("%d", p.Port), p.Service})
	}
	for _, s := range sites {
		_ = w.Write([]string{"站点", s.URL, s.Title, s.Fingerprint})
	}
	for _, l := range leaks {
		_ = w.Write([]string{"敏感信息", l.URL, l.Type, l.Path})
	}
	w.Flush()

	dir := filepath.Join(a.configDir, "exports")
	_ = os.MkdirAll(dir, 0o755)
	path := filepath.Join(dir, "task_"+taskID+".csv")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return "", err
	}
	return path, nil
}
