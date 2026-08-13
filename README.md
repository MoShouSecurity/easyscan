# Easy Scan

> ⚠️ **快速开发期**：本项目目前处于快速迭代阶段，功能与界面可能频繁变动，API 尚不稳定。请勿在生产环境直接使用，升级前注意备份数据与配置。

> 输入一个域名或 IP 段，自动完成「子域名枚举 → DNS 解析 → 端口扫描 → 服务识别 → Web 指纹 → 截图 → 漏洞检测」，构建可检索的资产库。

Easy Scan 是一款**跨平台桌面资产侦察工具**——单二进制 + SQLite 内嵌 + 原生 WebView 前端，部署零依赖、开箱即用。

---

## 功能特性

### 资产发现
- **子域名枚举**：三层引擎
  - `subfinder` 被动收集（多公开数据源，证书透明度 / 搜索引擎等）
  - `ksubdomain` 无状态主动爆破（10 万字典，最高 160 万包/秒）
  - 纯 Go 字典爆破（无权限 / Windows 时的兜底）
- **DNS 解析**：并发解析 A 记录，IPv4 / IPv6
- **端口扫描**：纯 Go TCP 扫描（goroutine 池），`test / top100 / top1000 / all` 四档
- **服务识别**：banner 抓取 + 常见服务指纹

### 资产识别
- **Web 指纹**：标题 / Server 头 / X-Powered-By / 20+ CMS 与中间件特征（WordPress、ThinkPHP、Tomcat、Shiro、Swagger、宝塔、若依 等），正确处理虚拟主机（Host 头 + SNI）
- **站点截图**：chromedp 无头浏览器，启动前自动检查 macOS 屏幕录制权限

### 漏洞检测
- **文件泄漏检测**：30+ 内置敏感路径（.git/.svn/.env/备份文件/phpinfo/actuator），支持自定义字典文件
- **nuclei POC 检测**：内置检测模板 + 支持官方 nuclei YAML 模板目录 + 一键下载官方模板库

### 桌面端 UI
- 任务首页（进度条、搜索、添加任务对话框、删除任务）
- 任务详情页（网站截图卡片 / IP 存活 / 端口 / 敏感信息泄露 四个标签页）
- 跨资产模糊搜索（域名 / IP / 标题 / URL / 指纹 / 泄露路径）
- CSV 导出、全局配置管理

---

## 技术栈

| 层 | 技术 |
|----|------|
| 语言 | Go 1.26 |
| 桌面框架 | [Wails v2](https://github.com/wailsapp/wails)（原生 WebView） |
| 存储 | SQLite（[modernc.org/sqlite](https://gitlab.com/cznic/sqlite) 纯 Go 驱动，免 CGO） |
| 前端 | 原生 HTML/CSS/JS（零 npm 构建，中国传统水墨配色） |
| 子域名被动 | [subfinder](https://github.com/projectdiscovery/subfinder) |
| 子域名主动 | [ksubdomain](https://github.com/boy-hack/ksubdomain) |
| 截图 | [chromedp](https://github.com/chromedp/chromedp) |

---

## 架构

```
main.go            桌面应用入口（含 --ksubdomain-enum helper 模式）
app.go             Wails 绑定层（暴露给前端的 API）
frontend/dist/     桌面 UI（静态 HTML/JS，中国风配色）

core/              纯 Go 引擎（GUI 无关，可独立运行 + 单测）
  model.go         领域模型（Domain/Subdomain/Port/Site/Leak/Task）
  store.go         SQLite 存储（WAL + upsert 去重 + 跨表搜索）
  config.go        任务策略 + 全局配置（config.yaml）
  subdomain.go     子域名枚举编排（subfinder + ksubdomain + 纯 Go 兜底）
  subfinder.go     subfinder 被动收集
  ksubdomain.go    ksubdomain 无状态爆破（macOS/Linux）
  privilege.go     提权机制（sudo 缓存 / osascript / pkexec）
  dns.go           并发 DNS 解析
  portscan.go      纯 Go TCP 扫描 + banner 服务识别
  fingerprint.go   Web 指纹（Host/SNI + 标题 + CMS 规则）
  screenshot.go    chromedp 截图 + macOS 屏幕权限检查
  leak.go          文件泄漏检测（内置 + 自定义字典）
  nuclei.go        nuclei POC（内置 + YAML 模板 + 官方库下载）
  pipeline.go      编排完整侦察闭环
  scheduler.go     进程内任务调度

cmd/easyscan/      CLI 入口（引擎独立运行与验证用）
```

---

## 快速开始

### 桌面版（macOS / Windows / Linux）

```bash
# 安装 Wails CLI
go install github.com/wailsapp/wails/v2/cmd/wails@latest

# 构建
wails build                                # 当前平台
wails build -platform windows/arm64        # 交叉编译 Windows ARM
wails build -platform windows/amd64        # 交叉编译 Windows x64

# 产物
#   macOS:   build/bin/easyscan.app
#   Windows: build/bin/easyscan.exe（x64）/ easyscan-arm64.exe（ARM）
```

> **Windows 依赖**：首次运行需安装 [WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/)（Windows 11 通常已预装）。

### 命令行版（验证引擎用）

```bash
go run ./cmd/easyscan -target example.com -ports top100
# 参数: -type domain|ip  -ports test|top100|top1000|all
#       -no-brute 关闭子域名爆破  -no-shot 关闭截图
#       -db 指定数据库路径  -shot-dir 截图目录
```

### 测试

```bash
go test ./...
```

---

## 配置文件

首次启动自动生成于各平台配置目录（macOS：`~/Library/Application Support/EasyScan/config.yaml`），也可在桌面端「配置」按钮里编辑：

```yaml
scan:
  concurrency: 100          # 扫描并发度
  timeout_sec: 5            # 单次探测超时（秒）
  default_port_mode: top1000

file_leak:
  dict_path: ""             # 文件泄漏自定义字典，空则用内置 30+ 路径

nuclei:
  templates_dir: ""         # 自定义 nuclei 模板目录（.yaml），空则用内置
  auto_download: false      # 是否自动下载官方模板库
  templates_repo: https://github.com/projectdiscovery/nuclei-templates.git

subfinder:
  provider_config: ""       # subfinder 的 provider-config.yaml（填 API key）

screenshot:
  chrome_path: ""           # 自定义 Chrome 路径，空则自动探测

proxy:
  http_url: ""              # HTTP 代理，如 http://127.0.0.1:7890

api_keys: {}                # 第三方数据源 Token
```

**文件泄漏字典格式**（每行 `路径 [类型]`，`#` 为注释，类型可省略自动推断）：
```
# 自定义泄漏字典
/.git/config git
/.env
/backup.zip backup
```

---

## 任务策略

| 模块 | 说明 |
|------|------|
| 子域名 | subfinder 被动 + ksubdomain 主动（需提权）+ 纯 Go 兜底 |
| 端口 | `test`（6）/ `top100` / `top1000` / `all`（1-65535） |
| 指纹 | 标题 / Server / 20+ CMS 与中间件特征 |
| 截图 | chromedp 无头浏览器（默认开启） |
| 泄漏 | 30+ 敏感路径 + 自定义字典 |
| POC | 内置模板 + 官方 nuclei YAML 模板 |

**提权说明**：ksubdomain 无状态爆破需要 root 权限（原始 socket）。桌面端会自动弹系统授权框（macOS 管理员授权 / Linux PolicyKit），授权后利用 sudo timestamp 缓存，**短时间内重复扫描不重复弹框**（默认 5 分钟，可在 sudoers 的 `timestamp_timeout` 调整）。用户取消授权则自动降级为纯 Go 字典爆破，不影响扫描。

---

## 致谢

本项目站在巨人的肩膀上，感谢以下开源项目：

- **[Wails](https://github.com/wailsapp/wails)** — 让 Go 开发者用 Web 技术构建跨平台桌面应用
- **[ksubdomain](https://github.com/boy-hack/ksubdomain)** — 高性能无状态子域名爆破引擎（boy-hack 大佬）
- **[subfinder](https://github.com/projectdiscovery/subfinder)** — 被动子域名收集器（ProjectDiscovery）
- **[chromedp](https://github.com/chromedp/chromedp)** — Go 的 Chrome DevTools 协议驱动，站点截图
- **[modernc.org/sqlite](https://gitlab.com/cznic/sqlite)** — 纯 Go SQLite 实现，免 CGO 交叉编译

以及所有间接依赖的贡献者。

---

## 免责声明

本工具仅用于**授权**的资产侦察与攻击面管理（甲方安全团队、渗透测试、SRC 报备目标、自有资产盘点）。未经授权扫描他人资产可能违法，使用者需自行承担相应责任。
