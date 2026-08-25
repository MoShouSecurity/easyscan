# Easy Scan

> ⚠️ **快速开发期**：本项目目前处于快速迭代阶段，功能与界面可能频繁变动，API 尚不稳定。请勿在生产环境直接使用，升级前注意备份数据与配置。

> 输入一个域名或 IP 段，自动完成「子域名枚举 → DNS 解析 → 端口扫描 → 服务识别 → Web 指纹 → 截图 → 漏洞检测」，构建可检索的资产库。

Easy Scan 是一款**跨平台桌面资产侦察工具**——单二进制 + SQLite 内嵌 + 原生 WebView 前端，部署零依赖、开箱即用。

---

## 功能特性

### 资产发现
- **子域名枚举**：三层引擎（macOS / Linux / Windows 三端一致）
  - `subfinder` 被动收集（多公开数据源，证书透明度 / 搜索引擎等）
  - `ksubdomain` 无状态主动爆破（10 万字典，最高 160 万包/秒，SDK 集成三端共用）
  - 纯 Go 字典爆破（无权限 / 缺驱动时的兜底）
- **DNS 解析**：并发解析 A 记录，IPv4 / IPv6
- **端口扫描**：存活探测三级降级（masscan 纯 ICMP → nmap 纯 ICMP → 纯 Go TCP）+ nmap 服务/版本识别，端口模式 `test / top100 / top1000 / all / custom` 五档（custom 支持范围语法，如 `1-1000,8080`）
- **服务识别**：nmap -sV 产品/版本（降级为 banner 抓取 + 常见服务指纹）

### 资产识别
- **Web 指纹**：标题 / Server 头 / X-Powered-By / 20+ CMS 与中间件特征（WordPress、ThinkPHP、Tomcat、Shiro、Swagger、宝塔、若依 等），正确处理虚拟主机（Host 头 + SNI）
- **站点截图**：chromedp 无头浏览器，启动前自动检查 macOS 屏幕录制权限

### 漏洞检测
- **文件泄漏检测**：默认快速扫描约 30,000 条敏感路径（高价值条目优先，再从完整字典均匀抽样）；深度模式可使用内置 153,737 条候选（.git/.svn/.env/配置/备份/数据库/密钥），支持自定义类型与响应签名，并通过软 404 基线降低误报
- **路径发现**：默认快速扫描约 30,000 条站内路径（常见入口优先，再从完整字典均匀抽样）；深度模式可使用内置 3,378,432 条路径，按 `directory / route / file` 分类，识别 200/3xx/401/403 并过滤统一错误页
- **nuclei POC 检测**：内置检测模板 + 支持官方 nuclei YAML 模板目录 + 一键下载官方模板库

### 桌面端 UI
- 任务首页（进度条、搜索、添加任务对话框、删除任务）
- 任务详情页（网站截图卡片 / IP 存活 / 端口 / 敏感信息泄露 / 路径发现结果）
- 跨资产模糊搜索（域名 / IP / 标题 / URL / 指纹 / 泄露路径 / 目录路径）
- CSV / JSON / XLSX 多格式导出（支持按子域名、存活 IP、端口、站点、泄漏和目录结果筛选）、全局配置管理

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
  model.go         领域模型（Domain/Subdomain/Port/Site/Leak/DirectoryResult/Task）
  store.go         SQLite 存储（WAL + upsert 去重 + 跨表搜索）
  config.go        任务策略 + 全局配置（config.yaml）
  subdomain.go     子域名枚举编排（subfinder + ksubdomain + 纯 Go 兜底）
  subfinder.go     subfinder 被动收集
  ksubdomain.go    ksubdomain 无状态爆破（三端 SDK 集成）
  privilege.go     提权机制（sudo 缓存 / osascript / pkexec / Windows UAC）
  dns.go           并发 DNS 解析
  masscan.go       masscan 纯 ICMP 存活探测（首选，降级 nmap / 纯 Go TCP）
  portscan.go      纯 Go TCP 扫描 + banner 服务识别
  fingerprint.go   Web 指纹（Host/SNI + 标题 + CMS 规则）
  screenshot.go    chromedp 截图 + macOS 屏幕权限检查
  leak.go          文件泄漏检测（内置 + 自定义字典）
  directory.go     路径发现（流式解压内置字典 + 自定义字典）
  dicts/paths.tsv.gz  337 万条分类后的压缩路径字典
  dicts/leaks.tsv.gz  15 万条压缩敏感文件字典
  pathscan.go      同源路径探测、并发控制与软 404 过滤
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
#       -file-leak [-leak-dict file]  -dir-scan [-dir-dict file]
#       -path-mode quick|deep（默认 quick；deep 使用完整内置字典）
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
  default_port_spec: ""     # 默认自定义端口（仅 default_port_mode 为 custom 时生效）
  nmap_path: ""             # nmap 路径，空则自动探测（含 Homebrew 常见目录）
  masscan_path: ""          # masscan 路径，空则自动探测（含 Homebrew 常见目录）

file_leak:
  dict_path: ""             # 文件泄漏自定义字典，空则用内置敏感文件字典

directory:
  dict_path: ""             # 路径发现字典；配置键为兼容旧版保留 directory 名称

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

**文件泄漏字典格式**（每行 `路径 [类型] [响应签名]`，后两列可省略）：
```
# 自定义泄漏字典
/.git/config git [core]
/.env
/backup.zip backup
```

**路径发现字典格式**（每行 `路径 [directory|route|file]`，类型省略时按 `route` 处理）：
```
# 自定义路径字典
/admin directory
/api/v1 route
/assets/app.js file
```

内置字典合并自 [enh123/DirectoryFuzz](https://github.com/enh123/DirectoryFuzz) 的全部 26 个 TXT 字典（快照 `10941567fc72be4ab93831221eca79ac38fcc154`）、[maurosoria/dirsearch](https://github.com/maurosoria/dirsearch) v0.5.0 的全部 34 个 categories TXT 字典（快照 `6d685189ed7f3871ab02ca2ce9c3d326fa457b27`），以及 EasyScan 原有条目。dirsearch 的 `%EXT%` 模板按其默认值 `php,asp,aspx,jsp,html,htm` 展开。合并结果经过稳定排序、去重和分类后直接压缩；扫描阶段流式解压，不在启动时展开 337 万条记录。

`paths.tsv.gz` 为 17 MiB，`leaks.tsv.gz` 为 693 KiB，均低于 GitHub 单文件 50 MiB 的目标，因此无需 Git LFS。完整内置扫描请求量很大，因此桌面端和 CLI 默认使用高价值快速集合；只有显式选择深度模式（CLI 为 `-path-mode deep`）才使用完整字典。也可通过 `directory.dict_path` 或 `-dir-dict` 指定精简字典。路径类型来自字典特征推断，用于结果筛选，不代表服务端一定以文件系统目录实现该 URL。

由于压缩字典包含 dirsearch 派生条目，[`core/dicts/paths.tsv.gz`](core/dicts/paths.tsv.gz) 与 [`core/dicts/leaks.tsv.gz`](core/dicts/leaks.tsv.gz) 按 dirsearch 的 `GPL-2.0-only` 许可证分发；EasyScan 自有代码仍使用项目根目录中的 MIT 许可证。

---

## 任务策略

| 模块 | 说明 |
|------|------|
| 子域名 | subfinder 被动 + ksubdomain 主动（需提权）+ 纯 Go 兜底 |
| 端口 | `test`（6）/ `top100` / `top1000` / `all`（1-65535）/ `custom`（范围语法，如 `1-1000,8080`） |
| 指纹 | 标题 / Server / 20+ CMS 与中间件特征 |
| 截图 | chromedp 无头浏览器（默认开启） |
| 泄漏 | 默认约 3 万条（高价值条目优先 + 完整字典均匀抽样）；深度模式使用完整压缩字典；支持自定义类型/签名和软 404 过滤 |
| 路径 | 默认约 3 万条（常见入口优先 + 完整字典均匀抽样）；深度模式使用完整目录/路由/文件分类字典；支持自定义字典和软 404 过滤 |
| POC | 内置模板 + 官方 nuclei YAML 模板 |

**提权说明**：ksubdomain 无状态爆破需要 root/管理员权限（原始 socket）。桌面端会自动弹系统授权框——macOS 管理员授权 / Linux PolicyKit / **Windows UAC（ShellExecuteExW runas）**。macOS/Linux 授权后利用 sudo timestamp 缓存，**短时间内重复扫描不重复弹框**（默认 5 分钟，可在 sudoers 的 `timestamp_timeout` 调整）；Windows 已是管理员则直接执行。用户取消授权则自动降级为纯 Go 字典爆破，不影响扫描。

> **Windows 依赖**：ksubdomain 爆破需安装 [Npcap](https://npcap.com/) 驱动（WinPcap 可能无效），未安装时自动降级为纯 Go 字典爆破。gopacket 的 Windows 实现为纯 Go 动态加载 Npcap DLL（`third_party/gopacket` 补齐了上游缺失的 ARM64 结构定义），交叉编译无需 mingw/Npcap SDK。

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
