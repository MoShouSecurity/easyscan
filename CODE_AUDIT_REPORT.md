# EasyScan 代码安全与质量审计报告

- **审计日期**：2026-08-14
- **审计范围**：`app.go`、`main.go`、`cmd/easyscan`、`core/`（36 个 Go 文件，共约 6,500 行）、`frontend/dist/index.html`、配置与仓库卫生
- **审计方式**：`gofmt`、`go vet`、`go test`（非沙箱模式）+ 人工逐文件代码审查 + 注入/越权/竞态/资源失控专项分析
- **基线状态**：`gofmt` ✅ 通过、`go vet` ✅ 通过、`go test ./...` ✅ 全部通过（10.0s）
- **总体结论**：项目格式规范、注释充分、测试覆盖核心纯函数，但存在 **1 个严重提权命令注入漏洞** 和 **1 个高危前端 DOM XSS**，以及多个中等危险的本地越权/文件读写问题；调度器与网段展开存在多处健壮性缺陷。

---

## 一、安全漏洞（按严重程度排序）

### 🔴 S-01【严重】macOS 提权命令注入（root 权限任意命令执行）

- **位置**：`core/privilege.go:40`（`enumerateWithKsubdomainPrivileged`）
- **类型**：CWE-78 操作系统命令注入
- **分析**：

```go
exeQuoted := strings.ReplaceAll(strings.ReplaceAll(exe, `\`, `\\`), `"`, `\"`)
domainQuoted := strings.ReplaceAll(strings.ReplaceAll(domain, `\`, `\\`), `"`, `\"`)
script := fmt.Sprintf(`do shell script "%s --ksubdomain-enum %s" ...`, exeQuoted, domainQuoted)
```

仅转义了 `"` 与 `\`，**未转义 `;`、`$()`、反引号、`&&`、`|` 等 shell 元字符**。而 `domain` 完全来自用户在前端输入的扫描目标，且 `StartScan` / `ScanDomain` 全链路**没有任何域名字符校验**（仅去空白/去协议头/去尾斜杠）。

- **攻击路径**：
  1. 用户提交域名目标 `a.com; touch /tmp/pwned`（前端 `isIPTarget()` 判定其为“域名”，原样放行）；
  2. 域名类型默认开启 `SubdomainBrute`，进入 `enumerateWithKsubdomainPrivileged`；
  3. sudo 缓存过期时走 `osascript ... with administrator privileges`，上述目标被拼接进 `do shell script`，由 `/bin/sh -c` 以 **root** 执行；
  4. 用户在授权框中输入密码后，注入的分号命令即以 root 身份执行。
- **影响**：任意命令以管理员权限执行（仅需求一次用户授权交互）。
- **修复建议**：
  1. **强制白名单校验域名**（仅 `[a-z0-9.-]`，逐标签 ≤63、总长 ≤253、禁止 `..`/首尾 `.`/首尾 `-`），在 `StartScan` 与 `ScanDomain` 双层校验；
  2. osascript 路径改用 shell 单引号包裹并转义 `'` → `'\''`（AppleScript 层再转义 `\` 与 `"`），双重防护；
  3. `sudo`/`pkexec` 分支虽使用参数数组无注入，但同样应只接受校验后的域名。

---

### 🟠 S-02【高危】前端 DOM XSS → Go 桥接接口全量暴露

- **位置**：`frontend/dist/index.html:359`（`renderSitesHTML`）
- **类型**：CWE-79 DOM 型跨站脚本
- **分析**：

```js
onclick="openURL('${esc(s.url)}')"
```

`esc()` 会把 `'` 转成 `&#39;`，但该值位于 **HTML 属性**中——浏览器先做 HTML 实体解码、再解析属性内的 JS，因此 `&#39;` 会还原成真实单引号，可闭合 JS 字符串。已验证 Go 的 `url.URL.String()` **不会转义单引号**：被扫描站点只要返回重定向 `Location: http://x/',<payload>,'`，最终 `site.url` 即携带引号。

- **攻击路径**：用户扫描攻击者控制的站点 → 站点 302 到含 `',恶意JS,'` 的 URL → 结果落库 → 详情页渲染时注入执行。Wails webview 中的 JS 可直接调用全部 Go 桥接方法，进一步组合：
  - `GetScreenshot(path)` 任意本地文件读取（见 S-04）；
  - `SaveConfig` 篡改 `TemplatesRepo` + `DownloadNucleiTemplates` 触发 `git clone ext::sh -c '...'` 实现 **RCE 链**（见 S-06）；
  - `ExportTask(id)` 路径穿越任意写（见 S-03）。
- **影响**：远程代码执行（需用户扫描恶意目标，这正是本工具的核心使用场景，风险现实）。
- **修复建议**：
  1. 移除内联 `onclick` 插值，改用 `data-url="${esc(s.url)}"` + 事件委托读取 `dataset.openUrl`；
  2. 其余内联 `onclick` 中的任务 ID 虽为服务端生成 hex（当前安全），建议一并改为事件委托消除此类上下文混淆；
  3. 在 `probeSite` 落库前对最终 URL 做规范化/编码校验。

---

### 🟠 S-03【高危】ExportTask 路径穿越任意文件写入

- **位置**：`app.go:449`
- **类型**：CWE-22 路径穿越
- **分析**：

```go
path := filepath.Join(dir, "task_"+taskID+".csv")
```

`taskID` 来自前端参数，未经任何校验；`filepath.Join` 会做 `Clean`，`../../...` 可逃出 `exports/` 目录。且 `ExportTask` **不先调用 `GetTask` 验证任务存在**，内容可部分受控（扫描资产值）。
- **影响**：配合 S-02 可向用户目录任意位置写入 CSV 文件。
- **修复建议**：先 `GetTask(taskID)` 校验存在性；用正则 `^[0-9a-f]{32}$` 限制 ID；再检查最终路径 `filepath.Rel` 结果不含 `..`。

---

### 🟠 S-04【中高】GetScreenshot 任意本地文件读取

- **位置**：`app.go:409`
- **类型**：CWE-22 / 敏感信息泄露
- **分析**：`os.ReadFile(path)` 直接读取前端传入的任意路径并 base64 返回，未限制在截图目录内。
- **影响**：配合 S-02 可读取 `~/.ssh/id_rsa`、`config.yaml`（含 FOFA key）等任意文件。
- **修复建议**：仅允许 `configDir/screenshots` 子树，使用 `filepath.EvalSymlinks` + `Rel` 双重校验前缀。

---

### 🟠 S-05【中危】CSV 公式注入（Excel 打开即执行）

- **位置**：`app.go`（`ExportTask`）
- **类型**：CWE-1236 CSV/公式注入
- **分析**：站点标题、指纹、Server 头、Banner 等均来自**被扫描的不可信服务器**，直接写入 CSV。若标题为 `=cmd|'/C calc'!A1`、`+HYPERLINK(...)`、`@SUM(...)` 等，Excel/WPS 打开时会被解释为公式。
- **修复建议**：写入前检测单元格以 `=`、`+`、`-`、`@`、制表符、CR 开头时前置 `'` 或包裹引号。

---

### 🟠 S-06【中危】git clone 仓库地址未校验 → ext:: 传输 RCE 链

- **位置**：`core/nuclei.go:326`（`DownloadNucleiTemplates`）
- **类型**：CWE-78（配置驱动的命令执行）
- **分析**：`TemplatesRepo` 来自配置文件/前端 `SaveConfig`，直接传给 `git clone`。git 的 `ext::sh -c '...'` 传输协议可执行任意命令；配合 S-02 即形成 XSS → 改配置 → 触发下载 → RCE 的完整链路。
- **修复建议**：强制 `https://` 且无 userinfo，主机名建议白名单（至少 `github.com`/`gitee.com`），拒绝 `ext::`/`file://` 等非 HTTPS scheme。

---

### 🟡 S-07【中危】Windows UAC 提权参数注入

- **位置**：`core/privilege_windows.go:48`
- **分析**：`params := fmt.Sprintf(`--ksubdomain-enum %s --ksubdomain-out "%s"`, domain, tmpPath)`，`domain` 未加引号。Windows 子进程会用 `CommandLineToArgvW` 重新拆分参数，含空格/引号的域名可注入额外 argv（如伪造 `--ksubdomain-out` 覆盖输出路径）。
- **修复建议**：与 S-01 共用严格域名白名单校验后，此问题自然消除；同时可对 domain 做引号转义作为纵深防御。

---

### 🟡 S-08【中危】敏感信息明文存储且权限过宽

- **位置**：`core/config.go:153`、`core/store.go`、`main.go:32`
- **分析**：
  - `config.yaml` 含 FOFA API key，`os.WriteFile(..., 0o644)` 创建，同机其他用户可读；
  - SQLite 资产库（扫描结果，含内网 IP/标题/指纹）按默认 umask 创建（通常 0644）；
  - UAC helper 输出文件 0o644（含子域名清单）。
- **修复建议**：配置与数据库统一 0600，配置目录 0700；helper 输出 0600。另建议 FOFA key 改走 keychain/凭据管理器（长期项）。

---

### ℹ️ S-09【低危/提示】SQL LIKE 通配符未转义

- **位置**：`core/store.go`（`Search`）
- **分析**：使用参数化查询，**无 SQL 注入风险**；但 `%`/`_` 未转义导致用户搜索 `%` 匹配全部记录。属功能性小瑕疵，非漏洞。

---

## 二、健壮性与正确性问题

### R-01【高】Scheduler.Submit / Resume 队列满时永久阻塞 UI

- **位置**：`core/scheduler.go:70,76`
- **分析**：`s.queue <- t` 为无超时阻塞发送，队列容量 256、worker 仅 2 个；一旦积压满，Wails 主线程调用 `StartScan`/`ResumeTask` 将永久挂起，界面冻结且无法恢复。
- **建议**：改用 `select` + `default` 返回“任务队列已满”错误，或带 `ctx` 超时。

### R-02【高】崩溃/强退后任务永久停留在 running，无启动恢复

- **位置**：`core/scheduler.go`、`app.go startup`
- **分析**：进程崩溃、被 kill 或 `ForceClose` 强退后，数据库中 `running/pending` 状态永远不会被更新。下次启动 `hasRunningTasks()` 仍返回 true，窗口关闭确认逻辑永久误判，任务也无法 Resume。
- **建议**：启动时执行 `UPDATE tasks SET status='paused', message='程序异常退出...' WHERE status IN ('running','pending')`。

### R-03【中】Stop 关闭调度器时任务状态残留

- **位置**：`core/scheduler.go run()`
- **分析**：`Stop()` 取消父 ctx 后，`run` 判断 `ctx.Err() != nil` 直接 return，不更新任务状态，与 R-02 叠加造成永久 running。
- **建议**：区分“用户暂停”与“调度器关闭”，后者应将任务标记为 paused。

### R-04【高】CIDR 展开无上限 → 自拒绝服务

- **位置**：`core/pipeline.go:591`（`expandTarget`）
- **分析**：`10.0.0.0/8` 会一次性物化 1,677 万个 IP 到内存切片；勾选“禁 ping”时还会全部进入端口扫描。`splitTargets` 对网段前缀长度无任何限制。
- **建议**：限制单任务主机总数（如 65,536），超限报错并提示拆分网段。

### R-05【中】IPv6 URL 构造错误，IPv6 站点探测全面失效

- **位置**：`core/fingerprint.go:53`（`probeSite`）
- **分析**：`fmt.Sprintf("%s://%s:%d/", scheme, host, port)` 对 IPv6 会生成 `http://::1:80/`（非法 URL，`http.NewRequest` 报错被静默吞掉）。同时 `benchmark.go` 用 `strings.Cut(k, ":")` 解析 `ip:port` 键，IPv6 下也会解析错乱。
- **建议**：统一使用 `net.JoinHostPort`；benchmark 键改用 `lastIndex(":")` 切分。

### R-06【中】非法端口模式在两条路径下默认值不一致

- **位置**：`core/dicts.go:11`（`portList` 默认 → top100）vs `core/nmap.go:106`（`nmapPortArgs` 默认 → test 6 端口）
- **分析**：配置写入未知模式时，nmap 路径扫 6 个端口、纯 Go 降级路径扫 top100，结果不可比。
- **建议**：抽出统一的 `ValidatePortMode` 白名单，两处共用同一默认值。

### R-07【中】请求级空 PortSpec 覆盖配置默认值

- **位置**：`app.go StartScan`
- **分析**：`opts.PortSpec = req.PortSpec` 无条件覆盖——配置里 `DefaultPortMode=custom` + `DefaultPortSpec="1-1000"` 时，前端传空 `port_spec` 会导致 `ParsePortSpec("")` 报错，用户无法使用配置默认值。
- **建议**：仅当 `req.PortSpec != ""` 时覆盖。

### R-08【低】nmap 错误丢失 stderr 诊断信息

- **位置**：`core/nmap.go run()`
- **分析**：`cmd.Output()` 捕获的 stderr 在 `ExitError.Stderr` 中但未被使用，用户只看到 `exit status 1`，无法排障。
- **建议**：显式绑定 stderr buffer 并在错误中附带摘要。

### R-09【低】readBodyLimited 忽略读取错误

- **位置**：`core/subdomain.go`
- **分析**：`io.ReadAll` 错误被丢弃，截断响应被当作完整内容参与指纹/签名匹配，可能误判。
- **建议**：返回 `(data, err)`，调用方降级处理。

### R-10【低】自定义 nuclei 模板命中状态码硬编码 200

- **位置**：`core/nuclei.go`（`runNucleiYAML` 中 `StatusCode: 200`）
- **建议**：由 `matchNucleiTemplate` 返回真实 `resp.StatusCode`。

### R-11【低】Store.Search 未检查 rows.Err()

- **位置**：`core/store.go`
- **分析**：迭代结束直接 `rows.Close()`，数据库迭代错误被静默吞掉，可能返回截断结果。

### R-12【低】空签名泄漏规则对 catch-all 路由大量误报

- **位置**：`core/leak.go`
- **分析**：`.DS_Store`、`.env`、`backup.zip` 等 `Sig==""` 的规则只判断 HTTP 200；SPA/软 404 站点任意路径都返回 200 时会产生成片误报。
- **建议**：增加内容长度/特征二次校验或软 404 指纹基线。

### R-13【低】PauseTask 与 worker 完成存在竞态

- **位置**：`app.go PauseTask`
- **分析**：`CancelTask` 后、`GetTask` 前任务可能刚好自然完成，仍会被改写为 paused。
- **建议**：先读取任务状态，仅 running/pending 才允许暂停。

### R-14【低】openFile 启动进程后不 Wait → 僵尸进程

- **位置**：`app.go openFile`
- **建议**：`cmd.Start()` 后异步 `cmd.Wait()` 回收。

---

## 三、代码格式与工程卫生

| 检查项 | 结果 |
|---|---|
| `gofmt -l`（全部自有 Go 文件） | ✅ 无未格式化文件 |
| `go vet ./...` | ✅ 无告警 |
| `go test ./...` | ✅ 通过（注：沙箱内因禁止本地端口监听会 panic，非沙箱环境通过） |
| 注释与命名 | ✅ 中文注释完整、命名清晰、无魔法数字滥用 |
| 单元测试 | ✅ 覆盖端口解析、nmap XML、FOFA、masscan、截图、nuclei 等核心纯函数 |
| 敏感文件入库 | ✅ `easyscan.db*`、`.DS_Store`、`bin/`、`.claude/`、`ksubdomain.yaml` 均已被 .gitignore 排除且未跟踪 |
| 工作区残留 | ⚠️ 本地存在 6MB 的 `easyscan.db-wal`（未跟踪），含真实扫描数据，建议及时清理/备份加密 |

---

## 四、修复优先级汇总

| 编号 | 等级 | 位置 | 问题 | 建议优先级 |
|---|---|---|---|---|
| S-01 | 🔴 严重 | `core/privilege.go:40` | osascript 提权命令注入 | **P0 立即修复** |
| S-02 | 🟠 高危 | `frontend/dist/index.html:359` | DOM XSS → 桥接接口暴露 | **P0 立即修复** |
| S-03 | 🟠 高危 | `app.go:449` | ExportTask 路径穿越 | P0/P1 |
| S-04 | 🟠 中高 | `app.go:409` | GetScreenshot 任意文件读 | P1 |
| R-04 | 🟠 高 | `core/pipeline.go:591` | CIDR 无上限展开 | P1 |
| S-05 | 🟠 中 | `app.go` | CSV 公式注入 | P1 |
| S-06 | 🟠 中 | `core/nuclei.go:326` | git clone ext:: RCE 链 | P1 |
| S-07 | 🟡 中 | `core/privilege_windows.go:48` | UAC 参数注入 | P1 |
| R-01 | 🟠 高 | `core/scheduler.go:70` | 队列满阻塞 UI | P1 |
| R-02 | 🟠 高 | `core/scheduler.go` | 崩溃后任务永久 running | P1 |
| S-08 | 🟡 中 | `core/config.go:153` 等 | 敏感文件权限过宽 | P2 |
| R-03 | 🟡 中 | `core/scheduler.go` | Stop 状态残留 | P2 |
| R-05 | 🟡 中 | `core/fingerprint.go:53` | IPv6 URL 构造错误 | P2 |
| R-06/R-07 | 🟡 中 | `app.go`/`dicts.go`/`nmap.go` | 端口模式不一致 | P2 |
| R-08~R-14 | 🟢 低 | 各处 | 诊断信息/竞态/误报 | P3 |

---

## 五、总结

代码工程质量整体良好（格式、注释、测试均到位），但**输入校验是最薄弱环节**：域名目标从 UI 到提权子进程全程无字符白名单，直接导致了 S-01 严重漏洞；前端虽有 `esc()` 但在 JS 字符串上下文中失效，形成 S-02 高危 XSS，并能串联多个本地桥接接口构成完整 RCE 链。

建议按上表优先级，先在入口层（`StartScan`/`ScanDomain`）建立统一的**目标白名单校验**，再修复前端事件绑定与文件路径校验，最后处理调度器与网段展开的健壮性问题。
