package core

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"

	_ "modernc.org/sqlite"
)

// Store 封装 SQLite 资产库的读写。
// 使用单写连接（MaxOpenConns(1)）序列化写入，配合 WAL + busy_timeout 保证并发安全。
type Store struct {
	db *sql.DB
	mu sync.Mutex // 保护写操作，避免多 goroutine 并发写导致 SQLITE_BUSY
}

// OpenStore 打开（或创建）SQLite 数据库并执行迁移。path 为空则使用内存库。
func OpenStore(path string) (*Store, error) {
	dsn := path
	if dsn == "" {
		dsn = ":memory:"
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	dsn += sep + "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	// 数据库含扫描资产信息，文件权限收紧为 0600（SQLite 默认按 umask 创建）。
	if path != "" {
		_ = os.Chmod(path, 0o600)
	}
	return s, nil
}

// ensureColumn 若列不存在则添加；已存在则忽略（用于旧库平滑迁移）。
func (s *Store) ensureColumn(table, column, decl string) error {
	_, err := s.db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, decl))
	if err != nil && strings.Contains(err.Error(), "duplicate column") {
		return nil
	}
	return err
}

func (s *Store) migrate() error {
	schema := `
CREATE TABLE IF NOT EXISTS domains (
	id TEXT PRIMARY KEY,
	domain TEXT NOT NULL UNIQUE,
	source TEXT DEFAULT '',
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS subdomains (
	id TEXT PRIMARY KEY,
	domain TEXT NOT NULL,
	subdomain TEXT NOT NULL,
	ip TEXT DEFAULT '',
	source TEXT DEFAULT '',
	task_id TEXT DEFAULT '',
	created_at INTEGER NOT NULL,
	UNIQUE(task_id, domain, subdomain)
);
CREATE INDEX IF NOT EXISTS idx_subdomains_domain ON subdomains(domain);
CREATE TABLE IF NOT EXISTS ips (
	id TEXT PRIMARY KEY,
	ip TEXT NOT NULL,
	domain TEXT DEFAULT '',
	task_id TEXT DEFAULT '',
	created_at INTEGER NOT NULL,
	UNIQUE(task_id, ip, domain)
);
CREATE TABLE IF NOT EXISTS ports (
	id TEXT PRIMARY KEY,
	ip TEXT NOT NULL,
	port INTEGER NOT NULL,
	protocol TEXT DEFAULT 'tcp',
	service TEXT DEFAULT '',
	banner TEXT DEFAULT '',
	title TEXT DEFAULT '',
	product TEXT DEFAULT '',
	version TEXT DEFAULT '',
	confidence INTEGER DEFAULT 0,
	task_id TEXT DEFAULT '',
	created_at INTEGER NOT NULL,
	UNIQUE(task_id, ip, port, protocol)
);
CREATE INDEX IF NOT EXISTS idx_ports_ip ON ports(ip);
CREATE TABLE IF NOT EXISTS sites (
	id TEXT PRIMARY KEY,
	ip TEXT NOT NULL,
	port INTEGER NOT NULL,
	url TEXT NOT NULL,
	title TEXT DEFAULT '',
	status_code INTEGER DEFAULT 0,
	server TEXT DEFAULT '',
	fingerprint TEXT DEFAULT '',
	screenshot TEXT DEFAULT '',
	task_id TEXT DEFAULT '',
	created_at INTEGER NOT NULL,
	UNIQUE(task_id, url)
);
CREATE TABLE IF NOT EXISTS leaks (
	id TEXT PRIMARY KEY,
	task_id TEXT DEFAULT '',
	url TEXT NOT NULL,
	path TEXT DEFAULT '',
	type TEXT DEFAULT '',
	status_code INTEGER DEFAULT 0,
	created_at INTEGER NOT NULL,
	UNIQUE(task_id, url)
);
CREATE INDEX IF NOT EXISTS idx_leaks_task ON leaks(task_id);
CREATE TABLE IF NOT EXISTS tasks (
	id TEXT PRIMARY KEY,
	target TEXT NOT NULL,
	type TEXT NOT NULL,
	status TEXT NOT NULL,
	progress INTEGER DEFAULT 0,
	message TEXT DEFAULT '',
	params TEXT DEFAULT '',
	created_at INTEGER NOT NULL,
	finished_at INTEGER DEFAULT 0
);
`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}

	// 旧库平滑迁移：补充新增列（存在则忽略）。
	for _, c := range []struct{ table, col, decl string }{
		{"subdomains", "task_id", "TEXT DEFAULT ''"},
		{"ips", "task_id", "TEXT DEFAULT ''"},
		{"ports", "task_id", "TEXT DEFAULT ''"},
		{"ports", "product", "TEXT DEFAULT ''"},
		{"ports", "version", "TEXT DEFAULT ''"},
		{"ports", "confidence", "INTEGER DEFAULT 0"},
		{"sites", "task_id", "TEXT DEFAULT ''"},
		{"sites", "screenshot", "TEXT DEFAULT ''"},
		{"tasks", "stage", "TEXT DEFAULT ''"},
	} {
		if err := s.ensureColumn(c.table, c.col, c.decl); err != nil {
			return err
		}
	}
	return s.migrateTaskScopedAssets()
}

// migrateTaskScopedAssets 将旧版“资产全局唯一、task_id 被后一次扫描覆盖”的表结构，
// 迁移为“任务内唯一”。旧数据原样复制；迁移后同一资产可同时属于多个任务，
// 删除或重扫一个任务不会再破坏其他任务的详情。
func (s *Store) migrateTaskScopedAssets() error {
	tables := []struct {
		name       string
		uniqueCols []string
	}{
		{"subdomains", []string{"task_id", "domain", "subdomain"}},
		{"ips", []string{"task_id", "ip", "domain"}},
		{"ports", []string{"task_id", "ip", "port", "protocol"}},
		{"sites", []string{"task_id", "url"}},
	}
	needsMigration := false
	for _, table := range tables {
		ok, err := s.hasUniqueIndex(table.name, table.uniqueCols)
		if err != nil {
			return err
		}
		if !ok {
			needsMigration = true
			break
		}
	}
	if !needsMigration {
		_, err := s.db.Exec(`
			CREATE INDEX IF NOT EXISTS idx_subdomains_task ON subdomains(task_id);
			CREATE INDEX IF NOT EXISTS idx_ips_task ON ips(task_id);
			CREATE INDEX IF NOT EXISTS idx_ports_task ON ports(task_id);
			CREATE INDEX IF NOT EXISTS idx_sites_task ON sites(task_id);
		`)
		return err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("开始任务资产迁移: %w", err)
	}
	rollback := func(err error) error {
		_ = tx.Rollback()
		return fmt.Errorf("迁移任务资产表: %w", err)
	}
	statements := []string{
		`ALTER TABLE subdomains RENAME TO subdomains_legacy`,
		`CREATE TABLE subdomains (id TEXT PRIMARY KEY, domain TEXT NOT NULL, subdomain TEXT NOT NULL, ip TEXT DEFAULT '', source TEXT DEFAULT '', task_id TEXT DEFAULT '', created_at INTEGER NOT NULL, UNIQUE(task_id, domain, subdomain))`,
		`INSERT INTO subdomains(id, domain, subdomain, ip, source, task_id, created_at) SELECT id, domain, subdomain, ip, source, task_id, created_at FROM subdomains_legacy`,
		`DROP TABLE subdomains_legacy`,
		`CREATE INDEX idx_subdomains_domain ON subdomains(domain)`,
		`CREATE INDEX idx_subdomains_task ON subdomains(task_id)`,

		`ALTER TABLE ips RENAME TO ips_legacy`,
		`CREATE TABLE ips (id TEXT PRIMARY KEY, ip TEXT NOT NULL, domain TEXT DEFAULT '', task_id TEXT DEFAULT '', created_at INTEGER NOT NULL, UNIQUE(task_id, ip, domain))`,
		`INSERT INTO ips(id, ip, domain, task_id, created_at) SELECT id, ip, domain, task_id, created_at FROM ips_legacy`,
		`DROP TABLE ips_legacy`,
		`CREATE INDEX idx_ips_task ON ips(task_id)`,

		`ALTER TABLE ports RENAME TO ports_legacy`,
		`CREATE TABLE ports (id TEXT PRIMARY KEY, ip TEXT NOT NULL, port INTEGER NOT NULL, protocol TEXT DEFAULT 'tcp', service TEXT DEFAULT '', product TEXT DEFAULT '', version TEXT DEFAULT '', banner TEXT DEFAULT '', title TEXT DEFAULT '', confidence INTEGER DEFAULT 0, task_id TEXT DEFAULT '', created_at INTEGER NOT NULL, UNIQUE(task_id, ip, port, protocol))`,
		`INSERT INTO ports(id, ip, port, protocol, service, product, version, banner, title, confidence, task_id, created_at) SELECT id, ip, port, protocol, service, product, version, banner, title, confidence, task_id, created_at FROM ports_legacy`,
		`DROP TABLE ports_legacy`,
		`CREATE INDEX idx_ports_ip ON ports(ip)`,
		`CREATE INDEX idx_ports_task ON ports(task_id)`,

		`ALTER TABLE sites RENAME TO sites_legacy`,
		`CREATE TABLE sites (id TEXT PRIMARY KEY, ip TEXT NOT NULL, port INTEGER NOT NULL, url TEXT NOT NULL, title TEXT DEFAULT '', status_code INTEGER DEFAULT 0, server TEXT DEFAULT '', fingerprint TEXT DEFAULT '', screenshot TEXT DEFAULT '', task_id TEXT DEFAULT '', created_at INTEGER NOT NULL, UNIQUE(task_id, url))`,
		`INSERT INTO sites(id, ip, port, url, title, status_code, server, fingerprint, screenshot, task_id, created_at) SELECT id, ip, port, url, title, status_code, server, fingerprint, screenshot, task_id, created_at FROM sites_legacy`,
		`DROP TABLE sites_legacy`,
		`CREATE INDEX idx_sites_task ON sites(task_id)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return rollback(err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交任务资产迁移: %w", err)
	}
	return nil
}

func (s *Store) hasUniqueIndex(table string, want []string) (bool, error) {
	rows, err := s.db.Query(`SELECT name FROM pragma_index_list(?) WHERE "unique"=1`, table)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	var indexes []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, err
		}
		indexes = append(indexes, name)
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	if err := rows.Close(); err != nil {
		return false, err
	}
	for _, index := range indexes {
		cols, err := s.indexColumns(index)
		if err != nil {
			return false, err
		}
		if equalStrings(cols, want) {
			return true, nil
		}
	}
	return false, nil
}

func (s *Store) indexColumns(index string) ([]string, error) {
	rows, err := s.db.Query(`SELECT name FROM pragma_index_info(?) ORDER BY seqno`, index)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			return nil, err
		}
		columns = append(columns, column)
	}
	return columns, rows.Err()
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Close 关闭数据库。
func (s *Store) Close() error { return s.db.Close() }

// MarkInterruptedTasks 将上次异常退出（崩溃/强杀）遗留的 running/pending
// 任务标记为 paused。应用启动时调用：防止任务永久停留 running，
// 避免关闭确认逻辑永久误判，且任务可通过「恢复」继续。
func (s *Store) MarkInterruptedTasks() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE tasks SET status='paused', message='程序异常退出，任务已暂停' WHERE status IN ('running','pending')`)
	return err
}

// ---- 写入（Upsert 语义，重复数据自动忽略/更新） ----

func (s *Store) UpsertDomain(d Domain) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		`INSERT INTO domains(id, domain, source, created_at) VALUES(?,?,?,?)
		 ON CONFLICT(domain) DO UPDATE SET source=excluded.source`,
		d.ID, d.Domain, d.Source, d.CreatedAt)
	return err
}

func (s *Store) UpsertSubdomain(sd Subdomain) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		`INSERT INTO subdomains(id, domain, subdomain, ip, source, task_id, created_at) VALUES(?,?,?,?,?,?,?)
		 ON CONFLICT(task_id, domain, subdomain) DO UPDATE SET ip=excluded.ip`,
		sd.ID, sd.Domain, sd.Subdomain, sd.IP, sd.Source, sd.TaskID, sd.CreatedAt)
	return err
}

func (s *Store) UpsertIP(ip IP) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		`INSERT INTO ips(id, ip, domain, task_id, created_at) VALUES(?,?,?,?,?)
		 ON CONFLICT(task_id, ip, domain) DO NOTHING`,
		ip.ID, ip.IP, ip.Domain, ip.TaskID, ip.CreatedAt)
	return err
}

func (s *Store) UpsertPort(p Port) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// 置信度取新旧最大值：同一端口被多种方式扫描时保留更可信的结果。
	_, err := s.db.Exec(
		`INSERT INTO ports(id, ip, port, protocol, service, product, version, banner, title, confidence, task_id, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(task_id, ip, port, protocol) DO UPDATE SET service=excluded.service, product=excluded.product, version=excluded.version, banner=excluded.banner, title=excluded.title, confidence=MAX(confidence, excluded.confidence)`,
		p.ID, p.IP, p.Port, p.Protocol, p.Service, p.Product, p.Version, p.Banner, p.Title, p.Confidence, p.TaskID, p.CreatedAt)
	return err
}

func (s *Store) UpsertSite(site Site) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		`INSERT INTO sites(id, ip, port, url, title, status_code, server, fingerprint, screenshot, task_id, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(task_id, url) DO UPDATE SET ip=excluded.ip, port=excluded.port, title=excluded.title, status_code=excluded.status_code, server=excluded.server, fingerprint=excluded.fingerprint, screenshot=excluded.screenshot`,
		site.ID, site.IP, site.Port, site.URL, site.Title, site.StatusCode, site.Server, site.Fingerprint, site.Screenshot, site.TaskID, site.CreatedAt)
	return err
}

func (s *Store) UpsertLeak(leak Leak) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		`INSERT INTO leaks(id, task_id, url, path, type, status_code, created_at) VALUES(?,?,?,?,?,?,?)
		 ON CONFLICT(task_id, url) DO UPDATE SET path=excluded.path, type=excluded.type, status_code=excluded.status_code`,
		leak.ID, leak.TaskID, leak.URL, leak.Path, leak.Type, leak.StatusCode, leak.CreatedAt)
	return err
}

// SetSiteScreenshot 更新站点截图路径。
func (s *Store) SetSiteScreenshot(taskID, url, path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE sites SET screenshot=? WHERE task_id=? AND url=?`, path, taskID, url)
	return err
}

// ---- 任务 ----

func (s *Store) CreateTask(t *Task) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		`INSERT INTO tasks(id, target, type, status, progress, message, stage, params, created_at, finished_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?)`,
		t.ID, t.Target, string(t.Type), string(t.Status), t.Progress, t.Message, t.Stage, t.Params, t.CreatedAt, t.FinishedAt)
	return err
}

func (s *Store) UpdateTask(t *Task) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		`UPDATE tasks SET status=?, progress=?, message=?, stage=?, finished_at=? WHERE id=?`,
		string(t.Status), t.Progress, t.Message, t.Stage, t.FinishedAt, t.ID)
	return err
}

// UpdateTaskIfStatus 仅当数据库中的任务仍处于 expected 状态时更新。
// 返回是否实际更新，用于防止暂停、完成和进度回调互相覆盖。
func (s *Store) UpdateTaskIfStatus(t *Task, expected TaskStatus) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(
		`UPDATE tasks SET status=?, progress=?, message=?, finished_at=? WHERE id=? AND status=?`,
		string(t.Status), t.Progress, t.Message, t.FinishedAt, t.ID, string(expected))
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

// PauseTask 原子地暂停 pending/running 任务，避免覆盖刚完成的任务状态。
func (s *Store) PauseTask(id, message string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(
		`UPDATE tasks SET status=?, message=? WHERE id=? AND status IN (?,?)`,
		string(TaskPaused), message, id, string(TaskPending), string(TaskRunning))
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

// QueuePausedTask 原子地把 paused 任务恢复为 pending。
func (s *Store) QueuePausedTask(id, message string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(
		`UPDATE tasks SET status=?, message=?, finished_at=0 WHERE id=? AND status=?`,
		string(TaskPending), message, id, string(TaskPaused))
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

// UpdateTaskStage 仅更新任务的当前阶段（用于断点续扫，不碰其他字段）。
func (s *Store) UpdateTaskStage(id, stage string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE tasks SET stage=? WHERE id=?`, stage, id)
	return err
}

func (s *Store) GetTask(id string) (*Task, error) {
	row := s.db.QueryRow(`SELECT id, target, type, status, progress, message, stage, params, created_at, finished_at FROM tasks WHERE id=?`, id)
	var t Task
	var typ, status string
	if err := row.Scan(&t.ID, &t.Target, &typ, &status, &t.Progress, &t.Message, &t.Stage, &t.Params, &t.CreatedAt, &t.FinishedAt); err != nil {
		return nil, err
	}
	t.Type, t.Status = TaskType(typ), TaskStatus(status)
	return &t, nil
}

// DeleteTask 删除任务及其全部关联数据：端口/站点/泄漏/存活 IP/子域名
// （子域名归属最后一个写入的任务，删除该任务即连同其子域名一起删除）。
// 根域名（domains）在该域名无任何子域名且无其他任务引用时一并清理。
func (s *Store) DeleteTask(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	rollback := func() {
		_ = tx.Rollback()
	}
	for _, stmt := range []string{
		`DELETE FROM ports WHERE task_id=?`,
		`DELETE FROM sites WHERE task_id=?`,
		`DELETE FROM leaks WHERE task_id=?`,
		`DELETE FROM ips WHERE task_id=?`,
		`DELETE FROM subdomains WHERE task_id=?`,
	} {
		if _, err := tx.Exec(stmt, id); err != nil {
			rollback()
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM tasks WHERE id=?`, id); err != nil {
		rollback()
		return err
	}
	// 清理无引用的根域名（无子域名且无其他任务引用）。
	if _, err := tx.Exec(`DELETE FROM domains WHERE domain NOT IN (
		SELECT DISTINCT domain FROM subdomains
	) AND domain NOT IN (
		SELECT DISTINCT target FROM tasks WHERE type='domain'
	)`); err != nil {
		rollback()
		return err
	}
	return tx.Commit()
}

func (s *Store) ListTasks(limit int) ([]Task, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT id, target, type, status, progress, message, stage, params, created_at, finished_at FROM tasks ORDER BY created_at DESC, rowid DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Task, 0)
	for rows.Next() {
		var t Task
		var typ, status string
		if err := rows.Scan(&t.ID, &t.Target, &typ, &status, &t.Progress, &t.Message, &t.Stage, &t.Params, &t.CreatedAt, &t.FinishedAt); err != nil {
			return nil, err
		}
		t.Type, t.Status = TaskType(typ), TaskStatus(status)
		out = append(out, t)
	}
	return out, rows.Err()
}

// ---- 查询 ----

func (s *Store) ListDomains(limit int) ([]Domain, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := s.db.Query(`SELECT id, domain, source, created_at FROM domains ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Domain, 0)
	for rows.Next() {
		var d Domain
		if err := rows.Scan(&d.ID, &d.Domain, &d.Source, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) SubdomainCount(domain string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(DISTINCT subdomain) FROM subdomains WHERE domain=?`, domain).Scan(&n)
	return n, err
}

func (s *Store) ListSubdomains(domain string, limit int) ([]Subdomain, error) {
	if limit == 0 {
		limit = 500
	}
	rows, err := s.db.Query(`SELECT id, domain, subdomain, ip, source, task_id, created_at
		FROM subdomains AS sd
		WHERE domain=? AND NOT EXISTS (
			SELECT 1 FROM subdomains AS newer
			WHERE newer.domain=sd.domain AND newer.subdomain=sd.subdomain
			AND (newer.created_at>sd.created_at OR (newer.created_at=sd.created_at AND newer.rowid>sd.rowid))
		)
		ORDER BY subdomain LIMIT ?`, domain, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSubdomains(rows)
}

func (s *Store) ListSubdomainsByTask(taskID string, limit int) ([]Subdomain, error) {
	if limit == 0 {
		limit = 1000
	}
	rows, err := s.db.Query(`SELECT id, domain, subdomain, ip, source, task_id, created_at FROM subdomains WHERE task_id=? ORDER BY subdomain LIMIT ?`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSubdomains(rows)
}

func scanSubdomains(rows *sql.Rows) ([]Subdomain, error) {
	out := make([]Subdomain, 0)
	for rows.Next() {
		var sd Subdomain
		if err := rows.Scan(&sd.ID, &sd.Domain, &sd.Subdomain, &sd.IP, &sd.Source, &sd.TaskID, &sd.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, sd)
	}
	return out, rows.Err()
}

func (s *Store) PortCount() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM (SELECT 1 FROM ports GROUP BY ip, port, protocol)`).Scan(&n)
	return n, err
}

func (s *Store) ListPorts(limit int) ([]Port, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := s.db.Query(`SELECT id, ip, port, protocol, service, product, version, banner, title, confidence, task_id, created_at
		FROM ports AS p
		WHERE NOT EXISTS (
			SELECT 1 FROM ports AS newer
			WHERE newer.ip=p.ip AND newer.port=p.port AND newer.protocol=p.protocol
			AND (newer.created_at>p.created_at OR (newer.created_at=p.created_at AND newer.rowid>p.rowid))
		)
		ORDER BY ip, port LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPorts(rows)
}

func (s *Store) ListIPsByTask(taskID string, limit int) ([]IP, error) {
	if limit == 0 {
		limit = 5000
	}
	rows, err := s.db.Query(`SELECT id, ip, domain, task_id, created_at FROM ips WHERE task_id=? ORDER BY ip LIMIT ?`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]IP, 0)
	for rows.Next() {
		var ip IP
		if err := rows.Scan(&ip.ID, &ip.IP, &ip.Domain, &ip.TaskID, &ip.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

func (s *Store) ListPortsByTask(taskID string, limit int) ([]Port, error) {
	if limit == 0 {
		limit = 2000
	}
	rows, err := s.db.Query(`SELECT id, ip, port, protocol, service, product, version, banner, title, confidence, task_id, created_at FROM ports WHERE task_id=? ORDER BY ip, port LIMIT ?`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPorts(rows)
}

func scanPorts(rows *sql.Rows) ([]Port, error) {
	out := make([]Port, 0)
	for rows.Next() {
		var p Port
		if err := rows.Scan(&p.ID, &p.IP, &p.Port, &p.Protocol, &p.Service, &p.Product, &p.Version, &p.Banner, &p.Title, &p.Confidence, &p.TaskID, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) ListSites(limit int) ([]Site, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := s.db.Query(`SELECT id, ip, port, url, title, status_code, server, fingerprint, screenshot, task_id, created_at
		FROM sites AS site
		WHERE NOT EXISTS (
			SELECT 1 FROM sites AS newer
			WHERE newer.url=site.url
			AND (newer.created_at>site.created_at OR (newer.created_at=site.created_at AND newer.rowid>site.rowid))
		)
		ORDER BY url LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSites(rows)
}

func (s *Store) ListSitesByTask(taskID string, limit int) ([]Site, error) {
	if limit == 0 {
		limit = 2000
	}
	rows, err := s.db.Query(`SELECT id, ip, port, url, title, status_code, server, fingerprint, screenshot, task_id, created_at FROM sites WHERE task_id=? ORDER BY url LIMIT ?`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSites(rows)
}

func scanSites(rows *sql.Rows) ([]Site, error) {
	out := make([]Site, 0)
	for rows.Next() {
		var site Site
		if err := rows.Scan(&site.ID, &site.IP, &site.Port, &site.URL, &site.Title, &site.StatusCode, &site.Server, &site.Fingerprint, &site.Screenshot, &site.TaskID, &site.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, site)
	}
	return out, rows.Err()
}

func (s *Store) ListLeaksByTask(taskID string, limit int) ([]Leak, error) {
	if limit == 0 {
		limit = 2000
	}
	rows, err := s.db.Query(`SELECT id, task_id, url, path, type, status_code, created_at FROM leaks WHERE task_id=? ORDER BY url LIMIT ?`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Leak, 0)
	for rows.Next() {
		var l Leak
		if err := rows.Scan(&l.ID, &l.TaskID, &l.URL, &l.Path, &l.Type, &l.StatusCode, &l.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// SearchResult 跨表搜索命中结果。
type SearchResult struct {
	Type   string `json:"type"`   // domain / subdomain / ip / port / site / leak
	Value  string `json:"value"`  // 主显示值
	Detail string `json:"detail"` // 补充信息
	TaskID string `json:"task_id"`
}

// Search 跨资产库模糊搜索域名、子域名、IP、标题、URL、指纹、泄露路径。
func (s *Store) Search(q string, limit int) ([]SearchResult, error) {
	if limit <= 0 {
		limit = 200
	}
	like := "%" + q + "%"
	out := make([]SearchResult, 0)
	add := func(typ, val, detail, taskID string) {
		out = append(out, SearchResult{Type: typ, Value: val, Detail: detail, TaskID: taskID})
	}

	queries := []struct {
		sql   string
		typ   string
		build func(vals []any) (val, detail, taskID string)
	}{
		{`SELECT domain, source, '' FROM domains WHERE domain LIKE ? LIMIT ?`, "domain", func(v []any) (string, string, string) { return v[0].(string), "根域名", "" }},
		{`SELECT subdomain, ip, task_id FROM subdomains WHERE subdomain LIKE ? OR ip LIKE ? LIMIT ?`, "subdomain", func(v []any) (string, string, string) { return v[0].(string), v[1].(string), v[2].(string) }},
		{`SELECT ip, title, task_id FROM ports WHERE ip LIKE ? OR service LIKE ? OR title LIKE ? LIMIT ?`, "port", func(v []any) (string, string, string) { return v[0].(string), v[1].(string), v[2].(string) }},
		{`SELECT url, title, task_id FROM sites WHERE url LIKE ? OR title LIKE ? OR fingerprint LIKE ? LIMIT ?`, "site", func(v []any) (string, string, string) { return v[0].(string), v[1].(string), v[2].(string) }},
		{`SELECT url, path, task_id FROM leaks WHERE url LIKE ? OR path LIKE ? LIMIT ?`, "leak", func(v []any) (string, string, string) { return v[0].(string), v[1].(string), v[2].(string) }},
	}

	for _, qq := range queries {
		var args []any
		switch qq.typ {
		case "domain":
			args = []any{like, limit}
		case "subdomain":
			args = []any{like, like, limit}
		case "port":
			args = []any{like, like, like, limit}
		case "site":
			args = []any{like, like, like, limit}
		case "leak":
			args = []any{like, like, limit}
		}
		rows, err := s.db.Query(qq.sql, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var a, b, c string
			if err := rows.Scan(&a, &b, &c); err != nil {
				rows.Close()
				return nil, err
			}
			val, detail, taskID := qq.build([]any{a, b, c})
			add(qq.typ, val, detail, taskID)
			if len(out) >= limit {
				rows.Close()
				return out, nil
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err // 迭代错误不静默，避免返回截断结果
		}
	}
	return out, nil
}
