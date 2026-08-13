// Package core 是 EasyScan 的核心引擎：领域模型、SQLite 存储、侦察流水线与任务调度。
// 该包不依赖任何 GUI 框架，可被 CLI、桌面应用或测试独立使用。
package core

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// newID 生成 16 字节随机 ID。
func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func nowUnix() int64 { return time.Now().Unix() }

// TaskStatus 任务状态。
type TaskStatus string

const (
	TaskPending  TaskStatus = "pending"
	TaskRunning  TaskStatus = "running"
	TaskFinished TaskStatus = "finished"
	TaskFailed   TaskStatus = "failed"
)

// TaskType 任务类型。
type TaskType string

const (
	TaskDomain TaskType = "domain" // 域名侦察
	TaskIP     TaskType = "ip"     // IP / 网段侦察
)

// Domain 根域名资产。
type Domain struct {
	ID        string `json:"id"`
	Domain    string `json:"domain"`
	Source    string `json:"source"`
	CreatedAt int64  `json:"created_at"`
}

// Subdomain 子域名资产，含解析到的 IP。
type Subdomain struct {
	ID        string `json:"id"`
	Domain    string `json:"domain"`    // 所属根域名
	Subdomain string `json:"subdomain"` // 完整子域名
	IP        string `json:"ip"`
	Source    string `json:"source"`
	TaskID    string `json:"task_id"`
	CreatedAt int64  `json:"created_at"`
}

// IP 存活 IP 资产（即使无开放端口也记录）。
type IP struct {
	ID        string `json:"id"`
	IP        string `json:"ip"`
	Domain    string `json:"domain"` // 关联域名，可为空
	TaskID    string `json:"task_id"`
	CreatedAt int64  `json:"created_at"`
}

// Port 开放端口与服务识别结果。
type Port struct {
	ID        string `json:"id"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"` // tcp / udp
	Service   string `json:"service"`
	Product   string `json:"product"` // 产品名，如 nginx / MySQL
	Version   string `json:"version"` // 版本号，如 1.18.0 / 5.7.32
	Banner    string `json:"banner"`
	Title     string `json:"title"`
	TaskID    string `json:"task_id"`
	CreatedAt int64  `json:"created_at"`
}

// Site Web 站点指纹识别结果。
type Site struct {
	ID          string `json:"id"`
	IP          string `json:"ip"`
	Port        int    `json:"port"`
	URL         string `json:"url"`
	Title       string `json:"title"`
	StatusCode  int    `json:"status_code"`
	Server      string `json:"server"`
	Fingerprint string `json:"fingerprint"`
	Screenshot  string `json:"screenshot"` // 截图文件路径，空表示未截图
	TaskID      string `json:"task_id"`
	CreatedAt   int64  `json:"created_at"`
}

// Leak 敏感信息/文件泄漏检测结果。
type Leak struct {
	ID         string `json:"id"`
	TaskID     string `json:"task_id"`
	URL        string `json:"url"`
	Path       string `json:"path"` // 泄露路径，如 /.git/config
	Type       string `json:"type"` // 泄露类型，如 git / env / backup
	StatusCode int    `json:"status_code"`
	CreatedAt  int64  `json:"created_at"`
}

// Task 侦察任务记录。
type Task struct {
	ID         string     `json:"id"`
	Target     string     `json:"target"`
	Type       TaskType   `json:"type"`
	Status     TaskStatus `json:"status"`
	Progress   int        `json:"progress"`
	Message    string     `json:"message"`
	Params     string     `json:"params"`
	CreatedAt  int64      `json:"created_at"`
	FinishedAt int64      `json:"finished_at"`
}
