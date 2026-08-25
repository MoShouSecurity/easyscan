package core

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
	"time"
)

var crashLogState struct {
	sync.RWMutex
	dir     string
	writeMu sync.Mutex
}

// SetCrashLogDir 设置 panic 日志目录。GUI 启动时应指向应用配置目录。
func SetCrashLogDir(dir string) {
	crashLogState.Lock()
	crashLogState.dir = dir
	crashLogState.Unlock()
}

// recoveredPanicError 持久化当前 goroutine 的堆栈，并返回适合写入任务状态的短错误。
func recoveredPanicError(component string, recovered any) error {
	crashLogState.RLock()
	dir := crashLogState.dir
	crashLogState.RUnlock()
	if dir == "" {
		return fmt.Errorf("%s 异常: %v（崩溃日志目录未初始化）", component, recovered)
	}
	crashLogState.writeMu.Lock()
	defer crashLogState.writeMu.Unlock()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("%s 异常: %v（创建崩溃日志目录失败: %w）", component, recovered, err)
	}
	logPath := filepath.Join(dir, "crash.log")
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("%s 异常: %v（写入崩溃日志失败: %w）", component, recovered, err)
	}
	_, writeErr := fmt.Fprintf(file, "[%s] component=%s panic=%v\n%s\n", time.Now().Format(time.RFC3339Nano), component, recovered, debug.Stack())
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("%s 异常: %v（写入崩溃日志失败: %w）", component, recovered, writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("%s 异常: %v（关闭崩溃日志失败: %w）", component, recovered, closeErr)
	}
	if err := os.Chmod(logPath, 0o600); err != nil {
		return fmt.Errorf("%s 异常: %v（收紧崩溃日志权限失败: %w）", component, recovered, err)
	}
	return fmt.Errorf("%s 异常: %v（详情见 %s）", component, recovered, logPath)
}
