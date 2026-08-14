//go:build windows

package core

import (
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// enumerateWithKsubdomainPrivileged Windows 上以管理员权限枚举子域名：
//  1. 当前进程已是管理员 → 直接库内直调（SDK 原始 socket 无需再提权）；
//  2. 非管理员 → ShellExecuteExW("runas") 弹 UAC 授权框，以管理员重新执行当前二进制
//     （--ksubdomain-enum helper 模式）。UAC 提权的进程无法继承 stdout，
//     因此 helper 将结果写入临时文件，父进程等待进程退出后读取。
//
// 用户取消 UAC 或提权失败时返回错误，由调用方降级为纯 Go 字典爆破。
func enumerateWithKsubdomainPrivileged(domain string) ([]string, error) {
	// 1. 已是管理员则子进程隔离执行（helper 模式，继承管理员权限）。
	// 不走库内直调：SDK Fatalf（os.Exit）会杀死 GUI 进程，子进程隔离后崩溃只影响 helper。
	if tok, err := windows.OpenCurrentProcessToken(); err == nil {
		if tok.IsElevated() {
			_ = tok.Close()
			return enumerateWithKsubdomainIsolated(context.Background(), domain)
		}
		_ = tok.Close()
	}

	// 2. 非管理员：UAC runas 提权执行 helper。
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp("", "easyscan-ksub-*.txt")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpPath)

	params := fmt.Sprintf(`--ksubdomain-enum %s --ksubdomain-out "%s"`, domain, tmpPath)
	proc, err := shellExecuteRunas(exe, params)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(proc)

	// 等待 helper 进程退出（ksubdomain 10 万字典爆破耗时较长，给足超时）。
	deadline := time.Now().Add(10 * time.Minute)
	for {
		event, _ := windows.WaitForSingleObject(proc, 1000)
		if event == windows.WAIT_OBJECT_0 {
			break
		}
		if time.Now().After(deadline) {
			_ = windows.TerminateProcess(proc, 1)
			return nil, fmt.Errorf("ksubdomain 提权执行超时")
		}
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("ksubdomain 提权执行失败（可能缺少 Npcap 驱动或授权被取消）")
		}
		return nil, err
	}
	return parseSubdomainOutput(data), nil
}

// shellExecuteExInfo ShellExecuteExW 参数结构。
type shellExecuteExInfo struct {
	cbSize         uint32
	fMask          uint32
	hwnd           uintptr
	lpVerb         *uint16
	lpFile         *uint16
	lpParameters   *uint16
	lpDirectory    *uint16
	nShow          int32
	hInstApp       uintptr
	lpIDList       uintptr
	lpClass        *uint16
	hkeyClass      uintptr
	dwHotKey       uint32
	hIconOrMonitor uintptr
	hProcess       windows.Handle
}

const (
	seeMaskNoCloseProcess = 0x00000040 // 返回 hProcess，允许等待进程退出
	seeMaskNoConsole      = 0x00008000 // 不弹出控制台窗口
	swHide                = 0          // 隐藏窗口
	errorCancelled        = 1223       // ERROR_CANCELLED：用户在 UAC 框点了「否」
)

// shellExecuteRunas 用 ShellExecuteExW("runas") 弹 UAC 授权框提权执行 exe，返回进程句柄。
func shellExecuteRunas(exe, params string) (windows.Handle, error) {
	shell32 := windows.NewLazySystemDLL("shell32.dll")
	shellExecuteExW := shell32.NewProc("ShellExecuteExW")

	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return 0, err
	}
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return 0, err
	}
	paramPtr, err := windows.UTF16PtrFromString(params)
	if err != nil {
		return 0, err
	}

	var info shellExecuteExInfo
	info.cbSize = uint32(unsafe.Sizeof(info))
	info.fMask = seeMaskNoCloseProcess | seeMaskNoConsole
	info.lpVerb = verb
	info.lpFile = file
	info.lpParameters = paramPtr
	info.nShow = swHide

	ret, _, callErr := shellExecuteExW.Call(uintptr(unsafe.Pointer(&info)))
	if ret == 0 {
		if code, ok := callErr.(syscall.Errno); ok && code == errorCancelled {
			return 0, fmt.Errorf("用户取消了 UAC 授权")
		}
		return 0, fmt.Errorf("ShellExecuteExW runas 失败: %v", callErr)
	}
	if info.hProcess == 0 {
		return 0, fmt.Errorf("ShellExecuteExW 未返回进程句柄")
	}
	return info.hProcess, nil
}

// parseSubdomainOutput 解析 helper 输出的子域名（一行一个）。
// 与 Unix 端（privilege.go）同名函数按 build tag 分平台，逻辑保持一致。
// 非域名字面量的行（SDK 日志混入 stdout 的 [INFO] 等）直接丢弃。
func parseSubdomainOutput(out []byte) []string {
	subs := make([]string, 0)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if isSubdomainLine(line) {
			subs = append(subs, line)
		}
	}
	return subs
}
