//go:build darwin

package core

/*
#cgo LDFLAGS: -framework CoreGraphics
#include <CoreGraphics/CoreGraphics.h>
*/
import "C"

// hasScreenCapturePermission 检查 macOS 屏幕录制（Screen Recording）权限。
func hasScreenCapturePermission() bool {
	return bool(C.CGPreflightScreenCaptureAccess())
}
