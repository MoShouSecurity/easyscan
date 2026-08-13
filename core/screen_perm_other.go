//go:build !darwin

package core

// hasScreenCapturePermission 非 macOS 平台无屏幕录制权限概念，默认通过。
func hasScreenCapturePermission() bool {
	return true
}
