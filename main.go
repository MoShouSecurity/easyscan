package main

import (
	"context"
	"embed"
	"fmt"
	"os"
	"strings"

	"easyscan/core"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// helper 模式：被提权机制重新执行（macOS/Linux sudo/osascript/pkexec，Windows UAC runas），
	// 用 ksubdomain 枚举子域名。默认输出到 stdout；Windows UAC 提权进程无法继承 stdout，
	// 通过 --ksubdomain-out <path> 将结果写入临时文件供父进程读取。
	if len(os.Args) >= 3 && os.Args[1] == "--ksubdomain-enum" {
		subs, err := core.EnumerateWithKsubdomain(context.Background(), os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		output := strings.Join(subs, "\n")
		if len(os.Args) >= 5 && os.Args[3] == "--ksubdomain-out" {
			if err := os.WriteFile(os.Args[4], []byte(output), 0o600); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		}
		fmt.Println(output)
		return
	}

	app := NewApp()

	err := wails.Run(&options.App{
		Title:     "Easy Scan",
		Width:     1280,
		Height:    800,
		MinWidth:  1024,
		MinHeight: 700,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 15, G: 20, B: 35, A: 1},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		OnBeforeClose:    app.beforeClose,
		Bind: []interface{}{
			app,
		},
	})
	if err != nil {
		println("Error:", err.Error())
	}
}
