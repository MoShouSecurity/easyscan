package main

import (
	"context"
	"embed"
	"fmt"
	"os"

	"easyscan/core"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// helper 模式：被提权机制以 root 重新执行，用 ksubdomain 枚举并输出结果到 stdout。
	if len(os.Args) >= 3 && os.Args[1] == "--ksubdomain-enum" {
		subs, err := core.EnumerateWithKsubdomain(context.Background(), os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		for _, s := range subs {
			fmt.Println(s)
		}
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
		Bind: []interface{}{
			app,
		},
	})
	if err != nil {
		println("Error:", err.Error())
	}
}
