.PHONY: test test-frontend cli desktop run-cli clean

# 运行单元测试
test:
	go test ./...
	$(MAKE) test-frontend

# 静态前端回归测试（Node.js 18+，无需安装 npm 依赖）
test-frontend:
	node --test frontend/tests/*.test.cjs

# 构建命令行版（纯 Go，免 CGO）
cli:
	CGO_ENABLED=0 go build -o bin/easyscan ./cmd/easyscan

# 构建桌面版（Wails）
desktop:
	wails build

# 快速运行命令行版
run-cli:
	go run ./cmd/easyscan -target example.com -ports test

# 清理
clean:
	rm -rf build bin
