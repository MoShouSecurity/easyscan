package core

import (
	"os"
	"strings"
	"testing"
)

// TestNmapTargetArgsSmall 少量目标直接作为命令行参数传递。
func TestNmapTargetArgsSmall(t *testing.T) {
	targets := []string{"127.0.0.1", "10.10.0.5"}
	args, cleanup, err := nmapTargetArgs(targets)
	if err != nil {
		t.Fatalf("nmapTargetArgs: %v", err)
	}
	defer cleanup()
	if len(args) != 2 || args[0] != "127.0.0.1" || args[1] != "10.10.0.5" {
		t.Fatalf("args = %v; want 原样返回 targets", args)
	}
}

// TestNmapTargetArgsLarge 大量目标（如 /16 网段）改用 -iL 临时文件，避免超出 Windows 命令行长度限制。
func TestNmapTargetArgsLarge(t *testing.T) {
	targets := make([]string, 5000)
	for i := range targets {
		targets[i] = "10.10.0.1" // 内容不重要，仅验证数量
	}
	args, cleanup, err := nmapTargetArgs(targets)
	if err != nil {
		t.Fatalf("nmapTargetArgs: %v", err)
	}
	if len(args) != 2 || args[0] != "-iL" || args[1] == "" {
		t.Fatalf("args = %v; want [-iL <临时文件>]", args)
	}
	data, err := os.ReadFile(args[1])
	if err != nil {
		t.Fatalf("读取目标文件: %v", err)
	}
	if got := len(strings.Split(strings.TrimSpace(string(data)), "\n")); got != len(targets) {
		t.Fatalf("目标文件行数 = %d; want %d", got, len(targets))
	}
	cleanup()
	if _, err := os.Stat(args[1]); !os.IsNotExist(err) {
		t.Fatalf("cleanup 后临时文件仍存在: %v", err)
	}
}

// TestParseNmapReportIP 验证 -sn 输出行的 IP 提取（纯 IP 与带主机名两种格式）。
func TestParseNmapReportIP(t *testing.T) {
	cases := map[string]string{
		"Nmap scan report for 10.10.0.5":                    "10.10.0.5",
		"Nmap scan report for localhost (127.0.0.1)":        "127.0.0.1",
		"Nmap scan report for gw.example.com (192.168.1.1)": "192.168.1.1",
		"Nmap scan report for some-hostname-only":           "",
	}
	for line, want := range cases {
		if got := parseNmapReportIP(line); got != want {
			t.Errorf("parseNmapReportIP(%q) = %q; want %q", line, got, want)
		}
	}
}

func TestParseNmapXML(t *testing.T) {
	xmlData := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
        <script id="http-title" output="Welcome to nginx!"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="open"/>
        <service name="mysql" product="MySQL" version="5.7.32"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>`)

	hosts, err := parseNmapXML(xmlData)
	if err != nil {
		t.Fatalf("parseNmapXML: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("len(hosts) = %d; want 1", len(hosts))
	}
	h := hosts[0]
	if h.IP != "192.168.1.1" {
		t.Fatalf("IP = %q; want 192.168.1.1", h.IP)
	}
	if len(h.Ports) != 2 {
		t.Fatalf("len(ports) = %d; want 2 (closed 22 应被忽略)", len(h.Ports))
	}

	p80 := h.Ports[0]
	if p80.Port != 80 || p80.Service != "http" || p80.Product != "nginx" || p80.Version != "1.18.0" {
		t.Fatalf("端口80解析错误: %+v", p80)
	}
	if p80.Title != "Welcome to nginx!" {
		t.Fatalf("端口80标题 = %q", p80.Title)
	}

	p3306 := h.Ports[1]
	if p3306.Port != 3306 || p3306.Service != "mysql" || p3306.Product != "MySQL" || p3306.Version != "5.7.32" {
		t.Fatalf("端口3306解析错误: %+v", p3306)
	}
}
