package core

import (
	"testing"
)

// TestParseMasscanJSON 验证 -oJ 输出的存活 IP 提取（数组 / 前缀噪音 / 逐行 / 去重 / 非法）。
func TestParseMasscanJSON(t *testing.T) {
	// 数组格式（ping 模式下 ports 可为空数组）。
	data := []byte(`[
  {"ip": "10.0.0.1", "timestamp": "1564774451", "ports": [{"port": 0, "proto": "icmp", "status": "open"}]},
  {"ip": "10.0.0.2", "timestamp": "1564774452", "ports": []}
]`)
	ips, err := parseMasscanJSON(data)
	if err != nil || len(ips) != 2 {
		t.Fatalf("parseMasscanJSON(array) = %v err=%v; want 2 IPs", ips, err)
	}

	// stdout 前缀噪音（masscan 可能输出 [WARNING] 提示行）。
	data = []byte("[WARNING] root required for ping scan, running anyway\n[\n  {\"ip\": \"10.0.0.3\", \"timestamp\": \"1564774453\"}\n]\n")
	ips, err = parseMasscanJSON(data)
	if err != nil || len(ips) != 1 || ips[0] != "10.0.0.3" {
		t.Fatalf("parseMasscanJSON(noise) = %v err=%v; want [10.0.0.3]", ips, err)
	}

	// 逐行 JSON 对象。
	data = []byte(`{"ip": "10.0.0.4", "timestamp": "1", "ports": []}
{"ip": "10.0.0.5", "timestamp": "2", "ports": []}`)
	ips, err = parseMasscanJSON(data)
	if err != nil || len(ips) != 2 {
		t.Fatalf("parseMasscanJSON(lines) = %v err=%v; want 2 IPs", ips, err)
	}

	// 去重。
	data = []byte(`[{"ip": "10.0.0.6", "timestamp": "1"}, {"ip": "10.0.0.6", "timestamp": "2"}]`)
	ips, err = parseMasscanJSON(data)
	if err != nil || len(ips) != 1 {
		t.Fatalf("parseMasscanJSON(dedup) = %v err=%v; want [10.0.0.6]", ips, err)
	}

	// 正则兜底（JSON 解析失败但含 ip 字段）。
	data = []byte(`{"ip": "10.0.0.7", "timestamp": "1", "ports": [`)
	ips, err = parseMasscanJSON(data)
	if err != nil || len(ips) != 1 || ips[0] != "10.0.0.7" {
		t.Fatalf("parseMasscanJSON(regex) = %v err=%v; want [10.0.0.7]", ips, err)
	}

	// 完全非法输出 → 报错（触发调用方降级）。
	if _, err := parseMasscanJSON([]byte("garbage output")); err == nil {
		t.Fatal("parseMasscanJSON(garbage) 应报错")
	}
}

// TestNmapPortArgsCustom 验证 custom 模式透传端口规范、test 模式为 6 个常见端口。
func TestNmapPortArgsCustom(t *testing.T) {
	if args := nmapPortArgs("custom", "1-1000,8080"); len(args) != 2 || args[0] != "-p" || args[1] != "1-1000,8080" {
		t.Fatalf("nmapPortArgs(custom) = %v", args)
	}
	if args := nmapPortArgs("test", ""); len(args) != 2 || args[1] != "22,80,443,3389,445,8080" {
		t.Fatalf("nmapPortArgs(test) = %v", args)
	}
}
