package core

import "testing"

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
