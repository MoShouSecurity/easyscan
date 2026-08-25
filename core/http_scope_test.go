package core

import (
	"net/url"
	"testing"
)

func TestHTTPOriginCanonicalDefaultPorts(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"https://apn.example.com:443/login", "https://apn.example.com/"},
		{"http://apn.example.com:80/login", "http://apn.example.com/"},
		{"https://apn.example.com:8443/login", "https://apn.example.com:8443/"},
		{"http://apn.example.com:443/login", "http://apn.example.com:443/"},
		{"https://[2001:db8::1]:443/login", "https://[2001:db8::1]/"},
	}
	for _, c := range cases {
		u, err := url.Parse(c.raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := httpOrigin(u); got != c.want {
			t.Errorf("httpOrigin(%q) = %q; want %q", c.raw, got, c.want)
		}
	}
}

func TestSiteScopeAllowsEquivalentDefaultPortOrigin(t *testing.T) {
	scope, err := newSiteScope(Site{
		IP:  "192.0.2.1",
		URL: "https://apn.example.com:443/",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{
		"https://apn.example.com/admin",
		"https://apn.example.com:443/admin",
	} {
		if !scope.allowsOrigin(candidate) {
			t.Errorf("同源默认端口 URL 被拒绝: %s", candidate)
		}
	}
	if scope.allowsOrigin("http://apn.example.com:443/admin") {
		t.Fatal("不同协议不应被视为同源")
	}
}
