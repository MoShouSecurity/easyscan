package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCSVSafe(t *testing.T) {
	for _, input := range []string{"=1+1", "+cmd", "-2+3", "@SUM(A1:A2)", "\tformula", "\rformula"} {
		if got := csvSafe(input); got != "'"+input {
			t.Errorf("csvSafe(%q) = %q", input, got)
		}
	}
	if got := csvSafe("normal"); got != "normal" {
		t.Errorf("csvSafe(normal) = %q", got)
	}
}

func TestPathWithinRejectsTraversalAndSymlink(t *testing.T) {
	root := t.TempDir()
	shotDir := filepath.Join(root, "screenshots")
	if err := os.MkdirAll(shotDir, 0o700); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(shotDir, "ok.png")
	outside := filepath.Join(root, "secret")
	if err := os.WriteFile(inside, []byte("png"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !pathWithin(shotDir, inside) {
		t.Fatal("inside screenshot rejected")
	}
	if pathWithin(shotDir, outside) {
		t.Fatal("outside path accepted")
	}
	link := filepath.Join(shotDir, "link.png")
	if err := os.Symlink(outside, link); err == nil && pathWithin(shotDir, link) {
		t.Fatal("symlink escape accepted")
	}
}
