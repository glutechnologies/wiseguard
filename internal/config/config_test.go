package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadFileAndEnvironment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.ini")
	contents := "profiles_dir = ./profiles\nwstunnel_url = wss://tunnel.example\nport_base = 54000\nauto_timeout = 5s\nwstunnel_arg = --http-upgrade-path-prefix\nwstunnel_arg = vpn\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WISEGUARD_PORT_BASE", "55000")
	c, gotPath, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != path {
		t.Fatalf("path=%q", gotPath)
	}
	if c.PortBase != 55000 || c.AutoTimeout != 5*time.Second {
		t.Fatalf("unexpected config: %#v", c)
	}
	if c.WSTunnelURL != "wss://tunnel.example" || len(c.WSTunnelArgs) != 2 {
		t.Fatalf("unexpected config: %#v", c)
	}
}

func TestLoadRejectsUnknownSetting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.ini")
	if err := os.WriteFile(path, []byte("mystery = value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(path); err == nil {
		t.Fatal("expected error")
	}
}
