package app

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHandshakeParsing(t *testing.T) {
	if hasHandshake("key\t0\n") {
		t.Fatal("zero is not a handshake")
	}
	if !hasHandshake("key\t1720000000\n") {
		t.Fatal("expected handshake")
	}
}

func TestFormatDestination(t *testing.T) {
	if got := formatDestination("vpn.example", 51820); got != "vpn.example:51820" {
		t.Fatal(got)
	}
	if got := formatDestination("2001:db8::1", 51820); got != "[2001:db8::1]:51820" {
		t.Fatal(got)
	}
}

func TestNormalizedWSTunnelEnv(t *testing.T) {
	got := normalizedWSTunnelEnv([]string{"PATH=/bin", "NO_COLOR=1", "OTHER=value"})
	want := []string{"PATH=/bin", "NO_COLOR=true", "OTHER=value"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestTunneledLifecycleWithFakeBinaries(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	profilesDir := filepath.Join(dir, "profiles")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(profilesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "interface-up")
	events := filepath.Join(dir, "events")
	writeExecutable(t, filepath.Join(binDir, "wg"), fmt.Sprintf(`#!/bin/sh
if [ "$1 $2" = "show interfaces" ]; then
  if [ -f %q ]; then printf 'wgtest\n'; fi
  exit 0
fi
printf 'wg %%s\n' "$*" >> %q
`, marker, events))
	writeExecutable(t, filepath.Join(binDir, "wg-quick"), fmt.Sprintf(`#!/bin/sh
printf 'wg-quick %%s\n' "$*" >> %q
if [ "$1" = "up" ]; then touch %q; else rm -f %q; fi
`, events, marker, marker))
	writeExecutable(t, filepath.Join(binDir, "wstunnel"), fmt.Sprintf(`#!/bin/sh
printf 'wstunnel %%s\n' "$*" >> %q
exec sleep 30
`, events))
	profile := `[Interface]
PrivateKey = secret
[Peer]
PublicKey = peerkey=
Endpoint = vpn.example:51820
`
	if err := os.WriteFile(filepath.Join(profilesDir, "office.conf"), []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "state.json")
	configPath := filepath.Join(dir, "config.ini")
	configText := fmt.Sprintf("profiles_dir=%s\nstate_file=%s\nlog_file=%s\nwstunnel_url=wss://tunnel.example\nwg_binary=%s\nwg_quick_binary=%s\nwstunnel_binary=%s\n", profilesDir, statePath, filepath.Join(dir, "wstunnel.log"), filepath.Join(binDir, "wg"), filepath.Join(binDir, "wg-quick"), filepath.Join(binDir, "wstunnel"))
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	if err := Run(context.Background(), []string{"--config", configPath, "up", "--mode", "wstunnel", "office"}, &out, &errOut, "test"); err != nil {
		t.Fatalf("up: %v; stderr=%s", err, errOut.String())
	}
	t.Cleanup(func() {
		if s, err := loadState(statePath); err == nil {
			_ = stopProcess(s.WSTunnelPID)
		}
	})
	data, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	eventText := string(data)
	for _, expected := range []string{"wstunnel client --tls-verify-certificate -L udp://127.0.0.1:55182:vpn.example:51820?timeout_sec=0 wss://tunnel.example", "wg-quick up", "wg set wgtest peer peerkey= endpoint 127.0.0.1:55182"} {
		if !strings.Contains(eventText, expected) {
			t.Fatalf("events missing %q:\n%s", expected, eventText)
		}
	}
	if err := Run(context.Background(), []string{"--config", configPath, "down"}, &out, &errOut, "test"); err != nil {
		t.Fatalf("down: %v", err)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("state still exists: %v", err)
	}
}

func writeExecutable(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
}
