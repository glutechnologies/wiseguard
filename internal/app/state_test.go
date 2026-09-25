package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadStateStoreMigratesLegacyState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	legacy := state{
		Profile:     "office",
		ProfilePath: "/profiles/office.conf",
		Interface:   "utun7",
		Mode:        "wstunnel",
		StartedAt:   time.Unix(100, 0),
	}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := loadStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(store.Tunnels) != 1 || store.Tunnels["office"].Interface != "utun7" {
		t.Fatalf("legacy state was not migrated: %#v", store)
	}
}

func TestAvailablePortBaseSkipsOtherProfiles(t *testing.T) {
	originalPortAvailable := udpPortAvailable
	udpPortAvailable = func(string, int) bool { return true }
	t.Cleanup(func() { udpPortAvailable = originalPortAvailable })

	c := cli{}
	c.config.PortBase = 55182
	c.config.BindAddress = "127.0.0.1"
	store := newStateStore()
	store.Tunnels["first"] = state{LocalTargets: []string{"127.0.0.1:55182", "127.0.0.1:55183"}}
	base, err := c.availablePortBase(store, 2)
	if err != nil {
		t.Fatal(err)
	}
	if base != 55184 {
		t.Fatalf("got port base %d, want 55184", base)
	}
}
