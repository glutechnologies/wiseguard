package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const stateVersion = 2

type state struct {
	Profile       string    `json:"profile"`
	ProfilePath   string    `json:"profile_path"`
	Interface     string    `json:"interface,omitempty"`
	Mode          string    `json:"mode"`
	WSTunnelPID   int       `json:"wstunnel_pid,omitempty"`
	RemoteTargets []string  `json:"remote_targets,omitempty"`
	LocalTargets  []string  `json:"local_targets,omitempty"`
	StartedAt     time.Time `json:"started_at"`
}

type stateStore struct {
	Version int              `json:"version"`
	Tunnels map[string]state `json:"tunnels"`
}

func newStateStore() stateStore {
	return stateStore{Version: stateVersion, Tunnels: make(map[string]state)}
}

func loadStateStore(path string) (stateStore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return stateStore{}, err
	}
	var store stateStore
	if err := json.Unmarshal(data, &store); err == nil && store.Tunnels != nil {
		if store.Version == 0 {
			store.Version = stateVersion
		}
		return store, nil
	}

	// Version 1 stored one tunnel as the top-level object. Accept it so
	// existing installations migrate automatically on their next write.
	var legacy state
	if err := json.Unmarshal(data, &legacy); err != nil {
		return stateStore{}, fmt.Errorf("decode state file: %w", err)
	}
	if legacy.Profile == "" {
		return stateStore{}, fmt.Errorf("decode state file: missing profile")
	}
	store = newStateStore()
	store.Tunnels[legacy.Profile] = legacy
	return store, nil
}

func loadStateStoreOrEmpty(path string) (stateStore, error) {
	store, err := loadStateStore(path)
	if errors.Is(err, os.ErrNotExist) {
		return newStateStore(), nil
	}
	return store, err
}

func saveStateStore(path string, store stateStore) error {
	if len(store.Tunnels) == 0 {
		return removeStateStore(path)
	}
	store.Version = stateVersion
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".state-*")
	if err != nil {
		return fmt.Errorf("create state file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace state file: %w", err)
	}
	return nil
}

func removeStateStore(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func stateNames(store stateStore) []string {
	names := make([]string, 0, len(store.Tunnels))
	for name := range store.Tunnels {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func withLockedState(path string, fn func(*stateStore) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	lock, err := lockStateFile(path + ".lock")
	if err != nil {
		return err
	}
	defer unlockStateFile(lock)

	store, err := loadStateStoreOrEmpty(path)
	if err != nil {
		return err
	}
	if err := fn(&store); err != nil {
		return err
	}
	return saveStateStore(path, store)
}
