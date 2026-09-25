package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ProfilesDir  string
	StateFile    string
	LogFile      string
	WSTunnelURL  string
	WG           string
	WGQuick      string
	WSTunnel     string
	BindAddress  string
	TLSVerify    bool
	PortBase     int
	AutoTimeout  time.Duration
	WSTunnelArgs []string
}

func Load(explicit string) (Config, string, error) {
	home, err := homeDir()
	if err != nil {
		return Config{}, "", err
	}
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		configHome = filepath.Join(home, ".config")
	}
	stateHome := os.Getenv("XDG_STATE_HOME")
	if stateHome == "" {
		stateHome = filepath.Join(home, ".local", "state")
	}

	c := Config{
		ProfilesDir: filepath.Join(configHome, "wiseguard", "profiles"),
		StateFile:   filepath.Join(stateHome, "wiseguard", "state.json"),
		LogFile:     filepath.Join(stateHome, "wiseguard", "wstunnel.log"),
		WG:          "wg",
		WGQuick:     "wg-quick",
		WSTunnel:    "wstunnel",
		BindAddress: "127.0.0.1",
		TLSVerify:   true,
		PortBase:    55182,
		AutoTimeout: 3 * time.Second,
	}

	path := explicit
	if path == "" {
		path = os.Getenv("WISEGUARD_CONFIG")
	}
	if path == "" {
		path = filepath.Join(configHome, "wiseguard", "config.ini")
	}
	path = expandHome(path, home)
	if err := readFile(path, &c, explicit != "" || os.Getenv("WISEGUARD_CONFIG") != ""); err != nil {
		return Config{}, path, err
	}
	if err := applyEnv(&c); err != nil {
		return Config{}, path, err
	}

	c.ProfilesDir = absExpand(c.ProfilesDir, home)
	c.StateFile = absExpand(c.StateFile, home)
	c.LogFile = absExpand(c.LogFile, home)
	if c.PortBase < 1 || c.PortBase > 65535 {
		return Config{}, path, fmt.Errorf("port_base must be between 1 and 65535")
	}
	if c.AutoTimeout <= 0 {
		return Config{}, path, fmt.Errorf("auto_timeout must be greater than zero")
	}
	return c, path, nil
}

func readFile(path string, c *Config, required bool) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) && !required {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open config %s: %w", path, err)
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for lineNo := 1; s.Scan(); lineNo++ {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || (strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]")) {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("%s:%d: expected key = value", path, lineNo)
		}
		if err := set(c, strings.TrimSpace(strings.ToLower(key)), strings.TrimSpace(value)); err != nil {
			return fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
	}
	if err := s.Err(); err != nil {
		return fmt.Errorf("read config %s: %w", path, err)
	}
	return nil
}

func set(c *Config, key, value string) error {
	switch key {
	case "profiles_dir":
		c.ProfilesDir = value
	case "state_file":
		c.StateFile = value
	case "log_file":
		c.LogFile = value
	case "wstunnel_url":
		c.WSTunnelURL = value
	case "wg_binary":
		c.WG = value
	case "wg_quick_binary":
		c.WGQuick = value
	case "wstunnel_binary":
		c.WSTunnel = value
	case "bind_address":
		c.BindAddress = value
	case "tls_verify":
		b, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid tls_verify: %w", err)
		}
		c.TLSVerify = b
	case "port_base":
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid port_base: %w", err)
		}
		c.PortBase = n
	case "auto_timeout":
		d, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid auto_timeout: %w", err)
		}
		c.AutoTimeout = d
	case "wstunnel_arg":
		c.WSTunnelArgs = append(c.WSTunnelArgs, value)
	default:
		return fmt.Errorf("unknown setting %q", key)
	}
	return nil
}

func applyEnv(c *Config) error {
	values := []struct {
		name string
		dst  *string
	}{
		{"WISEGUARD_PROFILES_DIR", &c.ProfilesDir},
		{"WISEGUARD_STATE_FILE", &c.StateFile},
		{"WISEGUARD_LOG_FILE", &c.LogFile},
		{"WISEGUARD_WSTUNNEL_URL", &c.WSTunnelURL},
		{"WISEGUARD_WG_BINARY", &c.WG},
		{"WISEGUARD_WG_QUICK_BINARY", &c.WGQuick},
		{"WISEGUARD_WSTUNNEL_BINARY", &c.WSTunnel},
		{"WISEGUARD_BIND_ADDRESS", &c.BindAddress},
	}
	for _, item := range values {
		if value, ok := os.LookupEnv(item.name); ok {
			*item.dst = value
		}
	}
	if value, ok := os.LookupEnv("WISEGUARD_PORT_BASE"); ok {
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("WISEGUARD_PORT_BASE: %w", err)
		}
		c.PortBase = n
	}
	if value, ok := os.LookupEnv("WISEGUARD_AUTO_TIMEOUT"); ok {
		d, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("WISEGUARD_AUTO_TIMEOUT: %w", err)
		}
		c.AutoTimeout = d
	}
	if value, ok := os.LookupEnv("WISEGUARD_TLS_VERIFY"); ok {
		b, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("WISEGUARD_TLS_VERIFY: %w", err)
		}
		c.TLSVerify = b
	}
	if value, ok := os.LookupEnv("WISEGUARD_WSTUNNEL_ARGS"); ok {
		c.WSTunnelArgs = strings.Fields(value)
	}
	return nil
}

func homeDir() (string, error) {
	// sudo normally replaces HOME. Use the invoking user's home so the same
	// configuration is found before and after privilege escalation.
	if os.Geteuid() == 0 {
		if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && sudoUser != "root" {
			if u, err := user.Lookup(sudoUser); err == nil && u.HomeDir != "" {
				return u.HomeDir, nil
			}
		}
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return home, nil
	}
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("determine home directory: %w", err)
	}
	return u.HomeDir, nil
}

func expandHome(path, home string) string {
	if path == "~" {
		return home
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, path[2:])
	}
	return path
}

func absExpand(path, home string) string {
	path = expandHome(path, home)
	if absolute, err := filepath.Abs(path); err == nil {
		return absolute
	}
	return path
}
