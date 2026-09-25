package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/glutec/wiseguard/internal/config"
	"github.com/glutec/wiseguard/internal/wgconf"
)

type cli struct {
	out     io.Writer
	errOut  io.Writer
	config  config.Config
	version string
}

func Run(ctx context.Context, args []string, out, errOut io.Writer, version string) error {
	global := flag.NewFlagSet("wiseguard", flag.ContinueOnError)
	global.SetOutput(errOut)
	configPath := global.String("config", "", "configuration file")
	global.Usage = func() { printUsage(errOut) }
	if err := global.Parse(args); err != nil {
		return err
	}
	cfg, _, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	c := cli{out: out, errOut: errOut, config: cfg, version: version}
	rest := global.Args()
	if len(rest) == 0 {
		printUsage(out)
		return nil
	}
	switch rest[0] {
	case "list":
		return c.list(rest[1:])
	case "up":
		return c.up(ctx, rest[1:])
	case "down":
		return c.down(rest[1:])
	case "status":
		return c.status(rest[1:])
	case "version":
		fmt.Fprintln(out, version)
		return nil
	case "help", "-h", "--help":
		printUsage(out)
		return nil
	default:
		return fmt.Errorf("unknown command %q", rest[0])
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  wiseguard [--config FILE] list
  wiseguard [--config FILE] up [--mode auto|direct|wstunnel] [--foreground] PROFILE
  wiseguard [--config FILE] down
  wiseguard [--config FILE] status
  wiseguard version`)
}

func (c cli) list(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("list takes no arguments")
	}
	entries, err := os.ReadDir(c.config.ProfilesDir)
	if err != nil {
		return fmt.Errorf("read profiles directory %s: %w", c.config.ProfilesDir, err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.EqualFold(filepath.Ext(entry.Name()), ".conf") {
			names = append(names, strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name())))
		}
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintln(c.out, name)
	}
	return nil
}

func (c cli) up(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	fs.SetOutput(c.errOut)
	mode := fs.String("mode", "auto", "transport mode: auto, direct, or wstunnel")
	foreground := fs.Bool("foreground", false, "stay attached and stop the VPN on exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("up requires exactly one profile")
	}
	if *mode != "auto" && *mode != "direct" && *mode != "wstunnel" {
		return fmt.Errorf("invalid mode %q", *mode)
	}
	if existing, err := loadState(c.config.StateFile); err == nil {
		return fmt.Errorf("profile %s is already recorded as active (run down first)", existing.Profile)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	profile, path, err := c.resolveProfile(fs.Arg(0))
	if err != nil {
		return err
	}
	if err := c.requireBinaries(*mode); err != nil {
		return err
	}

	if *mode == "direct" {
		return c.startDirect(ctx, profile, path, *foreground)
	}
	peers, err := wgconf.Parse(path)
	if err != nil {
		return err
	}
	if c.config.PortBase+len(peers)-1 > 65535 {
		return fmt.Errorf("not enough UDP ports starting at port_base for %d peers", len(peers))
	}
	if *mode == "auto" {
		fmt.Fprintf(c.out, "Trying direct WireGuard for %s...\n", c.config.AutoTimeout)
		iface, err := c.wgQuickUp(path)
		if err != nil {
			return err
		}
		if c.waitHandshake(ctx, iface, c.config.AutoTimeout) {
			s := state{Profile: profile, ProfilePath: path, Interface: iface, Mode: "direct", StartedAt: time.Now()}
			if err := saveState(c.config.StateFile, s); err != nil {
				_ = c.wgQuickDown(path)
				return err
			}
			fmt.Fprintf(c.out, "Connected directly on %s.\n", iface)
			return c.maybeForeground(ctx, s, *foreground, nil)
		}
		if err := ctx.Err(); err != nil {
			_ = c.wgQuickDown(path)
			return err
		}
		fmt.Fprintln(c.out, "No direct handshake observed; falling back to wstunnel.")
		if err := c.wgQuickDown(path); err != nil {
			return fmt.Errorf("stop direct WireGuard before fallback: %w", err)
		}
	}
	return c.startTunneled(ctx, profile, path, peers, *foreground)
}

func (c cli) startDirect(ctx context.Context, profile, path string, foreground bool) error {
	iface, err := c.wgQuickUp(path)
	if err != nil {
		return err
	}
	s := state{Profile: profile, ProfilePath: path, Interface: iface, Mode: "direct", StartedAt: time.Now()}
	if err := saveState(c.config.StateFile, s); err != nil {
		_ = c.wgQuickDown(path)
		return err
	}
	fmt.Fprintf(c.out, "Connected directly on %s.\n", iface)
	return c.maybeForeground(ctx, s, foreground, nil)
}

func (c cli) startTunneled(ctx context.Context, profile, path string, peers []wgconf.Peer, foreground bool) error {
	if c.config.WSTunnelURL == "" {
		return fmt.Errorf("wstunnel_url (or WISEGUARD_WSTUNNEL_URL) is required")
	}
	args := []string{"client"}
	if c.config.TLSVerify {
		args = append(args, "--tls-verify-certificate")
	}
	var remoteTargets, localTargets []string
	for i, peer := range peers {
		local := fmt.Sprintf("%s:%d", c.config.BindAddress, c.config.PortBase+i)
		remote := peer.Endpoint
		forward := fmt.Sprintf("udp://%s:%s?timeout_sec=0", local, formatDestination(peer.Host, peer.Port))
		args = append(args, "-L", forward)
		remoteTargets = append(remoteTargets, remote)
		localTargets = append(localTargets, local)
	}
	args = append(args, c.config.WSTunnelArgs...)
	args = append(args, c.config.WSTunnelURL)

	cmd, tunnelPID, cleanupLog, err := c.startWSTunnel(ctx, args, foreground)
	if err != nil {
		return err
	}
	if cleanupLog != nil {
		defer cleanupLog()
	}
	stopTunnel := func() { _ = stopProcess(tunnelPID) }
	iface, err := c.wgQuickUp(path)
	if err != nil {
		stopTunnel()
		return err
	}
	for i, peer := range peers {
		local := fmt.Sprintf("%s:%d", c.config.BindAddress, c.config.PortBase+i)
		if err := c.run(c.config.WG, "set", iface, "peer", peer.PublicKey, "endpoint", local); err != nil {
			_ = c.wgQuickDown(path)
			stopTunnel()
			return fmt.Errorf("override endpoint for peer %d: %w", i+1, err)
		}
	}
	s := state{Profile: profile, ProfilePath: path, Interface: iface, Mode: "wstunnel", WSTunnelPID: tunnelPID, RemoteTargets: remoteTargets, LocalTargets: localTargets, StartedAt: time.Now()}
	if err := saveState(c.config.StateFile, s); err != nil {
		_ = c.wgQuickDown(path)
		stopTunnel()
		return err
	}
	fmt.Fprintf(c.out, "Connected through wstunnel on %s.\n", iface)
	return c.maybeForeground(ctx, s, foreground, cmd)
}

func (c cli) maybeForeground(ctx context.Context, s state, foreground bool, tunnel *exec.Cmd) error {
	if !foreground {
		return nil
	}
	signalCtx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()
	fmt.Fprintln(c.out, "Running in foreground; press Ctrl-C to disconnect.")
	if tunnel == nil {
		<-signalCtx.Done()
	} else {
		exited := make(chan error, 1)
		go func() { exited <- tunnel.Wait() }()
		select {
		case <-signalCtx.Done():
		case err := <-exited:
			if err != nil {
				fmt.Fprintf(c.errOut, "wstunnel exited: %v\n", err)
			}
		}
	}
	return c.stop(s)
}

func (c cli) startWSTunnel(ctx context.Context, args []string, foreground bool) (*exec.Cmd, int, func(), error) {
	cmd := exec.CommandContext(ctx, c.config.WSTunnel, args...)
	cmd.Env = normalizedWSTunnelEnv(os.Environ())
	var log *os.File
	if foreground {
		cmd.Stdout, cmd.Stderr = c.out, c.errOut
		cmd.Stdin = os.Stdin
	} else {
		if err := os.MkdirAll(filepath.Dir(c.config.LogFile), 0o700); err != nil {
			return nil, 0, nil, fmt.Errorf("create log directory: %w", err)
		}
		var err error
		log, err = os.OpenFile(c.config.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, 0, nil, fmt.Errorf("open wstunnel log: %w", err)
		}
		cmd.Stdout, cmd.Stderr = log, log
		detach(cmd)
	}
	if err := cmd.Start(); err != nil {
		if log != nil {
			_ = log.Close()
		}
		return nil, 0, nil, fmt.Errorf("start wstunnel: %w", err)
	}
	pid := cmd.Process.Pid
	if !foreground {
		if err := cmd.Process.Release(); err != nil {
			_ = stopProcess(pid)
			_ = log.Close()
			return nil, 0, nil, err
		}
		// Catch invalid arguments, port conflicts, and other immediate startup
		// failures before bringing up WireGuard and redirecting its endpoints.
		time.Sleep(150 * time.Millisecond)
		if !processRunning(pid) {
			_ = log.Close()
			return nil, 0, nil, fmt.Errorf("wstunnel exited during startup; see %s", c.config.LogFile)
		}
	}
	return cmd, pid, func() {
		if log != nil {
			_ = log.Close()
		}
	}, nil
}

func normalizedWSTunnelEnv(environ []string) []string {
	result := make([]string, 0, len(environ))
	for _, entry := range environ {
		switch entry {
		case "NO_COLOR=1":
			entry = "NO_COLOR=true"
		case "NO_COLOR=0":
			entry = "NO_COLOR=false"
		}
		result = append(result, entry)
	}
	return result
}

func (c cli) down(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("down takes no arguments")
	}
	s, err := loadState(c.config.StateFile)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("no active profile")
	}
	if err != nil {
		return err
	}
	return c.stop(s)
}

func (c cli) stop(s state) error {
	var failures []error
	interfaces, interfacesErr := c.interfaces()
	if interfacesErr != nil || contains(interfaces, s.Interface) {
		if err := c.wgQuickDown(s.ProfilePath); err != nil {
			failures = append(failures, err)
		}
	}
	if s.WSTunnelPID != 0 && processRunning(s.WSTunnelPID) {
		if err := stopProcess(s.WSTunnelPID); err != nil {
			failures = append(failures, fmt.Errorf("stop wstunnel: %w", err))
		}
	}
	if len(failures) == 0 {
		if err := removeState(c.config.StateFile); err != nil {
			return err
		}
		fmt.Fprintln(c.out, "Disconnected.")
	}
	return errors.Join(failures...)
}

func (c cli) status(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("status takes no arguments")
	}
	s, err := loadState(c.config.StateFile)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(c.out, "Status: disconnected")
		return nil
	}
	if err != nil {
		return err
	}
	interfaces, wgErr := c.interfaces()
	active := contains(interfaces, s.Interface)
	fmt.Fprintf(c.out, "Status:         %s\n", map[bool]string{true: "connected", false: "stale"}[active])
	fmt.Fprintf(c.out, "Profile:        %s\nInterface:      %s\nTransport:      %s\nStarted:        %s\n", s.Profile, s.Interface, s.Mode, s.StartedAt.Local().Format(time.RFC3339))
	forwardCount := len(s.RemoteTargets)
	if len(s.LocalTargets) < forwardCount {
		forwardCount = len(s.LocalTargets)
	}
	for i := 0; i < forwardCount; i++ {
		fmt.Fprintf(c.out, "Forward:        %s -> %s\n", s.LocalTargets[i], s.RemoteTargets[i])
	}
	if s.WSTunnelPID != 0 {
		fmt.Fprintf(c.out, "wstunnel PID:   %d (%s)\n", s.WSTunnelPID, map[bool]string{true: "running", false: "not running"}[processRunning(s.WSTunnelPID)])
	}
	if wgErr != nil {
		return wgErr
	}
	if active {
		output, err := exec.Command(c.config.WG, "show", s.Interface, "latest-handshakes").Output()
		if err == nil {
			fmt.Fprintf(c.out, "Handshake:      %s\n", describeHandshake(string(output)))
		}
	}
	return nil
}

func (c cli) resolveProfile(name string) (string, string, error) {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, `/\\`) {
		return "", "", fmt.Errorf("invalid profile name %q", name)
	}
	name = strings.TrimSuffix(name, ".conf")
	path := filepath.Join(c.config.ProfilesDir, name+".conf")
	info, err := os.Stat(path)
	if err != nil {
		return "", "", fmt.Errorf("profile %q: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return "", "", fmt.Errorf("profile %q is not a regular file", name)
	}
	return name, path, nil
}

func (c cli) requireBinaries(mode string) error {
	needed := []string{c.config.WG, c.config.WGQuick}
	if mode != "direct" {
		needed = append(needed, c.config.WSTunnel)
	}
	for _, binary := range needed {
		if _, err := exec.LookPath(binary); err != nil {
			return fmt.Errorf("required binary %q not found in PATH", binary)
		}
	}
	return nil
}

func (c cli) wgQuickUp(path string) (string, error) {
	before, err := c.interfaces()
	if err != nil {
		return "", err
	}
	if err := c.run(c.config.WGQuick, "up", path); err != nil {
		return "", fmt.Errorf("wg-quick up: %w", err)
	}
	after, err := c.interfaces()
	if err != nil {
		_ = c.wgQuickDown(path)
		return "", err
	}
	var added []string
	for _, iface := range after {
		if !contains(before, iface) {
			added = append(added, iface)
		}
	}
	if len(added) != 1 {
		_ = c.wgQuickDown(path)
		return "", fmt.Errorf("could not uniquely identify new WireGuard interface (found %d)", len(added))
	}
	return added[0], nil
}

func (c cli) wgQuickDown(path string) error {
	return c.run(c.config.WGQuick, "down", path)
}

func (c cli) interfaces() ([]string, error) {
	output, err := exec.Command(c.config.WG, "show", "interfaces").Output()
	if err != nil {
		return nil, fmt.Errorf("list WireGuard interfaces: %w", err)
	}
	return strings.Fields(string(output)), nil
}

func (c cli) waitHandshake(ctx context.Context, iface string, timeout time.Duration) bool {
	deadline := time.NewTimer(timeout)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for {
		if output, err := exec.Command(c.config.WG, "show", iface, "latest-handshakes").Output(); err == nil && hasHandshake(string(output)) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-deadline.C:
			return false
		case <-ticker.C:
		}
	}
}

func (c cli) run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = c.out, c.errOut, os.Stdin
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func formatDestination(host string, port int) string {
	if strings.Contains(host, ":") {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func contains(items []string, wanted string) bool {
	for _, item := range items {
		if item == wanted {
			return true
		}
	}
	return false
}

func hasHandshake(output string) bool {
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			if timestamp, err := strconv.ParseInt(fields[len(fields)-1], 10, 64); err == nil && timestamp > 0 {
				return true
			}
		}
	}
	return false
}

func describeHandshake(output string) string {
	var newest int64
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			if timestamp, err := strconv.ParseInt(fields[len(fields)-1], 10, 64); err == nil && timestamp > newest {
				newest = timestamp
			}
		}
	}
	if newest == 0 {
		return "never"
	}
	age := time.Since(time.Unix(newest, 0)).Round(time.Second)
	if age < 0 {
		age = 0
	}
	return fmt.Sprintf("%s ago", age)
}
