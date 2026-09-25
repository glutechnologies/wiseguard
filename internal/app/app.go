package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
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
  wiseguard [--config FILE] down [PROFILE]
  wiseguard [--config FILE] status [PROFILE]
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
	profile, path, err := c.resolveProfile(fs.Arg(0))
	if err != nil {
		return err
	}
	if err := c.requireBinaries(*mode); err != nil {
		return err
	}

	var peers []wgconf.Peer
	if *mode != "direct" {
		peers, err = wgconf.Parse(path)
		if err != nil {
			return err
		}
	}
	portBase, err := c.reserveProfile(profile, path, *mode, len(peers))
	if err != nil {
		return err
	}
	defer c.deleteStartingState(profile)

	if *mode == "direct" {
		return c.startDirect(ctx, profile, path, *foreground)
	}
	if *mode == "auto" {
		fmt.Fprintf(c.out, "Trying direct WireGuard for %s...\n", c.config.AutoTimeout)
		iface, err := c.wgQuickUp(path)
		if err != nil {
			return err
		}
		if c.waitHandshake(ctx, iface, c.config.AutoTimeout) {
			s := state{Profile: profile, ProfilePath: path, Interface: iface, Mode: "direct", StartedAt: time.Now()}
			if err := c.setProfileState(s); err != nil {
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
	return c.startTunneled(ctx, profile, path, peers, portBase, *foreground)
}

func (c cli) startDirect(ctx context.Context, profile, path string, foreground bool) error {
	iface, err := c.wgQuickUp(path)
	if err != nil {
		return err
	}
	s := state{Profile: profile, ProfilePath: path, Interface: iface, Mode: "direct", StartedAt: time.Now()}
	if err := c.setProfileState(s); err != nil {
		_ = c.wgQuickDown(path)
		return err
	}
	fmt.Fprintf(c.out, "Connected directly on %s.\n", iface)
	return c.maybeForeground(ctx, s, foreground, nil)
}

func (c cli) startTunneled(ctx context.Context, profile, path string, peers []wgconf.Peer, portBase int, foreground bool) error {
	if c.config.WSTunnelURL == "" {
		return fmt.Errorf("wstunnel_url (or WISEGUARD_WSTUNNEL_URL) is required")
	}
	args := []string{"client"}
	if c.config.TLSVerify {
		args = append(args, "--tls-verify-certificate")
	}
	var remoteTargets, localTargets []string
	for i, peer := range peers {
		local := formatDestination(c.config.BindAddress, portBase+i)
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
		local := formatDestination(c.config.BindAddress, portBase+i)
		if err := c.run(c.config.WG, "set", iface, "peer", peer.PublicKey, "endpoint", local); err != nil {
			_ = c.wgQuickDown(path)
			stopTunnel()
			return fmt.Errorf("override endpoint for peer %d: %w", i+1, err)
		}
	}
	s := state{Profile: profile, ProfilePath: path, Interface: iface, Mode: "wstunnel", WSTunnelPID: tunnelPID, RemoteTargets: remoteTargets, LocalTargets: localTargets, StartedAt: time.Now()}
	if err := c.setProfileState(s); err != nil {
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
	if len(args) > 1 {
		return fmt.Errorf("down takes at most one profile")
	}
	store, err := loadStateStore(c.config.StateFile)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("no active profiles")
	}
	if err != nil {
		return err
	}
	name := ""
	if len(args) == 1 {
		name = strings.TrimSuffix(args[0], ".conf")
	} else {
		names := stateNames(store)
		if len(names) != 1 {
			return fmt.Errorf("multiple profiles are active; specify one: %s", strings.Join(names, ", "))
		}
		name = names[0]
	}
	s, ok := store.Tunnels[name]
	if !ok {
		return fmt.Errorf("profile %q is not active", name)
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
		if err := c.deleteProfileState(s.Profile); err != nil {
			return err
		}
		fmt.Fprintf(c.out, "Disconnected %s.\n", s.Profile)
	}
	return errors.Join(failures...)
}

func (c cli) status(args []string) error {
	if len(args) > 1 {
		return fmt.Errorf("status takes at most one profile")
	}
	store, err := loadStateStore(c.config.StateFile)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(c.out, "Status: disconnected")
		return nil
	}
	if err != nil {
		return err
	}
	names := stateNames(store)
	if len(args) == 1 {
		name := strings.TrimSuffix(args[0], ".conf")
		if _, ok := store.Tunnels[name]; !ok {
			return fmt.Errorf("profile %q is not active", name)
		}
		names = []string{name}
	}
	interfaces, wgErr := c.interfaces()
	for i, name := range names {
		if i > 0 {
			fmt.Fprintln(c.out)
		}
		c.printState(store.Tunnels[name], interfaces)
	}
	return wgErr
}

func (c cli) printState(s state, interfaces []string) {
	starting := strings.HasPrefix(s.Mode, "starting:")
	active := contains(interfaces, s.Interface)
	status := map[bool]string{true: "connected", false: "stale"}[active]
	if starting {
		status = "starting"
	}
	mode := strings.TrimPrefix(s.Mode, "starting:")
	fmt.Fprintf(c.out, "Status:         %s\n", status)
	fmt.Fprintf(c.out, "Profile:        %s\nInterface:      %s\nTransport:      %s\nStarted:        %s\n", s.Profile, s.Interface, mode, s.StartedAt.Local().Format(time.RFC3339))
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
	if active {
		output, err := exec.Command(c.config.WG, "show", s.Interface, "latest-handshakes").Output()
		if err == nil {
			fmt.Fprintf(c.out, "Handshake:      %s\n", describeHandshake(string(output)))
		}
	}
}

func (c cli) reserveProfile(profile, path, mode string, peerCount int) (int, error) {
	portBase := 0
	err := withLockedState(c.config.StateFile, func(store *stateStore) error {
		if existing, ok := store.Tunnels[profile]; ok {
			return fmt.Errorf("profile %s is already recorded as %s", profile, strings.TrimPrefix(existing.Mode, "starting:"))
		}
		if peerCount > 0 {
			var err error
			portBase, err = c.availablePortBase(*store, peerCount)
			if err != nil {
				return err
			}
		}
		reservedTargets := make([]string, 0, peerCount)
		for i := 0; i < peerCount; i++ {
			reservedTargets = append(reservedTargets, formatDestination(c.config.BindAddress, portBase+i))
		}
		store.Tunnels[profile] = state{Profile: profile, ProfilePath: path, Mode: "starting:" + mode, LocalTargets: reservedTargets, StartedAt: time.Now()}
		return nil
	})
	return portBase, err
}

func (c cli) availablePortBase(store stateStore, count int) (int, error) {
	used := make(map[int]bool)
	for _, s := range store.Tunnels {
		for _, target := range s.LocalTargets {
			_, portText, err := net.SplitHostPort(target)
			if err != nil {
				continue
			}
			if port, err := strconv.Atoi(portText); err == nil {
				used[port] = true
			}
		}
	}
	for base := c.config.PortBase; base+count-1 <= 65535; base++ {
		available := true
		for port := base; port < base+count; port++ {
			if used[port] || !udpPortAvailable(c.config.BindAddress, port) {
				available = false
				break
			}
		}
		if available {
			return base, nil
		}
	}
	return 0, fmt.Errorf("no block of %d UDP ports is available from port_base %d", count, c.config.PortBase)
}

var udpPortAvailable = func(address string, port int) bool {
	listener, err := net.ListenPacket("udp", formatDestination(address, port))
	if err != nil {
		return false
	}
	_ = listener.Close()
	return true
}

func (c cli) setProfileState(s state) error {
	return withLockedState(c.config.StateFile, func(store *stateStore) error {
		if _, ok := store.Tunnels[s.Profile]; !ok {
			return fmt.Errorf("startup of profile %s was cancelled", s.Profile)
		}
		store.Tunnels[s.Profile] = s
		return nil
	})
}

func (c cli) deleteProfileState(profile string) error {
	return withLockedState(c.config.StateFile, func(store *stateStore) error {
		delete(store.Tunnels, profile)
		return nil
	})
}

func (c cli) deleteStartingState(profile string) {
	_ = withLockedState(c.config.StateFile, func(store *stateStore) error {
		if s, ok := store.Tunnels[profile]; ok && strings.HasPrefix(s.Mode, "starting:") {
			delete(store.Tunnels, profile)
		}
		return nil
	})
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
