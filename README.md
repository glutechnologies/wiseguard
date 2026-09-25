# wiseguard

`wiseguard` is a small, dependency-free Go orchestrator that runs standard
WireGuard profiles either directly over UDP or through a system-installed
[`wstunnel`](https://github.com/erebe/wstunnel) client. It never rewrites the
WireGuard `.conf` files: tunneled peer endpoints are changed only at runtime
with `wg set`.

Supported systems: macOS and Linux.

## Requirements

- Go 1.22 or newer to build
- `wg`, `wg-quick`, and `wstunnel` available in `PATH`
- privileges required by `wg-quick` (normally run `wiseguard` as root)

Installing those system tools is deliberately outside this project's scope.

## Build

```sh
make test
make build
sudo install -m 0755 bin/wiseguard /usr/local/bin/wiseguard
```

There are no third-party Go modules.

## Configuration

Copy [`config.example.ini`](config.example.ini) to
`~/.config/wiseguard/config.ini`, then place unmodified WireGuard profiles in
`~/.config/wiseguard/profiles/`:

```ini
profiles_dir = ~/.config/wiseguard/profiles
wstunnel_url = wss://tunnel.example.net:443
tls_verify = true
bind_address = 127.0.0.1
port_base = 55182
auto_timeout = 3s
```

The configuration path can be selected with `--config FILE` or
`WISEGUARD_CONFIG`. Every scalar setting has an environment equivalent:

| Setting | Environment variable |
|---|---|
| `profiles_dir` | `WISEGUARD_PROFILES_DIR` |
| `state_file` | `WISEGUARD_STATE_FILE` |
| `log_file` | `WISEGUARD_LOG_FILE` |
| `wstunnel_url` | `WISEGUARD_WSTUNNEL_URL` |
| `bind_address` | `WISEGUARD_BIND_ADDRESS` |
| `tls_verify` | `WISEGUARD_TLS_VERIFY` |
| `port_base` | `WISEGUARD_PORT_BASE` |
| `auto_timeout` | `WISEGUARD_AUTO_TIMEOUT` |
| `wg_binary` | `WISEGUARD_WG_BINARY` |
| `wg_quick_binary` | `WISEGUARD_WG_QUICK_BINARY` |
| `wstunnel_binary` | `WISEGUARD_WSTUNNEL_BINARY` |
| repeated `wstunnel_arg` | `WISEGUARD_WSTUNNEL_ARGS` (space-separated) |

XDG configuration/state directories are honored. The default state file and
wstunnel log are under `~/.local/state/wiseguard/`.
When invoked through `sudo`, wiseguard uses the invoking user's home directory
(from `SUDO_USER`) rather than root's home.

## Usage

```sh
wiseguard list
sudo wiseguard up office
sudo wiseguard up lab
sudo wiseguard up --mode direct office
sudo wiseguard up --mode wstunnel office
sudo wiseguard up --foreground --mode wstunnel office
sudo wiseguard status
sudo wiseguard status office
sudo wiseguard down office
sudo wiseguard down lab
```

Multiple profiles can be active at the same time. Each `up` operation only
affects the selected profile, while `down PROFILE` disconnects that profile
without changing the others. `status` lists every recorded profile and
`status PROFILE` selects one. For backward compatibility, `down` without a
profile is accepted when exactly one profile is active.

`auto` is the default mode. It brings WireGuard up directly and waits for a
handshake. If none is observed within `auto_timeout`, it brings the interface
down and starts it again through wstunnel. A profile with no initial traffic
and no `PersistentKeepalive` may therefore fall back even when direct UDP is
available; use `--mode direct` when that distinction matters.

For every peer that has an `Endpoint`, tunneled mode creates a separate local
UDP forward starting at `port_base`, starts the original profile using
`wg-quick`, and then changes that peer's live endpoint to its local forward.
When multiple tunneled profiles are active, wiseguard allocates subsequent
available UDP ports so their local listeners do not collide.
Private keys and profile contents are never copied into the state file.
TLS certificate verification is enabled by default; only set
`tls_verify = false` for a deliberately self-signed deployment.

For full-tunnel profiles (`AllowedIPs = 0.0.0.0/0` or `::/0`), the wstunnel
server must remain reachable outside the VPN route. The simplest deployment is
to expose wstunnel on the same host/IP as the original WireGuard endpoint;
otherwise add an explicit host route for the wstunnel server.

Without `--foreground`, wstunnel is detached and logs to the configured log
file. With `--foreground`, logs remain attached and SIGINT/SIGTERM cleanly run
`wg-quick down` and stop wstunnel.
