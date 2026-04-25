# openhost-syncthing

[Syncthing](https://syncthing.net) — peer-to-peer continuous file synchronization — packaged for OpenHost.

Deploy this on your OpenHost instance and you get:

- A web UI at `https://syncthing.<your-zone>/` (gated by your zone's OpenHost SSO — only the owner can reach it)
- TCP+UDP sync protocol on host port `9101` (container port `22000`)
- UDP local-discovery on host port `9102` (container port `21027`)
- All sync state (config, certs, indexes, optional shared folders) under `$OPENHOST_APP_DATA_DIR`

## How it works

On first boot the container:

1. Generates a fresh Syncthing identity (device ID + TLS certs) under `$OPENHOST_APP_DATA_DIR/config/`.
2. Writes a hardened `config.xml` that:
   - Binds the GUI on `127.0.0.1:8385` by default (configurable via `SYNCTHING_UPSTREAM_PORT`) so only the auth-proxy sidecar — running in the same container — can reach it
   - Disables Syncthing's own GUI auth (no username/password — see "Authentication" below)
   - Sets `insecureSkipHostcheck=true` so the sidecar's rewritten Host header doesn't get rejected
   - Pins the sync ports to TCP+QUIC `0.0.0.0:22000` (matching the `[[ports]]` entries in `openhost.toml`)
   - Disables the in-app self-upgrader (`STNOUPGRADE=1`) — upgrades happen via the OpenHost reload-with-update flow
3. Starts Syncthing as the unprivileged UID 1000 (configurable via `PUID`/`PGID`) via `su-exec`. The upstream image uses numeric IDs and does not create a named user.
4. Starts the auth-proxy sidecar (`auth_proxy.py`) on `0.0.0.0:8384`.

If either child process exits, the container exits and OpenHost restarts it.

## Authentication

Syncthing has no per-user authentication model — it's a single-tenant daemon. Anyone who can reach the GUI can configure every aspect of the sync setup. So the only auth question is "is this the OpenHost owner?", and we answer it once at the proxy layer.

The auth-proxy sidecar verifies the visitor's `zone_auth` JWT cookie against the OpenHost router's JWKS at `$OPENHOST_ROUTER_URL/.well-known/jwks.json`. When the cookie is a valid RS256 token with `sub == "owner"`, the request is forwarded to Syncthing on the loopback upstream port (`127.0.0.1:$SYNCTHING_UPSTREAM_PORT`, default `8385`). Otherwise the proxy returns `403 Forbidden`.

A single path is whitelisted without a cookie:

- `/rest/noauth/health` — Syncthing's built-in unauthenticated liveness endpoint, used by the OpenHost router as the `health_check` target in `openhost.toml`.

Implementation choices that matter for security:

- **Syncthing binds 127.0.0.1, not 0.0.0.0.** The sidecar is the only loopback caller, so there's no in-container path that bypasses auth.
- **The sidecar strips any client-supplied `X-Openhost-User` header.** Syncthing doesn't read the header today, but stripping it is defence-in-depth against future configuration drift.
- **The JWKS is cached for 10 minutes with stale-fallback** so a transient router outage doesn't lock the owner out. Same pattern as `openhost-miniflux` and `openhost-mirotalk-p2p`.
- **`insecureSkipHostcheck` is enabled** so the sidecar's rewritten Host header (the user's original `syncthing.<zone>` hostname, taken from `X-Forwarded-Host`) doesn't trigger Syncthing's "Host header doesn't look like localhost" rejection. The rewrite itself happens in the sidecar, so dropping `insecureSkipHostcheck` is a future hardening option if Syncthing tightens its check semantics.

There is no Syncthing-local password to remember, leak, or rotate. Sign in to your OpenHost zone, and you're signed in to Syncthing.

## Deploying

```bash
oh app deploy https://github.com/imbue-openhost/openhost-syncthing --wait
```

Or, on `andrew-1`:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
    https://andrew-1.selfhost.imbue.com/api/add_app \
    -d 'repo_url=https://github.com/imbue-openhost/openhost-syncthing'
```

The app will be available at `https://syncthing.<zone-domain>/`. Browse to it from a session signed into the zone — you're already authenticated. Inside the GUI:

1. Note your device ID (top right → "Actions" → "Show ID"). Share this with peers you want to sync with.
2. Click "Add Folder", give it a path under `/data/data/` (the in-container path that maps to `$OPENHOST_APP_DATA_DIR/data/`). This is where your synced files end up on the OpenHost host.
3. Add the peer device IDs you want to sync with under "Add Remote Device".

## Data layout

All persistent state lives under `$OPENHOST_APP_DATA_DIR/`:

```
$OPENHOST_APP_DATA_DIR/
├── config/        # STHOMEDIR — config.xml, cert.pem, key.pem, https-cert.pem,
│   │              #             https-key.pem, index database, audit logs
│   ├── config.xml
│   ├── cert.pem    # device identity — back this up, losing it means losing your device ID
│   ├── key.pem
│   └── ...
└── data/          # default sync folder root — point new folders here from the GUI
```

You can configure folders anywhere readable under the container, but only files under `$OPENHOST_APP_DATA_DIR/` are persisted across deploys, restarts, and image rebuilds. Pointing a Syncthing folder at e.g. `/tmp` will sync to other peers but the contents won't survive a container restart.

This is the cleanest fit for OpenHost's per-app data model. Cross-app sync (e.g. backing up another OpenHost app's data via Syncthing) would need the `access_all_apps_data` manifest flag, which isn't in this manifest by design — every byte that lands in your zone via Syncthing is a byte the peer can see and an attacker can probe, so we keep the blast radius narrow.

## Ports

| Port | Protocol | Purpose | Host | Container |
|---|---|---|---|---|
| GUI | TCP | Web UI (sidecar) | `443` (router) | `8384` |
| Sync | TCP+UDP | sync protocol + QUIC | `9101` | `22000` |
| Discovery | UDP | local LAN discovery | `9102` | `21027` |

OpenHost binds each `[[ports]]` entry on both TCP and UDP automatically, so the single `sync` entry covers both the TCP sync protocol and the QUIC variant, and the single `discovery` entry covers UDP/21027 (TCP/21027 just goes nowhere — Syncthing doesn't listen on it).

## Configuration

The container regenerates `config.xml` on every boot, with one exception: the auto-generated `<apikey>` element (used by Syncthing's REST API) is preserved across reboots. This means:

- **GUI edits persist.** Anything you change in the web UI is written through to `config.xml` between reboots; the container only rewrites the file at startup, after `<gui>`/`<options>`/`<defaults>` have already been read by the running daemon. Folder configurations, device peers, and `<options>` you tweak from the GUI all stick.
- **Editing `config.xml` on disk does NOT persist.** If you exec into the container and hand-edit the file, your changes get clobbered on next boot. Use the GUI.
- **The hardened defaults (loopback bind, no auth, insecureSkipHostcheck, etc.) are re-applied on every boot.** If you want different defaults, fork this repo and edit `start.sh`'s heredoc.

A few overrideable knobs via env (set them in your zone's app overrides):

| Variable | Default | Notes |
|---|---|---|
| `AUTH_PROXY_LISTEN_PORT` | `8384` | Where the sidecar binds. Match `port` in `openhost.toml` if you change. |
| `SYNCTHING_UPSTREAM_PORT` | `8385` | Where Syncthing's GUI binds inside the container. `start.sh` and `auth_proxy.py` both read this var so it stays in sync. |
| `AUTH_PROXY_LOG_LEVEL` | `INFO` | Set to `DEBUG` for verbose proxy logs. |

## Upgrading

The Dockerfile pins the upstream image to a specific tag (`syncthing/syncthing:1.30.0`). To pick up a new Syncthing release:

1. Bump the tag in `Dockerfile`.
2. Commit + push.
3. In the OpenHost dashboard, click "Reload" on the syncthing app with the update option checked.

The data dir (`config/`, `data/`) is preserved across upgrades. Only the immutable install tree gets replaced.

## Smoke testing a deployment

After deploy, verify the auth gate from authenticated and unauthenticated sessions:

```bash
# With a valid zone_auth cookie from the zone's /login flow:
curl -b cookies.txt -IL https://syncthing.<zone-domain>/
# Should return 200 — you're the owner, the proxy lets you in.

# Without any cookies:
curl -IL https://syncthing.<zone-domain>/
# Should end at the OpenHost zone's /login page (router redirect)
# OR at a 403 from the sidecar, depending on which one wins. Either is correct.

# Header spoofing attempt:
curl -IL -H "X-Openhost-User: admin" https://syncthing.<zone-domain>/
# Should also fail — the sidecar strips the header (and Syncthing doesn't read it anyway).

# Health check (always public):
curl https://syncthing.<zone-domain>/rest/noauth/health
# Should return {"status":"OK"} regardless of authentication state.
```

## Caveats

- **Single-tenant only.** Syncthing has no per-user concept; the OpenHost owner is the only person who should be using this app. Don't share the proxy URL or invite Syncthing peers you don't trust — once a device pair is added, that peer can read every byte you put in shared folders.
- **Discovery via global servers means metadata leaks.** When `<globalAnnounceEnabled>` is true (the default), Syncthing tells the public discovery servers your device ID and current public IP. That's the only way peer-finding works through NAT. If you want to keep that private, set up a private discovery server, or sync only over `dynamic`/explicit addresses.
- **Sync ports are exposed to the open internet.** Anything that can reach host port `9101` can attempt to negotiate a Syncthing handshake with your device; without your device ID being in their config, they get rejected, but the existence of the daemon is observable. Firewall the OpenHost host ports if you want to restrict reachability to a VPN.
- **Ports `9101` and `9102` are pre-allocated for this app.** If you also try to deploy another app that wants those host ports, the second deploy will fail. The pre-allocation is done in the OpenHost shared-context to prevent this.
- **First-deploy race window.** Anyone who hits `https://syncthing.<zone>/` before you've signed into your zone's OpenHost dashboard will get `403`, but the daemon is already running and accepting peer-protocol connections on `9101`. Configure your peers from the GUI promptly after deploying.

## Files

- `Dockerfile` — extends `syncthing/syncthing:1.30.0` with bash + a Python venv for the auth-proxy.
- `openhost.toml` — OpenHost manifest. Pre-allocated host ports for sync (9101) and discovery (9102).
- `start.sh` — generates Syncthing identity on first boot, rewrites `config.xml` with hardened defaults, supervises the daemon and the auth-proxy sidecar.
- `auth_proxy.py` — JWT-verifying reverse proxy. Allows owner traffic and `/rest/noauth/health` probes; everything else gets 403.
- `README.md` — this file.
