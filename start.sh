#!/bin/bash
# Bash specifically (not /bin/sh): we use `wait -n` to block until
# the first of our two background processes exits. busybox ash
# (Alpine's /bin/sh) does not implement `wait -n`.
set -e

# OpenHost mounts persistent storage at OPENHOST_APP_DATA_DIR. Fall
# back to /var/syncthing (the upstream image's default volume path)
# for local testing / development outside OpenHost.
PERSIST="${OPENHOST_APP_DATA_DIR:-/var/syncthing}"

# Subdirectory layout under PERSIST:
#
#   config/   — Syncthing's STHOMEDIR: config.xml, cert.pem, key.pem,
#               https-cert.pem, https-key.pem, the index database, etc.
#               This is what defines the "device" — losing it means
#               losing your device ID, certs, and folder configs.
#   data/     — recommended top-level folder for synced data. Users
#               can point Syncthing folders elsewhere under PERSIST,
#               but data/ is the obvious starting place. We don't
#               auto-create any synced folders — the user does that
#               from the GUI.
#
# We don't symlink Syncthing's expected paths here because Syncthing
# lets us pass the config dir explicitly via STHOMEDIR — much cleaner
# than the symlink-the-install-tree trick the BBS package uses.
ST_CONFIG_DIR="$PERSIST/config"
ST_DATA_DIR="$PERSIST/data"

mkdir -p "$ST_CONFIG_DIR" "$ST_DATA_DIR"

# Syncthing inside the upstream image runs as UID 1000 (user `syncthing`).
# OpenHost's app_data dir comes in owned by whoever the container
# runtime mapped — typically root in plain Docker, or a UID-mapped
# owner under rootless podman. Make sure the syncthing user can read
# and write its own state regardless. We chown only the subdirs we
# manage (config/ and data/) rather than the entire PERSIST root, so
# that other tooling sharing app_data (none today, but futureproof)
# isn't affected.
chown -R syncthing:syncthing "$ST_CONFIG_DIR" "$ST_DATA_DIR"

# -----------------------------------------------------------------
# Generate Syncthing's config.xml on first boot.
#
# We could let `syncthing --no-default-folder generate` create one
# and then patch it, but the resulting config still has GUI auth,
# the default sync ports, and the default listen address — all of
# which we want to override. It's cleaner to write the parts we
# care about directly and let Syncthing fill in the device ID and
# certificates at first launch.
#
# Strategy:
#   1. If config.xml does not exist, run `syncthing generate` to
#      mint a fresh device ID + TLS certs + a starter config.xml.
#   2. Then overwrite config.xml with our hardened version,
#      preserving the auto-generated apikey value (some scripts
#      may want to talk to /rest/, and the apikey is the only
#      auth path with GUI auth disabled).
# -----------------------------------------------------------------
CONFIG_FILE="$ST_CONFIG_DIR/config.xml"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "[start.sh] First boot: generating Syncthing identity in $ST_CONFIG_DIR"
    # `syncthing generate` is idempotent on a populated dir but we
    # only run it when the config is missing to keep startup fast
    # on every other boot.
    su-exec syncthing:syncthing syncthing generate \
        --no-default-folder \
        --home "$ST_CONFIG_DIR"
fi

# Port that Syncthing's GUI binds inside the container. The auth-proxy
# sidecar reads the same env var so the two stay in sync if an operator
# overrides the default. Keep it on loopback always — the sidecar is
# the only legitimate caller.
SYNCTHING_UPSTREAM_PORT="${SYNCTHING_UPSTREAM_PORT:-8385}"
export SYNCTHING_UPSTREAM_PORT

# Extract the auto-generated API key. Syncthing wrote one into
# config.xml during `generate`. Even with GUI auth disabled, the
# REST API requires this key (or a matching auth cookie) — without
# it the API returns 403. We preserve it across config rewrites
# so any scripts an operator wires up keep working after reboot.
#
# The generate step above always produces a non-empty apikey, so
# parsing it out should never fail. If it does (corrupt config),
# we mint a fresh one rather than failing closed: a fresh apikey
# only changes which scripts can talk to /rest/, and is safer than
# refusing to start.
APIKEY=$(grep -oE '<apikey>[^<]+</apikey>' "$CONFIG_FILE" | head -n 1 \
    | sed -E 's|<apikey>([^<]+)</apikey>|\1|' || true)
if [ -z "$APIKEY" ]; then
    echo "[start.sh] Warning: could not parse apikey from existing config.xml; generating a new one"
    APIKEY=$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32)
fi

# Always rewrite config.xml on boot so that:
#   * upgrades to this image push fresh defaults forward
#   * an operator who edited the file in the container loses their
#     edits — but we deliberately make the file out-of-band: any
#     real customization should happen via the GUI (which writes
#     to config.xml at runtime, after we hand off to syncthing)
#
# That means our boot-time rewrite is racy with GUI edits made
# between two boots only if someone hand-edits the XML on disk
# rather than using the GUI. Document this in the README.
#
# We DON'T overwrite the device's cert.pem / key.pem (the device
# identity) — those stay put under $ST_CONFIG_DIR.
#
# Listen address `tcp://0.0.0.0:22000, quic://0.0.0.0:22000`
# matches the [[ports]] entries in openhost.toml so the host's
# 9101 maps cleanly to the container's 22000.
cat > "$CONFIG_FILE" <<XML
<configuration version="37">
    <gui enabled="true" tls="false">
        <!--
            Bind on loopback only. The auth-proxy sidecar
            (auth_proxy.py) is the only thing reaching this port,
            and it runs in the same container/pod, so 127.0.0.1
            is sufficient and prevents any path that bypasses the
            sidecar.
        -->
        <address>127.0.0.1:$SYNCTHING_UPSTREAM_PORT</address>
        <apikey>$APIKEY</apikey>
        <theme>default</theme>
        <!--
            Skip the Host-header check. Syncthing normally rejects
            requests whose Host header doesn't match localhost when
            it's bound to localhost. Our sidecar forwards the
            client's original Host (e.g. syncthing.<zone-domain>),
            so without this flag every GUI request gets a 403.
        -->
        <insecureSkipHostcheck>true</insecureSkipHostcheck>
        <!--
            No <user>/<password> elements: GUI auth disabled. The
            sidecar enforces auth instead. Syncthing won't accept
            unauthenticated remote connections in this state
            because we bound it to 127.0.0.1, and the sidecar is
            the only loopback caller.
        -->
    </gui>
    <options>
        <!--
            Sync protocol listeners. Match the [[ports]] entries
            in openhost.toml.
        -->
        <listenAddress>tcp://0.0.0.0:22000</listenAddress>
        <listenAddress>quic://0.0.0.0:22000</listenAddress>
        <!--
            Local discovery on UDP/21027. Useful only when peers
            share a broadcast domain with the host VM, but cheap
            to leave on.
        -->
        <localAnnounceEnabled>true</localAnnounceEnabled>
        <localAnnouncePort>21027</localAnnouncePort>
        <!--
            Global discovery + relay servers stay enabled; they're
            how peers reach us through NAT. Disable in your zone if
            you want pure-LAN-only operation.
        -->
        <globalAnnounceEnabled>true</globalAnnounceEnabled>
        <relaysEnabled>true</relaysEnabled>
        <!--
            UPnP / NAT-PMP probing inside a containerized environment
            never reaches a real router; disable so we don't burn
            CPU and emit log noise looking for something that isn't
            there. The OpenHost host-port mapping replaces what UPnP
            would do.
        -->
        <natEnabled>false</natEnabled>
        <!--
            Don't try to launch a browser on container start (there
            isn't one).
        -->
        <startBrowser>false</startBrowser>
        <!--
            Default usage-reporting opt-out. Operators can flip this
            in the GUI under Settings → Usage Reporting.
        -->
        <urAccepted>-1</urAccepted>
    </options>
    <defaults>
        <folder id="" label="" path="/data/data" type="sendreceive"
                rescanIntervalS="3600" fsWatcherEnabled="true">
            <filesystemType>basic</filesystemType>
            <minDiskFree unit="%">1</minDiskFree>
            <maxConflicts>10</maxConflicts>
        </folder>
    </defaults>
</configuration>
XML

# Make sure the rewritten config is owned by the syncthing user;
# we wrote it as root just now.
chown syncthing:syncthing "$CONFIG_FILE"

# -----------------------------------------------------------------
# Launch syncthing in the background under the syncthing user.
#
# `STGUIADDRESS=` (empty) cancels the upstream image's ENTRYPOINT
# default. We're not using their entrypoint, but several scripts
# inspect this var; passing empty string ensures Syncthing reads
# config.xml's <gui><address> instead of an env override.
#
# `STNOUPGRADE=1` disables the in-app self-upgrader. OpenHost
# rebuilds the image to upgrade; mixing two upgrade paths leads
# to image-vs-data drift that's painful to debug.
# -----------------------------------------------------------------

echo "[start.sh] Starting Syncthing on 127.0.0.1:$SYNCTHING_UPSTREAM_PORT"
su-exec syncthing:syncthing env \
    STGUIADDRESS= \
    STNOUPGRADE=1 \
    HOME=/tmp \
    syncthing serve \
        --no-browser \
        --no-restart \
        --home "$ST_CONFIG_DIR" &
SYNCTHING_PID=$!

# Give syncthing a moment to bind 127.0.0.1:$SYNCTHING_UPSTREAM_PORT so the sidecar's
# first probe doesn't get connection-refused. Polling the socket
# is more reliable than a fixed sleep — under load syncthing's
# initial scan can take a few seconds before it accepts GUI
# connections.
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if SYNC_PORT="$SYNCTHING_UPSTREAM_PORT" python3 -c 'import os,socket,sys
p = int(os.environ["SYNC_PORT"])
s = socket.socket()
s.settimeout(0.5)
sys.exit(0 if s.connect_ex(("127.0.0.1", p)) == 0 else 1)' 2>/dev/null; then
        break
    fi
    # If syncthing already crashed, surface the exit code now
    # rather than waiting another five seconds.
    if ! kill -0 "$SYNCTHING_PID" 2>/dev/null; then
        wait "$SYNCTHING_PID" || true
        echo "[start.sh] Syncthing exited before binding — see logs above"
        exit 1
    fi
    sleep 0.5
done

echo "[start.sh] Starting auth-proxy on 0.0.0.0:${AUTH_PROXY_LISTEN_PORT:-8384}"
/opt/auth-venv/bin/python3 /app/auth_proxy.py &
PROXY_PID=$!

# Forward SIGTERM/SIGINT to both children so a `docker stop` /
# OpenHost stop signal lets Syncthing flush its index DB cleanly
# instead of the sidecar lingering on after the daemon dies.
trap 'kill -TERM "$SYNCTHING_PID" "$PROXY_PID" 2>/dev/null; wait' TERM INT

# Block until either child exits, then tear down the survivor.
# `wait -n` is bash-only. We disable errexit around it so a
# non-zero child exit (or signal-driven exit) doesn't abort the
# script before our explicit cleanup runs. See openhost-miniflux's
# start.sh for the same pattern + reasoning.
set +e
wait -n "$SYNCTHING_PID" "$PROXY_PID"
EXIT_CODE=$?
set -e

echo "[start.sh] Child exited (code=$EXIT_CODE); shutting down"
kill -TERM "$SYNCTHING_PID" "$PROXY_PID" 2>/dev/null || true
wait || true
exit "$EXIT_CODE"
