# Syncthing for OpenHost.
#
# Built on top of the official syncthing/syncthing image — a minimal
# Alpine container with the syncthing binary. We layer on:
#
#   * python3 + a venv with PyJWT[crypto] and requests — the runtime
#     for our auth-proxy sidecar (auth_proxy.py).
#   * bash — start.sh uses `wait -n`, which Alpine's default
#     /bin/sh (busybox ash) does not implement.
#   * curl — the official image's bundled entrypoint script
#     (/bin/entrypoint.sh) uses curl for the healthcheck command;
#     our healthcheck path goes through the OpenHost router, so we
#     don't actually need curl, but several debug paths in the
#     image's existing scripts also reach for it. Cheap to keep.
#
# We bypass the upstream entrypoint entirely. It does PUID/PGID
# remapping, which OpenHost handles via its container runtime, and
# starts syncthing under su-exec which would lose track of our
# auth-proxy sidecar. Our start.sh runs as root and starts both
# processes itself (the sidecar runs as root because it binds the
# container's main port; syncthing runs via `su-exec syncthing` so
# its data files are owned by the unprivileged user, matching the
# upstream image's behavior).

# Pin to a specific version rather than `latest` so deploys are
# reproducible. v1.30.0 is the September 2025 release. Bump
# intentionally — the OpenHost owner sees an upgrade prompt.
FROM syncthing/syncthing:1.30.0

# All install steps need root; the upstream image switches to UID
# 1000 partway through. Reset to root for our additions, then
# start.sh handles the privilege drop.
USER root

# bash for `wait -n`, python3 for the auth-proxy, py3-pip for
# venv-bootstrap, su-exec to drop privileges back to the syncthing
# user when launching the daemon. su-exec is already in the upstream
# image but list it explicitly so a future base-image change doesn't
# silently remove it.
RUN apk add --no-cache \
        bash \
        python3 \
        py3-pip \
        su-exec

# PyJWT[crypto] gives us RS256 verification; requests is used to
# fetch the OpenHost router's JWKS. Pinned for reproducibility —
# bump intentionally. Installed into a venv so we never collide
# with system Python's PEP 668 protections on Alpine 3.20+.
RUN python3 -m venv /opt/auth-venv \
 && /opt/auth-venv/bin/pip install --no-cache-dir \
        'PyJWT[crypto]==2.9.0' \
        'requests==2.32.3'

# Our wrapper + sidecar.
COPY start.sh /app/start.sh
COPY auth_proxy.py /app/auth_proxy.py
RUN chmod +x /app/start.sh

# Container listens here (the auth-proxy sidecar). Syncthing itself
# listens on 127.0.0.1:8385 inside the container — see start.sh.
EXPOSE 8384

# Override the upstream image's ENTRYPOINT (which is /bin/entrypoint.sh
# from the official syncthing image — does PUID remap and execs
# syncthing under su-exec). Our start.sh handles supervision of
# both syncthing and the sidecar.
ENTRYPOINT []
CMD ["/app/start.sh"]
