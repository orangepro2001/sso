#!/usr/bin/env bash
# deploy/scripts/install.sh — install or upgrade the SSO service on this host.
#
#   sudo ./deploy/scripts/install.sh            # install / upgrade
#   ./deploy/scripts/install.sh --user          # same, as the current user
#   ./deploy/scripts/install.sh --uninstall
#
# What it does:
#   1. builds localhost/sso:current from the checked out tree (podman, no registry)
#   2. writes ~/.config/sso/env on first run (never overwrites an existing file)
#   3. installs the quadlet unit and the systemd credential
#   4. reloads systemd --user and (re)starts sso.service
#
# Prerequisites that are deliberately *not* automated: the PostgreSQL role and
# database on the AI host, and the caddy route (see deploy/caddy/sso.caddy).

set -euo pipefail

SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/sso"
QUADLET_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/containers/systemd"
UNIT=sso.container
SERVICE=sso.service
IMAGE=localhost/sso:current

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

as_root() {
    if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi
}

uninstall() {
    log "stopping $SERVICE"
    systemctl --user disable --now "$SERVICE" 2>/dev/null || true
    rm -f "$QUADLET_DIR/$UNIT"
    systemctl --user daemon-reload || true
    log "removed the unit; $CONFIG_DIR and the database were left untouched"
}

main() {
    [ -f "$SRC/deploy/Containerfile" ] || die "$SRC does not look like the SSO repository"

    log "building $IMAGE from $SRC"
    podman build --format docker -f "$SRC/deploy/Containerfile" -t "$IMAGE" "$SRC"

    mkdir -p "$CONFIG_DIR" "$QUADLET_DIR"

    if [ ! -f "$CONFIG_DIR/env" ]; then
        log "writing $CONFIG_DIR/env from .env.example"
        cp "$SRC/.env.example" "$CONFIG_DIR/env"

        # Fill in the values that can be generated locally; everything the operator
        # must supply (database password, guest secret) is left blank on purpose.
        app_key="base64:$(head -c 32 /dev/urandom | base64)"
        sed -i "s|^APP_KEY=.*|APP_KEY=$app_key|" "$CONFIG_DIR/env"
        sed -i "s|^SSO_BOOTSTRAP_ADMIN_PASSWORD_FILE=.*|SSO_BOOTSTRAP_ADMIN_PASSWORD_FILE=/run/secrets/sso_bootstrap_admin_password|" "$CONFIG_DIR/env"
        chmod 600 "$CONFIG_DIR/env"

        log "generated an APP_KEY"
        log "edit $CONFIG_DIR/env now: DB_PASSWORD, SSO_GUEST_SECRET, SSO_ISSUER, SSO_BOOTSTRAP_ADMIN_EMAIL"
    fi

    log "installing the bootstrap password secret"
    pw_file=$CONFIG_DIR/bootstrap_admin_password
    if [ ! -f "$pw_file" ]; then
        printf 'bootstrap-password-%s' "$(head -c 18 /dev/urandom | base64 | tr -d '/+=')" > "$pw_file"
        chmod 600 "$pw_file"
        log "generated $pw_file (edit it before the first boot to choose your own)"
    fi
    # podman secrets are what the quadlet unit mounts; keep them in sync.
    podman secret rm sso-bootstrap-admin-password >/dev/null 2>&1 || true
    podman secret create sso-bootstrap-admin-password "$pw_file" >/dev/null

    log "installing $QUADLET_DIR/$UNIT"
    # The unit uses %h/... paths, so it works unchanged for any user.
    as_root install -m 0644 "$SRC/deploy/quadlet/$UNIT" "$QUADLET_DIR/$UNIT"

    log "reloading systemd --user"
    systemctl --user daemon-reload

    log "enabling and restarting $SERVICE"
    systemctl --user enable "$SERVICE" >/dev/null 2>&1 || true
    systemctl --user restart "$SERVICE"

    log "waiting for the health check"
    for _ in $(seq 1 30); do
        if curl -fsS -m 2 http://127.0.0.1:3550/healthz >/dev/null 2>&1; then
            log "healthy: http://127.0.0.1:3550/healthz"
            printf '\nNext steps:\n'
            printf '  1. caddy: add `import prefix sso 127.0.0.1:3550` to /etc/caddy/Caddyfile and `systemctl reload caddy`\n'
            printf '  2. verify: curl -fsS https://<host>/sso/healthz\n'
            printf '  3. open  https://<host>/sso/admin and sign in with the bootstrap administrator\n'
            return 0
        fi
        sleep 1
    done

    journalctl --user -u "$SERVICE" -n 40 --no-pager || true
    die "the service did not become healthy"
}

case "${1:-install}" in
    --uninstall|uninstall) uninstall ;;
    *) main ;;
esac
