#!/bin/sh
# SSO container entrypoint.
#
# Runs the one-time boot chores (migrations, bootstrap administrator, config cache)
# and then hands over to supervisord (php-fpm + nginx). Every step is idempotent, so
# restarting the container is always safe.
set -eu

log() { printf '%s entrypoint: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

cd /app

# storage/ and bootstrap/cache are tmpfs mounts because the rootfs is read-only
# and Laravel writes compiled config, routes and views at boot.
mkdir -p storage/framework/{cache/data,sessions,views} storage/logs bootstrap/cache /tmp/nginx

# The package manifest lives in bootstrap/cache too, so rebuild it on every boot
# (it is derived from vendor/composer/installed.json and takes milliseconds).
log "discovering packages"
php artisan package:discover --ansi >/dev/null

if [ -z "${APP_KEY:-}" ]; then
    log "APP_KEY is empty: generate one with 'php artisan key:generate --show' and pass it in the environment."
    exit 1
fi

log "caching configuration"
php artisan config:cache --no-interaction >/dev/null

log "running migrations"
php artisan migrate --force --no-interaction

log "bootstrapping the administrator"
php artisan sso:bootstrap --no-interaction || log "bootstrap skipped"

# Route/view caching speeds up the console. Route caching is safe here because we
# use no closures in route files.
php artisan route:cache --no-interaction >/dev/null 2>&1 || true
php artisan view:cache --no-interaction >/dev/null 2>&1 || true

case "${1:-serve}" in
    serve)
        log "starting php-fpm and nginx"
        exec supervisord -c /etc/supervisor/supervisord.conf
        ;;
    migrate)
        exec php artisan migrate --force
        ;;
    prune)
        # Drop the "prune" dispatch word, keep everything else (--dry-run, ...).
        shift
        exec php artisan sso:prune "$@"
        ;;
    *)
        exec "$@"
        ;;
esac
