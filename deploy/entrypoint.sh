#!/bin/sh
# SSO container entrypoint.
#
# Runs the one-time boot chores (migrations, bootstrap administrator, config cache)
# and then hands over to supervisord (php-fpm + nginx). Every step is idempotent, so
# restarting the container is always safe.
set -eu

log() { printf '%s entrypoint: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

cd /app

# Writable state, expected to be backed by tmpfs because the rootfs is read-only.
mkdir -p storage/framework/{cache/data,sessions,views} storage/logs bootstrap/cache
chown -R nobody:nobody storage bootstrap/cache 2>/dev/null || true

if [ -z "${APP_KEY:-}" ]; then
    log "APP_KEY is empty: generate one with 'php artisan key:generate --show' and pass it in the environment."
    exit 1
fi

# Configuration is baked into a cache file for speed; it must be dumped before the
# first request because the rootfs is read-only and PHP cannot write it later.
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
    *)
        exec "$@"
        ;;
esac
