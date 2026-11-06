# SSO — 계정 센터 (authorization center)

Self-hosted OAuth 2.0 / OpenID Connect issuer for the internal tools, and the one
place where people and their accounts are managed. Laravel on PostgreSQL, one
container, no asset build.

1. **One user space, two roles.** Everybody is a `user`; a `super_admin` also gets
   the console. Anyone may register (`/register`), no password policy.
2. **People first.** The console opens on the user list; every account action is
   one button on that person's page, and the same actions exist as a JSON API
   (`docs/api.md`) for applications.
3. **Disabling is immediate.** Tokens are database rows, checked with the user's
   status on every use; disabling also deletes the person's browser sessions.

---

## Endpoints

All paths are relative to the issuer (`SSO_ISSUER`, e.g. `https://sso.521985.xyz`).

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/.well-known/openid-configuration` | discovery (RFC 8414 / OIDC) |
| `GET` | `/.well-known/jwks.json` | RS256 public keys |
| `GET` | `/oauth/authorize` | authorization code, PKCE `S256` (mandatory for public clients) |
| `POST` | `/oauth/token` | `authorization_code`, `refresh_token`, `client_credentials` |
| `POST` | `/oauth/introspect` | RFC 7662, requires client authentication |
| `POST` | `/oauth/revoke` | RFC 7009 |
| `GET`/`POST` | `/oauth/userinfo` | bearer-protected identity document (`name`, `preferred_username`, `role`, `picture`) |
| `*` | `/api/me`, `/api/users` | account API, bearer token (`docs/api.md`) |
| `GET` | `/avatar/{id}/{v}?sig=` | profile picture, anonymous, HMAC-signed URL |
| `GET` | `/healthz` | liveness |
| `GET` | `/admin` | console (super administrators) |

## Identities

One account space. A user has a display name, a **username** (the sign-in
identifier, lower-case), a password, an optional picture and a role (`user` or
`super_admin`). There is no e-mail address, so no `email` scope or claim and no
verification mail. The console is the same sign-in as every application; the
`admin` middleware only checks the role.

## Token policy

| Subject | Access token | Lifetime | Refresh |
| --- | --- | --- | --- |
| User (code flow) | RS256 JWT, `jti` in the database | **7 days** | rotating `refresh_token` (with `offline_access`) |
| Confidential client | RS256 JWT | 7 days | re-request (no refresh token) |

Every token is a database row, so revocation is immediate and does not have to wait
for a JWT to expire: revoking a token, or disabling its user, takes effect on the
next `userinfo`, introspection or API call.

Refresh tokens rotate on every use. Replaying an already rotated token is treated as
theft and revokes the whole `family_id` — the client has to re-authenticate.

## Housekeeping

`sso:prune` deletes rows that can no longer authenticate anything (revoked or
expired tokens, spent authorization codes) and audit rows older than 90 days.

```bash
php artisan sso:prune --dry-run        # via `podman exec sso php artisan sso:prune`
php artisan sso:prune
```

Installed as `sso-prune.timer` (nightly, `Persistent=true`) by `install.sh`.

## Password reset without e-mail

There is no "forgot password" mail. On the person's page the administrator either
sets a password (blank = a 12-character one is generated and shown once) or mints a
**one-time link** to hand over out of band:

- single use, expires after `SSO_RESET_LINK_TTL` (default 24 h)
- issuing a new link revokes any earlier unused one
- only the SHA-256 is stored, so a database dump is not a pile of live credentials
- the URL is built from `SSO_ISSUER`, so it is publicly openable

**Any** password change revokes that user's access and refresh tokens: the old
password stops opening things, so what it opened is closed.

Lost the last administrator password? `php artisan sso:user-password <username>`.

## Console (`/admin`, Korean)

- **사용자** — search (`/` focuses it), filter chips (관리자 / 일반 / 비활성) with counts,
  a dialog to create someone. Each person has one page: quick actions (관리자 지정,
  비활성화, 모든 곳에서 로그아웃), name / username / note, password or reset link,
  picture, the applications they are signed in to, their recent activity, and
  deletion behind typing the username.
- **활동 기록** — the audit trail as sentences, filtered by person and by kind; the raw
  event and metadata stay one click away.
- **연결된 앱** — OAuth clients; registering a client *is* the consent step.
- **내 계정** — what every person can change themselves: name, username (with the
  current password), password, picture, signing out everywhere.

Two rules hold in the console and the API alike (`App\Services\UserAccounts`): there is
always one active super administrator, and nobody can demote, disable or delete
themselves.

Pictures are cropped to a square and shrunk to 512 px **in the browser**
(`public/assets/console.js`) — the image has no GD — so a phone photo arrives as
~50 KB WebP. The server accepts JPEG/PNG/WebP/GIF up to 1 MB.

Times are stored in UTC and printed in `SSO_DISPLAY_TIMEZONE` (default Asia/Seoul).

The first administrator comes from the environment (`sso:bootstrap`, run on every boot,
no-op once one exists); `sso:role <username> super_admin` promotes from the shell.

## Configuration

See `.env.example`. The ones that matter:

| Variable | Meaning |
| --- | --- |
| `APP_URL` | internal origin the container listens on (`http://127.0.0.1:3550`) |
| `SSO_ISSUER` | public base URL; becomes the `iss` claim and the origin of picture and reset URLs |
| `DB_*` | PostgreSQL on the AI host over the tailnet, TLS required |
| `SSO_ACCESS_TOKEN_TTL` | user access token lifetime, default `604800` (7 days) |
| `SSO_DISPLAY_TIMEZONE` | zone the console prints times in, default `Asia/Seoul` |
| `SSO_BOOTSTRAP_ADMIN_*` | first super administrator (skipped once one exists) |

## Deploy

```bash
# 1. build + install the service (idempotent, also used for upgrades)
./deploy/scripts/install.sh

# 2. expose it: add `import prefix sso 127.0.0.1:3550` to /etc/caddy/Caddyfile
sudo systemctl reload caddy

# 3. check
curl -fsS https://host/sso/healthz
```

The unit (`deploy/quadlet/sso.container`) runs the image with a read-only rootfs,
`--cap-drop all`, `no-new-privileges` and tmpfs for the two writable paths, as an
unprivileged user. The bootstrap password is a **podman secret** mounted at
`/run/secrets/sso_bootstrap_admin_password`, never an environment variable:

```bash
podman secret create sso-bootstrap-admin-password ~/.config/sso/bootstrap_admin_password
podman exec sso cat /run/secrets/sso_bootstrap_admin_password   # read it back when needed
```

### Public entry point

The service binds every interface by design, so it is also served publicly. Two
caddy listeners exist on this host. The tailnet one strips `/sso` before forwarding;
the public one gives the service its own origin and proxies root paths unchanged,
with the old `521985.xyz/sso…` URLs answered by a 308 to `sso.521985.xyz`:

| Listener | File | Serves |
| --- | --- | --- |
| tailnet | `/etc/caddy/Caddyfile` (`http://:8080`) | `https://egg.tail9f7f1f.ts.net/sso` |
| public | `/etc/daily-work-web/Caddyfile` (`521985.xyz:443`) | `https://sso.521985.xyz` |

`deploy/caddy/public.Caddyfile` is the public file verbatim. It exposes only what
actually runs on the host; everything else answers 404 rather than proxying to a
dead backend.

`SSO_ISSUER` must be the **canonical public** URL (`https://sso.521985.xyz`), not
the tailnet name: the issuer is embedded in every token and in the discovery
document, and a public client cannot resolve a tailnet host. Requests arriving
through the tailnet still get tailnet-hosted links and redirects, because the
middleware derives the root from the request's `Host`.

### Database

Provisioned once on the PostgreSQL host:

```sql
CREATE ROLE sso LOGIN PASSWORD '…';
CREATE DATABASE sso OWNER sso;
CREATE DATABASE sso_test OWNER sso;   -- for the test suite
```

`pg_hba.conf` must accept the service host over the tailnet (`hostssl … 100.64.0.0/10
scram-sha-256`), which it already does on the AI host.

## Development

```bash
composer install
php artisan test          # needs sso_test in PostgreSQL, see phpunit.xml
vendor/bin/pint
```

No Node, no bundler: the console is Blade plus one hand-written stylesheet at
`public/assets/app.css`.

## Layout

```
app/Http/Controllers/OAuth/   protocol endpoints
app/Http/Controllers/Admin/   console
app/Http/Controllers/Api/     account API (docs/api.md)
app/Services                  UserAccounts (every account change), TokenService, Jwt,
                              SigningKeyService, ClientAuthenticator, AuditLogger
deploy/                       Containerfile, nginx/php/supervisor config, quadlet, caddy
docs/DESIGN.md                decisions and threat notes
docs/api.md                   account API
```
