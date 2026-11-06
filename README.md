# SSO — authorization center

Self-hosted OAuth 2.0 / OpenID Connect issuer for internal services. Laravel 12 on
PostgreSQL, one container, no external asset build (`no npm`).

The service is designed around three rules:

1. **No public registration.** Every account is created by an administrator.
2. **Machines never wait for a human.** A client that can prove itself with a shared
   secret gets a working token in the same request, every time.
3. **Review happens afterwards.** The administrator looks at what happened and
   blacklists; that decision takes effect on the next request.

---

## Endpoints

All paths are relative to the public mount point (`SSO_ISSUER`, e.g. `https://host/sso`).

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/.well-known/openid-configuration` | discovery (RFC 8414 / OIDC) |
| `GET` | `/.well-known/jwks.json` | RS256 public keys |
| `GET` | `/oauth/authorize` | authorization code, PKCE `S256` (mandatory for public clients) |
| `POST` | `/oauth/token` | `authorization_code`, `refresh_token`, `client_credentials` |
| `POST` | `/oauth/introspect` | RFC 7662, requires client authentication |
| `POST` | `/oauth/revoke` | RFC 7009 |
| `GET`/`POST` | `/oauth/userinfo` | bearer-protected identity document |
| `POST` | `/oauth/guest` | silent guest enrolment (see below) |
| `GET` | `/healthz` | liveness |
| `GET` | `/admin` | console (session auth, administrators only) |

## Identities

Two separate account spaces, on purpose:

| Space | Signs in with | Where | Cookie | Fields |
| --- | --- | --- | --- | --- |
| User (token subject) | username + password | `/sso/login` | `sso_session` | display name, username, password |
| Administrator (console) | e-mail + password | `/sso/admin/login` | `sso_admin_session` | name, e-mail, password |

The two use **separate session cookies**, so "signed in" is never ambiguous:
being signed in to the console is not a client identity, and signing out of one
does not sign out of the other. When a client sends a browser to
`/oauth/authorize` that has no *user* session, the sign-in page names the
application and says console accounts cannot be used — instead of showing a bare
login form that invites the person to type their console credentials.

A user account carries no e-mail address: the `email` scope and the `email` /
`email_verified` claims were removed with it. `profile` now yields `name` and
`preferred_username` (the username), which is what an OIDC client should read
anyway.

## Token policy

| Subject | Access token | Lifetime | Refresh |
| --- | --- | --- | --- |
| User (code flow) | RS256 JWT, `jti` in the database | **7 days** | rotating `refresh_token`, silent |
| Confidential client | RS256 JWT | 7 days | re-request (no refresh token) |
| Guest device | opaque `sso_g_…`, stored as SHA-256 | **none** (`expires_at = null`) | re-post to `/oauth/guest` |

Every token is a database row, so revocation is immediate and does not have to wait
for a JWT to expire. Revoking an access token, blacklisting a device, disabling a
user or a client all take effect on the next introspection or `userinfo` call.

Refresh tokens rotate on every use. Replaying an already rotated token is treated as
theft and revokes the whole `family_id` — the client has to re-authenticate.

## The silent guest channel

For machines that hold only a read-only database credential and no user in the loop.

```
signature = hex( HMAC-SHA256( key = SSO_GUEST_SECRET, message = "sso-guest-v1\n" + device_id ) )
device_id = a stable environment value: hostname, /etc/machine-id, serial number, container name
```

```bash
curl -sS -X POST https://host/sso/oauth/guest \
  -H 'Content-Type: application/json' \
  -d '{"device_id":"lab-host-07","algo":"hmac-sha256","signature":"…"}'
```

```json
{
  "access_token": "sso_g_…",
  "token_type": "Bearer",
  "expires_in": null,
  "scope": "db:read",
  "device_id": "lab-host-07",
  "device_status": "active",
  "signature_valid": true,
  "newly_enrolled": true
}
```

Behaviour, exactly as specified:

- **Every request is approved.** Yes, a wrong or missing signature is approved too — it
  is recorded as suspicious in the audit log and shown in the console, never rejected.
- **First sight enrols the device** (`guest_devices`, with IP and user agent) and the
  token works immediately. No approval queue, no delay.
- **Only one thing refuses service:** an explicit administrator blacklist. A blacklisted
  device gets `403 access_denied` and its outstanding tokens stop introspecting.
- **No expiry.** Guest tokens live until revoked or blacklisted. Setting
  `SSO_GUEST_TOKEN_TTL` gives them a fixed lifetime, in which case a client just calls
  `/oauth/guest` again — the refresh is silent by construction.

Compute the signature with the built-in command or one shell line:

```bash
php artisan sso:guest-sign lab-host-07        # prints payload, signature and a ready curl
printf 'sso-guest-v1\nlab-host-07' | openssl dgst -sha256 -hmac "$SSO_GUEST_SECRET" -r | cut -d' ' -f1
```

## Housekeeping

Guest tokens never expire, so `sso:prune` is what keeps the tables bounded. It
deletes only rows that can no longer authenticate anything: revoked/expired
tokens, spent authorization codes, superseded guest tokens (the newest live token
per device is always kept), devices unseen for 180 days — active ones only, so a
blacklist can never be silently forgotten — and audit rows older than 90 days.

```bash
php artisan sso:prune --dry-run        # via `podman exec sso php artisan sso:prune`
php artisan sso:prune                  # default: 90d audit, 180d devices
```

Installed as `sso-prune.timer` (nightly, `Persistent=true`) by `install.sh`.

## Password reset without e-mail

Users have no e-mail address, so there is no "forgot password" mail. The
administrator mints a **one-time link** and hands it over out of band:

```
console → Users → <user> → "Create reset link"
   ↓
https://<host>/sso/password/reset/sso_pw_<48 chars>      (shown once)
   ↓
the user opens it, sets their own password, the link dies
```

- single use, expires after `SSO_RESET_LINK_TTL` (default 24 h)
- issuing a new link revokes any earlier unused one
- only the SHA-256 is stored, so a database dump is not a pile of live credentials
- the URL is built from `SSO_ISSUER`, so it is publicly openable
- every creation, use and refusal is in the audit log

**Any** password change — this link or the console's "Replace password" — revokes
that user's access and refresh tokens. One rule: the old password stops opening
things, so what it opened is closed.

Lost password with no link at hand? `php artisan sso:user-password <username>`.

## Console

`/admin` — administrators only, no registration route exists anywhere in the app.

- **Users** — create, disable, replace password. A user has exactly three fields:
  display name, **username** (the sign-in identifier) and password. There is no
  e-mail address and therefore no verification mail to send. Disabling kills live
  tokens immediately.
- **Clients** — register OAuth clients (public/PKCE or confidential with a secret shown
  once); registering a client *is* the consent step, so users never see a consent screen.
- **Guest devices** — the a-posteriori review list: first/last seen, IP, user agent,
  request count; blacklist (revokes existing tokens) or reinstate.
- **Tokens** — everything live, with a per-token kill switch.
- **Blacklist** — deny list for `device`, `user`, `token` (jti) and `client`.
- **Audit** — append-only trail with a prefix filter.

The first administrator comes from the environment (`sso:bootstrap`, run on every boot,
no-op once an admin exists).

## Configuration

See `.env.example`. The ones that matter:

| Variable | Meaning |
| --- | --- |
| `APP_URL` | internal origin the container listens on (`http://127.0.0.1:3550`) |
| `SSO_ISSUER` | public base URL **including** `/sso`; becomes the `iss` claim |
| `SESSION_PATH` | cookie path for the `/sso` mount point |
| `DB_*` | PostgreSQL on the AI host over the tailnet, TLS required |
| `SSO_GUEST_SECRET` | HMAC key for the guest channel (empty = signatures unverifiable) |
| `SSO_GUEST_TOKEN_TTL` | `0` = guest tokens never expire |
| `SSO_ACCESS_TOKEN_TTL` | user access token lifetime, default `604800` (7 days) |
| `SSO_BOOTSTRAP_ADMIN_*` | first super administrator (a user; skipped once one exists) |

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
caddy listeners exist on this host and both strip `/sso` before forwarding:

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
app/Services                  Jwt, SigningKeyService, TokenService, GuestService,
                              BlacklistService, ClientAuthenticator, AuditLogger
deploy/                       Containerfile, nginx/php/supervisor config, quadlet, caddy
docs/DESIGN.md                decisions and threat notes
```
