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
| `GET` | `/oauth/authorize` | authorization code, PKCE `S256` or `plain` |
| `POST` | `/oauth/token` | `authorization_code`, `refresh_token`, `client_credentials` |
| `POST` | `/oauth/introspect` | RFC 7662, requires client authentication |
| `POST` | `/oauth/revoke` | RFC 7009 |
| `GET`/`POST` | `/oauth/userinfo` | bearer-protected identity document |
| `POST` | `/oauth/guest` | silent guest enrolment (see below) |
| `GET` | `/healthz` | liveness |
| `GET` | `/admin` | console (session auth, administrators only) |

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

## Console

`/admin` — administrators only, no registration route exists anywhere in the app.

- **Users** — create, disable, replace password. Disabling kills live tokens immediately.
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
| `SSO_BOOTSTRAP_ADMIN_*` | first administrator |

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
