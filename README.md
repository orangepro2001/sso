# SSO — 계정 센터, in Go

The authorization center (OAuth 2.0 / OpenID Connect issuer + admin console) of
`/home/ubuntu/dev/SSO`, ported 1:1 to a single Go binary. Same routes, same
HTML, same JSON, same token policy — with SQLite where PostgreSQL used to be, so
the result runs with **nothing installed**.

```
sso                       # serve
sso -bootstrap            # create the first super administrator from the env
sso -users                # list accounts
sso -user-password NAME   # set or generate a password
sso -role NAME -set-role super_admin
sso -rotate-keys          # retire the active RS256 key, generate a new one
sso -prune [-dry-run]     # expired tokens, spent codes, old audit rows
sso -backup /path.sqlite  # consistent copy of the data file
sso -import-postgres DSN  # copy production's PostgreSQL data in (see below)
```

## Build

```sh
cd sso
go build ./...            # or: go build -o sso .
go vet ./...
go test ./...             # smoke test: temp SQLite file, full flows
```

Cross-compiling is the point of the dependency set (pure Go SQLite, standard
library crypto):

```sh
GOOS=windows GOARCH=amd64 go build -o sso.exe .
GOOS=linux   GOARCH=amd64 go build -o sso .
```

Two things ship next to the binary if you want them: `web/` is embedded in the
executable (templates and assets), and only the **importer** is a separate
program (below), because it is the one part that needs a PostgreSQL driver.

## Configuration

Same env keys and defaults as `.env.example`; see that file for the full list.

| Variable | Meaning | Default |
| --- | --- | --- |
| `APP_KEY` | avatar HMAC key and the seed of the signing-key encryption key | — (set it) |
| `APP_URL` | internal origin used for URL generation | `http://127.0.0.1:3550` |
| `SSO_ISSUER` | public base URL, including the mount point; becomes `iss` | `$APP_URL/sso` |
| `SSO_LISTEN` | listen address | `0.0.0.0:3550` |
| `SSO_URL_SCHEME` | scheme for generated absolute links | `https` |
| `SSO_FORCE_ROOT_URL` | put the mount point into generated URLs | `true` |
| `SESSION_PATH` | session cookie path / mount point | `/sso` |
| `SESSION_SECURE_COOKIE` | `Secure` on the session cookie | `true` |
| `SESSION_LIFETIME` | session idle lifetime, minutes | `720` |
| `WR_DB` | the SQLite data file | `storage/sso.db` |
| `WR_STORAGE` | avatar tree root | `storage` |
| `SSO_ACCESS_TOKEN_TTL` | access token lifetime, seconds | `604800` (7 days) |
| `SSO_REFRESH_TOKEN_TTL` | refresh token lifetime, seconds | `2592000` (30 days) |
| `SSO_RESET_LINK_TTL` | password reset link lifetime, seconds | `86400` |
| `SSO_DISPLAY_TIMEZONE` | zone the console prints times in (clock stays UTC) | `Asia/Seoul` |
| `SSO_BOOTSTRAP_ADMIN_USERNAME` / `_NAME` / `_PASSWORD` / `_PASSWORD_FILE` | first super administrator | — |

`APP_KEY` is read as the exact string in the environment — the avatar URL is
`hex(HMAC-SHA256(APP_KEY, "<id>|<version>"))`, which is what the PHP hashed
(`config('app.key')`), so links minted before the switch keep working. The
signing key's private half is encrypted with AES-256-GCM under a key derived
from the same value.

Mail is stubbed deliberately: users have no address, so there is no
"forgot password" flow. An administrator mints a one-time link and the service
logs it (`password reset link for <username>: <url>`) as well as showing it
once in the console.

## The data file

`WR_DB` is one SQLite database (WAL mode, `busy_timeout`, foreign keys on). The
schema is created on open from idempotent `CREATE TABLE IF NOT EXISTS`
statements equivalent to the PHP migrations' final state, so a restart is always
safe and an empty directory is a valid deployment.

- Tokens and codes are rows as well as signatures: revoking one, or disabling a
  person, takes effect on the next request (`docs/DESIGN.md` §3 in the PHP repo).
- Sessions are rows too, so "sign out everywhere" reaches browsers.
- Signing keys are generated on first boot and kept here, private half
  encrypted with `APP_KEY`; `-rotate-keys` retires the active key but keeps the
  old public key in the JWKS so 7-day tokens signed before the rotation still
  verify.
- `-backup` uses SQLite's `VACUUM INTO`, which is consistent while the service
  runs.

Avatars live under `WR_STORAGE/avatars/<user>/<file>`; the database stores the
same relative path the PHP's local disk used.

## Importing the PostgreSQL data

Production data must survive the switch. The importer is a separate module and
binary so the shipped service links no PostgreSQL driver:

```sh
# 1. create the SQLite schema (any run of the service does this)
./sso -bootstrap          # or just start it once and stop it

# 2. build the importer
cd tools/pgmigrate && go build -o ../../sso-pgmigrate . && cd ../..

# 3. copy (the service finds sso-pgmigrate beside itself, or use -pgmigrate)
./sso -import-postgres 'postgres://sso@host:5432/sso?sslmode=require'
```

What it copies: `users` (bcrypt hashes included — existing passwords keep
working), `oauth_clients`, `access_tokens`, `refresh_tokens`,
`oauth_auth_codes`, `user_password_resets`, `audit_logs`, and the **public**
halves of `signing_keys`. Ids are preserved, so `subject` claims, avatar URLs
and audit references still line up. Rows are counted on both sides; a mismatch
fails the import instead of leaving half a table.

What it does not copy, on purpose:

| Skipped | Why |
| --- | --- |
| `sessions` | Laravel stores a PHP-serialised payload; people sign in again. |
| `signing_keys.private_key` | Encrypted with Laravel's encrypter, which this service cannot open (and should not). The public halves are imported as retired keys so existing tokens verify; a fresh active key is generated on first boot, so new tokens are signed. |
| `created_by`, `reviewed_by` | Pointed at the old `admins` table; the PHP's own migration cleared them because admin ids do not map to user ids. |
| `guest_devices`, `blacklist_entries`, `registration_invites` | Tables the design left in place, unread (`DESIGN.md` §5). |

After the import, everybody's access and refresh tokens keep working until they
expire; the only user-visible change is that a token issued by the old key is
verified against the imported public key rather than a new one.

## Endpoints

Identical paths to the PHP (relative to `SSO_ISSUER`): discovery and JWKS,
`/oauth/authorize` (code + mandatory PKCE S256 for public clients),
`/oauth/token` (authorization_code, refresh_token with rotation and family
revocation, client_credentials), `/oauth/userinfo`, `/oauth/introspect`,
`/oauth/revoke`, `/api/me`, `/api/users`, `/avatar/{id}/{v}?sig=`,
`/healthz`, and the console under `/admin`.

`/healthz` never touches the database: a brief outage should not restart-loop
the proxy layer.

## Layout

```
main.go                    flags, embed, boot (bootstrap admin), serve
smoke_test.go              discovery, code+PKCE, userinfo, refresh, console, healthz
internal/config            env, defaults, scope vocabulary
internal/store             schema.sql + typed SQL (users, clients, tokens, audit, keys, sessions)
internal/secure            RS256 JWT, RSA keys and their envelope, PKCE, bcrypt, random strings
internal/service           UserAccounts, TokenService, SigningKeyService, resets, audit, client auth
internal/server            net/http routes, session/CSRF/flash, handlers, templates
web/templates              html/template mirroring the Blade markup
web/assets                 app.css, theme.css, console.js, theme-init.js — copied verbatim
tools/pgmigrate            PostgreSQL → SQLite importer (own go.mod, not shipped)
```

## The one dependency

`golang.org/x/crypto/bcrypt` is the only library beyond the SQLite driver, and
it exists for one reason: the PHP stored Laravel bcrypt hashes (`$2y$…`), and
people must sign in after the switch. bcrypt is an algorithm, not a framework
feature — `bcrypt.CompareHashAndPassword` reads exactly what `Hash::make` wrote,
and new passwords are written in the same format. Everything else (JWT, JWKS,
PKCE, AES-GCM, HMAC, random tokens) is `crypto/*` and `encoding/*`.

## Differences worth knowing

- Rate limiting is in-memory (one process owns the counters) rather than the
  database/Redis cache. Same limits: 10 sign-in attempts per 5 minutes per
  username+IP; the API's 120/240 per minute.
- `go test` covers the protocol and console flows against a temporary SQLite
  file; it does not start a second process, so the smoke test is the contract
  for "the binary works", not a re-implementation of every PHPUnit case.
- The console's CSRF handling matches Laravel's `419` behaviour for the login
  form sent twice (it carries on to the parked authorization request), but the
  status code is `419` only for non-login form replays.
- "이 브라우저에서 로그인 유지" sets no separate remember-me cookie: the session
  row already lives `SESSION_LIFETIME` minutes, and the checkbox is kept in the
  markup so the page looks the same. Nothing is lost except a longer idle
  timeout on that one browser.
