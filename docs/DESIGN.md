# Design notes

Why the implementation looks the way it does. Short, and honest about trade-offs.

## 1. Scope

An internal authorization center: a handful of administrators, a modest number of
users, and machines that need database access without a human in the loop. The
requirement was "simple, not crude" — so the protocol surface is standard and the
operational surface is small.

Not implemented on purpose: consent screens, user self-registration, e-mail flows,
multi-tenancy, dynamic client registration, scopes finer than a service needs.

## 2. Two identity spaces

`admins` and `users` are separate tables and separate session guards. An administrator
is an operator of the console; a user is a subject that receives tokens. Conflating
them is the usual way an SSO installs a privilege-escalation path, and it buys nothing
here.

There is no registration route in the application at all. The first administrator is
bootstrapped from the environment and every other account is created from the console.

## 3. Tokens are rows, not just signatures

Access tokens are RS256 JWTs so clients can verify them offline, **and** their `jti`
is stored. That combination is deliberate:

- offline verification for the common case (no round trip per request),
- instant revocation for the case that matters (a leaked laptop, a runaway script).

Because every token has a row, `introspect`, `userinfo`, the console's revoke button
and the blacklist all agree immediately. A pure-JWT design would have to wait out the
`exp` claim.

Guest tokens are the inverse: opaque (`sso_g_…`), stored only as SHA-256, no signature,
no expiry. A guest is a machine with a read-only credential; there is nothing to verify
offline, and the blacklist is the only thing that must be fast. Opaque is also what
makes "no expiry" safe: a leaked guest token can be killed server-side in one request.

## 4. Refresh rotation with family revocation

Non-expiring sessions are a request in disguise. The design gives users a 7-day access
token and a rotating refresh token, so a client refreshes silently, and it treats a
replayed refresh token as proof of theft: the whole `family_id` is revoked and the
client must authenticate again. This is the standard defence and it costs one column.

## 5. The guest channel deliberately has no gate

Requirement: even suspicious requests are approved, a human reviews later. So
`/oauth/guest` has exactly one rejection path — an explicit blacklist — and everything
else is recorded and allowed:

- unknown device → enrol, return a working token, flag `newly_enrolled`,
- bad or missing signature → return a working token, flag `signature_valid: false`,
- a device that spams → rate limit (120/min per IP) only, because a rate limit is not
  a review queue.

What makes this defensible instead of reckless:

| Risk | Mitigation |
| --- | --- |
| Anyone on the network can ask for a token | the token is only as useful as `db:read`; the guest scope is fixed by `SSO_GUEST_SCOPE` |
| A stranger enrols a device | it is visible in the console with IP/user agent, and one click blacklists it |
| Signature is bypassable | the signature is not a gate, it is a *label*: `signature_valid` tells the reviewer whether the device knew the secret |
| The secret leaks | rotate `SSO_GUEST_SECRET`; existing devices keep working, new signatures differ, and the review list shows the change |

The signature exists to let the reviewer sort a long list, not to keep people out.
That is a real design choice, not an accident.

`signature = hex(HMAC-SHA256(SSO_GUEST_SECRET, "sso-guest-v1\n" + device_id))`

The `sso-guest-v1` prefix is a version tag: if the scheme ever changes, v1 signatures
become distinguishable instead of silently wrong. The device id is compared with
`hash_equals`, and the device id itself is length-bounded and trimmed before use.

## 6. Key handling

The RSA key pair is generated on first boot and stored in the database, private half
encrypted with `APP_KEY` (Laravel's `encrypted` cast). Reasons: the rootfs is read-only,
no key material ships in the image, and a database clone is not immediately a signing
oracle. `sso:keys:rotate` retires the active key without invalidating tokens signed by
it — old keys stay in the JWKS until they are deleted.

The `alg` header is validated on every decode (RS256 only), so there is no algorithm
confusion surface.

## 7. Session strategy

Sessions are database-backed rather than a signed cookie, one row per browser. A cookie
session cannot be invalidated by an administrator, and "disable this account *now*" is
a requirement here. The extra query per console request is irrelevant at this scale.

The `users` and `admins` guards share the session cookie; they differ in provider and
in the `admin` middleware.

## 8. Running under `/sso`

The reverse proxy strips the prefix, so the container sees plain paths (`/oauth/token`)
while clients see `https://host/sso/oauth/token`. Two things follow:

- `SSO_ISSUER` (public, with `/sso`) is used for every value that leaves the service:
  the `iss` claim, the discovery document, generated links in responses.
- `APP_URL` stays the internal origin, so the framework does not rewrite paths the
  container does not serve.

This split is why there is no `ForceRootUrl` trickery in production, and why the test
suite can serve the app at `/` while still asserting `issuer == https://host/sso`.

## 9. Container

Multi-stage alpine image, php-fpm + nginx under supervisor, unprivileged user, no
capabilities, read-only rootfs, tmpfs for `storage/` and `bootstrap/cache/`. The
entrypoint rebuilds the package manifest, caches config/routes/views, runs migrations
and the bootstrap administrator before supervisord starts — all steps idempotent, so a
restart is always safe.

`/healthz` intentionally does not touch the database: a brief PostgreSQL outage should
not restart-loop the proxy layer.

The service binds `0.0.0.0:3550` with no IP allow-list, per the requirement. Behind
caddy it is also reachable directly on the host network; that is a documented
consequence, not an oversight.

## 10. Findings from the independent review

An external audit of this codebase (2026-11-04) turned up four defects that were
fixed and are now regression-tested. Recording them, because they are the kind of
thing that silently comes back:

| # | Symptom | Root cause | Fix |
| --- | --- | --- | --- |
| 1 | Ticking "remember this browser" on the console login made the login itself fail (500) | `admins` had no `remember_token` column while the form offered the option | migration + test |
| 2 | A public client could finish `/oauth/authorize` with no `code_challenge`, contradicting this document | the PKCE step treated "no challenge" as acceptable for every client type | PKCE now mandatory for public clients; only S256 accepted |
| 3 | After a failed login the browser landed on a 404 | the root URL was forced *after* `StartSession`, so the session stored a prefix-less previous URL and `back()` replayed it | force the root before the session; also repair the stored URL on the way in and out |
| 4 | A user who signed in to resume an interrupted authorization ended up on a client error page | `response_type` was not part of the parked request | park and replay the whole parameter set |

Two further gaps (guest tokens growing without bound, guest rate limiting keyed by
IP and therefore shared across a NAT) led to `sso:prune` and a device-keyed limit.

## 11. What is not protected

Honest list, so nobody assumes otherwise:

- **No IP restriction.** Explicit requirement. Anyone who can reach the port can reach
  `/oauth/guest`.
- **No consent screen.** Client registration is the consent. An administrator who
  registers a malicious client has already lost.
- **No brute-force lockout beyond rate limiting.** 10 login attempts per 5 minutes per
  e-mail+IP for users, 5 for admins; a distributed attack is not stopped by this.
- **`client_credentials` tokens are as powerful as the client.** Scope them tightly
  when registering the client.
- **Audit logs are append-only by convention**, not by database permissions. An actor
  with SQL access can rewrite history.
