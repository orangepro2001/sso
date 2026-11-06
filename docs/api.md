# Account API

For applications that want people to manage their account without leaving the
application (work-report's 「내 프로필」), and for scripts that administer users.
Same rules as the console: both call `App\Services\UserAccounts`.

## Authentication

`Authorization: Bearer <access token>` — the access token the application received
from `/oauth/token` at sign-in. It must:

- belong to an active user (a disabled user's token stops working at once),
- carry the `profile` scope,
- for `/api/users`, belong to a `super_admin`.

No session, no CSRF token. Errors are JSON:

| Status | `error` | Meaning |
| --- | --- | --- |
| 401 | `invalid_token` | missing, unknown, revoked or expired token, or a disabled user — sign in again |
| 403 | `insufficient_scope` | the token has no `profile` scope |
| 403 | `forbidden` | `/api/users` called by somebody who is not a super administrator |
| 422 | — | validation or an account rule: `{"message", "errors": {field: [..]}}` |

Rate limits: 120 requests/minute on `/api/me`, 240 on `/api/users`.

## The user object

```json
{
  "id": 6,
  "username": "tony",
  "name": "정태훈 대리",
  "role": "user",
  "status": "active",
  "picture": "https://sso.521985.xyz/avatar/6/1793863395?sig=…",
  "created_at": "2026-11-04T23:51:02+00:00",
  "last_login_at": "2026-11-06T01:12:40+00:00"
}
```

`picture` is `null` without a picture. Its URL is public, signed, built from the
issuer and changes whenever the picture changes, so it can be cached forever.
A super administrator additionally sees `note`, `last_login_ip` and `created_by`.

## `/api/me` — your own account

| Method | Path | Body | Returns |
| --- | --- | --- | --- |
| `GET` | `/api/me` | — | user |
| `PATCH` | `/api/me` | `name` | user |
| `POST` | `/api/me/avatar` | multipart `avatar` (JPEG/PNG/WebP/GIF, ≤ 1 MB) | user |
| `DELETE` | `/api/me/avatar` | — | user |
| `PUT` | `/api/me/password` | `current_password`, `password` | `{message}` |

The username cannot be changed here: that needs the password, which an application
should never handle — the SSO's own 「내 계정」 page does it. A password change through
the API revokes every other token of the user but keeps the one that made the call.

Resize pictures before sending (the console does it in the browser: centred square,
512 px, WebP); the server stores what it receives.

## `/api/users` — administration (super administrators)

| Method | Path | Body / query | Returns |
| --- | --- | --- | --- |
| `GET` | `/api/users` | `q`, `role`, `status`, `per_page` (≤ 200), `page` | `{data: [user], links, meta}` |
| `POST` | `/api/users` | `name`, `username`, `password`?, `role`?, `note`? | 201 user (+ `generated_password` when `password` was blank) |
| `GET` | `/api/users/{id}` | — | user |
| `PATCH` | `/api/users/{id}` | any of `name`, `username`, `role`, `status`, `note` | user |
| `DELETE` | `/api/users/{id}` | — | 204 |
| `POST` | `/api/users/{id}/password` | `password`? (blank = generate) | `{password}` |
| `POST` | `/api/users/{id}/reset-link` | — | `{url, expires_at}` |
| `POST` | `/api/users/{id}/avatar` | multipart `avatar` | user |
| `DELETE` | `/api/users/{id}/avatar` | — | user |
| `POST` | `/api/users/{id}/sign-out` | — | `{access_tokens, refresh_tokens, sessions}` |

Account rules (422):

- the last active super administrator cannot be demoted, disabled or deleted;
- nobody can demote, disable or delete themselves.

Setting `status` to `disabled` revokes the user's tokens and deletes their browser
sessions in the same request. Every call is in the audit log, attributed to the
token's user.

## Example

```sh
curl -sS https://sso.521985.xyz/api/me -H "Authorization: Bearer $TOKEN"
curl -sS -X POST https://sso.521985.xyz/api/me/avatar -H "Authorization: Bearer $TOKEN" -F avatar=@me.webp
curl -sS -X PATCH https://sso.521985.xyz/api/users/6 -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{"status":"disabled"}'
```
