<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Issuer
    |--------------------------------------------------------------------------
    | The public base URL of this service including the /sso path prefix, as
    | exposed by the reverse proxy. It becomes the "iss" claim of every JWT and
    | is echoed by the discovery document.
    |
    | SSO_ISSUER is the public, proxy-facing base URL (it carries the /sso mount
    | point). APP_URL stays the internal origin the container actually listens
    | on, so framework URL resolution and the JWT issuer never fight.
    */
    'issuer' => rtrim(
        (string) (env('SSO_ISSUER') ?: env('APP_URL', 'http://127.0.0.1:3550').'/sso'),
        '/'
    ),

    /*
    |--------------------------------------------------------------------------
    | Public URL shape
    |--------------------------------------------------------------------------
    | The reverse proxy strips /sso before forwarding, so the framework has to be
    | told the public scheme and path prefix to build correct absolute URLs.
    */
    'url_scheme' => (string) env('SSO_URL_SCHEME', 'https'),
    // Off only for the test suite, where requests are served at "/".
    'force_root_url' => filter_var(env('SSO_FORCE_ROOT_URL', true), FILTER_VALIDATE_BOOL),
    'session_path' => (string) env('SESSION_PATH', '/sso'),

    /*
    |--------------------------------------------------------------------------
    | Token lifetimes (seconds)
    |--------------------------------------------------------------------------
    | Users get a 7 day access token plus a rotating refresh token, so clients
    | can refresh silently and never bother the user. Guests get a token that
    | does not expire at all (0 = no expiry) unless SSO_GUEST_TOKEN_TTL is set.
    */
    'access_token_ttl' => (int) env('SSO_ACCESS_TOKEN_TTL', 604800),
    'refresh_token_ttl' => (int) env('SSO_REFRESH_TOKEN_TTL', 2592000),
    'auth_code_ttl' => 300,

    /*
    |--------------------------------------------------------------------------
    | Guest (silent) channel
    |--------------------------------------------------------------------------
    | A client proves itself with a stable environment value (hostname, machine
    | id, serial) plus a shared secret. Every request with a valid signature is
    | approved automatically and a usable token is returned immediately; the
    | administrator reviews devices afterwards and may blacklist them.
    */
    'guest' => [
        'enabled' => (bool) env('SSO_GUEST_ENABLED', true),
        'secret' => (string) env('SSO_GUEST_SECRET', ''),
        'algo' => 'hmac-sha256',
        'prefix' => 'sso-guest-v1',
        'scope' => (string) env('SSO_GUEST_SCOPE', 'db:read'),
        'token_ttl' => (int) env('SSO_GUEST_TOKEN_TTL', 0),
        'require_signature' => (bool) env('SSO_GUEST_REQUIRE_SIGNATURE', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Scopes
    |--------------------------------------------------------------------------
    */
    'scopes' => [
        'openid' => 'OpenID Connect subject identity',
        'profile' => 'Display name and account creation time',
        'db:read' => 'Read-only database access',
        'db:write' => 'Read-write database access',
        'offline_access' => 'Allows the refresh_token grant',
        'admin' => 'Administrative operations',
    ],

    /*
    |--------------------------------------------------------------------------
    | Bootstrap administrator
    |--------------------------------------------------------------------------
    | No public registration exists: administrators create every account. The
    | very first one comes from the environment and is only created when the
    | admins table is still empty.
    */
    'bootstrap' => [
        'email' => (string) env('SSO_BOOTSTRAP_ADMIN_EMAIL', ''),
        'name' => (string) env('SSO_BOOTSTRAP_ADMIN_NAME', 'admin'),
        'password' => (string) env('SSO_BOOTSTRAP_ADMIN_PASSWORD', ''),
        'password_file' => (string) env('SSO_BOOTSTRAP_ADMIN_PASSWORD_FILE', ''),
    ],
];
