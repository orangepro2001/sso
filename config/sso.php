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
    | can refresh silently and never bother the user.
    */
    'access_token_ttl' => (int) env('SSO_ACCESS_TOKEN_TTL', 604800),
    'refresh_token_ttl' => (int) env('SSO_REFRESH_TOKEN_TTL', 2592000),
    'auth_code_ttl' => 300,

    // What the console prints times in (App\Support\When); the clock stays UTC.
    'display_timezone' => (string) env('SSO_DISPLAY_TIMEZONE', 'Asia/Seoul'),

    /*
    |--------------------------------------------------------------------------
    | Password reset links
    |--------------------------------------------------------------------------
    | Users have no e-mail address, so a reset credential is a one-time URL an
    | administrator generates and hands over out of band. Short by default: it is
    | a bearer token for someone's account.
    */
    'reset_link_ttl' => (int) env('SSO_RESET_LINK_TTL', 86400),

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
        'username' => (string) env('SSO_BOOTSTRAP_ADMIN_USERNAME', ''),
        'name' => (string) env('SSO_BOOTSTRAP_ADMIN_NAME', 'admin'),
        'password' => (string) env('SSO_BOOTSTRAP_ADMIN_PASSWORD', ''),
        'password_file' => (string) env('SSO_BOOTSTRAP_ADMIN_PASSWORD_FILE', ''),
    ],
];
