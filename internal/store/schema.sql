-- The schema, flattened from database/migrations into the state the last
-- migration leaves behind: one user space (role on `users`), usernames instead
-- of e-mail, launcher fields on clients, pictures on users. Every statement is
-- IF NOT EXISTS, so opening an existing file is a no-op (the PHP ran migrations
-- on every boot for the same reason: a restart must always be safe).
--
-- Types are SQLite's. Timestamps are the text layout Laravel used
-- ("Y-m-d H:i:s", UTC) so an imported dump needs no conversion and every
-- comparison stays a string comparison against the same UTC clock.

CREATE TABLE IF NOT EXISTS users (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    name              TEXT    NOT NULL,
    username          TEXT    NOT NULL,
    role              TEXT    NOT NULL DEFAULT 'user',
    password          TEXT    NOT NULL,
    status            TEXT    NOT NULL DEFAULT 'active',
    last_login_at     TEXT,
    last_login_ip     TEXT,
    created_by        INTEGER,
    note              TEXT,
    remember_token    TEXT,
    avatar_path       TEXT,
    avatar_mime       TEXT,
    avatar_updated_at TEXT,
    created_at        TEXT    NOT NULL,
    updated_at        TEXT    NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS users_username_unique ON users (username);

CREATE TABLE IF NOT EXISTS oauth_clients (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id      TEXT    NOT NULL,
    name           TEXT    NOT NULL,
    type           TEXT    NOT NULL DEFAULT 'public',
    secret_hash    TEXT,
    redirect_uris  TEXT    NOT NULL DEFAULT '[]',
    home_url       TEXT,
    sort_order     INTEGER NOT NULL DEFAULT 0,
    in_launcher    INTEGER NOT NULL DEFAULT 1,
    allowed_scopes TEXT    NOT NULL DEFAULT '[]',
    active         INTEGER NOT NULL DEFAULT 1,
    created_by     INTEGER,
    note           TEXT,
    created_at     TEXT    NOT NULL,
    updated_at     TEXT    NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS oauth_clients_client_id_unique ON oauth_clients (client_id);

CREATE TABLE IF NOT EXISTS oauth_auth_codes (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    code_hash             TEXT    NOT NULL,
    client_id             TEXT    NOT NULL,
    user_id               INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    redirect_uri          TEXT    NOT NULL,
    scopes                TEXT    NOT NULL DEFAULT '[]',
    code_challenge        TEXT,
    code_challenge_method TEXT,
    expires_at            TEXT    NOT NULL,
    consumed_at           TEXT,
    created_at            TEXT    NOT NULL,
    updated_at            TEXT    NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS oauth_auth_codes_code_hash_unique ON oauth_auth_codes (code_hash);
CREATE INDEX IF NOT EXISTS oauth_auth_codes_client_id_index ON oauth_auth_codes (client_id);

CREATE TABLE IF NOT EXISTS access_tokens (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    kind         TEXT    NOT NULL DEFAULT 'jwt',
    jti          TEXT    NOT NULL,
    token_hash   TEXT,
    subject_type TEXT    NOT NULL,
    user_id      INTEGER REFERENCES users (id) ON DELETE CASCADE,
    client_id    TEXT,
    scopes       TEXT    NOT NULL DEFAULT '[]',
    expires_at   TEXT,
    revoked_at   TEXT,
    issued_ip    TEXT,
    user_agent   TEXT,
    created_at   TEXT    NOT NULL,
    updated_at   TEXT    NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS access_tokens_jti_unique ON access_tokens (jti);
CREATE UNIQUE INDEX IF NOT EXISTS access_tokens_token_hash_unique ON access_tokens (token_hash);
CREATE INDEX IF NOT EXISTS access_tokens_client_id_index ON access_tokens (client_id);
CREATE INDEX IF NOT EXISTS access_tokens_subject_expires_index ON access_tokens (subject_type, expires_at);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT    NOT NULL,
    family_id  TEXT    NOT NULL,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id  TEXT    NOT NULL,
    scopes     TEXT    NOT NULL DEFAULT '[]',
    expires_at TEXT    NOT NULL,
    revoked_at TEXT,
    rotated_at TEXT,
    created_at TEXT    NOT NULL,
    updated_at TEXT    NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS refresh_tokens_token_hash_unique ON refresh_tokens (token_hash);
CREATE INDEX IF NOT EXISTS refresh_tokens_family_id_index ON refresh_tokens (family_id);
CREATE INDEX IF NOT EXISTS refresh_tokens_client_id_index ON refresh_tokens (client_id);

CREATE TABLE IF NOT EXISTS audit_logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    event        TEXT    NOT NULL,
    actor_type   TEXT,
    actor_id     TEXT,
    subject_type TEXT,
    subject_id   TEXT,
    ip           TEXT,
    user_agent   TEXT,
    meta         TEXT,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS audit_logs_event_index ON audit_logs (event);
CREATE INDEX IF NOT EXISTS audit_logs_created_at_index ON audit_logs (created_at);

CREATE TABLE IF NOT EXISTS signing_keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kid         TEXT    NOT NULL,
    alg         TEXT    NOT NULL DEFAULT 'RS256',
    private_key TEXT    NOT NULL,
    public_key  TEXT    NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1,
    retired_at  TEXT,
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS signing_keys_kid_unique ON signing_keys (kid);

CREATE TABLE IF NOT EXISTS user_password_resets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash TEXT    NOT NULL,
    created_by INTEGER,
    expires_at TEXT    NOT NULL,
    used_at    TEXT,
    used_ip    TEXT,
    revoked_at TEXT,
    created_at TEXT    NOT NULL,
    updated_at TEXT    NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS user_password_resets_token_hash_unique ON user_password_resets (token_hash);
CREATE INDEX IF NOT EXISTS user_password_resets_user_used_index ON user_password_resets (user_id, used_at);

-- Server-side sessions, same shape as Laravel's: one row per browser, so an
-- administrator disabling an account can end it (DESIGN.md §7).
CREATE TABLE IF NOT EXISTS sessions (
    id            TEXT    PRIMARY KEY,
    user_id       INTEGER,
    ip_address    TEXT,
    user_agent    TEXT,
    payload       TEXT    NOT NULL,
    last_activity INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_id_index ON sessions (user_id);
CREATE INDEX IF NOT EXISTS sessions_last_activity_index ON sessions (last_activity);

-- Tables the design left in place, unread (DESIGN.md §5). They are created so an
-- import from PostgreSQL never has to think about them, and so a future feature
-- has somewhere to start.
CREATE TABLE IF NOT EXISTS guest_devices (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       TEXT    NOT NULL UNIQUE,
    status          TEXT    NOT NULL DEFAULT 'active',
    request_count   INTEGER NOT NULL DEFAULT 0,
    first_seen_ip   TEXT,
    last_seen_ip    TEXT,
    first_user_agent TEXT,
    last_user_agent TEXT,
    first_seen_at   TEXT,
    last_seen_at    TEXT,
    reviewed_at     TEXT,
    reviewed_by     INTEGER,
    note            TEXT,
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS blacklist_entries (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT    NOT NULL,
    value      TEXT    NOT NULL,
    reason     TEXT,
    created_by INTEGER,
    expires_at TEXT,
    created_at TEXT    NOT NULL,
    updated_at TEXT    NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS blacklist_entries_kind_value_unique ON blacklist_entries (kind, value);

CREATE TABLE IF NOT EXISTS registration_invites (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    code_hash  TEXT    NOT NULL UNIQUE,
    note       TEXT,
    created_by INTEGER,
    expires_at TEXT    NOT NULL,
    used_at    TEXT,
    used_ip    TEXT,
    used_by    INTEGER,
    revoked_at TEXT,
    created_at TEXT    NOT NULL,
    updated_at TEXT    NOT NULL
);
