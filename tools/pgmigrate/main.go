// Command sso-pgmigrate copies the production PostgreSQL database into the
// SQLite file the Go service runs on.
//
// It is a separate module on purpose: the shipped `sso` binary must run with
// nothing installed, so it must not link a PostgreSQL driver for a job that
// runs once. `sso -import-postgres <dsn>` finds this executable beside itself
// (or on PATH) and runs it.
//
// What it copies: users (bcrypt hashes included, which is why existing people
// still sign in), OAuth clients, access and refresh tokens, authorization
// codes, password reset links, audit rows, and the public halves of the signing
// keys. What it does not copy, and why:
//
//   - sessions: Laravel's payload is a PHP-serialised blob and a session is not
//     worth reading back; people sign in again.
//   - signing_keys.private_key: encrypted with Laravel's encrypter, which the
//     Go service cannot (and should not) open. The public halves are imported
//     as retired keys so tokens signed before the switch keep verifying; the
//     service generates a fresh active key on first boot.
//   - created_by / reviewed_by: those pointed at the old `admins` table, whose
//     ids do not map to user ids; the PHP's own migration cleared them.
//   - guest_devices, blacklist_entries, registration_invites: tables the design
//     left in place, unread (docs/DESIGN.md §5).
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	_ "modernc.org/sqlite"
)

const timeLayout = "2006-01-02 15:04:05"

type table struct {
	// name is the table in both databases.
	name string
	// columns are the destination columns, in insert order.
	columns []string
	// selectSQL reads the source. Columns must line up with `columns`.
	selectSQL string
	// transform may rewrite a scanned value; nil keeps it.
	transform func(column string, value any) any
}

func main() {
	dsn := flag.String("dsn", "", "PostgreSQL DSN, e.g. postgres://sso@host:5432/sso?sslmode=require")
	dbPath := flag.String("db", "storage/sso.db", "destination SQLite file (schema must already exist)")
	dryRun := flag.Bool("dry-run", false, "read PostgreSQL and report counts without writing")
	flag.Parse()

	if *dsn == "" {
		fmt.Fprintln(os.Stderr, "usage: sso-pgmigrate -dsn <postgres-dsn> -db <sqlite-file>")
		os.Exit(2)
	}
	if err := run(context.Background(), *dsn, *dbPath, *dryRun); err != nil {
		fmt.Fprintln(os.Stderr, "import:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, dsn, dbPath string, dryRun bool) error {
	pg, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer pg.Close(ctx)
	if err := pg.Ping(ctx); err != nil {
		return fmt.Errorf("postgres: %w", err)
	}

	// The destination file is created (schema and all) by the sso binary; the
	// importer only fills it. Writing to a file whose schema is unknown would
	// produce a database neither program can use.
	lite, err := sql.Open("sqlite", "file:"+url.PathEscape(dbPath)+
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=foreign_keys(0)")
	if err != nil {
		return fmt.Errorf("sqlite: %w", err)
	}
	defer lite.Close()

	var schemaCount int
	if err := lite.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'users'`).Scan(&schemaCount); err != nil {
		return fmt.Errorf("sqlite: %w", err)
	}
	if schemaCount == 0 {
		return fmt.Errorf("%s has no schema: run `sso` once (or `sso -bootstrap`) against it first", dbPath)
	}

	fmt.Printf("source  %s\n", redactDSN(dsn))
	fmt.Printf("target  %s\n", dbPath)

	tx, err := lite.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	total := 0
	for _, t := range tables() {
		count, err := copyTable(ctx, pg, tx, t, dryRun)
		if err != nil {
			return fmt.Errorf("%s: %w", t.name, err)
		}
		total += count
	}

	// The PHP kept operators in a separate `admins` table; the Go service has one
	// user space and a `super_admin` role. Copying them keeps the console login
	// that existed before the switch — with its bcrypt hash and last login.
	adminCount, err := importAdmins(ctx, pg, tx, dryRun)
	if err != nil {
		return fmt.Errorf("admins: %w", err)
	}
	total += adminCount

	if dryRun {
		fmt.Printf("%-24s %d rows (would copy)\n", "total", total)
		return nil
	}

	// A sequence left at 0 after explicit ids would hand out ids that already
	// exist. SQLite derives the next rowid from the largest one on insert, but
	// saying it out loud costs nothing and removes the doubt.
	for _, t := range tables() {
		if _, err := tx.ExecContext(ctx, `UPDATE sqlite_sequence SET seq = (SELECT MAX(id) FROM `+t.name+`) WHERE name = ?`, t.name); err != nil {
			// sqlite_sequence only exists once an AUTOINCREMENT row was inserted.
			if strings.Contains(err.Error(), "no such table") {
				break
			}
			return fmt.Errorf("sequence %s: %w", t.name, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	fmt.Printf("%-24s %d rows\n", "total", total)
	fmt.Println()
	fmt.Println("Signing keys: old public keys were imported as retired so existing tokens keep")
	fmt.Println("verifying. The sso service generates a new active key on its first boot.")
	return nil
}

func tables() []table {
	asIs := func(string, any) any { return nil }
	return []table{
		{
			name:    "users",
			columns: []string{"id", "name", "username", "role", "password", "status", "last_login_at", "last_login_ip", "created_by", "note", "remember_token", "avatar_path", "avatar_mime", "avatar_updated_at", "created_at", "updated_at"},
			selectSQL: `SELECT id, name, username, COALESCE(role, 'user'), password, status, last_login_at, last_login_ip,
				NULL, note, remember_token, avatar_path, avatar_mime, avatar_updated_at, created_at, updated_at
				FROM users ORDER BY id`,
			transform: asIs,
		},
		{
			name:    "oauth_clients",
			columns: []string{"id", "client_id", "name", "type", "secret_hash", "redirect_uris", "home_url", "sort_order", "in_launcher", "allowed_scopes", "active", "created_by", "note", "created_at", "updated_at"},
			selectSQL: `SELECT id, client_id, name, type, secret_hash, redirect_uris, home_url,
				COALESCE(sort_order, 0), COALESCE(in_launcher, true), allowed_scopes, active,
				NULL, note, created_at, updated_at
				FROM oauth_clients ORDER BY id`,
			transform: asIs,
		},
		{
			name:    "access_tokens",
			columns: []string{"id", "kind", "jti", "token_hash", "subject_type", "user_id", "client_id", "scopes", "expires_at", "revoked_at", "issued_ip", "user_agent", "created_at", "updated_at"},
			selectSQL: `SELECT id, kind, jti, token_hash, subject_type, user_id, client_id, scopes,
				expires_at, revoked_at, issued_ip, user_agent, created_at, updated_at
				FROM access_tokens ORDER BY id`,
			transform: asIs,
		},
		{
			name:    "refresh_tokens",
			columns: []string{"id", "token_hash", "family_id", "user_id", "client_id", "scopes", "expires_at", "revoked_at", "rotated_at", "created_at", "updated_at"},
			selectSQL: `SELECT id, token_hash, family_id, user_id, client_id, scopes, expires_at,
				revoked_at, rotated_at, created_at, updated_at
				FROM refresh_tokens ORDER BY id`,
			transform: asIs,
		},
		{
			name:    "oauth_auth_codes",
			columns: []string{"id", "code_hash", "client_id", "user_id", "redirect_uri", "scopes", "code_challenge", "code_challenge_method", "expires_at", "consumed_at", "created_at", "updated_at"},
			selectSQL: `SELECT id, code_hash, client_id, user_id, redirect_uri, scopes,
				code_challenge, code_challenge_method, expires_at, consumed_at, created_at, updated_at
				FROM oauth_auth_codes ORDER BY id`,
			transform: asIs,
		},
		{
			name:    "user_password_resets",
			columns: []string{"id", "user_id", "token_hash", "created_by", "expires_at", "used_at", "used_ip", "revoked_at", "created_at", "updated_at"},
			selectSQL: `SELECT id, user_id, token_hash, NULL, expires_at, used_at, used_ip, revoked_at,
				created_at, updated_at
				FROM user_password_resets ORDER BY id`,
			transform: asIs,
		},
		{
			name:    "audit_logs",
			columns: []string{"id", "event", "actor_type", "actor_id", "subject_type", "subject_id", "ip", "user_agent", "meta", "created_at"},
			selectSQL: `SELECT id, event, actor_type, actor_id, subject_type, subject_id, ip, user_agent, meta, created_at
				FROM audit_logs ORDER BY id`,
			transform: asIs,
		},
		{
			// Public halves only. The private half is Laravel-encrypted; the Go
			// service cannot open it, and it does not need to: existing tokens
			// verify against these keys, new ones are signed with a fresh key.
			name:    "signing_keys",
			columns: []string{"id", "kid", "alg", "private_key", "public_key", "active", "retired_at", "created_at", "updated_at"},
			selectSQL: `SELECT id, kid, alg, '', public_key, false, COALESCE(retired_at, now()), created_at, updated_at
				FROM signing_keys ORDER BY id`,
		},
	}
}

func copyTable(ctx context.Context, pg *pgx.Conn, tx *sql.Tx, t table, dryRun bool) (int, error) {
	rows, err := pg.Query(ctx, t.selectSQL)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	fields := rows.FieldDescriptions()
	if len(fields) != len(t.columns) {
		return 0, fmt.Errorf("source has %d columns, destination wants %d", len(fields), len(t.columns))
	}

	placeholders := make([]string, len(t.columns))
	for i := range placeholders {
		placeholders[i] = "?"
	}
	insert := `INSERT INTO ` + t.name + ` (` + strings.Join(t.columns, ", ") + `) VALUES (` +
		strings.Join(placeholders, ", ") + `)`

	if !dryRun {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+t.name); err != nil {
			return 0, fmt.Errorf("clear: %w", err)
		}
	}

	count := 0
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			return count, err
		}
		args := make([]any, len(values))
		for i, value := range values {
			args[i] = normalize(t.columns[i], value)
			if t.transform != nil {
				if replacement := t.transform(t.columns[i], args[i]); replacement != nil {
					args[i] = replacement
				}
			}
		}
		if !dryRun {
			if _, err := tx.ExecContext(ctx, insert, args...); err != nil {
				return count, err
			}
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return count, err
	}

	// Counts are the only proof the copy is complete; a truncated table is
	// worse than a failed import.
	var source int
	if err := pg.QueryRow(ctx, `SELECT COUNT(*) FROM `+t.name).Scan(&source); err != nil {
		return count, err
	}
	if source != count {
		return count, fmt.Errorf("source has %d rows, read %d", source, count)
	}

	fmt.Printf("%-24s %d rows\n", t.name, count)
	return count, nil
}

// normalize converts PostgreSQL values into what the SQLite driver stores: the
// PHP's text timestamp layout, JSON as text, and byte slices as strings.
func normalize(column string, value any) any {
	switch v := value.(type) {
	case nil:
		return nil
	case time.Time:
		return v.UTC().Format(timeLayout)
	case []byte:
		if json.Valid(v) {
			return string(v)
		}
		return string(v)
	case map[string]any, []any:
		encoded, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprint(v)
		}
		return string(encoded)
	case bool:
		if v {
			return 1
		}
		return 0
	case int32:
		return int64(v)
	case uint32:
		return int64(v)
	}
	return value
}

// importAdmins maps the PHP's separate operators onto users with the
// super_admin role. The e-mail (the old login) has no column in the new schema,
// so it moves into `note` and the username is its local part.
func importAdmins(ctx context.Context, pg *pgx.Conn, tx *sql.Tx, dryRun bool) (int, error) {
	rows, err := pg.Query(ctx, `SELECT id, name, email, password, active, last_login_at,
		last_login_ip, created_at, updated_at FROM admins ORDER BY id`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	taken := map[string]bool{}
	existing, err := tx.QueryContext(ctx, `SELECT username FROM users`)
	if err != nil {
		return 0, err
	}
	for existing.Next() {
		var u string
		if err := existing.Scan(&u); err != nil {
			existing.Close()
			return 0, err
		}
		taken[u] = true
	}
	existing.Close()

	count := 0
	for rows.Next() {
		var id int64
		var name, email, password string
		var active bool
		var lastAt, createdAt, updatedAt *time.Time
		var lastIP *string
		if err := rows.Scan(&id, &name, &email, &password, &active, &lastAt, &lastIP, &createdAt, &updatedAt); err != nil {
			return count, err
		}
		base := email
		if i := strings.IndexByte(base, '@'); i > 0 {
			base = base[:i]
		}
		base = strings.ToLower(strings.TrimSpace(base))
		base = strings.Map(func(r rune) rune {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
				return r
			}
			return '-'
		}, base)
		if base == "" {
			base = "admin"
		}
		username := base
		for i := 2; taken[username]; i++ {
			username = fmt.Sprintf("%s-%d", base, i)
		}
		taken[username] = true

		status := "disabled"
		if active {
			status = "active"
		}
		format := func(t *time.Time, fallback string) string {
			if t == nil {
				return fallback
			}
			return t.UTC().Format(timeLayout)
		}
		var lastAtValue any
		if lastAt != nil {
			lastAtValue = lastAt.UTC().Format(timeLayout)
		}
		var lastIPValue any
		if lastIP != nil {
			lastIPValue = *lastIP
		}
		now := time.Now().UTC().Format(timeLayout)
		if !dryRun {
			if _, err := tx.ExecContext(ctx, `INSERT INTO users
				(name, username, role, password, status, last_login_at, last_login_ip,
				 created_by, note, remember_token, avatar_path, avatar_mime, avatar_updated_at,
				 created_at, updated_at)
				VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				name, username, "super_admin", password, status, lastAtValue, lastIPValue,
				nil, "imported admin "+email, nil, nil, nil, nil,
				format(createdAt, now), format(updatedAt, now)); err != nil {
				return count, err
			}
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return count, err
	}
	var source int
	if err := pg.QueryRow(ctx, `SELECT COUNT(*) FROM admins`).Scan(&source); err != nil {
		return count, err
	}
	if source != count {
		return count, fmt.Errorf("source has %d rows, read %d", source, count)
	}
	fmt.Printf("%-24s %d rows\n", "admins → users", count)
	return count, nil
}

func redactDSN(dsn string) string {
	parsed, err := url.Parse(dsn)
	if err != nil {
		return "(unparseable DSN)"
	}
	if parsed.User != nil {
		parsed.User = url.User(parsed.User.Username())
	}
	return parsed.String()
}
