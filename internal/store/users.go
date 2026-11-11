package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// AvatarSignature is hash_hmac('sha256', "<id>|<version>", APP_KEY).
//
// The key is the raw APP_KEY string, "base64:" prefix included, because that is
// what PHP hashed (config('app.key')). Same input, same key, same signature —
// links handed out before the switch keep working.
func AvatarSignature(appKey string, userID int64, version string) string {
	mac := hmac.New(sha256.New, []byte(appKey))
	mac.Write([]byte(itoa(userID) + "|" + version))
	return hex.EncodeToString(mac.Sum(nil))
}

const userColumns = `id, name, username, role, password, status, last_login_at, last_login_ip,
	created_by, note, remember_token, avatar_path, avatar_mime, avatar_updated_at, created_at, updated_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var (
		u                                                   User
		lastLoginIP, note, remember, avatarPath, avatarMime sql.NullString
		createdBy                                           sql.NullInt64
		lastLoginAt                                         Timestamp
		avatarUpdated, createdAt, updatedAt                 Timestamp
	)
	err := row.Scan(&u.ID, &u.Name, &u.Username, &u.Role, &u.Password, &u.Status,
		&lastLoginAt, &lastLoginIP, &createdBy, &note, &remember,
		&avatarPath, &avatarMime, &avatarUpdated, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.LastLoginAt = lastLoginAt
	u.LastLoginIP = strPtr(lastLoginIP)
	u.CreatedBy = intPtr(createdBy)
	u.Note = strPtr(note)
	u.RememberToken = strPtr(remember)
	u.AvatarPath = strPtr(avatarPath)
	u.AvatarMime = strPtr(avatarMime)
	u.AvatarUpdatedAt = avatarUpdated
	u.CreatedAt = createdAt
	u.UpdatedAt = updatedAt
	return &u, nil
}

func (s *Store) UserByID(ctx context.Context, id int64) (*User, error) {
	row := s.DB.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = ?`, id)
	return scanUser(row)
}

// UserByUsername looks up the lower-case identifier; usernames are stored
// lower-case and every lookup lower-cases what was typed.
func (s *Store) UserByUsername(ctx context.Context, username string) (*User, error) {
	row := s.DB.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE username = ?`, strings.ToLower(strings.TrimSpace(username)))
	return scanUser(row)
}

func (s *Store) InsertUser(ctx context.Context, u *User) error {
	now := Now()
	if !u.CreatedAt.Valid {
		u.CreatedAt = now
	}
	u.UpdatedAt = now
	res, err := s.DB.ExecContext(ctx, `INSERT INTO users
		(name, username, role, password, status, last_login_at, last_login_ip, created_by, note, remember_token,
		 avatar_path, avatar_mime, avatar_updated_at, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		u.Name, u.Username, u.Role, u.Password, u.Status,
		nullTime(u.LastLoginAt), nullString(u.LastLoginIP), nullInt(u.CreatedBy), nullString(u.Note), nullString(u.RememberToken),
		nullString(u.AvatarPath), nullString(u.AvatarMime), nullTime(u.AvatarUpdatedAt),
		u.CreatedAt.Time.Format(TimeLayout), u.UpdatedAt.Time.Format(TimeLayout))
	if err != nil {
		return err
	}
	u.ID, err = res.LastInsertId()
	return err
}

// SaveUser writes every mutable column. The services load a row, change what
// they mean to change and save it, which is how the Eloquent models behaved.
func (s *Store) SaveUser(ctx context.Context, u *User) error {
	u.UpdatedAt = Now()
	_, err := s.DB.ExecContext(ctx, `UPDATE users SET
		name = ?, username = ?, role = ?, password = ?, status = ?,
		last_login_at = ?, last_login_ip = ?, created_by = ?, note = ?, remember_token = ?,
		avatar_path = ?, avatar_mime = ?, avatar_updated_at = ?, updated_at = ?
		WHERE id = ?`,
		u.Name, u.Username, u.Role, u.Password, u.Status,
		nullTime(u.LastLoginAt), nullString(u.LastLoginIP), nullInt(u.CreatedBy), nullString(u.Note), nullString(u.RememberToken),
		nullString(u.AvatarPath), nullString(u.AvatarMime), nullTime(u.AvatarUpdatedAt),
		u.UpdatedAt.Time.Format(TimeLayout), u.ID)
	return err
}

func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return err
}

// OtherActiveAdmins answers the question the account rules ask: is there a
// super administrator besides this one?
func (s *Store) OtherActiveAdmins(ctx context.Context, excludeID int64) (bool, error) {
	var count int
	err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE role = ? AND status = ? AND id <> ?`,
		RoleSuperAdmin, StatusActive, excludeID).Scan(&count)
	return count > 0, err
}

// CountActiveAdmins is used by the bootstrap command.
func (s *Store) CountActiveAdmins(ctx context.Context) (int, error) {
	var count int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = ? AND status = ?`,
		RoleSuperAdmin, StatusActive).Scan(&count)
	return count, err
}

// UserFilter is the console's list query and the account API's at once.
type UserFilter struct {
	Search    string
	Role      string
	Status    string
	AdminLike bool   // console filter=admin
	OrderBy   string // "" (console order) or "name" (API)
	Limit     int
	Offset    int
}

func (f UserFilter) where() (string, []any) {
	clauses := []string{"1=1"}
	args := []any{}
	if term := strings.TrimSpace(f.Search); term != "" {
		escaped := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(term)
		like := "%" + escaped + "%"
		clauses = append(clauses, `(username LIKE ? ESCAPE '\' OR name LIKE ? ESCAPE '\')`)
		args = append(args, like, like)
	}
	if f.Role != "" {
		clauses = append(clauses, "role = ?")
		args = append(args, f.Role)
	}
	if f.Status != "" {
		clauses = append(clauses, "status = ?")
		args = append(args, f.Status)
	}
	return strings.Join(clauses, " AND "), args
}

func (f UserFilter) order() string {
	if f.OrderBy == "name" {
		return " ORDER BY name"
	}
	// Disabled accounts sink; within a group the person most recently active
	// comes first, which is who an administrator usually looks for.
	return ` ORDER BY CASE WHEN status = '` + StatusActive + `' THEN 0 ELSE 1 END, last_login_at DESC, name`
}

func (s *Store) ListUsers(ctx context.Context, f UserFilter) ([]*User, int, error) {
	where, args := f.where()

	var total int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := `SELECT ` + userColumns + ` FROM users WHERE ` + where + f.order()
	runArgs := append([]any{}, args...)
	if f.Limit > 0 {
		query += " LIMIT ? OFFSET ?"
		runArgs = append(runArgs, f.Limit, f.Offset)
	}

	rows, err := s.DB.QueryContext(ctx, query, runArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	users := make([]*User, 0, 16)
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, 0, err
		}
		users = append(users, u)
	}
	return users, total, rows.Err()
}

func (s *Store) AllUsersBrief(ctx context.Context) ([]*User, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, name, username FROM users ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*User{}
	for rows.Next() {
		u := &User{}
		if err := rows.Scan(&u.ID, &u.Name, &u.Username); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UserCounts powers the filter chips' numbers.
func (s *Store) UserCounts(ctx context.Context) (map[string]int, error) {
	counts := map[string]int{}
	queries := map[string]string{
		"all":      `SELECT COUNT(*) FROM users`,
		"admin":    `SELECT COUNT(*) FROM users WHERE role = '` + RoleSuperAdmin + `'`,
		"user":     `SELECT COUNT(*) FROM users WHERE role = '` + RoleUser + `'`,
		"disabled": `SELECT COUNT(*) FROM users WHERE status = '` + StatusDisabled + `'`,
	}
	for key, q := range queries {
		var n int
		if err := s.DB.QueryRowContext(ctx, q).Scan(&n); err != nil {
			return nil, fmt.Errorf("count %s: %w", key, err)
		}
		counts[key] = n
	}
	return counts, nil
}

// UsernamesTaken answers both the unique validator and the duplicate check.
func (s *Store) UsernameTaken(ctx context.Context, username string, ignoreID int64) (bool, error) {
	q := `SELECT COUNT(*) FROM users WHERE username = ?`
	args := []any{strings.ToLower(strings.TrimSpace(username))}
	if ignoreID > 0 {
		q += ` AND id <> ?`
		args = append(args, ignoreID)
	}
	var n int
	err := s.DB.QueryRowContext(ctx, q, args...).Scan(&n)
	return n > 0, err
}
