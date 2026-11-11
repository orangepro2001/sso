package store

import (
	"context"
	"database/sql"
	"errors"
)

// SessionRow is one browser session. It is database-backed rather than a signed
// cookie so an administrator can end it: "disable this account now" is a
// requirement, and a signed cookie cannot be recalled (DESIGN.md §7).
type SessionRow struct {
	ID           string
	UserID       *int64
	IP           *string
	UserAgent    *string
	Payload      string
	LastActivity int64
}

func (s *Store) SessionByID(ctx context.Context, id string) (*SessionRow, error) {
	var (
		row       SessionRow
		userID    sql.NullInt64
		ip, agent sql.NullString
	)
	err := s.DB.QueryRowContext(ctx, `SELECT id, user_id, ip_address, user_agent, payload, last_activity
		FROM sessions WHERE id = ?`, id).Scan(&row.ID, &userID, &ip, &agent, &row.Payload, &row.LastActivity)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	row.UserID = intPtr(userID)
	row.IP = strPtr(ip)
	row.UserAgent = strPtr(agent)
	return &row, nil
}

func (s *Store) UpsertSession(ctx context.Context, row *SessionRow) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO sessions (id, user_id, ip_address, user_agent, payload, last_activity)
		VALUES (?,?,?,?,?,?)
		ON CONFLICT (id) DO UPDATE SET
			user_id = excluded.user_id,
			ip_address = excluded.ip_address,
			user_agent = excluded.user_agent,
			payload = excluded.payload,
			last_activity = excluded.last_activity`,
		row.ID, nullInt(row.UserID), nullString(row.IP), nullString(row.UserAgent), row.Payload, row.LastActivity)
	return err
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	return err
}

// DeleteSessionsForUser ends every browser session of a person, optionally
// keeping the one that is asking (an administrator signing themselves out of
// other browsers).
func (s *Store) DeleteSessionsForUser(ctx context.Context, userID int64, keepID string) (int64, error) {
	var (
		res sql.Result
		err error
	)
	if keepID != "" {
		res, err = s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND id <> ?`, userID, keepID)
	} else {
		res, err = s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
	}
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// VacuumSessions drops rows whose last activity is older than the session
// lifetime; the PHP ran a lottery on every request, we do it on a timer.
func (s *Store) VacuumSessions(ctx context.Context, olderThan int64) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE last_activity < ?`, olderThan)
	return err
}
