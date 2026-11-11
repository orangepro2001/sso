package store

import (
	"context"
	"database/sql"
	"errors"
)

const resetColumns = `id, user_id, token_hash, created_by, expires_at, used_at, used_ip, revoked_at, created_at, updated_at`

func scanReset(row interface{ Scan(...any) error }) (*PasswordReset, error) {
	var (
		r                            PasswordReset
		createdBy                    sql.NullInt64
		expiresAt, usedAt, revokedAt Timestamp
		usedIP                       sql.NullString
		createdAt, updatedAt         Timestamp
	)
	err := row.Scan(&r.ID, &r.UserID, &r.TokenHash, &createdBy, &expiresAt, &usedAt, &usedIP, &revokedAt, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.CreatedBy = intPtr(createdBy)
	r.ExpiresAt, r.UsedAt, r.RevokedAt = expiresAt, usedAt, revokedAt
	r.UsedIP = strPtr(usedIP)
	r.CreatedAt, r.UpdatedAt = createdAt, updatedAt
	return &r, nil
}

func (s *Store) InsertPasswordReset(ctx context.Context, r *PasswordReset) error {
	now := Now()
	r.CreatedAt, r.UpdatedAt = now, now
	res, err := s.DB.ExecContext(ctx, `INSERT INTO user_password_resets
		(user_id, token_hash, created_by, expires_at, created_at, updated_at)
		VALUES (?,?,?,?,?,?)`,
		r.UserID, r.TokenHash, nullInt(r.CreatedBy), r.ExpiresAt.Time.Format(TimeLayout),
		now.Time.Format(TimeLayout), now.Time.Format(TimeLayout))
	if err != nil {
		return err
	}
	r.ID, err = res.LastInsertId()
	return err
}

func (s *Store) PasswordResetByHash(ctx context.Context, hash string) (*PasswordReset, error) {
	return scanReset(s.DB.QueryRowContext(ctx, `SELECT `+resetColumns+` FROM user_password_resets WHERE token_hash = ?`, hash))
}

// RevokeOpenPasswordResets supersedes every unused link of a person: a person
// following an old link must not be able to set a password behind the
// administrator's back.
func (s *Store) RevokeOpenPasswordResets(ctx context.Context, userID int64) error {
	now := Now().Time.Format(TimeLayout)
	_, err := s.DB.ExecContext(ctx, `UPDATE user_password_resets SET revoked_at = ?, updated_at = ?
		WHERE user_id = ? AND used_at IS NULL AND revoked_at IS NULL`, now, now, userID)
	return err
}

func (s *Store) ConsumePasswordReset(ctx context.Context, id int64, ip *string) error {
	now := Now().Time.Format(TimeLayout)
	_, err := s.DB.ExecContext(ctx, `UPDATE user_password_resets SET used_at = ?, used_ip = ?, updated_at = ? WHERE id = ?`,
		now, nullString(ip), now, id)
	return err
}
