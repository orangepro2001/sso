package store

import (
	"context"
	"database/sql"
	"errors"
)

// ---- authorization codes -------------------------------------------------

func (s *Store) InsertAuthCode(ctx context.Context, c *AuthCode) error {
	now := Now()
	c.CreatedAt, c.UpdatedAt = now, now
	res, err := s.DB.ExecContext(ctx, `INSERT INTO oauth_auth_codes
		(code_hash, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method,
		 expires_at, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		c.CodeHash, c.ClientID, c.UserID, c.RedirectURI, c.Scopes,
		nullString(c.CodeChallenge), nullString(c.CodeChallengeMethod),
		c.ExpiresAt.Time.Format(TimeLayout), now.Time.Format(TimeLayout), now.Time.Format(TimeLayout))
	if err != nil {
		return err
	}
	c.ID, err = res.LastInsertId()
	return err
}

func (s *Store) AuthCodeByHash(ctx context.Context, hash string) (*AuthCode, error) {
	var (
		c                     AuthCode
		scopes                JSONList
		challenge, method     sql.NullString
		expiresAt, consumedAt Timestamp
		createdAt, updatedAt  Timestamp
	)
	err := s.DB.QueryRowContext(ctx, `SELECT id, code_hash, client_id, user_id, redirect_uri, scopes,
		code_challenge, code_challenge_method, expires_at, consumed_at, created_at, updated_at
		FROM oauth_auth_codes WHERE code_hash = ?`, hash).Scan(
		&c.ID, &c.CodeHash, &c.ClientID, &c.UserID, &c.RedirectURI, &scopes,
		&challenge, &method, &expiresAt, &consumedAt, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.Scopes = scopes
	c.CodeChallenge = strPtr(challenge)
	c.CodeChallengeMethod = strPtr(method)
	c.ExpiresAt = expiresAt
	c.ConsumedAt = consumedAt
	c.CreatedAt, c.UpdatedAt = createdAt, updatedAt
	return &c, nil
}

func (s *Store) ConsumeAuthCode(ctx context.Context, id int64) error {
	now := Now()
	_, err := s.DB.ExecContext(ctx, `UPDATE oauth_auth_codes SET consumed_at = ?, updated_at = ? WHERE id = ?`,
		now.Time.Format(TimeLayout), now.Time.Format(TimeLayout), id)
	return err
}

// ---- access tokens -------------------------------------------------------

const accessTokenColumns = `id, kind, jti, token_hash, subject_type, user_id, client_id, scopes,
	expires_at, revoked_at, issued_ip, user_agent, created_at, updated_at`

func scanAccessToken(row interface{ Scan(...any) error }) (*AccessToken, error) {
	var (
		t                    AccessToken
		tokenHash, clientID  sql.NullString
		issuedIP, agent      sql.NullString
		userID               sql.NullInt64
		scopes               JSONList
		expiresAt, revokedAt Timestamp
		createdAt, updatedAt Timestamp
	)
	err := row.Scan(&t.ID, &t.Kind, &t.JTI, &tokenHash, &t.SubjectType, &userID, &clientID, &scopes,
		&expiresAt, &revokedAt, &issuedIP, &agent, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t.TokenHash = strPtr(tokenHash)
	t.UserID = intPtr(userID)
	t.ClientID = strPtr(clientID)
	t.Scopes = scopes
	t.ExpiresAt = expiresAt
	t.RevokedAt = revokedAt
	t.IssuedIP = strPtr(issuedIP)
	t.UserAgent = strPtr(agent)
	t.CreatedAt, t.UpdatedAt = createdAt, updatedAt
	return &t, nil
}

func (s *Store) InsertAccessToken(ctx context.Context, t *AccessToken) error {
	now := Now()
	t.CreatedAt, t.UpdatedAt = now, now
	res, err := s.DB.ExecContext(ctx, `INSERT INTO access_tokens
		(kind, jti, token_hash, subject_type, user_id, client_id, scopes, expires_at, revoked_at,
		 issued_ip, user_agent, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		t.Kind, t.JTI, nullString(t.TokenHash), t.SubjectType, nullInt(t.UserID), nullString(t.ClientID),
		t.Scopes, nullTime(t.ExpiresAt), nullTime(t.RevokedAt),
		nullString(t.IssuedIP), nullString(t.UserAgent),
		now.Time.Format(TimeLayout), now.Time.Format(TimeLayout))
	if err != nil {
		return err
	}
	t.ID, err = res.LastInsertId()
	return err
}

func (s *Store) AccessTokenByJTI(ctx context.Context, jti string) (*AccessToken, error) {
	return scanAccessToken(s.DB.QueryRowContext(ctx, `SELECT `+accessTokenColumns+` FROM access_tokens WHERE jti = ?`, jti))
}

func (s *Store) RevokeAccessToken(ctx context.Context, id int64) error {
	now := Now()
	_, err := s.DB.ExecContext(ctx, `UPDATE access_tokens SET revoked_at = ?, updated_at = ? WHERE id = ?`,
		now.Time.Format(TimeLayout), now.Time.Format(TimeLayout), id)
	return err
}

// TokenWithClient is one row of the "signed in to" list: the token record plus
// the application's name (null when the client was deleted).
type TokenWithClient struct {
	Token      *AccessToken
	ClientName *string
}

// AppName is what the account page prints: the application's name, its
// client_id if the row is gone, or a neutral label.
func (t TokenWithClient) AppName() string {
	if t.ClientName != nil && *t.ClientName != "" {
		return *t.ClientName
	}
	if t.Token != nil && t.Token.ClientID != nil && *t.Token.ClientID != "" {
		return *t.Token.ClientID
	}
	return "알 수 없는 앱"
}

func (s *Store) ActiveTokensForUser(ctx context.Context, userID int64, limit int) ([]TokenWithClient, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT t.id, t.kind, t.jti, t.token_hash, t.subject_type, t.user_id,
			t.client_id, t.scopes, t.expires_at, t.revoked_at, t.issued_ip, t.user_agent, t.created_at, t.updated_at,
			c.name
		FROM access_tokens t LEFT JOIN oauth_clients c ON c.client_id = t.client_id
		WHERE t.user_id = ? AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at > ?)
		ORDER BY t.id DESC LIMIT ?`, userID, Now().Time.Format(TimeLayout), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []TokenWithClient{}
	for rows.Next() {
		var (
			t                             AccessToken
			tokenHash, clientID, issuedIP sql.NullString
			agent, clientName             sql.NullString
			userIDCol                     sql.NullInt64
			scopes                        JSONList
			expiresAt, revokedAt          Timestamp
			createdAt, updatedAt          Timestamp
		)
		if err := rows.Scan(&t.ID, &t.Kind, &t.JTI, &tokenHash, &t.SubjectType, &userIDCol, &clientID, &scopes,
			&expiresAt, &revokedAt, &issuedIP, &agent, &createdAt, &updatedAt, &clientName); err != nil {
			return nil, err
		}
		t.TokenHash = strPtr(tokenHash)
		t.UserID = intPtr(userIDCol)
		t.ClientID = strPtr(clientID)
		t.Scopes = scopes
		t.ExpiresAt = expiresAt
		t.RevokedAt = revokedAt
		t.IssuedIP = strPtr(issuedIP)
		t.UserAgent = strPtr(agent)
		t.CreatedAt, t.UpdatedAt = createdAt, updatedAt
		out = append(out, TokenWithClient{Token: &t, ClientName: strPtr(clientName)})
	}
	return out, rows.Err()
}

// RevokeAccessTokensForUser ends every live access token of a person; keepJTI
// spares the one an API client used to make the change it is asking for.
func (s *Store) RevokeAccessTokensForUser(ctx context.Context, userID int64, keepJTI string) (int64, error) {
	now := Now().Time.Format(TimeLayout)
	var (
		res sql.Result
		err error
	)
	if keepJTI != "" {
		res, err = s.DB.ExecContext(ctx, `UPDATE access_tokens SET revoked_at = ?, updated_at = ?
			WHERE user_id = ? AND revoked_at IS NULL AND jti <> ?`, now, now, userID, keepJTI)
	} else {
		res, err = s.DB.ExecContext(ctx, `UPDATE access_tokens SET revoked_at = ?, updated_at = ?
			WHERE user_id = ? AND revoked_at IS NULL`, now, now, userID)
	}
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---- refresh tokens ------------------------------------------------------

func (s *Store) InsertRefreshToken(ctx context.Context, t *RefreshToken) error {
	now := Now()
	t.CreatedAt, t.UpdatedAt = now, now
	res, err := s.DB.ExecContext(ctx, `INSERT INTO refresh_tokens
		(token_hash, family_id, user_id, client_id, scopes, expires_at, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?)`,
		t.TokenHash, t.FamilyID, t.UserID, t.ClientID, t.Scopes,
		t.ExpiresAt.Time.Format(TimeLayout), now.Time.Format(TimeLayout), now.Time.Format(TimeLayout))
	if err != nil {
		return err
	}
	t.ID, err = res.LastInsertId()
	return err
}

func (s *Store) RefreshTokenByHash(ctx context.Context, hash string) (*RefreshToken, error) {
	var (
		t                    RefreshToken
		scopes               JSONList
		expiresAt            Timestamp
		revokedAt, rotatedAt Timestamp
		createdAt, updatedAt Timestamp
	)
	err := s.DB.QueryRowContext(ctx, `SELECT id, token_hash, family_id, user_id, client_id, scopes,
		expires_at, revoked_at, rotated_at, created_at, updated_at
		FROM refresh_tokens WHERE token_hash = ?`, hash).Scan(
		&t.ID, &t.TokenHash, &t.FamilyID, &t.UserID, &t.ClientID, &scopes,
		&expiresAt, &revokedAt, &rotatedAt, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t.Scopes = scopes
	t.ExpiresAt = expiresAt
	t.RevokedAt = revokedAt
	t.RotatedAt = rotatedAt
	t.CreatedAt, t.UpdatedAt = createdAt, updatedAt
	return &t, nil
}

func (s *Store) RotateRefreshToken(ctx context.Context, id int64) error {
	now := Now().Time.Format(TimeLayout)
	_, err := s.DB.ExecContext(ctx, `UPDATE refresh_tokens SET rotated_at = ?, updated_at = ? WHERE id = ?`, now, now, id)
	return err
}

// RevokeRefreshFamily kills every token descended from one login. Presenting an
// already rotated token is the classic stolen-token signal (DESIGN.md §4).
func (s *Store) RevokeRefreshFamily(ctx context.Context, familyID string) (int64, error) {
	now := Now().Time.Format(TimeLayout)
	res, err := s.DB.ExecContext(ctx, `UPDATE refresh_tokens SET revoked_at = ?, updated_at = ?
		WHERE family_id = ? AND revoked_at IS NULL`, now, now, familyID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) RevokeRefreshTokensForUser(ctx context.Context, userID int64) (int64, error) {
	now := Now().Time.Format(TimeLayout)
	res, err := s.DB.ExecContext(ctx, `UPDATE refresh_tokens SET revoked_at = ?, updated_at = ?
		WHERE user_id = ? AND revoked_at IS NULL`, now, now, userID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---- housekeeping (sso:prune) -------------------------------------------

type PruneCounts struct {
	AccessTokens  int64
	RefreshTokens int64
	AuthCodes     int64
	AuditLogs     int64
}

func (s *Store) Prune(ctx context.Context, auditDays int, dryRun bool) (PruneCounts, error) {
	now := Now().Time.Format(TimeLayout)
	cutoff := FromTime(Now().Time.AddDate(0, 0, -auditDays)).Time.Format(TimeLayout)

	queries := []struct {
		count string
		del   string
		args  []any
		dest  *int64
	}{
		{
			count: `SELECT COUNT(*) FROM access_tokens WHERE revoked_at IS NOT NULL OR (expires_at IS NOT NULL AND expires_at < ?)`,
			del:   `DELETE FROM access_tokens WHERE revoked_at IS NOT NULL OR (expires_at IS NOT NULL AND expires_at < ?)`,
			args:  []any{now},
		},
		{
			count: `SELECT COUNT(*) FROM refresh_tokens WHERE revoked_at IS NOT NULL OR expires_at < ?`,
			del:   `DELETE FROM refresh_tokens WHERE revoked_at IS NOT NULL OR expires_at < ?`,
			args:  []any{now},
		},
		{
			count: `SELECT COUNT(*) FROM oauth_auth_codes WHERE consumed_at IS NOT NULL OR expires_at < ?`,
			del:   `DELETE FROM oauth_auth_codes WHERE consumed_at IS NOT NULL OR expires_at < ?`,
			args:  []any{now},
		},
		{
			count: `SELECT COUNT(*) FROM audit_logs WHERE created_at < ?`,
			del:   `DELETE FROM audit_logs WHERE created_at < ?`,
			args:  []any{cutoff},
		},
	}

	var out PruneCounts
	dest := []*int64{&out.AccessTokens, &out.RefreshTokens, &out.AuthCodes, &out.AuditLogs}

	for i, q := range queries {
		if dryRun {
			if err := s.DB.QueryRowContext(ctx, q.count, q.args...).Scan(dest[i]); err != nil {
				return out, err
			}
			continue
		}
		res, err := s.DB.ExecContext(ctx, q.del, q.args...)
		if err != nil {
			return out, err
		}
		*dest[i], _ = res.RowsAffected()
	}
	return out, nil
}
