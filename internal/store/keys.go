package store

import (
	"context"
	"database/sql"
	"errors"
)

const signingKeyColumns = `id, kid, alg, private_key, public_key, active, retired_at, created_at, updated_at`

func scanSigningKey(row interface{ Scan(...any) error }) (*SigningKey, error) {
	var (
		k                    SigningKey
		active               bool
		retiredAt            Timestamp
		createdAt, updatedAt Timestamp
	)
	err := row.Scan(&k.ID, &k.Kid, &k.Alg, &k.PrivateKey, &k.PublicKey, &active, &retiredAt, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	k.Active = active
	k.RetiredAt = retiredAt
	k.CreatedAt, k.UpdatedAt = createdAt, updatedAt
	return &k, nil
}

func (s *Store) ActiveSigningKey(ctx context.Context) (*SigningKey, error) {
	return scanSigningKey(s.DB.QueryRowContext(ctx,
		`SELECT `+signingKeyColumns+` FROM signing_keys WHERE active = 1 ORDER BY id DESC LIMIT 1`))
}

func (s *Store) SigningKeyByKid(ctx context.Context, kid string) (*SigningKey, error) {
	return scanSigningKey(s.DB.QueryRowContext(ctx, `SELECT `+signingKeyColumns+` FROM signing_keys WHERE kid = ?`, kid))
}

// PublishableKeys are the keys that may still have live tokens in circulation:
// every key, newest active first. A rotated key stays published until somebody
// deletes it, which is what keeps 7-day tokens working across a rotation.
func (s *Store) PublishableKeys(ctx context.Context) ([]*SigningKey, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT `+signingKeyColumns+` FROM signing_keys ORDER BY active DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*SigningKey{}
	for rows.Next() {
		k, err := scanSigningKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) InsertSigningKey(ctx context.Context, k *SigningKey) error {
	now := Now()
	k.CreatedAt, k.UpdatedAt = now, now
	res, err := s.DB.ExecContext(ctx, `INSERT INTO signing_keys
		(kid, alg, private_key, public_key, active, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?)`,
		k.Kid, k.Alg, k.PrivateKey, k.PublicKey, k.Active,
		now.Time.Format(TimeLayout), now.Time.Format(TimeLayout))
	if err != nil {
		return err
	}
	k.ID, err = res.LastInsertId()
	return err
}

func (s *Store) RetireActiveSigningKeys(ctx context.Context) error {
	now := Now().Time.Format(TimeLayout)
	_, err := s.DB.ExecContext(ctx, `UPDATE signing_keys SET active = 0, retired_at = ?, updated_at = ? WHERE active = 1`,
		now, now)
	return err
}
