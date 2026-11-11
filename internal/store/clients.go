package store

import (
	"context"
	"database/sql"
	"errors"
)

const clientColumns = `id, client_id, name, type, secret_hash, redirect_uris, home_url, sort_order,
	in_launcher, allowed_scopes, active, created_by, note, created_at, updated_at`

func scanClient(row interface{ Scan(...any) error }) (*Client, error) {
	var (
		c                         Client
		secretHash, homeURL, note sql.NullString
		createdBy                 sql.NullInt64
		redirects, scopes         JSONList
		active, inLauncher        bool
		createdAt, updatedAt      Timestamp
	)
	err := row.Scan(&c.ID, &c.ClientID, &c.Name, &c.Type, &secretHash, &redirects, &homeURL, &c.SortOrder,
		&inLauncher, &scopes, &active, &createdBy, &note, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.SecretHash = strPtr(secretHash)
	c.HomeURL = strPtr(homeURL)
	c.Note = strPtr(note)
	c.CreatedBy = intPtr(createdBy)
	c.RedirectURIs = redirects
	c.AllowedScopes = scopes
	c.Active = active
	c.InLauncher = inLauncher
	c.CreatedAt = createdAt
	c.UpdatedAt = updatedAt
	return &c, nil
}

func (s *Store) ClientByID(ctx context.Context, id int64) (*Client, error) {
	return scanClient(s.DB.QueryRowContext(ctx, `SELECT `+clientColumns+` FROM oauth_clients WHERE id = ?`, id))
}

func (s *Store) ClientByClientID(ctx context.Context, clientID string) (*Client, error) {
	return scanClient(s.DB.QueryRowContext(ctx, `SELECT `+clientColumns+` FROM oauth_clients WHERE client_id = ?`, clientID))
}

func (s *Store) InsertClient(ctx context.Context, c *Client) error {
	now := Now()
	if !c.CreatedAt.Valid {
		c.CreatedAt = now
	}
	c.UpdatedAt = now
	res, err := s.DB.ExecContext(ctx, `INSERT INTO oauth_clients
		(client_id, name, type, secret_hash, redirect_uris, home_url, sort_order, in_launcher,
		 allowed_scopes, active, created_by, note, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.ClientID, c.Name, c.Type, nullString(c.SecretHash), c.RedirectURIs, nullString(c.HomeURL),
		c.SortOrder, c.InLauncher, c.AllowedScopes, c.Active, nullInt(c.CreatedBy), nullString(c.Note),
		c.CreatedAt.Time.Format(TimeLayout), c.UpdatedAt.Time.Format(TimeLayout))
	if err != nil {
		return err
	}
	c.ID, err = res.LastInsertId()
	return err
}

func (s *Store) SaveClient(ctx context.Context, c *Client) error {
	c.UpdatedAt = Now()
	_, err := s.DB.ExecContext(ctx, `UPDATE oauth_clients SET
		name = ?, type = ?, secret_hash = ?, redirect_uris = ?, home_url = ?, sort_order = ?,
		in_launcher = ?, allowed_scopes = ?, active = ?, note = ?, updated_at = ?
		WHERE id = ?`,
		c.Name, c.Type, nullString(c.SecretHash), c.RedirectURIs, nullString(c.HomeURL), c.SortOrder,
		c.InLauncher, c.AllowedScopes, c.Active, nullString(c.Note),
		c.UpdatedAt.Time.Format(TimeLayout), c.ID)
	return err
}

func (s *Store) ListClients(ctx context.Context, limit, offset int) ([]*Client, int, error) {
	var total int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM oauth_clients`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT `+clientColumns+` FROM oauth_clients ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []*Client{}
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

// LauncherClients are the applications a person can open: active, pointed at a
// page, and offered on the start screen. A client registered only for machine
// use has no home_url and stays invisible.
func (s *Store) LauncherClients(ctx context.Context) ([]*Client, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, client_id, name, home_url, note, sort_order
		FROM oauth_clients
		WHERE active = 1 AND in_launcher = 1 AND home_url IS NOT NULL AND home_url <> ''
		ORDER BY sort_order, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Client{}
	for rows.Next() {
		c := &Client{}
		var homeURL, note sql.NullString
		if err := rows.Scan(&c.ID, &c.ClientID, &c.Name, &homeURL, &note, &c.SortOrder); err != nil {
			return nil, err
		}
		c.HomeURL = strPtr(homeURL)
		c.Note = strPtr(note)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ClientNames is client_id => name, for the audit page's "who was it done to".
func (s *Store) ClientNames(ctx context.Context) (map[string]string, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT client_id, name FROM oauth_clients`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		out[id] = name
	}
	return out, rows.Err()
}
