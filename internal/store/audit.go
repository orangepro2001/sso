package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// InsertAudit appends one row. Callers never update or delete; the trail is
// append-only by convention (DESIGN.md §11).
func (s *Store) InsertAudit(ctx context.Context, l *AuditLog) error {
	if !l.CreatedAt.Valid {
		l.CreatedAt = Now()
	}
	res, err := s.DB.ExecContext(ctx, `INSERT INTO audit_logs
		(event, actor_type, actor_id, subject_type, subject_id, ip, user_agent, meta, created_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		l.Event, nullString(l.ActorType), nullString(l.ActorID), nullString(l.SubjectType), nullString(l.SubjectID),
		nullString(l.IP), nullString(l.UserAgent), l.Meta, l.CreatedAt.Time.Format(TimeLayout))
	if err != nil {
		return err
	}
	l.ID, err = res.LastInsertId()
	return err
}

const auditColumns = `id, event, actor_type, actor_id, subject_type, subject_id, ip, user_agent, meta, created_at`

func scanAudit(row interface{ Scan(...any) error }) (*AuditLog, error) {
	var (
		l                                          AuditLog
		actorType, actorID, subjectType, subjectID sql.NullString
		ip, agent                                  sql.NullString
		meta                                       Meta
		createdAt                                  Timestamp
	)
	err := row.Scan(&l.ID, &l.Event, &actorType, &actorID, &subjectType, &subjectID, &ip, &agent, &meta, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	l.ActorType = strPtr(actorType)
	l.ActorID = strPtr(actorID)
	l.SubjectType = strPtr(subjectType)
	l.SubjectID = strPtr(subjectID)
	l.IP = strPtr(ip)
	l.UserAgent = strPtr(agent)
	l.Meta = meta
	l.CreatedAt = createdAt
	return &l, nil
}

// AuditFilter matches the activity page: event prefixes and/or one person
// (as subject, as actor, or as the anonymous username a failed login records).
type AuditFilter struct {
	Prefixes []string
	PersonID int64
	Username string
	Limit    int
	Offset   int
}

func (f AuditFilter) where() (string, []any) {
	clauses := []string{"1=1"}
	args := []any{}

	if len(f.Prefixes) > 0 {
		or := make([]string, 0, len(f.Prefixes))
		for _, p := range f.Prefixes {
			or = append(or, "event LIKE ?")
			args = append(args, p+"%")
		}
		clauses = append(clauses, "("+strings.Join(or, " OR ")+")")
	}

	if f.PersonID > 0 {
		id := itoa(f.PersonID)
		clauses = append(clauses, `((subject_type = 'user' AND subject_id = ?)
			OR (actor_type IN ('user','admin') AND actor_id = ?)
			OR (actor_type = 'anonymous' AND actor_id = ?))`)
		args = append(args, id, id, f.Username)
	}

	return strings.Join(clauses, " AND "), args
}

func (s *Store) ListAudit(ctx context.Context, f AuditFilter) ([]*AuditLog, int, error) {
	where, args := f.where()

	var total int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_logs WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := `SELECT ` + auditColumns + ` FROM audit_logs WHERE ` + where + ` ORDER BY id DESC LIMIT ? OFFSET ?`
	runArgs := append(append([]any{}, args...), f.Limit, f.Offset)

	rows, err := s.DB.QueryContext(ctx, query, runArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []*AuditLog{}
	for rows.Next() {
		l, err := scanAudit(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, l)
	}
	return out, total, rows.Err()
}

// AuditForUser is the person page's recent activity: everything done to them
// and everything they did.
func (s *Store) AuditForUser(ctx context.Context, userID int64, limit int) ([]*AuditLog, error) {
	id := itoa(userID)
	rows, err := s.DB.QueryContext(ctx, `SELECT `+auditColumns+` FROM audit_logs
		WHERE (subject_type = 'user' AND subject_id = ?)
		   OR (actor_type IN ('user','admin') AND actor_id = ?)
		ORDER BY id DESC LIMIT ?`, id, id, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*AuditLog{}
	for rows.Next() {
		l, err := scanAudit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// UserNames resolves the ids mentioned by a page of audit rows in one query
// (AuditPresenter::people).
func (s *Store) UserNames(ctx context.Context, ids []int64) (map[int64]string, error) {
	out := map[int64]string{}
	if len(ids) == 0 {
		return out, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id, name FROM users WHERE id IN (`+strings.Join(placeholders, ",")+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		out[id] = name
	}
	return out, rows.Err()
}
