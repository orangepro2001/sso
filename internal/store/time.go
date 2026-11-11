package store

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// Timestamp is a nullable UTC timestamp stored as text in SQLite.
//
// Laravel stored "Y-m-d H:i:s" strings (timestamp without time zone) and every
// expiry comparison is a naive one against the application clock, which stays
// UTC (App\Support\When only moves what is printed). Keeping that layout means
// the SQL comparisons in the ported queries are the same ones the PHP wrote,
// and a value imported from PostgreSQL needs no rewriting at all.
type Timestamp struct {
	Time  time.Time
	Valid bool
}

const TimeLayout = "2006-01-02 15:04:05"

func Now() Timestamp { return Timestamp{Time: time.Now().UTC().Truncate(time.Second), Valid: true} }

func FromTime(t time.Time) Timestamp {
	return Timestamp{Time: t.UTC().Truncate(time.Second), Valid: true}
}

func FromUnix(sec int64) Timestamp { return FromTime(time.Unix(sec, 0)) }

func (t Timestamp) Value() (driver.Value, error) {
	if !t.Valid {
		return nil, nil
	}
	return t.Time.UTC().Format(TimeLayout), nil
}

func (t *Timestamp) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		t.Valid = false
		return nil
	case time.Time:
		t.Time, t.Valid = v.UTC(), true
		return nil
	case string:
		return t.parse(v)
	case []byte:
		return t.parse(string(v))
	case int64:
		t.Time, t.Valid = time.Unix(v, 0).UTC(), true
		return nil
	}
	return fmt.Errorf("store: cannot scan %T into Timestamp", src)
}

// parse accepts the SQLite layout and the shapes a dump or an older row may
// carry (RFC 3339 from the importer, Postgres' own output).
func (t *Timestamp) parse(s string) error {
	if s == "" {
		t.Valid = false
		return nil
	}
	for _, layout := range []string{
		TimeLayout,
		"2006-01-02 15:04:05.999999",
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02",
	} {
		if parsed, err := time.Parse(layout, s); err == nil {
			t.Time, t.Valid = parsed.UTC(), true
			return nil
		}
	}
	return fmt.Errorf("store: cannot parse timestamp %q", s)
}

// IsFuture is the comparison the PHP spelled `->isFuture()`.
func (t Timestamp) IsFuture() bool { return t.Valid && t.Time.After(time.Now().UTC()) }

// IsPast is `->isPast()`.
func (t Timestamp) IsPast() bool { return t.Valid && t.Time.Before(time.Now().UTC()) }

func (t Timestamp) Unix() int64 {
	if !t.Valid {
		return 0
	}
	return t.Time.Unix()
}

// ISO renders the offset form Laravel's toIso8601String() produced, which is
// what the account API documents ("2026-11-04T23:51:02+00:00").
func (t Timestamp) ISO() string {
	if !t.Valid {
		return ""
	}
	return t.Time.UTC().Format("2006-01-02T15:04:05+00:00")
}

// JSONList is a []string stored as a JSON array, the way the Eloquent `array`
// cast stored redirect_uris, allowed_scopes, scopes and audit meta.
type JSONList []string

func (l JSONList) Value() (driver.Value, error) {
	if l == nil {
		l = JSONList{}
	}
	b, err := json.Marshal([]string(l))
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

func (l *JSONList) Scan(src any) error {
	raw, err := textBytes(src)
	if err != nil {
		return err
	}
	if len(raw) == 0 {
		*l = JSONList{}
		return nil
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("store: json list: %w", err)
	}
	*l = out
	return nil
}

// Meta is the audit row's free-form metadata object.
type Meta map[string]any

func (m Meta) Value() (driver.Value, error) {
	if len(m) == 0 {
		return nil, nil
	}
	b, err := json.Marshal(map[string]any(m))
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

func (m *Meta) Scan(src any) error {
	raw, err := textBytes(src)
	if err != nil {
		return err
	}
	if len(raw) == 0 {
		*m = nil
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("store: json meta: %w", err)
	}
	*m = out
	return nil
}

func textBytes(src any) ([]byte, error) {
	switch v := src.(type) {
	case nil:
		return nil, nil
	case string:
		return []byte(v), nil
	case []byte:
		return v, nil
	case int64:
		return []byte(strconv.FormatInt(v, 10)), nil
	}
	return nil, fmt.Errorf("store: cannot scan %T as text", src)
}
