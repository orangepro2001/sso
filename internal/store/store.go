// Package store is the persistence layer: plain SQL over database/sql.
//
// The database is SQLite through modernc.org/sqlite (pure Go, no cgo). One
// binary, one data file, nothing else to install — that is the whole point of
// this port. WAL plus a single writer keeps a small host comfortable; the
// pragmas below are the entire tuning story, and nothing in this package needs
// a database server or a driver beyond the standard library.
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

type Store struct {
	DB         *sql.DB
	Path       string
	StorageDir string
}

// Open opens (or creates) the data file and applies the schema. The schema is a
// set of CREATE TABLE IF NOT EXISTS statements, which is the Go answer to the
// PHP's "run migrations on every boot": a restart is always safe.
func Open(path, storageDir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("data directory: %w", err)
	}
	if err := os.MkdirAll(storageDir, 0o755); err != nil {
		return nil, fmt.Errorf("storage directory: %w", err)
	}

	dsn := "file:" + url.PathEscape(path) +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=busy_timeout(10000)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=cache_size(-32768)" +
		"&_pragma=temp_store(MEMORY)" +
		"&_txlock=immediate" +
		"&_time_format=sqlite"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// Reads are cheap and concurrent; SQLite serialises the writes itself and
	// busy_timeout covers the wait. Four connections is enough for the console
	// and leaves room for a request that reads while another writes.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("database unreachable: %w", err)
	}

	s := &Store{DB: db, Path: path, StorageDir: storageDir}
	if err := s.Migrate(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.DB.ExecContext(ctx, schemaSQL); err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	return nil
}

func (s *Store) Close() error { return s.DB.Close() }

// Backup writes a consistent copy of the database next to itself. SQLite's
// VACUUM INTO is the portable way to do it without pausing the process.
func (s *Store) Backup(ctx context.Context, dest string) error {
	_, err := s.DB.ExecContext(ctx, `VACUUM INTO ?`, dest)
	return err
}

// nullString turns an optional string into something the driver accepts.
func nullString(v *string) any {
	if v == nil || *v == "" {
		return nil
	}
	return *v
}

func nullInt(v *int64) any {
	if v == nil || *v == 0 {
		return nil
	}
	return *v
}

func nullTime(v Timestamp) any {
	if !v.Valid {
		return nil
	}
	value, err := v.Value()
	if err != nil {
		return nil
	}
	return value
}

func strPtr(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	v := ns.String
	return &v
}

func intPtr(ni sql.NullInt64) *int64 {
	if !ni.Valid {
		return nil
	}
	v := ni.Int64
	return &v
}
