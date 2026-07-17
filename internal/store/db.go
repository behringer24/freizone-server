// Package store implements SQLite persistence: schema migrations and typed
// repository access for accounts, devices, nonces, bootstrap state, and
// invite codes.
package store

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// DBTX is satisfied by both *sql.DB and *sql.Tx, letting repository
// functions run standalone or as part of a caller-managed transaction.
type DBTX interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

// Open opens (creating if necessary) the SQLite database at path, configured
// for a single-writer/many-readers workload: WAL journaling and a busy
// timeout so concurrent access waits briefly instead of failing immediately.
func Open(path string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: opening database: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: pinging database: %w", err)
	}
	return db, nil
}
