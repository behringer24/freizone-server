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
// for a single-writer/many-readers workload: WAL journaling, synchronous=NORMAL
// (WAL-safe: only the last transaction can be lost on an OS crash/power loss,
// never on a mere process crash, in exchange for skipping a full fsync per
// commit -- a large write-throughput win), and a busy timeout so concurrent
// access waits briefly instead of failing immediately.
func Open(path string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: opening database: %w", err)
	}
	// One connection, so writes serialize cleanly in-process instead of many
	// pooled connections contending on SQLite's single write lock and retrying
	// against busy_timeout (which is what made higher request concurrency
	// perform *worse* under load). Safe here: the only multi-statement
	// transaction is the startup migration (single-threaded, before serving),
	// and the SSE stream handlers hold no connection while parked -- they wait
	// on a Go channel, not on the DB. If reads ever become the hot path, the
	// next step would be a separate many-connection read pool alongside this
	// single-writer one; not needed while the write load is light.
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: pinging database: %w", err)
	}
	return db, nil
}
