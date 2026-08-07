package client

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// openDB opens (creating if necessary) the account database at path.
//
// Same pragmas as the server's own store: WAL, synchronous=NORMAL (only the
// last transaction can be lost on power loss, never on a process crash) and a
// busy timeout. Deliberately a separate implementation rather than a shared
// one: internal/store cannot be imported from pkg/, because pkg/client is
// consumed by other modules and Go would refuse the transitive internal
// import. The duplication is a few dozen lines of well-understood setup and
// buys a clean module boundary.
//
// MaxOpenConns(1) for the same reason it is 1 there -- SQLite has a single
// write lock, and many pooled connections contending on it perform worse than
// one serialising in-process. The client's write load is a handful of rows per
// message; nothing here justifies a read pool.
func openDB(path string) (*sql.DB, error) {
	dsn := fmt.Sprintf(
		"file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)",
		path,
	)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("client: opening database: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("client: pinging database: %w", err)
	}
	return db, nil
}

// migrate applies any not-yet-applied migrations in filename order, each in
// its own transaction. Idempotent.
func migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		filename   TEXT NOT NULL,
		applied_at TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("client: creating schema_migrations table: %w", err)
	}

	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("client: reading migrations directory: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	applied, err := appliedVersions(db)
	if err != nil {
		return err
	}

	for _, name := range names {
		version, err := versionFromFilename(name)
		if err != nil {
			return err
		}
		if applied[version] {
			continue
		}
		if err := applyMigration(db, name, version); err != nil {
			return err
		}
	}
	return nil
}

func appliedVersions(db *sql.DB) (map[int]bool, error) {
	rows, err := db.Query(`SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("client: querying applied migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[int]bool)
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("client: scanning applied migration: %w", err)
		}
		applied[v] = true
	}
	return applied, rows.Err()
}

func applyMigration(db *sql.DB, name string, version int) error {
	contents, err := migrationFiles.ReadFile("migrations/" + name)
	if err != nil {
		return fmt.Errorf("client: reading migration %s: %w", name, err)
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("client: beginning transaction for %s: %w", name, err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit

	for _, stmt := range splitStatements(string(contents)) {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("client: applying migration %s: %w", name, err)
		}
	}

	if _, err := tx.Exec(
		`INSERT INTO schema_migrations (version, filename, applied_at) VALUES (?, ?, ?)`,
		version, name, time.Now().UTC().Format(time.RFC3339),
	); err != nil {
		return fmt.Errorf("client: recording migration %s: %w", name, err)
	}

	return tx.Commit()
}

func versionFromFilename(name string) (int, error) {
	prefix, _, ok := strings.Cut(name, "_")
	if !ok {
		return 0, fmt.Errorf("client: migration filename %q missing version prefix", name)
	}
	version, err := strconv.Atoi(prefix)
	if err != nil {
		return 0, fmt.Errorf("client: migration filename %q has non-numeric version prefix: %w", name, err)
	}
	return version, nil
}

// splitStatements strips "--" line comments, then splits the rest on ";".
//
// Comments go first because a semicolon inside one otherwise cuts a statement
// in half and the migration fails with a syntax error pointing at prose --
// which is exactly what happened while writing 001, and is an easy trap to
// re-lay every time a schema comment explains something in two clauses. The
// schema's comments are documentation in the .sql file; SQLite has no use for
// them.
//
// Assumes no "--" and no ";" inside a string literal, which holds for this
// package's own DDL and is checked by the migration simply failing if it ever
// stops holding.
func splitStatements(script string) []string {
	var stripped strings.Builder
	for line := range strings.Lines(script) {
		if before, _, found := strings.Cut(line, "--"); found {
			stripped.WriteString(before)
			stripped.WriteString("\n")
			continue
		}
		stripped.WriteString(line)
	}

	parts := strings.Split(stripped.String(), ";")
	statements := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			statements = append(statements, trimmed)
		}
	}
	return statements
}
