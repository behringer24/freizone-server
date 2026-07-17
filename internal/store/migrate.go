package store

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Migrate applies any not-yet-applied migrations from migrations/*.sql, in
// filename order, each inside its own transaction. It is idempotent: running
// it again on an already-migrated database is a no-op.
func Migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		filename   TEXT NOT NULL,
		applied_at TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("store: creating schema_migrations table: %w", err)
	}

	names, err := migrationFilenames()
	if err != nil {
		return err
	}

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

func migrationFilenames() ([]string, error) {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return nil, fmt.Errorf("store: reading migrations directory: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func appliedVersions(db *sql.DB) (map[int]bool, error) {
	rows, err := db.Query(`SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("store: querying applied migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[int]bool)
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("store: scanning applied migration: %w", err)
		}
		applied[v] = true
	}
	return applied, rows.Err()
}

func applyMigration(db *sql.DB, name string, version int) error {
	contents, err := migrationFiles.ReadFile("migrations/" + name)
	if err != nil {
		return fmt.Errorf("store: reading migration %s: %w", name, err)
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("store: beginning transaction for %s: %w", name, err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit

	for _, stmt := range splitStatements(string(contents)) {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("store: applying migration %s: %w", name, err)
		}
	}

	if _, err := tx.Exec(
		`INSERT INTO schema_migrations (version, filename, applied_at) VALUES (?, ?, ?)`,
		version, name, time.Now().UTC().Format(time.RFC3339),
	); err != nil {
		return fmt.Errorf("store: recording migration %s: %w", name, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: committing migration %s: %w", name, err)
	}
	return nil
}

func versionFromFilename(name string) (int, error) {
	prefix, _, ok := strings.Cut(name, "_")
	if !ok {
		return 0, fmt.Errorf("store: migration filename %q missing version prefix", name)
	}
	version, err := strconv.Atoi(prefix)
	if err != nil {
		return 0, fmt.Errorf("store: migration filename %q has non-numeric version prefix: %w", name, err)
	}
	return version, nil
}

// splitStatements splits a SQL script into individual statements on ";",
// dropping empty/whitespace-only fragments. Sufficient for our own
// straightforward DDL (no semicolons embedded in string literals).
func splitStatements(script string) []string {
	parts := strings.Split(script, ";")
	statements := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			statements = append(statements, trimmed)
		}
	}
	return statements
}
