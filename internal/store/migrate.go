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
// dropping empty/whitespace-only fragments.
//
// A semicolon inside a line comment, a block comment or a string literal does
// **not** split, which a plain strings.Split got wrong in a way that only
// showed up at runtime: migration 0016's comment read "...updates the category
// and evidence; it never adds a row...", and the migration failed with a
// syntax error pointing at the word "it". Prose is where a semicolon is most
// likely to appear and least likely to be suspected, so this scans rather than
// splits.
//
// Comments are kept in the statement they belong to. SQLite ignores them, and
// dropping them would make an error message about a failing statement harder
// to place in the file it came from.
func splitStatements(script string) []string {
	var statements []string
	start := 0

	for i := 0; i < len(script); i++ {
		switch {
		case strings.HasPrefix(script[i:], "--"):
			// To end of line, or to the end of the script if the comment is
			// the last thing in it.
			if next := strings.IndexByte(script[i:], '\n'); next >= 0 {
				i += next
			} else {
				i = len(script)
			}

		case strings.HasPrefix(script[i:], "/*"):
			if next := strings.Index(script[i+2:], "*/"); next >= 0 {
				i += 2 + next + 1
			} else {
				// Unterminated: the rest of the script is comment. Refusing
				// here would be defensible too, but the statement handed to
				// SQLite is then whatever came before, which fails with a
				// message about the actual SQL rather than about our scanner.
				i = len(script)
			}

		case script[i] == '\'':
			// SQL escapes a quote by doubling it, which needs no special case:
			// the closing quote of the first pair puts the scanner back
			// outside, and the second pair opens and closes again.
			if next := strings.IndexByte(script[i+1:], '\''); next >= 0 {
				i += 1 + next
			} else {
				i = len(script)
			}

		case script[i] == ';':
			if trimmed := strings.TrimSpace(script[start:i]); trimmed != "" {
				statements = append(statements, trimmed)
			}
			start = i + 1
		}
	}

	// Whatever follows the last semicolon, for a script that does not end with
	// one.
	if trimmed := strings.TrimSpace(script[start:]); trimmed != "" {
		statements = append(statements, trimmed)
	}
	return statements
}
