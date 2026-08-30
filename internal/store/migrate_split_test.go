package store

import (
	"reflect"
	"testing"
)

// A semicolon in prose is the case that broke a migration at runtime: the
// splitter cut mid-sentence and handed SQLite the remainder as a statement,
// which failed with a syntax error pointing at an English word.
func TestSplitStatements(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script string
		want   []string
	}{
		{
			name:   "two plain statements",
			script: "CREATE TABLE a (id INTEGER);\nCREATE TABLE b (id INTEGER);",
			want: []string{
				"CREATE TABLE a (id INTEGER)",
				"CREATE TABLE b (id INTEGER)",
			},
		},
		{
			name:   "no trailing semicolon",
			script: "CREATE TABLE a (id INTEGER)",
			want:   []string{"CREATE TABLE a (id INTEGER)"},
		},
		{
			name:   "semicolon inside a line comment",
			script: "-- one thing; and another\nCREATE TABLE a (id INTEGER);",
			want: []string{
				"-- one thing; and another\nCREATE TABLE a (id INTEGER)",
			},
		},
		{
			name:   "line comment as the last thing in the script",
			script: "CREATE TABLE a (id INTEGER);\n-- trailing note; with a semicolon",
			want: []string{
				"CREATE TABLE a (id INTEGER)",
				"-- trailing note; with a semicolon",
			},
		},
		{
			name:   "semicolon inside a block comment",
			script: "/* one; two */ CREATE TABLE a (id INTEGER);",
			want:   []string{"/* one; two */ CREATE TABLE a (id INTEGER)"},
		},
		{
			name:   "block comment spanning lines",
			script: "/*\n a; b\n*/\nCREATE TABLE a (id INTEGER);",
			want:   []string{"/*\n a; b\n*/\nCREATE TABLE a (id INTEGER)"},
		},
		{
			name:   "semicolon inside a string literal",
			script: "INSERT INTO a (t) VALUES ('one; two');",
			want:   []string{"INSERT INTO a (t) VALUES ('one; two')"},
		},
		{
			name:   "doubled quote inside a string literal",
			script: "INSERT INTO a (t) VALUES ('it''s; fine');\nSELECT 1;",
			want: []string{
				"INSERT INTO a (t) VALUES ('it''s; fine')",
				"SELECT 1",
			},
		},
		{
			name:   "empty fragments are dropped",
			script: ";;\nCREATE TABLE a (id INTEGER);\n\n;",
			want:   []string{"CREATE TABLE a (id INTEGER)"},
		},
		{
			name:   "empty script",
			script: "\n  \n",
			want:   nil,
		},
		{
			// Exactly what migration 0016 originally read, shortened.
			name: "the comment that started this",
			script: "-- One reporter counts once. Reporting again updates the\n" +
				"-- category and evidence; it never adds a row.\n" +
				"CREATE UNIQUE INDEX idx_a ON a (b);",
			want: []string{
				"-- One reporter counts once. Reporting again updates the\n" +
					"-- category and evidence; it never adds a row.\n" +
					"CREATE UNIQUE INDEX idx_a ON a (b)",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := splitStatements(tc.script)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("splitStatements()\n got: %q\nwant: %q", got, tc.want)
			}
		})
	}
}
