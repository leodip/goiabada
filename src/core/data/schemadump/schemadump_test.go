package schemadump

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseDialect covers the arm that used to be a silent fallback. Every switch this
// package replaced fell through its default to SQLite, so a misspelled dialect in a
// four-engine process would have read SQLite's catalog against a PostgreSQL connection,
// found nothing, and reported success.
func TestParseDialect(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Dialect
	}{
		{"", SQLite},
		{"sqlite", SQLite},
		{"  mysql  ", MySQL},
		{`"postgres"`, Postgres},
		{"'mssql'", MSSQL},
	} {
		got, err := ParseDialect(tc.in)
		require.NoErrorf(t, err, "ParseDialect(%q)", tc.in)
		assert.Equalf(t, tc.want, got, "ParseDialect(%q)", tc.in)
	}

	for _, bad := range []string{"postgresql", "sqlite3", "SQLITE", "oracle"} {
		_, err := ParseDialect(bad)
		assert.Errorf(t, err, "ParseDialect(%q) must not fall back to a dialect", bad)
	}
}

// TestCheckIdentifier holds the one place a table or index name reaches a catalog query by
// interpolation. Every name the package meets comes from the catalog or from a test
// constant, so this rejects nothing legitimate; it is here so that never stops being true
// by accident.
func TestCheckIdentifier(t *testing.T) {
	for _, ok := range []string{"users", "refresh_tokens", "sqlite_autoindex_clients_1", "_x9"} {
		assert.NoErrorf(t, checkIdentifier("table", ok), "%q is a plain identifier", ok)
	}
	for _, bad := range []string{"", "users; DROP TABLE clients", "dbo.users", "9lives", "user`s"} {
		assert.Errorf(t, checkIdentifier("table", bad), "%q is not a plain identifier", bad)
	}
}

// TestSplitTopLevel and TestColumnDefsOf cover the SQLite declaration reader's two string
// primitives. SQLite is the only engine whose collation and AUTOINCREMENT have to be parsed
// out of DDL rather than projected, so a bug in either silently blanks two fields on one
// engine and the cross-engine comparison then reports a divergence that is not there.
func TestSplitTopLevel(t *testing.T) {
	assert.Equal(t,
		[]string{"a INTEGER", " b DECIMAL(10,2)", " c TEXT DEFAULT 'x,y'", " PRIMARY KEY (a)"},
		splitTopLevel("a INTEGER, b DECIMAL(10,2), c TEXT DEFAULT 'x,y', PRIMARY KEY (a)"),
		"a comma inside parentheses or a quoted string does not split a definition")
}

func TestColumnDefsOf(t *testing.T) {
	assert.Equal(t, "a INTEGER, b TEXT",
		columnDefsOf("CREATE TABLE t (a INTEGER, b TEXT)"))
	assert.Equal(t, "a DECIMAL(10,2)",
		columnDefsOf(`CREATE TABLE "t" (a DECIMAL(10,2))`),
		"the outermost parentheses, not the first inner pair")
	assert.Empty(t, columnDefsOf("CREATE TABLE t"), "no parentheses is no column list")
}

// TestParseSqliteColumnFacts asserts both facts in both polarities on one declaration,
// because a parser that returned a constant for either would otherwise pass: every column
// in the real schema is BINARY, and every table's id is AUTOINCREMENT.
func TestParseSqliteColumnFacts(t *testing.T) {
	facts := parseSqliteColumnFacts(`CREATE TABLE codes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		code_hash TEXT NOT NULL,
		nonce TEXT COLLATE NOCASE,
		used INTEGER NOT NULL DEFAULT 0,
		CONSTRAINT fk_codes_user FOREIGN KEY (user_id) REFERENCES users(id),
		UNIQUE (code_hash)
	)`)

	assert.True(t, facts["id"].Generated, "id declares AUTOINCREMENT")
	assert.False(t, facts["code_hash"].Generated, "code_hash does not")
	assert.False(t, facts["used"].Generated, "used does not")

	assert.Equal(t, "BINARY", facts["code_hash"].Collation, "a declaration with no COLLATE is BINARY")
	assert.Equal(t, "NOCASE", facts["nonce"].Collation, "a declaration with COLLATE reports it")

	_, hasConstraint := facts["CONSTRAINT"]
	assert.False(t, hasConstraint, "a table constraint is not a column")
	_, hasUnique := facts["UNIQUE"]
	assert.False(t, hasUnique, "a table constraint is not a column")
}

// TestSqliteUnrepresentableInDDL covers the two constructs SQLite has no catalog view for,
// and the negative case that matters more: the real schema's own DDL must pass, or the
// guard would refuse every table in the chain.
func TestSqliteUnrepresentableInDDL(t *testing.T) {
	assert.NoError(t, sqliteUnrepresentableInDDL(`CREATE TABLE codes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		code_hash TEXT NOT NULL,
		description TEXT DEFAULT 'checked out',
		user_id INTEGER,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	)`, "codes"), "the shape of every table in the chain today")

	assert.ErrorContains(t, sqliteUnrepresentableInDDL(
		`CREATE TABLE t (n INTEGER CHECK (n > 0))`, "t"),
		"CHECK constraint", "a column-level CHECK")
	assert.ErrorContains(t, sqliteUnrepresentableInDDL(
		`CREATE TABLE t (n INTEGER, CHECK(n > 0))`, "t"),
		"CHECK constraint", "a table-level CHECK, written without a space")
	assert.ErrorContains(t, sqliteUnrepresentableInDDL(
		`CREATE TABLE t (a INTEGER REFERENCES u(id) DEFERRABLE INITIALLY DEFERRED)`, "t"),
		"DEFERRABLE constraint")
}

// TestTableShapeLookups covers the three accessors, in the found and not-found polarity
// each, because the not-found arm is what a migration test's failure message depends on.
func TestTableShapeLookups(t *testing.T) {
	s := TableShape{
		Columns:     []ColumnShape{{Name: "id", Generated: true}},
		Indexes:     []IndexShape{{Name: "idx_a", Exists: true, Origin: OriginCreated}},
		ForeignKeys: []ForeignKeyShape{{Column: "user_id", RefTable: "users", RefColumn: "id"}},
	}

	col, ok := s.Column("id")
	assert.True(t, ok)
	assert.True(t, col.Generated)
	_, ok = s.Column("missing")
	assert.False(t, ok)

	assert.True(t, s.Index("idx_a").Exists)
	assert.False(t, s.Index("idx_b").Exists, "an absent index reads as a zero shape, not a panic")

	fk, ok := s.ForeignKey("user_id")
	assert.True(t, ok)
	assert.Equal(t, "users", fk.RefTable)
	_, ok = s.ForeignKey("client_id")
	assert.False(t, ok)

	schema := Schema{{Name: "codes", Table: s}}
	_, ok = schema.Table("codes")
	assert.True(t, ok)
	_, ok = schema.Table("clients")
	assert.False(t, ok)
}
