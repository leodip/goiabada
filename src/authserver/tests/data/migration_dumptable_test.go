package datatests

import (
	"fmt"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/data/schemadump"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDumpTable_ReadsTheCatalog is the control for dumpTable (see
// migration_testdb_helper.go). The dumper's own failure mode is the one that matters to
// the migration tests that lean on it: a per-engine branch that silently reports nothing
// makes a before-and-after comparison read as "nothing changed" and pass. Every
// assertion below is chosen so that a projection which under-reports, or reports a
// constant, fails here rather than in the migration test that trusts it.
//
// It runs against an ISOLATED database pinned at 000035, never at head. Two reasons:
//
//   - The nullability of codes.code_challenge and the on-delete action of
//     refresh_tokens.user_id are asserted AS THEY STAND TODAY, which is exactly what
//     issue #282 changes. Read off a moving head, this control would start failing the
//     moment that change lands, which is the wrong signal from a control.
//   - Migrate(N) for an N the engine does not have fails outright rather than migrating
//     to the nearest: golang-migrate's read() calls versionExists(to) first. 000035 is
//     the last version all four engines share.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestDumpTable_ReadsTheCatalog
func TestDumpTable_ReadsTheCatalog(t *testing.T) {
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(35), "migrate to 000035")

	refreshTokens := dumpTable(t, h, "refresh_tokens")
	codes := dumpTable(t, h, "codes")

	// The column projection reaches every column, on every engine. Both counts are the
	// ones the four schema.golden files record, unchanged from 000035 to head.
	assert.Lenf(t, refreshTokens.Columns, 17,
		"refresh_tokens has 17 columns at 000035 on every engine; got %d on %s",
		len(refreshTokens.Columns), dbType())
	assert.Lenf(t, codes.Columns, 22,
		"codes has 22 columns at 000035 on every engine (id, the 19 original columns, "+
			"auth_state_generation from 000024 and revoked from 000026); got %d on %s",
		len(codes.Columns), dbType())

	// Nullability, in BOTH polarities, on every engine. A branch that collapses
	// nullability to either constant passes one of these and fails the other, where
	// asserting a single column would let it half-pass.
	assert.False(t, refreshTokens.column(t, "refresh_token_jti").Nullable,
		"refresh_tokens.refresh_token_jti is NOT NULL on every engine at 000035")
	assert.True(t, refreshTokens.column(t, "created_at").Nullable,
		"refresh_tokens.created_at is nullable on every engine at 000035")

	// Type and default, per dialect. These are the only two projections nothing else
	// here exercises, and a rebuilt table is trusted to preserve both.
	wantType, wantDefault := authStateGenerationShape(t)
	gen := refreshTokens.column(t, "auth_state_generation")
	assert.Equalf(t, wantType, gen.Type,
		"refresh_tokens.auth_state_generation reads %q on %s", wantType, dbType())
	assert.Equalf(t, wantDefault, gen.Default,
		"refresh_tokens.auth_state_generation defaults to %q on %s", wantDefault, dbType())
	assert.NotEmpty(t, gen.Type, "the type projection returned nothing")
	assert.NotEmpty(t, gen.Default, "the default projection returned nothing")

	// The index projection, in both uniqueness polarities. Names, uniqueness and key
	// columns are all three of what indexShape carries.
	jti := refreshTokens.index("idx_refresh_token_jti")
	require.Truef(t, jti.Exists, "idx_refresh_token_jti is missing from the dump on %s", dbType())
	assert.True(t, jti.Unique, "idx_refresh_token_jti is UNIQUE on every engine")
	assert.Equal(t, []string{"refresh_token_jti"}, jti.Columns,
		"idx_refresh_token_jti covers exactly refresh_token_jti")

	// idx_refresh_tokens_user_id and not the code_id one: InnoDB creates an index for
	// every foreign key and names it after the constraint, so MySQL covers code_id under
	// fk_refresh_tokens_code and has no idx_refresh_tokens_code_id at all. The user_id
	// index is declared by hand on all four.
	userID := refreshTokens.index("idx_refresh_tokens_user_id")
	require.Truef(t, userID.Exists, "idx_refresh_tokens_user_id is missing from the dump on %s", dbType())
	assert.False(t, userID.Unique, "idx_refresh_tokens_user_id is not unique on any engine")
	assert.Equal(t, []string{"user_id"}, userID.Columns,
		"idx_refresh_tokens_user_id covers exactly user_id")

	// The foreign key projection. Exactly three, so a branch returning extra rows (a
	// join that fans out) fails as loudly as one returning none.
	require.Lenf(t, refreshTokens.ForeignKeys, 3,
		"refresh_tokens has exactly three foreign keys on every engine; got %v on %s",
		refreshTokens.ForeignKeys, dbType())

	assert.Equal(t,
		foreignKeyShape{Column: "code_id", RefTable: "codes", RefColumn: "id", OnDelete: "CASCADE"},
		refreshTokens.foreignKey(t, "code_id"),
		"refresh_tokens.code_id cascades from codes on every engine")

	// This pair is the control that matters most: it is divergence 5 of #282 as it
	// stands today, read out of four different catalogs. A dumper that could not see the
	// difference could not be used to prove the difference was removed.
	wantUserClientAction := "CASCADE"
	if dbType() == "mssql" {
		// SQL Server refuses the cascade here: users <- codes <- refresh_tokens(code_id)
		// alongside users <- refresh_tokens(user_id) is a multiple cascade path (Msg
		// 1785), so 000011 declared NO ACTION.
		wantUserClientAction = "NO ACTION"
	}
	assert.Equalf(t,
		foreignKeyShape{Column: "user_id", RefTable: "users", RefColumn: "id", OnDelete: wantUserClientAction},
		refreshTokens.foreignKey(t, "user_id"),
		"refresh_tokens.user_id reads %s on %s at 000035", wantUserClientAction, dbType())
	assert.Equalf(t,
		foreignKeyShape{Column: "client_id", RefTable: "clients", RefColumn: "id", OnDelete: wantUserClientAction},
		refreshTokens.foreignKey(t, "client_id"),
		"refresh_tokens.client_id reads %s on %s at 000035", wantUserClientAction, dbType())

	// And divergence 3 as it stands today, on the other axis the dumper is trusted for:
	// SQLite still holds codes.code_challenge NOT NULL where the other three do not.
	wantChallengeNullable := dbType() != "" && dbType() != "sqlite"
	assert.Equalf(t, wantChallengeNullable, codes.column(t, "code_challenge").Nullable,
		"codes.code_challenge is NOT NULL on sqlite and nullable on the other three at 000035 (%s)",
		dbType())

	// The default constraint's NAME, which SQL Server alone gives one. It is asserted in
	// both polarities for the reason nullability is: a branch reporting a constant passes
	// one and fails the other.
	assertDefaultNameProjection(t, h, refreshTokens)

	// The two projections #284 added that sweep the WHOLE schema run before anything below
	// creates a probe table, and the order is load-bearing: both count what the migrations
	// built, and a table this test made itself would be counted with them.
	assertEnumerationReachesEveryTable(t, h)
	assertGenerationProjection(t, h, refreshTokens)

	// These two build a table each, so they come last.
	assertCollationProjectionIsNotAConstant(t, h)
	assertOriginProjectionIsNotAConstant(t, h)
}

// tablesAt000035 is how many tables a database migrated to 000035 holds: the 25 application
// tables plus schema_migrations. Recounted from
// grep -c "^table" src/core/data/<engine>db/schema.golden, which reports 26 on every
// engine at head, and checked against 000036 to 000042, none of which adds or drops a table:
// 000039 rebuilds two on SQLite and 000041 rebuilds schema_migrations there, and all three
// go back.
//
// A mismatch here is a finding rather than a number to adjust. It means enumeration reached
// a different set of tables than the migrations build, which is the whole property.
const tablesAt000035 = 26

// assertEnumerationReachesEveryTable is the control for the enumeration schemadump added, so
// the dump is of a whole schema rather than a named table. A branch listing the wrong catalog
// returns nothing and is refused; one listing too much, views on MySQL or the internal
// sqlite_% tables on SQLite, fails the count.
func assertEnumerationReachesEveryTable(t *testing.T, h *isolatedDB) {
	t.Helper()

	names := listTables(t, h)
	assert.Lenf(t, names, tablesAt000035,
		"a database at 000035 holds %d tables on every engine; %s reported %v",
		tablesAt000035, dbType(), names)

	assert.Containsf(t, names, "schema_migrations",
		"schema_migrations is dumped like any other table (#284 decision 7), not excluded by name")
	assert.Containsf(t, names, "browser_sessions",
		"browser_sessions is 000035's own table, so enumeration that stopped short would miss it")
	for _, name := range names {
		assert.NotContainsf(t, name, "sqlite_",
			"SQLite's internal tables are not part of the schema and must not be enumerated on %s", dbType())
	}

	assert.Lenf(t, dumpSchema(t, h), len(names),
		"Dump must reach every table Tables enumerates on %s", dbType())
}

// assertOriginProjectionIsNotAConstant is the control for IndexShape.Origin, and it builds
// its own table to be one.
//
// The migrated schema cannot serve: every index in it is an explicit CREATE INDEX or a named
// inline KEY, so a branch reporting the constant "c" would pass on all 26 tables. And every
// primary key in it is a single auto-numbered column, which SQLite makes a rowid alias with
// no index object at all, so SQLite has no origin "pk" anywhere to read.
//
// So: a composite primary key, which every engine including SQLite backs with a real index,
// an inline UNIQUE, and an index created by name.
//
// MySQL is asserted for two of the three rather than all three, because its catalog cannot
// answer the difference: it maps CREATE UNIQUE INDEX onto ALTER TABLE ADD UNIQUE INDEX, so
// both spellings report the same constraint type. Its unique key is named here for the same
// reason the migrations name theirs, and reads as "c".
func assertOriginProjectionIsNotAConstant(t *testing.T, h *isolatedDB) {
	t.Helper()

	unique := "u BIGINT NOT NULL UNIQUE,"
	if dbType() == "mysql" {
		unique = "u BIGINT NOT NULL, UNIQUE KEY uq_dumptable_origin_probe_u (u),"
	}
	ddl := fmt.Sprintf(`CREATE TABLE dumptable_origin_probe (
		a BIGINT NOT NULL,
		b BIGINT NOT NULL,
		%s
		c BIGINT NOT NULL,
		PRIMARY KEY (a, b))`, unique)

	_, err := h.SQL.Exec(ddl)
	require.NoError(t, err, "create the index origin probe table")
	t.Cleanup(func() { _, _ = h.SQL.Exec("DROP TABLE dumptable_origin_probe") })
	_, err = h.SQL.Exec("CREATE INDEX idx_dumptable_origin_probe_c ON dumptable_origin_probe (c)")
	require.NoError(t, err, "create the named index on the origin probe table")

	probe := dumpTable(t, h, "dumptable_origin_probe")
	origins := map[schemadump.IndexOrigin]int{}
	for _, ix := range probe.Indexes {
		origins[ix.Origin]++
	}

	assert.NotZerof(t, origins[schemadump.OriginPrimaryKey],
		"a composite primary key is backed by an index on every engine, and it must read pk on %s; got %v",
		dbType(), probe.Indexes)
	assert.NotZerof(t, origins[schemadump.OriginCreated],
		"an index created by name must read c on %s; got %v", dbType(), probe.Indexes)

	if dbType() == "mysql" {
		assert.Zerof(t, origins[schemadump.OriginUnique],
			"MySQL's catalog cannot report u, so reporting one would mean the branch is guessing; got %v",
			probe.Indexes)
		return
	}
	assert.NotZerof(t, origins[schemadump.OriginUnique],
		"an inline UNIQUE is named by the engine and must read u on %s; got %v", dbType(), probe.Indexes)
}

// assertGenerationProjection is the control for ColumnShape.Generated, decision 11's answer.
//
// Both polarities on the same table, so a branch returning either constant fails one of them.
// Then the claim the four golden files are expected to agree on with no allowlist rule: every
// application table's id is auto-numbered on every engine. schema_migrations is the one table
// with no id at all, which is golang-migrate's shape and not Goiabada's.
func assertGenerationProjection(t *testing.T, h *isolatedDB, refreshTokens tableShape) {
	t.Helper()

	assert.Truef(t, refreshTokens.column(t, "id").Generated,
		"refresh_tokens.id is auto-numbered on %s: AUTO_INCREMENT, IDENTITY, BIGSERIAL or AUTOINCREMENT",
		dbType())
	assert.Falsef(t, refreshTokens.column(t, "refresh_token_jti").Generated,
		"refresh_tokens.refresh_token_jti is not auto-numbered on any engine, so a projection returning a constant fails here")

	seen := 0
	for _, entry := range dumpSchema(t, h) {
		if entry.Name == "schema_migrations" {
			continue
		}
		col, ok := entry.Table.Column("id")
		require.Truef(t, ok, "%s carries an id column on %s", entry.Name, dbType())
		assert.Truef(t, col.Generated, "%s.id is auto-numbered on %s", entry.Name, dbType())
		seen++
	}
	assert.Equalf(t, tablesAt000035-1, seen,
		"every table but schema_migrations was checked for an auto-numbered id on %s", dbType())
}

// assertDefaultNameProjection holds columnShape.DefaultName to what each engine can
// actually report. SQL Server names default constraints and the other three do not: MySQL,
// PostgreSQL and SQLite attach a default to the column with no nameable object behind it,
// so "" there is the truth and not an unfilled field.
func assertDefaultNameProjection(t *testing.T, h *isolatedDB, refreshTokens tableShape) {
	t.Helper()

	gen := refreshTokens.column(t, "auth_state_generation")
	jti := refreshTokens.column(t, "refresh_token_jti")

	assert.Emptyf(t, jti.DefaultName,
		"refresh_tokens.refresh_token_jti carries no default at all, so it can carry no default constraint name on %s",
		dbType())
	assert.Falsef(t, jti.DefaultIsSystemNamed,
		"a column with no default constraint has no name for the engine to have invented, on %s", dbType())

	if dbType() != "mssql" {
		assert.Emptyf(t, gen.DefaultName,
			"%s names no default constraint, so DefaultName must stay empty even for a column that has a default",
			dbType())
		assert.Falsef(t, gen.DefaultIsSystemNamed,
			"%s names no default constraint at all, so none of them can be system-named", dbType())
		return
	}
	assert.Equal(t, "df_refresh_tokens_auth_state_generation", gen.DefaultName,
		"000024 named this constraint so a later migration could drop it without a catalog lookup")
	assert.False(t, gen.DefaultIsSystemNamed,
		"000024 chose this name, so SQL Server did not invent it")

	// The other polarity, which is the one section 4.2 needs: 42 of the 64 SQL Server
	// defaults are unnamed in the migrations, and the golden file has to mask exactly those
	// because their generated names carry a per-database suffix. dc.name alone cannot
	// separate them from the 22 a migration named. clients.display_name is one of the three
	// 000040 later renames, so at 000035 it still carries SQL Server's own.
	display := dumpTable(t, h, "clients").column(t, "display_name")
	assert.Truef(t, display.DefaultIsSystemNamed,
		"clients.display_name still carries the name SQL Server invented at 000035; got %q", display.DefaultName)
	assert.Truef(t, strings.HasPrefix(display.DefaultName, "DF__"),
		"a system-named SQL Server default is spelled DF__<table>__<column>__<random>; got %q", display.DefaultName)
}

// assertCollationProjectionIsNotAConstant is the control for columnShape.Collation, and it
// builds its own table to be one.
//
// Reading the collation off the schema instead would prove nothing on any engine: every
// string column in the migrated schema carries the same collation, so a branch that
// returned that one name as a literal, or that read the DATABASE default rather than the
// COLUMN's, would pass. SQLite is the sharpest case, because its collation is parsed out of
// the CREATE TABLE text rather than projected by a pragma, and every column in the real
// schema is BINARY.
//
// So: two string columns in one table, one at the engine's default and one at an explicitly
// different collation, plus an integer column. The projection has to tell all three apart.
func assertCollationProjectionIsNotAConstant(t *testing.T, h *isolatedDB) {
	t.Helper()

	var ddl, wantOverride string
	switch dbType() {
	case "mysql":
		ddl = `CREATE TABLE dumptable_collation_probe (
			inherited VARCHAR(16) NOT NULL,
			overridden VARCHAR(16) COLLATE utf8mb4_bin NOT NULL,
			n BIGINT NOT NULL)`
		wantOverride = "utf8mb4_bin"
	case "postgres":
		ddl = `CREATE TABLE dumptable_collation_probe (
			inherited text NOT NULL,
			overridden text COLLATE "C" NOT NULL,
			n bigint NOT NULL)`
		wantOverride = "C"
	case "mssql":
		ddl = `CREATE TABLE dumptable_collation_probe (
			inherited NVARCHAR(16) NOT NULL,
			overridden NVARCHAR(16) COLLATE Latin1_General_BIN2 NOT NULL,
			n BIGINT NOT NULL)`
		wantOverride = "Latin1_General_BIN2"
	default: // sqlite
		ddl = `CREATE TABLE dumptable_collation_probe (
			inherited TEXT NOT NULL,
			overridden TEXT COLLATE NOCASE NOT NULL,
			n INTEGER NOT NULL)`
		wantOverride = "NOCASE"
	}

	_, err := h.SQL.Exec(ddl)
	require.NoError(t, err, "create the collation probe table")
	t.Cleanup(func() { _, _ = h.SQL.Exec("DROP TABLE dumptable_collation_probe") })

	probe := dumpTable(t, h, "dumptable_collation_probe")
	inherited := probe.column(t, "inherited").Collation
	overridden := probe.column(t, "overridden").Collation
	numeric := probe.column(t, "n").Collation

	assert.NotEmptyf(t, inherited, "the collation projection returned nothing for a string column on %s", dbType())
	assert.Equalf(t, wantOverride, overridden,
		"the collation projection must read the COLUMN's own collation, not the database's, on %s", dbType())
	assert.NotEqualf(t, inherited, overridden,
		"two columns at different collations must not report the same one on %s", dbType())

	if dbType() == "" || dbType() == "sqlite" {
		// SQLite assigns BINARY to every column whatever it holds, and reports no
		// collation for any of them, so its integer column reads BINARY rather than "".
		assert.Equal(t, "BINARY", numeric,
			"SQLite's declared collating sequence is BINARY wherever a declaration omits one")
		return
	}
	assert.Emptyf(t, numeric,
		"a column that holds no string has no collation on %s, and reporting one would mean the projection is a constant",
		dbType())
}

// authStateGenerationShape is the type and default that refresh_tokens
// .auth_state_generation reads as in this engine's catalog. Per-dialect literals rather
// than a shared vocabulary, because dumpTable records each engine's own spelling and
// compares a table only against itself.
func authStateGenerationShape(t *testing.T) (typ, def string) {
	t.Helper()

	switch dbType() {
	case "mysql":
		return "bigint", "0"
	case "postgres":
		return "bigint", "0"
	case "mssql":
		// A named default constraint (df_refresh_tokens_auth_state_generation), whose
		// definition SQL Server renders with its own parentheses.
		return "bigint", "((0))"
	default: // sqlite
		return "INTEGER", "0"
	}
}
