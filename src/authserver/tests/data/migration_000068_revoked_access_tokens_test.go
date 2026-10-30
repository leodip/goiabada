package datatests

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/schemadump"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Migration 000068 (#676 decision 1) creates revoked_access_tokens on all four engines. The golden
// files record the result of the migration and so cannot say WHY each column is what it is; this
// holds the migration to the claims its comments make, against an ISOLATED database of the
// configured dialect (see migration_testdb_helper_test.go).
//
//   - jti is the table's primary key and is pinned case-sensitive, 64 wide as
//     refresh_tokens.refresh_token_jti is: a token is revoked once, so a second row of one jti is
//     refused by the key, while a jti differing only by case is another token;
//   - expires_at is a microsecond datetime, NOT NULL, with a plain index for the worker's sweep;
//   - there is no foreign key, and nothing else in the schema changes; the down migration drops the
//     table it created.
//
// The baseline is 000066, the last version on every engine: SQLite has no 000067, and that
// migration alters no table, so the list of tables is the same at 66 and 67 everywhere.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000068_RevokedAccessTokens
func TestMigration000068_RevokedAccessTokens(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(ctx, 66), "migrate to 66")
	before := listTables(t, h)
	assert.NotContains(t, before, "revoked_access_tokens",
		"the table must not exist before 000068, so what is found afterwards is what 000068 added")

	require.NoError(t, h.Migrator.Migrate(ctx, 68), "apply 000068")
	assertRevokedAccessTokensShape(t, h, "after apply")
	assertRevokedAccessTokensKey(t, h, "after apply")
	assert.ElementsMatch(t, append(append([]string{}, before...), "revoked_access_tokens"), listTables(t, h),
		"000068 must add the one table and no other")

	// Down, then up again: the table is empty again after the round trip, which the key check relies
	// on.
	require.NoError(t, h.Migrator.Migrate(ctx, 66), "roll back to 66")
	assert.Equal(t, before, listTables(t, h), "the down migration must drop revoked_access_tokens and nothing else")

	require.NoError(t, h.Migrator.Migrate(ctx, 68), "apply 000068 again")
	assertRevokedAccessTokensShape(t, h, "after down then up")
	assertRevokedAccessTokensKey(t, h, "after down then up")
}

// assertRevokedAccessTokensShape holds the table to the shape the migration's comments promise.
func assertRevokedAccessTokensShape(t *testing.T, h *isolatedDB, when string) {
	t.Helper()

	// The pin each engine's catalog reports for a string column: MySQL and SQL Server spell the
	// case-sensitive collation; PostgreSQL and SQLite compare byte-wise by default and report it.
	stringCollation := map[data.Dialect]string{
		data.MySQL:    "utf8mb4_0900_as_cs",
		data.MSSQL:    "Latin1_General_100_CS_AS_KS_WS_SC_UTF8",
		data.Postgres: "default",
		data.SQLite:   "BINARY",
	}
	jtiType := map[data.Dialect]string{
		data.MySQL: "varchar(64)", data.Postgres: "character varying(64)", data.MSSQL: "nvarchar(64)", data.SQLite: "TEXT",
	}
	expiresAtType := map[data.Dialect]string{
		data.MySQL: "datetime(6)", data.Postgres: "timestamp(6) without time zone", data.MSSQL: "datetime2(6)", data.SQLite: "DATETIME",
	}
	engine := dbType()

	shape := dumpTable(t, h, "revoked_access_tokens")

	jti := shape.column(t, "jti")
	assert.Equalf(t, jtiType[engine], jti.Type, "jti's type %s", when)
	assert.Falsef(t, jti.Nullable, "jti is NOT NULL %s", when)
	// The isolated database is created at the case-sensitive collation, so a column that lost its pin
	// would still read as pinned here: TestMigrationSource_TheFourCommittedDirectories holds the
	// pin's presence, and this holds that the column ends up case-sensitive.
	assert.Equalf(t, stringCollation[engine], jti.Collation, "jti's effective collation is the case-sensitive one %s", when)

	expiresAt := shape.column(t, "expires_at")
	assert.Equalf(t, expiresAtType[engine], expiresAt.Type, "expires_at keeps the microseconds Go writes %s", when)
	assert.Falsef(t, expiresAt.Nullable, "expires_at is NOT NULL %s", when)

	assert.Lenf(t, shape.Columns, 2, "the two columns and no more %s", when)
	assert.Emptyf(t, shape.ForeignKeys, "nothing references a token, which has no row of its own %s", when)

	var primaryKeys, others []indexShape
	for _, index := range shape.Indexes {
		if index.Origin == schemadump.OriginPrimaryKey {
			primaryKeys = append(primaryKeys, index)
		} else {
			others = append(others, index)
		}
	}
	require.Lenf(t, primaryKeys, 1, "the jti is the primary key %s; indexes read: %v", when, shape.Indexes)
	assert.Truef(t, primaryKeys[0].Unique, "and the key is unique %s", when)
	assert.Equalf(t, []string{"jti"}, primaryKeys[0].Columns, "over the jti alone %s", when)

	require.Lenf(t, others, 1, "one index beside the key, for the sweep %s; indexes read: %v", when, shape.Indexes)
	assert.Equalf(t, "idx_revoked_access_tokens_expires_at", others[0].Name, "the sweep's index %s", when)
	assert.Equalf(t, []string{"expires_at"}, others[0].Columns, "over expires_at alone %s", when)
	assert.Falsef(t, others[0].Unique, "and not unique: many tokens expire at one moment %s", when)
}

// assertRevokedAccessTokensKey holds the key to what it does, rather than to what the catalog says
// about it: a second insert of one jti is refused, where the control insert of another jti, and of
// the same jti in another case, is accepted.
//
// Literals rather than placeholders because the four dialects disagree on placeholder syntax, and
// every value here is test-controlled. The table is empty on entry, both times this is called.
func assertRevokedAccessTokensKey(t *testing.T, h *isolatedDB, when string) {
	t.Helper()
	ctx := context.Background()

	insert := func(jti string) error {
		_, err := h.SQL.ExecContext(ctx, fmt.Sprintf(
			"INSERT INTO revoked_access_tokens (jti, expires_at) VALUES ('%s', '2026-01-02 03:04:05')", jti))
		return err
	}
	count := func() int {
		var n int
		require.NoError(t, h.SQL.QueryRowContext(ctx, "SELECT COUNT(*) FROM revoked_access_tokens").Scan(&n))
		return n
	}

	// The prefix puts a lower-case letter in the jti, so its upper-case spelling is another string.
	jti := "at-" + fake.UUID()
	require.NotEqual(t, jti, strings.ToUpper(jti))
	require.Zerof(t, count(), "the table starts empty %s", when)

	require.NoErrorf(t, insert(jti), "the first revocation of a token is accepted %s", when)
	require.Errorf(t, insert(jti), "a second row of the same token is refused by the key %s", when)
	assert.Equalf(t, 1, count(), "and writes nothing %s", when)

	assert.NoErrorf(t, insert("at-"+fake.UUID()), "another token is accepted %s", when)
	assert.NoErrorf(t, insert(strings.ToUpper(jti)), "and so is the same jti in another case: the key is case-sensitive %s", when)
	assert.Equalf(t, 3, count(), "three tokens, three rows %s", when)

	_, err := h.SQL.ExecContext(ctx, fmt.Sprintf(
		"INSERT INTO revoked_access_tokens (jti, expires_at) VALUES ('at-%s', NULL)", fake.UUID()))
	require.Errorf(t, err, "a row with no expiry is refused: expires_at is NOT NULL %s", when)

	// Leave the table as it was found, so the second call in this test starts empty too.
	_, err = h.SQL.ExecContext(ctx, "DELETE FROM revoked_access_tokens")
	require.NoErrorf(t, err, "empty the table again %s", when)
}
