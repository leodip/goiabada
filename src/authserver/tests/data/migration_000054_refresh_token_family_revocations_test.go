package datatests

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/schemadump"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Migration 000054 (#132, #259, #437) creates refresh_token_family_revocations on all four
// engines. The golden files record the result of the migration and so cannot say WHY each column
// is what it is; this holds the migration to the claims its comments make, against an ISOLATED
// database of the configured dialect (see migration_testdb_helper_test.go).
//
//   - first_refresh_token_jti is the table's primary key and is pinned case-sensitive, as
//     refresh_tokens.first_refresh_token_jti is, at the same width: a family is revoked once, so a
//     second record of one jti is refused by the key, while a jti differing only by case is another
//     family;
//   - reason is a short pinned string and revoked_at a microsecond datetime, both NOT NULL;
//   - there is no foreign key, because first_refresh_token_jti is not unique in refresh_tokens,
//     which holds one row per member, and no index beside the key: the key is the lookup;
//   - nothing else in the schema changes, and the down migration drops the table it created.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000054_RefreshTokenFamilyRevocations
func TestMigration000054_RefreshTokenFamilyRevocations(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(ctx, 53), "migrate to 53")
	before := listTables(t, h)
	assert.NotContains(t, before, "refresh_token_family_revocations",
		"the table must not exist at 000053, so what is found afterwards is what 000054 added")

	require.NoError(t, h.Migrator.Migrate(ctx, 54), "apply 000054")
	assertRefreshTokenFamilyRevocationsShape(t, h, "after apply")
	assertRefreshTokenFamilyRevocationsKey(t, h, "after apply")
	assert.ElementsMatch(t, append(append([]string{}, before...), "refresh_token_family_revocations"), listTables(t, h),
		"000054 must add the one table and no other")

	// Down, then up again. SQL Server's and MySQL's DDL behave differently in both directions, and
	// the table is empty again after the round trip, which the key check below relies on.
	require.NoError(t, h.Migrator.Migrate(ctx, 53), "roll back to 53")
	assert.Equal(t, before, listTables(t, h), "the down migration must drop refresh_token_family_revocations and nothing else")

	require.NoError(t, h.Migrator.Migrate(ctx, 54), "apply 000054 again")
	assertRefreshTokenFamilyRevocationsShape(t, h, "after down then up")
	assertRefreshTokenFamilyRevocationsKey(t, h, "after down then up")
}

// assertRefreshTokenFamilyRevocationsShape holds the table to the shape the migration's comments
// promise.
func assertRefreshTokenFamilyRevocationsShape(t *testing.T, h *isolatedDB, when string) {
	t.Helper()

	// The pin each engine's catalog reports for a string column: MySQL and SQL Server spell the
	// case-sensitive collation; PostgreSQL and SQLite compare byte-wise by default and report it.
	stringCollation := map[string]string{
		"mysql":    "utf8mb4_0900_as_cs",
		"mssql":    "Latin1_General_100_CS_AS_KS_WS_SC_UTF8",
		"postgres": "default",
		"sqlite":   "BINARY",
	}
	// Both string columns are 64 wide, the width refresh_tokens.first_refresh_token_jti has.
	stringType := map[string]string{
		"mysql": "varchar(64)", "postgres": "character varying(64)", "mssql": "nvarchar(64)", "sqlite": "TEXT",
	}
	revokedAtType := map[string]string{
		"mysql": "datetime(6)", "postgres": "timestamp(6) without time zone", "mssql": "datetime2(6)", "sqlite": "DATETIME",
	}
	engine := dbType()
	if engine == "" {
		engine = "sqlite"
	}

	shape := dumpTable(t, h, "refresh_token_family_revocations")

	jti := shape.column(t, "first_refresh_token_jti")
	assert.Equalf(t, stringType[engine], jti.Type, "first_refresh_token_jti's type %s", when)
	assert.Falsef(t, jti.Nullable, "first_refresh_token_jti is NOT NULL %s", when)
	// The isolated database is created at the case-sensitive collation, so a column that lost its pin
	// would still read as pinned here: TestMigrationSource_TheFourCommittedDirectories holds the
	// pin's presence, and this holds that the column ends up case-sensitive.
	assert.Equalf(t, stringCollation[engine], jti.Collation,
		"first_refresh_token_jti's effective collation is the case-sensitive one %s", when)

	reason := shape.column(t, "reason")
	assert.Equalf(t, stringType[engine], reason.Type, "reason's type %s", when)
	assert.Falsef(t, reason.Nullable, "reason is NOT NULL %s", when)
	assert.Equalf(t, stringCollation[engine], reason.Collation, "reason is pinned like the jti %s", when)

	revokedAt := shape.column(t, "revoked_at")
	assert.Equalf(t, revokedAtType[engine], revokedAt.Type,
		"revoked_at keeps the microseconds Go writes, on every engine %s", when)
	assert.Falsef(t, revokedAt.Nullable, "revoked_at is NOT NULL %s", when)

	assert.Lenf(t, shape.Columns, 3, "the three columns and no more %s", when)
	assert.Emptyf(t, shape.ForeignKeys,
		"first_refresh_token_jti is not unique in refresh_tokens, so nothing can reference it %s", when)

	var primaryKeys []indexShape
	for _, index := range shape.Indexes {
		if index.Origin == schemadump.OriginPrimaryKey {
			primaryKeys = append(primaryKeys, index)
		}
	}
	require.Lenf(t, primaryKeys, 1, "the jti is the primary key %s; indexes read: %v", when, shape.Indexes)
	assert.Truef(t, primaryKeys[0].Unique, "and the key is unique %s", when)
	assert.Equalf(t, []string{"first_refresh_token_jti"}, primaryKeys[0].Columns, "over the jti alone %s", when)
	assert.Lenf(t, shape.Indexes, 1, "the key is the lookup, so there is no index beside it %s", when)
}

// assertRefreshTokenFamilyRevocationsKey holds the key to what it does, rather than to what the
// catalog says about it: a second insert of one jti is refused, where the control insert of another
// jti, and of the same jti in another case, is accepted. Each refusal is therefore the key's and not
// a mistake in the statement, which differs from the control in the one value.
//
// Literals rather than placeholders because the four dialects disagree on placeholder syntax, and
// every value here is test-controlled. The table is empty on entry, both times this is called.
func assertRefreshTokenFamilyRevocationsKey(t *testing.T, h *isolatedDB, when string) {
	t.Helper()
	ctx := context.Background()

	insert := func(jti string) error {
		_, err := h.SQL.ExecContext(ctx, fmt.Sprintf(
			"INSERT INTO refresh_token_family_revocations (first_refresh_token_jti, reason, revoked_at) "+
				"VALUES ('%s', 'replay', '2026-01-02 03:04:05')", jti))
		return err
	}
	count := func() int {
		var n int
		require.NoError(t, h.SQL.QueryRowContext(ctx, "SELECT COUNT(*) FROM refresh_token_family_revocations").Scan(&n))
		return n
	}

	// The prefix puts a lower-case letter in the jti, so its upper-case spelling is another string.
	jti := "fam-" + fake.UUID()
	require.NotEqual(t, jti, strings.ToUpper(jti))
	require.Zerof(t, count(), "the table starts empty %s", when)

	require.NoErrorf(t, insert(jti), "the first record of a family is accepted %s", when)
	assert.Errorf(t, insert(jti), "a second record of the same family is refused by the key %s", when)
	assert.Equalf(t, 1, count(), "and writes nothing %s", when)

	assert.NoErrorf(t, insert("fam-"+fake.UUID()), "a record of another family is accepted %s", when)
	assert.NoErrorf(t, insert(strings.ToUpper(jti)), "and so is the same jti in another case: the key is case-sensitive %s", when)
	assert.Equalf(t, 3, count(), "three families, three rows %s", when)

	_, err := h.SQL.ExecContext(ctx, fmt.Sprintf(
		"INSERT INTO refresh_token_family_revocations (first_refresh_token_jti, reason, revoked_at) "+
			"VALUES ('fam-%s', NULL, '2026-01-02 03:04:05')", fake.UUID()))
	assert.Errorf(t, err, "a record with no reason is refused: reason is NOT NULL %s", when)

	// Leave the table as it was found, so the second call in this test starts empty too.
	_, err = h.SQL.ExecContext(ctx, "DELETE FROM refresh_token_family_revocations")
	require.NoErrorf(t, err, "empty the table again %s", when)
}
