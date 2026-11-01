package datatests

import (
	"context"
	"fmt"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/schemadump"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Migration 000073 (#257 decision 3) creates user_recovery_codes on all four engines: a user's set
// of recovery codes, one row per code, each stored as its SHA-256 and marked used rather than
// deleted. This holds the migration to the claims its comments make, against an ISOLATED database
// of the configured dialect (see migration_testdb_helper_test.go):
//
//   - id is the key, user_id NOT NULL with the users id's type, code_hash a case-sensitive string
//     64 wide, created_at a NOT NULL microsecond datetime and used_at the same type but nullable;
//   - a code appears once in a user's set, so the pair of user_id and code_hash is unique, and that
//     index, leading with user_id, serves the user's whole set too;
//   - the foreign key cascades, so deleting a user removes their codes;
//   - nothing else in the schema changes, and the down migration drops the table it created.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000073_UserRecoveryCodes
func TestMigration000073_UserRecoveryCodes(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(ctx, 72), "migrate to 72")
	// The fixture user is written through the data layer, whose record follows head; the users
	// columns added after 000073 are scaffolded on, and no down below 000073 touches them.
	scaffoldHeadUsersColumns(t, h)
	before := listTables(t, h)
	assert.NotContains(t, before, "user_recovery_codes",
		"the table must not exist before 000073, so what is found afterwards is what 000073 added")

	require.NoError(t, h.Migrator.Migrate(ctx, 73), "apply 000073")
	assertUserRecoveryCodesShape(t, h, "after apply")
	assertUserRecoveryCodesBehaviour(t, h, "after apply")
	assert.ElementsMatch(t, append(append([]string{}, before...), "user_recovery_codes"), listTables(t, h),
		"000073 must add the one table and no other")

	require.NoError(t, h.Migrator.Migrate(ctx, 72), "roll back to 72")
	assert.Equal(t, before, listTables(t, h), "the down migration must drop user_recovery_codes and nothing else")

	require.NoError(t, h.Migrator.Migrate(ctx, 73), "apply 000073 again")
	assertUserRecoveryCodesShape(t, h, "after down then up")
	assertUserRecoveryCodesBehaviour(t, h, "after down then up")
}

func assertUserRecoveryCodesShape(t *testing.T, h *isolatedDB, when string) {
	t.Helper()
	idType := map[data.Dialect]string{
		data.MySQL: "bigint unsigned", data.Postgres: "bigint", data.MSSQL: "bigint", data.SQLite: "INTEGER",
	}
	timeType := map[data.Dialect]string{
		data.MySQL: "datetime(6)", data.Postgres: "timestamp(6) without time zone", data.MSSQL: "datetime2(6)", data.SQLite: "DATETIME",
	}
	hashType := map[data.Dialect]string{
		data.MySQL: "varchar(64)", data.Postgres: "character varying(64)", data.MSSQL: "nvarchar(64)", data.SQLite: "TEXT",
	}
	// The collation every hash column carries on each engine (#283): case-sensitive on the two
	// engines whose default is not, and the engines' own byte-wise default on the other two.
	hashCollation := map[data.Dialect]string{
		data.MySQL: "utf8mb4_0900_as_cs", data.Postgres: "default",
		data.MSSQL: "Latin1_General_100_CS_AS_KS_WS_SC_UTF8", data.SQLite: "BINARY",
	}
	engine := dbType()

	shape := dumpTable(t, h, "user_recovery_codes")
	assert.Lenf(t, shape.Columns, 5, "id, user_id, code_hash, created_at and used_at %s", when)

	id := shape.column(t, "id")
	assert.Equalf(t, idType[engine], id.Type, "id's type %s", when)
	assert.Truef(t, id.Generated, "id is generated %s", when)

	userId := shape.column(t, "user_id")
	assert.Equalf(t, idType[engine], userId.Type, "user_id has the type of the id it names %s", when)
	assert.Falsef(t, userId.Nullable, "user_id is NOT NULL %s", when)

	codeHash := shape.column(t, "code_hash")
	assert.Equalf(t, hashType[engine], codeHash.Type, "code_hash holds a hex SHA-256 %s", when)
	assert.Falsef(t, codeHash.Nullable, "code_hash is NOT NULL %s", when)
	assert.Equalf(t, hashCollation[engine], codeHash.Collation, "code_hash compares case-sensitively %s", when)

	createdAt := shape.column(t, "created_at")
	assert.Equalf(t, timeType[engine], createdAt.Type, "created_at keeps the microseconds Go writes %s", when)
	assert.Falsef(t, createdAt.Nullable, "created_at is NOT NULL %s", when)

	usedAt := shape.column(t, "used_at")
	assert.Equalf(t, timeType[engine], usedAt.Type, "used_at keeps the microseconds Go writes %s", when)
	assert.Truef(t, usedAt.Nullable, "used_at is empty while the code is unused %s", when)

	fk := shape.foreignKey(t, "user_id")
	assert.Equalf(t, "users", fk.RefTable, "user_id references users %s", when)
	assert.Equalf(t, "id", fk.RefColumn, "by id %s", when)
	assert.Equalf(t, "CASCADE", fk.OnDelete, "deleting the user removes their codes %s", when)
	assert.Lenf(t, shape.ForeignKeys, 1, "the one foreign key %s", when)

	pair := shape.index("idx_user_recovery_codes_user_code_hash")
	require.Truef(t, pair.Exists, "the pair's unique index %s; indexes read: %v", when, shape.Indexes)
	assert.Truef(t, pair.Unique, "a code appears once in a user's set %s", when)
	assert.Equalf(t, []string{"user_id", "code_hash"}, pair.Columns, "over the pair, user first %s", when)
	assert.NotEqualf(t, schemadump.OriginPrimaryKey, pair.Origin, "and it is not the key %s", when)
}

// assertUserRecoveryCodesBehaviour holds the key, the NOT NULL columns and the cascade to what they
// do. The user is written through the isolated handle's own data layer, which the database accepts
// with the head-only users columns scaffolded on; the codes and the deletion are plain SQL on the table under test. Literals rather than
// placeholders because the four dialects disagree on placeholder syntax, and every value here is
// test-controlled.
func assertUserRecoveryCodesBehaviour(t *testing.T, h *isolatedDB, when string) {
	t.Helper()
	ctx := context.Background()
	exec := func(query string, args ...any) error {
		_, err := h.SQL.ExecContext(ctx, fmt.Sprintf(query, args...))
		return err
	}
	user := createTestUserOn(t, h.DB)
	count := func() int64 {
		var n int64
		require.NoError(t, h.SQL.QueryRowContext(ctx, fmt.Sprintf(
			"SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = %d", user.Id)).Scan(&n))
		return n
	}
	now := "'2026-10-31 12:00:00'"

	insert := "INSERT INTO user_recovery_codes (user_id, code_hash, created_at) VALUES (%d, '%s', %s)"
	hash := "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00"
	require.NoErrorf(t, exec(insert, user.Id, hash, now), "the first code is accepted %s", when)
	require.Errorf(t, exec(insert, user.Id, hash, now), "the same code twice in one set is refused by the key %s", when)
	require.NoErrorf(t, exec(insert, user.Id, "C0FFEE00C0FFEE00C0FFEE00C0FFEE00C0FFEE00C0FFEE00C0FFEE00C0FFEE00", now),
		"the key compares case-sensitively %s", when)
	assert.Equalf(t, int64(2), count(), "and the refused one wrote nothing %s", when)
	require.Errorf(t, exec(insert, user.Id+1_000_000, hash, now), "a code of no user is refused %s", when)
	require.Errorf(t, exec("INSERT INTO user_recovery_codes (user_id, code_hash) VALUES (%d, '%s')", user.Id, "ab"),
		"a code with no created_at is refused %s", when)

	require.NoError(t, exec("DELETE FROM users WHERE id = %d", user.Id))
	assert.Equalf(t, int64(0), count(), "deleting the user removed their codes %s", when)
}
