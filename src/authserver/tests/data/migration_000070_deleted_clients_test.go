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

// Migration 000070 (#676 decision 6) creates deleted_clients on all four engines. The golden files
// record the result of the migration and so cannot say WHY each column is what it is; this holds the
// migration to the claims its comments make, against an ISOLATED database of the configured dialect
// (see migration_testdb_helper_test.go).
//
//   - client_identifier is the table's primary key and is pinned case-sensitive, 40 wide as
//     clients.client_identifier is: one row per identifier, while an identifier differing only by
//     case is another client's;
//   - deleted_at is a microsecond datetime, NOT NULL;
//   - there is no foreign key and no other index, and nothing else in the schema changes; the down
//     migration drops the table it created.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000070_DeletedClients
func TestMigration000070_DeletedClients(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(ctx, 69), "migrate to 69")
	before := listTables(t, h)
	assert.NotContains(t, before, "deleted_clients",
		"the table must not exist before 000070, so what is found afterwards is what 000070 added")

	require.NoError(t, h.Migrator.Migrate(ctx, 70), "apply 000070")
	assertDeletedClientsShape(t, h, "after apply")
	assertDeletedClientsKey(t, h, "after apply")
	assert.ElementsMatch(t, append(append([]string{}, before...), "deleted_clients"), listTables(t, h),
		"000070 must add the one table and no other")

	require.NoError(t, h.Migrator.Migrate(ctx, 69), "roll back to 69")
	assert.Equal(t, before, listTables(t, h), "the down migration must drop deleted_clients and nothing else")

	require.NoError(t, h.Migrator.Migrate(ctx, 70), "apply 000070 again")
	assertDeletedClientsShape(t, h, "after down then up")
	assertDeletedClientsKey(t, h, "after down then up")
}

// assertDeletedClientsShape holds the table to the shape the migration's comments promise.
func assertDeletedClientsShape(t *testing.T, h *isolatedDB, when string) {
	t.Helper()

	stringCollation := map[data.Dialect]string{
		data.MySQL:    "utf8mb4_0900_as_cs",
		data.MSSQL:    "Latin1_General_100_CS_AS_KS_WS_SC_UTF8",
		data.Postgres: "default",
		data.SQLite:   "BINARY",
	}
	identifierType := map[data.Dialect]string{
		data.MySQL: "varchar(40)", data.Postgres: "character varying(40)", data.MSSQL: "nvarchar(40)", data.SQLite: "TEXT",
	}
	deletedAtType := map[data.Dialect]string{
		data.MySQL: "datetime(6)", data.Postgres: "timestamp(6) without time zone", data.MSSQL: "datetime2(6)", data.SQLite: "DATETIME",
	}
	engine := dbType()

	shape := dumpTable(t, h, "deleted_clients")

	identifier := shape.column(t, "client_identifier")
	assert.Equalf(t, identifierType[engine], identifier.Type, "client_identifier's type %s", when)
	assert.Falsef(t, identifier.Nullable, "client_identifier is NOT NULL %s", when)
	assert.Equalf(t, stringCollation[engine], identifier.Collation,
		"client_identifier's effective collation is the case-sensitive one %s", when)

	deletedAt := shape.column(t, "deleted_at")
	assert.Equalf(t, deletedAtType[engine], deletedAt.Type, "deleted_at keeps the microseconds Go writes %s", when)
	assert.Falsef(t, deletedAt.Nullable, "deleted_at is NOT NULL %s", when)

	assert.Lenf(t, shape.Columns, 2, "the two columns and no more %s", when)
	assert.Emptyf(t, shape.ForeignKeys, "the client it names is gone %s", when)

	require.Lenf(t, shape.Indexes, 1, "the primary key alone %s; indexes read: %v", when, shape.Indexes)
	assert.Equalf(t, schemadump.OriginPrimaryKey, shape.Indexes[0].Origin, "the index is the primary key %s", when)
	assert.Truef(t, shape.Indexes[0].Unique, "and the key is unique %s", when)
	assert.Equalf(t, []string{"client_identifier"}, shape.Indexes[0].Columns, "over the identifier alone %s", when)
}

// assertDeletedClientsKey holds the key to what it does: a second row of one identifier is refused,
// where another identifier, and the same one in another case, is accepted. The table is empty on
// entry, both times this is called.
func assertDeletedClientsKey(t *testing.T, h *isolatedDB, when string) {
	t.Helper()
	ctx := context.Background()

	insert := func(identifier string) error {
		_, err := h.SQL.ExecContext(ctx, fmt.Sprintf(
			"INSERT INTO deleted_clients (client_identifier, deleted_at) VALUES ('%s', '2026-01-02 03:04:05')", identifier))
		return err
	}
	count := func() int {
		var n int
		require.NoError(t, h.SQL.QueryRowContext(ctx, "SELECT COUNT(*) FROM deleted_clients").Scan(&n))
		return n
	}

	identifier := "client-" + strings.ToLower(fake.LetterN(12))
	require.Zerof(t, count(), "the table starts empty %s", when)

	require.NoErrorf(t, insert(identifier), "the first deletion of an identifier is accepted %s", when)
	require.Errorf(t, insert(identifier), "a second row of the same identifier is refused by the key %s", when)
	assert.Equalf(t, 1, count(), "and writes nothing %s", when)

	assert.NoErrorf(t, insert("client-"+strings.ToLower(fake.LetterN(12))), "another identifier is accepted %s", when)
	assert.NoErrorf(t, insert(strings.ToUpper(identifier)),
		"and so is the same identifier in another case: the key is case-sensitive %s", when)
	assert.Equalf(t, 3, count(), "three identifiers, three rows %s", when)

	_, err := h.SQL.ExecContext(ctx, fmt.Sprintf(
		"INSERT INTO deleted_clients (client_identifier, deleted_at) VALUES ('client-%s', NULL)", strings.ToLower(fake.LetterN(12))))
	require.Errorf(t, err, "a row with no deletion time is refused: deleted_at is NOT NULL %s", when)

	_, err = h.SQL.ExecContext(ctx, "DELETE FROM deleted_clients")
	require.NoErrorf(t, err, "empty the table again %s", when)
}
