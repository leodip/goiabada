package datatests

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/schemadump"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Migration 000071 (#147 decision 2) creates post_logout_redirect_uris on all four engines, a
// client's sign-out redirect URIs, mirroring redirect_uris exactly. This holds the migration to the
// claims its comments make, against an ISOLATED database of the configured dialect (see
// migration_testdb_helper_test.go):
//
//   - id, created_at, uri and client_id, with redirect_uris' types, its 2048-wide uri and its
//     case-sensitive collation;
//   - client_id NOT NULL, its foreign key cascading from clients;
//   - the same indexes as redirect_uris, and no unique one: duplicates are refused by the list save;
//   - nothing else in the schema changes, and the down migration drops the table it created.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000071_PostLogoutRedirectURIs
func TestMigration000071_PostLogoutRedirectURIs(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(ctx, 70), "migrate to 70")
	before := listTables(t, h)
	assert.NotContains(t, before, "post_logout_redirect_uris",
		"the table must not exist before 000071, so what is found afterwards is what 000071 added")
	redirectURIs := dumpTable(t, h, "redirect_uris")

	require.NoError(t, h.Migrator.Migrate(ctx, 71), "apply 000071")
	assertPostLogoutRedirectURIsShape(t, h, redirectURIs, "after apply")
	assertPostLogoutRedirectURIsBehaviour(t, h, "after apply")
	assert.ElementsMatch(t, append(append([]string{}, before...), "post_logout_redirect_uris"), listTables(t, h),
		"000071 must add the one table and no other")
	assert.Equal(t, redirectURIs, dumpTable(t, h, "redirect_uris"), "000071 leaves redirect_uris as it was")

	require.NoError(t, h.Migrator.Migrate(ctx, 70), "roll back to 70")
	assert.Equal(t, before, listTables(t, h), "the down migration must drop post_logout_redirect_uris and nothing else")

	require.NoError(t, h.Migrator.Migrate(ctx, 71), "apply 000071 again")
	assertPostLogoutRedirectURIsShape(t, h, redirectURIs, "after down then up")
	assertPostLogoutRedirectURIsBehaviour(t, h, "after down then up")
}

func assertPostLogoutRedirectURIsShape(t *testing.T, h *isolatedDB, redirectURIs tableShape, when string) {
	t.Helper()
	idType := map[data.Dialect]string{
		data.MySQL: "bigint unsigned", data.Postgres: "bigint", data.MSSQL: "bigint", data.SQLite: "INTEGER",
	}
	createdAtType := map[data.Dialect]string{
		data.MySQL: "datetime(6)", data.Postgres: "timestamp(6) without time zone", data.MSSQL: "datetime2(6)", data.SQLite: "DATETIME",
	}
	uriType := map[data.Dialect]string{
		data.MySQL: "varchar(2048)", data.Postgres: "character varying(2048)", data.MSSQL: "nvarchar(2048)", data.SQLite: "TEXT",
	}
	uriCollation := map[data.Dialect]string{
		data.MySQL: "utf8mb4_0900_as_cs", data.MSSQL: "Latin1_General_100_CS_AS_KS_WS_SC_UTF8", data.Postgres: "default", data.SQLite: "BINARY",
	}
	engine := dbType()

	shape := dumpTable(t, h, "post_logout_redirect_uris")
	assert.Lenf(t, shape.Columns, 4, "id, created_at, uri and client_id %s", when)

	id := shape.column(t, "id")
	assert.Equalf(t, idType[engine], id.Type, "id's type %s", when)
	assert.Truef(t, id.Generated, "id is generated %s", when)

	createdAt := shape.column(t, "created_at")
	assert.Equalf(t, createdAtType[engine], createdAt.Type, "created_at keeps the microseconds Go writes %s", when)
	assert.Truef(t, createdAt.Nullable, "created_at is nullable, as redirect_uris' is %s", when)

	uri := shape.column(t, "uri")
	assert.Equalf(t, uriType[engine], uri.Type, "uri is as wide as redirect_uris.uri %s", when)
	assert.Falsef(t, uri.Nullable, "uri is NOT NULL %s", when)
	assert.Equalf(t, uriCollation[engine], uri.Collation, "uri compares case-sensitively %s", when)

	clientId := shape.column(t, "client_id")
	assert.Equalf(t, idType[engine], clientId.Type, "client_id has the type of the id it names %s", when)
	assert.Falsef(t, clientId.Nullable, "client_id is NOT NULL %s", when)

	fk := shape.foreignKey(t, "client_id")
	assert.Equalf(t, "clients", fk.RefTable, "client_id references clients %s", when)
	assert.Equalf(t, "id", fk.RefColumn, "by id %s", when)
	assert.Equalf(t, "CASCADE", fk.OnDelete, "deleting the client removes its sign-out redirect URIs %s", when)
	assert.Lenf(t, shape.ForeignKeys, 1, "the one foreign key %s", when)

	for _, index := range shape.Indexes {
		assert.Falsef(t, index.Unique && index.Origin != schemadump.OriginPrimaryKey,
			"no unique index but the key: a duplicate is the list save's to refuse %s; indexes read: %v", when, shape.Indexes)
	}

	// The mirror: every column and foreign key reads as redirect_uris' does, and the indexes cover the
	// same columns with the same origins, whatever each engine names them.
	assert.Equalf(t, columnsOutside(redirectURIs, "redirect_uris"), columnsOutside(shape, "post_logout_redirect_uris"),
		"the columns mirror redirect_uris' %s", when)
	assert.Equalf(t, redirectURIs.ForeignKeys, shape.ForeignKeys, "the foreign key mirrors redirect_uris' %s", when)
	assert.Equalf(t, indexOutlines(redirectURIs), indexOutlines(shape), "the indexes mirror redirect_uris' %s", when)
}

// columnsOutside is a table's columns with its own name taken out of their defaults: PostgreSQL's id
// default names the table's sequence.
func columnsOutside(shape tableShape, table string) []schemadump.ColumnShape {
	columns := []schemadump.ColumnShape{}
	for _, column := range shape.Columns {
		column.Default = strings.ReplaceAll(column.Default, table, "<table>")
		columns = append(columns, column)
	}
	return columns
}

// indexOutlines is a table's indexes without their names, which differ by table.
func indexOutlines(shape tableShape) []string {
	outlines := []string{}
	for _, index := range shape.Indexes {
		outlines = append(outlines, fmt.Sprintf("columns=%v unique=%v origin=%s", index.Columns, index.Unique, index.Origin))
	}
	return outlines
}

// assertPostLogoutRedirectURIsBehaviour holds the table to what it does: a duplicate row is accepted,
// a row naming no client is refused, and deleting the client removes its rows. The client is seeded
// in SQL by seedClient, since the data layer writes every column the record carries at head; the
// rows are plain SQL on the table under test, with literals because the four dialects disagree on
// placeholder syntax and every value is test-controlled.
func assertPostLogoutRedirectURIsBehaviour(t *testing.T, h *isolatedDB, when string) {
	t.Helper()
	ctx := context.Background()
	exec := func(query string, args ...any) error {
		_, err := h.SQL.ExecContext(ctx, fmt.Sprintf(query, args...))
		return err
	}
	client := &record.Client{Id: seedClient(t, h, "signout-client-"+fake.LetterN(8))}
	count := func() int64 {
		var n int64
		require.NoError(t, h.SQL.QueryRowContext(ctx, fmt.Sprintf(
			"SELECT COUNT(*) FROM post_logout_redirect_uris WHERE client_id = %d", client.Id)).Scan(&n))
		return n
	}

	row := "INSERT INTO post_logout_redirect_uris (uri, client_id) VALUES ('https://app.example/bye', %d)"
	require.NoErrorf(t, exec(row, client.Id), "the first row is accepted %s", when)
	require.NoErrorf(t, exec(row, client.Id), "and so is a duplicate: no unique index %s", when)
	assert.Equalf(t, int64(2), count(), "two rows %s", when)
	require.Errorf(t, exec(row, client.Id+1_000_000), "a row naming no client is refused %s", when)

	require.NoError(t, exec("DELETE FROM clients WHERE id = %d", client.Id))
	assert.Equalf(t, int64(0), count(), "deleting the client removed its rows %s", when)
}
