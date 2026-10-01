package datatests

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Migration 000053 (#246, #437) creates authorize_requests on all four engines. The golden files
// record the result of the migration and so cannot say WHY each column is what it is; this holds
// the migration to the claims its comments make, against an ISOLATED database of the configured
// dialect (see migration_testdb_helper_test.go).
//
//   - handle_hash and request_form are pinned case-sensitive on the engines whose default is not,
//     because `=` over a handle's digest must mean what it says, and the pin is spelled per table
//     on MySQL and per column on SQL Server;
//   - request_form is the engine's largest text type, so it holds a form past MySQL's 65,535-byte
//     TEXT ceiling, which the merged query and body of a request can exceed;
//   - handle_hash is the table's unique lookup key and expires_at has an index of its own for the
//     sweep;
//   - nothing else in the schema changes, and the down migration drops the table it created.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000053_AuthorizeRequests
func TestMigration000053_AuthorizeRequests(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(ctx, 51), "migrate to 51")
	before := listTables(t, h)
	assert.NotContains(t, before, "authorize_requests",
		"the table must not exist at 000051, so what is found afterwards is what 000053 added")

	require.NoError(t, h.Migrator.Migrate(ctx, 53), "apply 000053")
	assertAuthorizeRequestsShape(t, h, "after apply")
	assert.ElementsMatch(t, append(append([]string{}, before...), "authorize_requests"), listTables(t, h),
		"000053 must add the one table and no other")

	// Down, then up again. SQL Server's and MySQL's DDL behave differently in both directions.
	require.NoError(t, h.Migrator.Migrate(ctx, 51), "roll back to 51")
	assert.Equal(t, before, listTables(t, h), "the down migration must drop authorize_requests and nothing else")

	require.NoError(t, h.Migrator.Migrate(ctx, 53), "apply 000053 again")
	assertAuthorizeRequestsShape(t, h, "after down then up")
}

// assertAuthorizeRequestsShape holds the table to the shape the migration's comments promise.
func assertAuthorizeRequestsShape(t *testing.T, h *isolatedDB, when string) {
	t.Helper()

	// The pin each engine's catalog reports for a string column: MySQL and SQL Server spell the
	// case-sensitive collation; PostgreSQL and SQLite compare byte-wise by default and report it.
	stringCollation := map[data.Dialect]string{
		data.MySQL:    "utf8mb4_0900_as_cs",
		data.MSSQL:    "Latin1_General_100_CS_AS_KS_WS_SC_UTF8",
		data.Postgres: "default",
		data.SQLite:   "BINARY",
	}
	handleHashType := map[data.Dialect]string{
		data.MySQL: "varchar(64)", data.Postgres: "character varying(64)", data.MSSQL: "nvarchar(64)", data.SQLite: "TEXT",
	}
	// The unbounded type of each engine. MySQL's TEXT stops at 65,535 bytes, so it is LONGTEXT.
	requestFormType := map[data.Dialect]string{
		data.MySQL: "longtext", data.Postgres: "text", data.MSSQL: "nvarchar(max)", data.SQLite: "TEXT",
	}
	engine := dbType()

	shape := dumpTable(t, h, "authorize_requests")

	handleHash := shape.column(t, "handle_hash")
	assert.Equalf(t, handleHashType[engine], handleHash.Type, "handle_hash's type %s", when)
	assert.Falsef(t, handleHash.Nullable, "handle_hash is NOT NULL %s", when)
	// The isolated database is created at the case-sensitive collation, so a column that lost its pin
	// would still read as pinned here: TestMigrationSource_TheFourCommittedDirectories holds the
	// pin's presence, and this holds that the column ends up case-sensitive.
	assert.Equalf(t, stringCollation[engine], handleHash.Collation,
		"handle_hash's effective collation is the case-sensitive one %s", when)

	requestForm := shape.column(t, "request_form")
	assert.Equalf(t, requestFormType[engine], requestForm.Type,
		"request_form is the engine's unbounded text type %s: the merged query and body can pass 65,535 bytes", when)
	assert.Falsef(t, requestForm.Nullable, "request_form is NOT NULL %s", when)
	assert.Equalf(t, stringCollation[engine], requestForm.Collation, "request_form is pinned like handle_hash %s", when)

	assert.Falsef(t, shape.column(t, "expires_at").Nullable, "expires_at is NOT NULL %s", when)
	assert.Truef(t, shape.column(t, "created_at").Nullable, "created_at, as on every table here %s", when)
	assert.Truef(t, shape.column(t, "updated_at").Nullable, "updated_at, as on every table here %s", when)
	assert.Lenf(t, shape.Columns, 6, "the six columns and no more %s", when)
	assert.Emptyf(t, shape.ForeignKeys, "a parked request belongs to no row of another table %s", when)

	lookup := describeIndex(t, h, "authorize_requests", "idx_authorize_requests_handle_hash")
	assert.Truef(t, lookup.Exists, "the handle lookup index exists %s", when)
	assert.Truef(t, lookup.Unique, "and is unique, or one link could name two requests %s", when)
	assert.Equalf(t, []string{"handle_hash"}, lookup.Columns, "over the digest alone %s", when)

	sweep := describeIndex(t, h, "authorize_requests", "idx_authorize_requests_expires_at")
	assert.Truef(t, sweep.Exists, "the sweep's index exists %s", when)
	assert.Falsef(t, sweep.Unique, "and is not unique: many requests expire at one instant %s", when)
	assert.Equalf(t, []string{"expires_at"}, sweep.Columns, "over expires_at alone %s", when)
}
