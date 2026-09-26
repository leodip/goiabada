package datatests

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tables000049 are the three tables 000049 alters, in the order its up file alters them.
var tables000049 = []string{"redirect_uris", "codes", "web_origins"}

// TestMigration000049_UpRollsBackALateFailure holds SQL Server's 000049 to being atomic. The
// runner hands a SQL Server file to one Exec and opens no transaction, so each ALTER COLUMN would
// autocommit on its own: a failure on the last one would leave the first two widened and the
// version dirty, with nothing in the schema saying which statements ran. The file opens its own
// transaction under SET XACT_ABORT ON, as 000040 does, and this is the case that proves it (#428).
//
// The other engines skip: MySQL has no transactional DDL, and its file says so and is idempotent
// instead, and SQLite has no 000049.
//
// On its own isolated database, as TestMigration000040_UpRollsBackALateFailure is, because its
// first attempt ends dirty.
func TestMigration000049_UpRollsBackALateFailure(t *testing.T) {
	if dbType() != "mssql" {
		t.Skipf("%s has no transactional 000049 up file to roll back", dbType())
	}

	h := newIsolatedDB(t)
	require.NoError(t, h.Migrator.Migrate(context.Background(), 48), "migrate to 48")

	// The failure, injected as a dependency the migration knows nothing about: a schema-bound view
	// over web_origins.origin, which SQL Server refuses to ALTER a column under (Msg 5074). Measured
	// before this case was written: a CHECK constraint and a plain or unique index on the column
	// both let a widening through, so neither could stand in. On web_origins.origin deliberately,
	// because it is the LAST column the file alters, so the refusal lands after redirect_uris.uri
	// and codes.redirect_uri have both been widened. A failure on the first statement would pass
	// against an unwrapped file too.
	const unmanagedView = "v_operators_own_000049"
	mustExec(t, h.SQL, "CREATE VIEW ["+unmanagedView+"] WITH SCHEMABINDING AS SELECT [origin] FROM [dbo].[web_origins]")

	before := map[string]tableShape{}
	for _, table := range tables000049 {
		before[table] = dumpTable(t, h, table)
	}

	err := h.Migrator.Migrate(context.Background(), 49)
	require.Error(t, err, "an ALTER COLUMN under a schema-bound view must fail")
	// Msg 4922 names the column: "ALTER TABLE ALTER COLUMN origin failed because one or more
	// objects access this column." Asserted because the failure has to be the one injected here;
	// any other error would prove the rollback of something else.
	assert.Containsf(t, strings.ToLower(err.Error()), "alter column origin",
		"the failure must be the injected one, on the last column the file alters: %v", err)

	for _, table := range tables000049 {
		assert.Equalf(t, before[table], dumpTable(t, h, table),
			"the failed up must leave %s exactly as it found it, including a column it had already widened before the failure", table)
	}

	// And the recovery works: resolve the dependency, clear the dirty version, run it again.
	mustExec(t, h.SQL, "DROP VIEW ["+unmanagedView+"]")
	require.NoError(t, h.Migrator.Force(context.Background(), 48),
		"clear the dirty version the deliberate failure left, which is the operator's own step")
	require.NoError(t, h.Migrator.Migrate(context.Background(), 49),
		"the retry must reach 49; if it does not, the first attempt left something it cannot redo")

	assert.Equal(t, "nvarchar(2048)", dumpTable(t, h, "redirect_uris").column(t, "uri").Type)
	assert.Equal(t, "nvarchar(2048)", dumpTable(t, h, "codes").column(t, "redirect_uri").Type)
	webOrigins := dumpTable(t, h, "web_origins")
	assert.Equal(t, "nvarchar(267)", webOrigins.column(t, "origin").Type)
	index := webOrigins.index("idx_web_origins_origin_client")
	assert.True(t, index.Exists && index.Unique, "the unique index on (origin, client_id) must survive the widening")
}
