package datatests

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// columns000052 are the five columns 000052 widens, by table, in the order its up file alters them.
var (
	tables000052  = []string{"codes", "refresh_tokens", "user_consents"}
	columns000052 = map[string][]string{
		"codes":          {"state", "nonce", "scope"},
		"refresh_tokens": {"scope"},
		"user_consents":  {"scope"},
	}
)

// skipWithout000052 skips on SQLite, which stores all five columns as TEXT and has no 000052.
func skipWithout000052(t *testing.T) {
	t.Helper()
	if dbType() == "" || dbType() == "sqlite" {
		t.Skip("sqlite stores these columns as TEXT and has no 000052")
	}
}

// varchar000052 is the engine's spelling of a string column of the given width, as the dumper
// reads it back.
func varchar000052(t *testing.T, width int) string {
	t.Helper()
	switch dbType() {
	case "mysql":
		return fmt.Sprintf("varchar(%d)", width)
	case "postgres":
		return fmt.Sprintf("character varying(%d)", width)
	case "mssql":
		return fmt.Sprintf("nvarchar(%d)", width)
	}
	require.FailNow(t, "no spelling for this engine", "%s", dbType())
	return ""
}

// dumpTables000052 reads the three tables 000052 alters.
func dumpTables000052(t *testing.T, h *isolatedDB) map[string]tableShape {
	t.Helper()
	shapes := map[string]tableShape{}
	for _, table := range tables000052 {
		shapes[table] = dumpTable(t, h, table)
	}
	return shapes
}

// widened000052 is what the tables must read once 000052 has run: the shapes before it with the
// five columns' types replaced and nothing else touched.
func widened000052(t *testing.T, before map[string]tableShape) map[string]tableShape {
	t.Helper()
	want := map[string]tableShape{}
	for table, shape := range before {
		shape.Columns = slices.Clone(shape.Columns)
		for i := range shape.Columns {
			if slices.Contains(columns000052[table], shape.Columns[i].Name) {
				shape.Columns[i].Type = varchar000052(t, 2048)
			}
		}
		want[table] = shape
	}
	return want
}

// TestMigration000052_WidensTheFiveColumnsAndNothingElse holds the migration to its claim (#437).
// ALTER COLUMN and MODIFY replace a column's whole definition, so a file that
// forgot to restate the collation pin or NOT NULL would widen the column and quietly change
// another thing about it; comparing the whole table shape before and after, with only the five
// types replaced, is what shows the restatement is complete. The golden files record the result of
// the migration and so cannot catch it.
//
// It then runs the up file a second time over the widened columns, which is what an operator does
// after clearing a dirty version (MySQL's DDL is not transactional, so a part-applied file is a
// real state), and steps down and up again. On one isolated database in that order, because
// creating an isolated database is the expensive part on SQL Server.
//
// Skipped on SQLite, which has no 000052.
func TestMigration000052_WidensTheFiveColumnsAndNothingElse(t *testing.T) {
	skipWithout000052(t)
	ctx := context.Background()
	h := newIsolatedDB(t)
	require.NoError(t, h.Migrator.Migrate(ctx, 51), "migrate to 51")

	before := dumpTables000052(t, h)
	for table, columns := range columns000052 {
		for _, column := range columns {
			require.Equalf(t, varchar000052(t, 512), before[table].column(t, column).Type,
				"%s.%s is 512 wide at 000051, so the comparison below observes a widening", table, column)
		}
	}

	require.NoError(t, h.Migrator.Migrate(ctx, 52), "migrate to 52")
	widened := dumpTables000052(t, h)
	want := widened000052(t, before)
	for _, table := range tables000052 {
		assert.Equalf(t, want[table], widened[table],
			"%s must differ from its 000051 shape in the widths of %v and nowhere else, "+
				"the collation, nullability, defaults, indexes and foreign keys included", table, columns000052[table])
	}

	// Running the file again over columns already 2048 wide completes without change.
	require.NoError(t, h.Migrator.Force(ctx, 51), "clear the version, as an operator does after a dirty run")
	require.NoError(t, h.Migrator.Migrate(ctx, 52), "the up file must run again over the widened columns")
	for _, table := range tables000052 {
		assert.Equalf(t, widened[table], dumpTable(t, h, table), "a second run of the up file must change nothing in %s", table)
	}

	// Down restores the 000051 shape exactly, the collation pin included, and up widens again.
	require.NoError(t, h.Migrator.Migrate(ctx, 51), "step down to 51")
	for _, table := range tables000052 {
		assert.Equalf(t, before[table], dumpTable(t, h, table), "the down file must restore %s exactly", table)
	}
	require.NoError(t, h.Migrator.Migrate(ctx, 52), "step up to 52 again")
	for _, table := range tables000052 {
		assert.Equalf(t, widened[table], dumpTable(t, h, table), "%s after down and up again", table)
	}
}

// TestMigration000052_UpRollsBackALateFailure holds SQL Server's 000052 to being atomic, for the
// reason 000049's case gives: the runner hands the file to one Exec and opens no transaction, so
// each ALTER COLUMN would autocommit on its own, and a failure on the last would leave the first
// four widened and the version dirty. The file opens its own transaction under SET XACT_ABORT ON.
//
// The other engines skip: MySQL has no transactional DDL, and its file says so and is idempotent
// instead, which the case above shows, and PostgreSQL runs a file in one statement batch.
//
// On its own isolated database, as 000049's is, because its first attempt ends dirty.
func TestMigration000052_UpRollsBackALateFailure(t *testing.T) {
	if dbType() != "mssql" {
		t.Skipf("%s has no transactional 000052 up file to roll back", dbType())
	}
	ctx := context.Background()
	h := newIsolatedDB(t)
	require.NoError(t, h.Migrator.Migrate(ctx, 51), "migrate to 51")

	// The failure, injected as a dependency the migration knows nothing about: a schema-bound view
	// over user_consents.scope, which SQL Server refuses to ALTER a column under (Msg 4922). On the
	// LAST column the file alters, deliberately, so the refusal lands after codes.state, codes.nonce,
	// codes.scope and refresh_tokens.scope have all been widened. A failure on the first statement
	// would pass against an unwrapped file too.
	const unmanagedView = "v_operators_own_000052"
	mustExec(t, h.SQL, "CREATE VIEW ["+unmanagedView+"] WITH SCHEMABINDING AS SELECT [scope] FROM [dbo].[user_consents]")

	before := dumpTables000052(t, h)

	err := h.Migrator.Migrate(ctx, 52)
	require.Error(t, err, "an ALTER COLUMN under a schema-bound view must fail")
	// Msg 4922 names the column: "ALTER TABLE ALTER COLUMN scope failed because one or more objects
	// access this column." Asserted because the failure has to be the one injected here; any other
	// error would prove the rollback of something else.
	assert.Containsf(t, strings.ToLower(err.Error()), "alter column scope",
		"the failure must be the injected one, on the last column the file alters: %v", err)

	for _, table := range tables000052 {
		assert.Equalf(t, before[table], dumpTable(t, h, table),
			"the failed up must leave %s exactly as it found it, including a column it had already widened before the failure", table)
	}

	// And the recovery works: resolve the dependency, clear the dirty version, run it again.
	mustExec(t, h.SQL, "DROP VIEW ["+unmanagedView+"]")
	require.NoError(t, h.Migrator.Force(ctx, 51),
		"clear the dirty version the deliberate failure left, which is the operator's own step")
	require.NoError(t, h.Migrator.Migrate(ctx, 52),
		"the retry must reach 52; if it does not, the first attempt left something it cannot redo")

	want := widened000052(t, before)
	for _, table := range tables000052 {
		assert.Equalf(t, want[table], dumpTable(t, h, table), "%s after the retry", table)
	}
}
