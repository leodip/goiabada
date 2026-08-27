package datatests

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// oidcClaimsDefaultConstraint000038 is the name the migration gives the default constraint
// it has to drop and recreate, lowercase df_<table>_<column> like the nine named default
// constraints mssqldb already carries.
const oidcClaimsDefaultConstraint000038 = "df_clients_include_open_id_connect_claims_in_id_token"

// nvarcharColumns000038 is the exact set of columns the migration retypes: table, column,
// the type the catalog reports before, the type it must report after, and whether the
// column is nullable. The nullability is recorded here because it must be UNCHANGED, which
// is the trap this migration is written around: ALTER COLUMN with no NULL or NOT NULL
// keyword makes the column nullable whatever it was.
var nvarcharColumns000038 = []struct {
	table    string
	column   string
	before   string
	after    string
	nullable bool
}{
	{"codes", "code_challenge", "varchar(256)", "nvarchar(256)", true},
	{"codes", "code_challenge_method", "varchar(10)", "nvarchar(10)", true},
	{"user_profile_pictures", "content_type", "varchar(64)", "nvarchar(64)", false},
	{"client_logos", "content_type", "varchar(64)", "nvarchar(64)", false},
	{"clients", "include_open_id_connect_claims_in_id_token", "varchar(10)", "nvarchar(10)", false},
}

// TestMigration000038_NvarcharColumns is goal 5 of #282 stated as a test: the five SQL
// Server columns declared VARCHAR become NVARCHAR, and the auto-named default constraint
// on clients.include_open_id_connect_claims_in_id_token is replaced by a named one. It
// runs against an ISOLATED database of the configured dialect (see
// migration_testdb_helper.go).
//
// SQL Server only. The other three engines have no non-Unicode string type to migrate away
// from: SQLite has one TEXT type, MySQL's tables are utf8mb4 throughout, and PostgreSQL's
// text is Unicode by definition. The migration file exists on mssql alone and Migrate
// refuses a target version the engine's source does not carry.
//
// The assertions, and why each is here:
//
//  1. The five columns' type changes and their NULLABILITY DOES NOT. Three of the five are
//     NOT NULL, and ALTER COLUMN written without the keyword would silently make them
//     nullable, trading one divergence for another that nothing else in the tree would
//     notice.
//  2. Everything else about the four affected tables is byte-identical, computed as a
//     difference over stage 1's dumps rather than as a hand-written list of what should
//     have stayed. That catches a column the migration dropped even when the test author
//     forgot the column existed, which is the property decision 5 exists for, applied here
//     to an ALTER rather than to a rebuild.
//  3. The seeded row's value survives. A shape dump cannot tell ALTER COLUMN apart from
//     DROP COLUMN followed by ADD COLUMN, and the second would silently blank the column
//     for every existing client.
//  4. The default constraint's NAME: auto-generated before (SQL Server's DF__ prefix),
//     the name above after. dumpTable deliberately carries no constraint name, and the
//     name is the entire reason a later migration can drop this constraint without
//     repeating the catalog lookup this one has to do.
//
// Run via: ./run-tests.sh --type data --db mssql --run TestMigration000038_NvarcharColumns
func TestMigration000038_NvarcharColumns(t *testing.T) {
	if dbType() != "mssql" {
		t.Skipf("SQL Server only: %s has no non-Unicode string type to migrate away from, so it has no 000038 file", dbType())
	}

	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(35), "migrate to 000035")

	clientId := seedClient000035(t, h, "mig38-client")
	setOidcClaimsSetting000038(t, h, clientId, "on")

	before := dumpAffectedTables000038(t, h)
	assertNvarcharColumnTypes000038(t, h, before, "at 000035", func(c int) string { return nvarcharColumns000038[c].before })
	assert.Truef(t, strings.HasPrefix(oidcClaimsConstraintName000038(t, h), "DF__"),
		"at 000035 the default constraint must still be the auto-generated one 000013 left; got %q",
		oidcClaimsConstraintName000038(t, h))

	require.NoError(t, h.Migrator.Migrate(38), "apply 000038")

	after := dumpAffectedTables000038(t, h)
	assertNvarcharColumnTypes000038(t, h, after, "after apply", func(c int) string { return nvarcharColumns000038[c].after })
	assertOnlyTheFiveTypesMoved000038(t, before, after, "after apply")
	assert.Equalf(t, "on", readOidcClaimsSetting000038(t, h, clientId),
		"after apply, the seeded client's setting must survive the retype")
	assert.Equal(t, oidcClaimsDefaultConstraint000038, oidcClaimsConstraintName000038(t, h),
		"after apply, the default constraint must carry the name a later migration can drop it by")

	require.NoError(t, h.Migrator.Migrate(35), "roll back 000038")

	down := dumpAffectedTables000038(t, h)
	assertNvarcharColumnTypes000038(t, h, down, "after roll back", func(c int) string { return nvarcharColumns000038[c].before })
	assertOnlyTheFiveTypesMoved000038(t, before, down, "after roll back")
	assert.Equalf(t, "on", readOidcClaimsSetting000038(t, h, clientId),
		"after roll back, the seeded client's setting must survive the retype")
	assert.Truef(t, strings.HasPrefix(oidcClaimsConstraintName000038(t, h), "DF__"),
		"the down migration must restore an UNNAMED default, so 000035 is the shape 000013 left")

	require.NoError(t, h.Migrator.Migrate(38), "re-apply 000038")

	reapplied := dumpAffectedTables000038(t, h)
	assertNvarcharColumnTypes000038(t, h, reapplied, "after down/up round trip", func(c int) string { return nvarcharColumns000038[c].after })
	assertOnlyTheFiveTypesMoved000038(t, before, reapplied, "after down/up round trip")
	assert.Equal(t, oidcClaimsDefaultConstraint000038, oidcClaimsConstraintName000038(t, h),
		"after the round trip, the default constraint must be named again")
}

// affectedTables000038 is the four tables the migration touches, in a fixed order so the
// before and after dumps line up.
var affectedTables000038 = []string{"client_logos", "clients", "codes", "user_profile_pictures"}

func dumpAffectedTables000038(t *testing.T, h *isolatedDB) map[string]tableShape {
	t.Helper()

	shapes := map[string]tableShape{}
	for _, table := range affectedTables000038 {
		shapes[table] = dumpTable(t, h, table)
	}
	return shapes
}

// assertNvarcharColumnTypes000038 checks each of the five columns against the type want
// returns for it, and checks its nullability against the fixed value in the table, which
// never changes in either direction.
func assertNvarcharColumnTypes000038(t *testing.T, h *isolatedDB, shapes map[string]tableShape, phase string, want func(int) string) {
	t.Helper()

	for i, c := range nvarcharColumns000038 {
		got := shapes[c.table].column(t, c.column)
		assert.Equalf(t, want(i), got.Type, "[%s] %s.%s", phase, c.table, c.column)
		assert.Equalf(t, c.nullable, got.Nullable,
			"[%s] %s.%s changed nullability: ALTER COLUMN written without an explicit NULL/NOT NULL keyword makes a column nullable",
			phase, c.table, c.column)
	}
}

// assertOnlyTheFiveTypesMoved000038 is the exhaustive half. It compares the before and
// after dumps of all four tables and requires that the ONLY difference anywhere is the
// Type of the five listed columns: same columns, same nullability, same defaults, same
// indexes, same foreign keys.
func assertOnlyTheFiveTypesMoved000038(t *testing.T, before, after map[string]tableShape, phase string) {
	t.Helper()

	retyped := map[string]bool{}
	for _, c := range nvarcharColumns000038 {
		retyped[c.table+"."+c.column] = true
	}

	for _, table := range affectedTables000038 {
		b, a := before[table], after[table]

		require.Lenf(t, a.Columns, len(b.Columns),
			"[%s] %s gained or lost a column", phase, table)
		for i := range b.Columns {
			bc, ac := b.Columns[i], a.Columns[i]
			require.Equalf(t, bc.Name, ac.Name, "[%s] %s column %d", phase, table, i)

			if !retyped[table+"."+bc.Name] {
				assert.Equalf(t, bc.Type, ac.Type,
					"[%s] %s.%s is not one of the five columns 000038 retypes and must not move",
					phase, table, bc.Name)
			}
			assert.Equalf(t, bc.Nullable, ac.Nullable, "[%s] %s.%s nullability", phase, table, bc.Name)
			assert.Equalf(t, bc.Default, ac.Default, "[%s] %s.%s default", phase, table, bc.Name)
		}

		assert.Equalf(t, b.Indexes, a.Indexes, "[%s] %s indexes", phase, table)
		assert.Equalf(t, b.ForeignKeys, a.ForeignKeys, "[%s] %s foreign keys", phase, table)
	}
}

// oidcClaimsConstraintName000038 reads the name of the default constraint on
// clients.include_open_id_connect_claims_in_id_token. dumpTable carries the default's
// definition and deliberately not its name, so this is read separately; the name is what
// makes the constraint droppable by a later migration.
func oidcClaimsConstraintName000038(t *testing.T, h *isolatedDB) string {
	t.Helper()

	var name string
	require.NoError(t, h.SQL.QueryRow(
		`SELECT dc.name FROM sys.default_constraints dc
		   JOIN sys.columns c ON c.object_id = dc.parent_object_id AND c.column_id = dc.parent_column_id
		  WHERE dc.parent_object_id = OBJECT_ID('dbo.clients')
		    AND c.name = 'include_open_id_connect_claims_in_id_token'`).Scan(&name),
		"read the default constraint name on clients.include_open_id_connect_claims_in_id_token")
	return name
}

func setOidcClaimsSetting000038(t *testing.T, h *isolatedDB, clientId int64, value string) {
	t.Helper()

	_, err := h.SQL.Exec(fmt.Sprintf(
		`UPDATE clients SET include_open_id_connect_claims_in_id_token = '%s' WHERE id = %d`,
		value, clientId))
	require.NoError(t, err, "seed the client's OIDC claims setting")
}

func readOidcClaimsSetting000038(t *testing.T, h *isolatedDB, clientId int64) string {
	t.Helper()

	var value string
	require.NoError(t, h.SQL.QueryRow(fmt.Sprintf(
		`SELECT include_open_id_connect_claims_in_id_token FROM clients WHERE id = %d`, clientId)).Scan(&value),
		"read back the client's OIDC claims setting")
	return value
}
