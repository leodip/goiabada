package datatests

import (
	"fmt"
	"testing"

	"github.com/leodip/goiabada/core/data/migrator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigrationDowns_DropOnlyTheirOwnDefaultConstraints holds the eight SQL Server downs that
// have to discover a constraint by catalog lookup to the object they are actually reverting.
//
// Why a lookup exists at all. Migrations 000004 to 000018 added columns with UNNAMED DEFAULT
// constraints, so each one carries a per-database generated name and there is nothing for a DROP
// CONSTRAINT to name. SQL Server refuses to drop a column while a default depends on it, so the
// down has to read sys.default_constraints to find the name before it can drop the column. The
// rule that every added default be named arrived with 000040, after these files.
//
// What this test is about. sys.default_constraints spans the WHOLE database, not one schema, and
// the statement those downs build is schema-qualified. So a discovery filtered on a table NAME
// matches a same-named table in any other schema on the database and then drops that table's
// defaults too, silently, in the middle of a rollback the operator asked for. Nothing else in the
// repository can see this: every test database holds exactly one schema, so a name-only filter and
// an object-identity filter select the same rows and the chain round trip passes either way (#268).
//
// The fixture is therefore the missing schema. It builds a companion table for every table those
// eight downs touch, in a schema of its own, each carrying an unnamed default on every column
// name the discovery queries look for, and then rolls the application all the way down. The
// companion defaults must all still be there afterwards.
//
// SQL Server only: no other engine needs the lookup, because the other three drop a column with
// its default attached.
//
// Run via: ./run-tests.sh --type data --db mssql --run TestMigrationDowns
func TestMigrationDowns_DropOnlyTheirOwnDefaultConstraints(t *testing.T) {
	if dbType() != "mssql" {
		t.Skipf("%s drops a column with its default attached, so no down there discovers a constraint by catalog lookup", dbType())
	}

	h := newIsolatedDB(t)

	// Up to the highest version whose down carries a discovery query. Going further would work
	// too and costs the rest of the chain for nothing.
	const highestDiscoveringDown = 18
	require.NoErrorf(t, h.Migrator.Migrate(highestDiscoveringDown),
		"apply the chain up to %06d on %s", highestDiscoveringDown, dbType())

	seedCompanionSchema(t, h)

	// All the way down, which runs every one of the eight.
	require.NoErrorf(t, h.Migrator.Migrate(migrator.NilVersion),
		"roll the whole chain back on %s", dbType())

	for _, c := range companionDefaults {
		assert.Truef(t, companionDefaultExists(t, h, c.table, c.column),
			"the default on %s.%s.%s belongs to nobody in this repository and must survive a rollback: "+
				"a down that discovers its own constraint by table NAME drops this one too",
			companionSchema, c.table, c.column)
	}
}

// companionSchema is a schema Goiabada does not own and never writes to. The name says what it is
// for, so a database left behind by a failed run reads as a fixture rather than as something an
// operator has to identify.
const companionSchema = "not_goiabada"

// companionColumn is one column an mssql down's discovery query looks for, and the type to give
// the companion so a DEFAULT can sit on it.
type companionColumn struct {
	table  string
	column string
	sqlDef string
}

// companionDefaults is every (table, column) pair the eight discovery queries name, read off the
// down files themselves. Written out here rather than derived, deliberately: this list is the
// independent statement of what those queries must NOT match, and deriving it from the same SQL
// would make it agree with a broken query by construction.
var companionDefaults = []companionColumn{
	// 000004
	{"settings", "dynamic_client_registration_enabled", "BIT NOT NULL"},
	// 000006
	{"settings", "pkce_required", "BIT NOT NULL"},
	{"clients", "pkce_required", "BIT NOT NULL"},
	// 000009
	{"settings", "implicit_flow_enabled", "BIT NOT NULL"},
	{"clients", "implicit_grant_enabled", "BIT NOT NULL"},
	// 000010
	{"clients", "resource_owner_password_credentials_enabled", "BIT NOT NULL"},
	{"settings", "resource_owner_password_credentials_enabled", "BIT NOT NULL"},
	// 000013
	{"clients", "include_open_id_connect_claims_in_id_token", "BIT NOT NULL"},
	{"settings", "include_open_id_connect_claims_in_id_token", "BIT NOT NULL"},
	// 000016
	{"clients", "website_url", "NVARCHAR(255) NOT NULL"},
	// 000017
	{"clients", "display_name", "NVARCHAR(255) NOT NULL"},
	{"clients", "show_logo", "BIT NOT NULL"},
	{"clients", "show_display_name", "BIT NOT NULL"},
	{"clients", "show_description", "BIT NOT NULL"},
	{"clients", "show_website_url", "BIT NOT NULL"},
	// 000018
	{"settings", "audit_logs_in_console_enabled", "BIT NOT NULL"},
	{"settings", "audit_logs_in_database_enabled", "BIT NOT NULL"},
	{"settings", "audit_log_retention_days", "INT NOT NULL"},
}

// seedCompanionSchema builds the tables the discovery queries would match on name alone, in a
// schema of their own, with the defaults UNNAMED so they are found exactly the way the
// application's own were.
func seedCompanionSchema(t *testing.T, h *isolatedDB) {
	t.Helper()

	// CREATE SCHEMA has to be the first statement in its batch, so it goes on its own.
	mustExec(t, h.SQL, fmt.Sprintf("CREATE SCHEMA %s", companionSchema))

	byTable := map[string][]companionColumn{}
	order := []string{}
	for _, c := range companionDefaults {
		if _, seen := byTable[c.table]; !seen {
			order = append(order, c.table)
		}
		byTable[c.table] = append(byTable[c.table], c)
	}

	for _, table := range order {
		columns := ""
		for _, c := range byTable[table] {
			// DEFAULT with no CONSTRAINT name in front of it: SQL Server invents one, which is
			// the whole shape these downs have to go looking for.
			columns += fmt.Sprintf(", [%s] %s DEFAULT %s", c.column, c.sqlDef, defaultLiteral(c.sqlDef))
		}
		mustExec(t, h.SQL, fmt.Sprintf("CREATE TABLE %s.[%s] (id BIGINT NOT NULL PRIMARY KEY%s)",
			companionSchema, table, columns))
	}

	// The fixture is worthless if it did not actually create unnamed defaults, so it is checked
	// before the rollback rather than inferred from the assertions after it.
	for _, c := range companionDefaults {
		require.Truef(t, companionDefaultExists(t, h, c.table, c.column),
			"fixture: %s.%s.%s must start with a default on it", companionSchema, c.table, c.column)
	}
}

// defaultLiteral is a value of the right type for the column, since what the default IS does not
// matter here, only that one exists and carries a generated name.
func defaultLiteral(sqlDef string) string {
	switch {
	case sqlDef == "BIT NOT NULL":
		return "0"
	case sqlDef == "INT NOT NULL":
		return "0"
	default:
		return "N''"
	}
}

// companionDefaultExists asks the same catalog view the downs read, restricted to the companion
// schema, so a surviving default and a dropped one are told apart by the engine rather than by
// the migration's own query.
func companionDefaultExists(t *testing.T, h *isolatedDB, table, column string) bool {
	t.Helper()

	const query = `
SELECT COUNT(*)
FROM sys.default_constraints dc
JOIN sys.columns c ON c.object_id = dc.parent_object_id AND c.column_id = dc.parent_column_id
WHERE dc.parent_object_id = OBJECT_ID(@p1) AND c.name = @p2`

	var count int
	err := h.SQL.QueryRow(query, companionSchema+"."+table, column).Scan(&count)
	require.NoErrorf(t, err, "read the defaults on %s.%s on %s", companionSchema, table, dbType())
	return count > 0
}
