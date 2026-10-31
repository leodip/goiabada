package datatests

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Migration 000074 (#631 decision 8) adds users.page_language on all four engines: the language a
// user chose for Goiabada's own pages and emails, the tag of a loaded catalog or empty for
// Automatic. This holds the migration to the claims its comments make, against an ISOLATED
// database of the configured dialect (see migration_testdb_helper_test.go):
//
//   - the column is absent at 000073, so what is found afterwards is what 000074 added;
//   - it is a string 32 wide (varchar on MySQL and PostgreSQL, nvarchar on SQL Server, TEXT on
//     SQLite), NOT NULL with the empty string as its default, and case-sensitive like every string
//     column (#283);
//   - a users row that predates it reads the empty string, which is Automatic: nobody's pages
//     change at upgrade;
//   - the down migration drops it and nothing else, and re-applying is clean. SQL Server refuses to
//     drop a column a default constraint depends on, so 000074 names its constraint.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000074_UsersPageLanguage
func TestMigration000074_UsersPageLanguage(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(ctx, 73), "migrate to 73")
	before := usersColumns000074(t, h)
	assert.NotContains(t, before, "page_language", "users.page_language must not exist at 000073")

	// Seeded with raw SQL rather than CreateUser: the Go record already carries PageLanguage, so
	// an ORM insert at 000073 would name a column that does not exist yet.
	userId := seedUser(t, h, userSeed{Enabled: true})

	require.NoError(t, h.Migrator.Migrate(ctx, 74), "apply 000074")
	assertPageLanguageShape000074(t, h, "after apply")
	assert.ElementsMatch(t, append(append([]string{}, before...), "page_language"), usersColumns000074(t, h),
		"000074 must add the one column and no other")
	assert.Empty(t, readPageLanguage000074(t, h, userId), "a users row that predates the column lands on Automatic")

	require.NoError(t, h.Migrator.Migrate(ctx, 73), "roll back 000074")
	assert.Equal(t, before, usersColumns000074(t, h), "the down migration must drop page_language and nothing else")

	require.NoError(t, h.Migrator.Migrate(ctx, 74), "re-apply 000074")
	assertPageLanguageShape000074(t, h, "after down then up")
	assert.Empty(t, readPageLanguage000074(t, h, userId), "the row after the down/up round trip")
}

func usersColumns000074(t *testing.T, h *isolatedDB) []string {
	t.Helper()
	shape := dumpTable(t, h, "users")
	names := make([]string, 0, len(shape.Columns))
	for _, c := range shape.Columns {
		names = append(names, c.Name)
	}
	return names
}

func readPageLanguage000074(t *testing.T, h *isolatedDB, userId int64) string {
	t.Helper()
	var pageLanguage string
	q := fmt.Sprintf("SELECT page_language FROM users WHERE id = %d", userId)
	require.NoError(t, h.SQL.QueryRow(q).Scan(&pageLanguage), "read page_language")
	return pageLanguage
}

func assertPageLanguageShape000074(t *testing.T, h *isolatedDB, when string) {
	t.Helper()
	columnType := map[data.Dialect]string{
		data.MySQL: "varchar(32)", data.Postgres: "character varying(32)", data.MSSQL: "nvarchar(32)", data.SQLite: "TEXT",
	}
	collation := map[data.Dialect]string{
		data.MySQL: "utf8mb4_0900_as_cs", data.Postgres: "default",
		data.MSSQL: "Latin1_General_100_CS_AS_KS_WS_SC_UTF8", data.SQLite: "BINARY",
	}
	engine := dbType()

	c := dumpTable(t, h, "users").column(t, "page_language")
	assert.Equalf(t, columnType[engine], c.Type, "page_language holds a catalog's tag %s", when)
	assert.Falsef(t, c.Nullable, "page_language is NOT NULL %s", when)
	assert.Truef(t, c.HasDefault, "page_language has a default %s", when)
	// The engines spell an empty-string default '', ''::character varying, ('') and, on MySQL, "".
	def := strings.TrimSuffix(strings.Trim(c.Default, "()"), "::character varying")
	assert.Emptyf(t, strings.Trim(def, "'"), "page_language defaults to the empty string %s, got %q", when, c.Default)
	assert.Equalf(t, collation[engine], c.Collation, "page_language compares case-sensitively %s", when)
}
