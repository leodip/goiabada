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

// The two versions migration 000095 sits between. Literals: nothing in production code names this
// number.
const (
	beforeEmailTemplates000095 = 94
	emailTemplates000095       = 95
)

// Migration 000095 (#818 decision 7) creates email_templates on all four engines: an
// administrator's edit of one email in one language. This holds the migration to the claims its
// comments make, against an ISOLATED database of the configured dialect (see
// migration_testdb_helper_test.go):
//
//   - the columns: the email's identifier and the language, NOT NULL; the subject, the button label
//     and the body, each nullable, NULL for a field left as the built-in text; every string column
//     pinned case-sensitive; the subject and the button label as wide as their bounds, and the body
//     unbounded;
//   - at most one row for an email and a language, the engine's to refuse, and another language or
//     another case is another row;
//   - nothing else in the schema changes, and the down migration drops the table.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000095_EmailTemplates
func TestMigration000095_EmailTemplates(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(ctx, beforeEmailTemplates000095), "migrate to 94")
	before := listTables(t, h)
	assert.NotContains(t, before, "email_templates")

	require.NoError(t, h.Migrator.Migrate(ctx, emailTemplates000095), "apply 000095")
	assertEmailTemplatesShape000095(t, h, "after apply")
	assertEmailTemplatesBehaviour000095(t, h, "after apply")
	assert.ElementsMatch(t, append(append([]string{}, before...), "email_templates"),
		listTables(t, h), "000095 must add the one table and no other")

	require.NoError(t, h.Migrator.Migrate(ctx, beforeEmailTemplates000095), "roll back to 94")
	assert.Equal(t, before, listTables(t, h), "the down migration must drop the table and nothing else")

	require.NoError(t, h.Migrator.Migrate(ctx, emailTemplates000095), "apply 000095 again")
	assertEmailTemplatesShape000095(t, h, "after down then up")
	assertEmailTemplatesBehaviour000095(t, h, "after down then up")
}

func assertEmailTemplatesShape000095(t *testing.T, h *isolatedDB, when string) {
	t.Helper()
	engine := dbType()

	idType := map[data.Dialect]string{
		data.MySQL: "bigint unsigned", data.Postgres: "bigint", data.MSSQL: "bigint", data.SQLite: "INTEGER",
	}[engine]
	timeType := map[data.Dialect]string{
		data.MySQL: "datetime(6)", data.Postgres: "timestamp(6) without time zone", data.MSSQL: "datetime2(6)", data.SQLite: "DATETIME",
	}[engine]
	stringType := func(width int) string {
		return map[data.Dialect]string{
			data.MySQL: fmt.Sprintf("varchar(%d)", width), data.Postgres: fmt.Sprintf("character varying(%d)", width),
			data.MSSQL: fmt.Sprintf("nvarchar(%d)", width), data.SQLite: "TEXT",
		}[engine]
	}
	unboundedType := map[data.Dialect]string{
		data.MySQL: "longtext", data.Postgres: "text", data.MSSQL: "nvarchar(max)", data.SQLite: "TEXT",
	}[engine]
	collation := map[data.Dialect]string{
		data.MySQL: "utf8mb4_0900_as_cs", data.MSSQL: "Latin1_General_100_CS_AS_KS_WS_SC_UTF8", data.Postgres: "default", data.SQLite: "BINARY",
	}[engine]

	type want struct {
		typ      string
		nullable bool
		text     bool
	}
	columns := map[string]want{
		"id":             {typ: idType},
		"created_at":     {typ: timeType, nullable: true},
		"updated_at":     {typ: timeType, nullable: true},
		"email_template": {typ: stringType(64), text: true},
		"language":       {typ: stringType(32), text: true},
		// The subject's bound is 200 and the button label's 60, in the unit NVARCHAR counts.
		"subject":      {typ: stringType(200), nullable: true, text: true},
		"button_label": {typ: stringType(60), nullable: true, text: true},
		// The body's bound, 20,000, is past what an NVARCHAR(n) holds, so it is unbounded.
		"body": {typ: unboundedType, nullable: true, text: true},
	}

	templates := dumpTable(t, h, "email_templates")
	assert.Lenf(t, templates.Columns, len(columns), "email_templates has exactly its columns %s", when)
	for name, w := range columns {
		c := templates.column(t, name)
		assert.Equalf(t, w.typ, c.Type, "email_templates.%s's type %s on %s", name, when, engine)
		if name != "id" || engine != data.SQLite {
			assert.Equalf(t, w.nullable, c.Nullable, "email_templates.%s's nullability %s on %s", name, when, engine)
		}
		if w.text {
			assert.Equalf(t, collation, c.Collation, "email_templates.%s compares case-sensitively %s on %s", name, when, engine)
		}
	}
	assert.Truef(t, templates.column(t, "id").Generated, "email_templates.id is generated %s", when)

	pair := templates.index("idx_email_templates_email_template_language")
	assert.Truef(t, pair.Exists && pair.Unique, "one row for an email and a language %s: %v", when, templates.Indexes)
	assert.Equalf(t, []string{"email_template", "language"}, pair.Columns, "keyed by the email, then the language, %s", when)
	for _, index := range templates.Indexes {
		if index.Origin == schemadump.OriginPrimaryKey || index.Name == pair.Name {
			continue
		}
		assert.Failf(t, "an index the migration did not ask for", "%v %s", index, when)
	}
	assert.Emptyf(t, templates.ForeignKeys, "an edit references nothing %s", when)
}

// assertEmailTemplatesBehaviour000095 holds the table to what it does, in plain SQL with literals
// because the four dialects disagree on placeholder syntax and every value is test-controlled.
func assertEmailTemplatesBehaviour000095(t *testing.T, h *isolatedDB, when string) {
	t.Helper()
	ctx := context.Background()
	exec := func(query string) error {
		_, err := h.SQL.ExecContext(ctx, query)
		return err
	}
	scalar := func(query string) int64 {
		var n int64
		require.NoError(t, h.SQL.QueryRowContext(ctx, query).Scan(&n))
		return n
	}

	require.NoErrorf(t, exec("INSERT INTO email_templates (email_template, language) VALUES ('welcome', 'en')"),
		"an edit needs only its email and language, every field left as the built-in text, %s", when)
	assert.Equalf(t, int64(1), scalar("SELECT COUNT(*) FROM email_templates "+
		"WHERE email_template = 'welcome' AND subject IS NULL AND button_label IS NULL AND body IS NULL"),
		"a field not written is NULL %s", when)

	require.Errorf(t, exec("INSERT INTO email_templates (email_template, language, subject) VALUES ('welcome', 'en', 'Hi')"),
		"a second row for the same email and language is refused %s", when)
	require.NoErrorf(t, exec("INSERT INTO email_templates (email_template, language) VALUES ('welcome', 'fr')"),
		"another language is another row %s", when)
	require.NoErrorf(t, exec("INSERT INTO email_templates (email_template, language) VALUES ('test', 'en')"),
		"another email is another row %s", when)
	require.NoErrorf(t, exec("INSERT INTO email_templates (email_template, language) VALUES ('welcome', 'EN')"),
		"another case is another language %s", when)
	require.NoErrorf(t, exec("INSERT INTO email_templates (email_template, language) VALUES ('Welcome', 'en')"),
		"and another case another email %s", when)

	require.Errorf(t, exec("INSERT INTO email_templates (language) VALUES ('de')"),
		"an edit names its email %s", when)
	require.Errorf(t, exec("INSERT INTO email_templates (email_template) VALUES ('test')"),
		"and its language %s", when)

	require.NoError(t, exec("DELETE FROM email_templates"))
}
