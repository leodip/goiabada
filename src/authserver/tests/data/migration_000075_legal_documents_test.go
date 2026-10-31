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

// Migration 000075 (#622 decisions 1, 2 and 5) creates legal_documents and legal_document_versions
// on all four engines. This holds the migration to the claims its comments make, against an
// ISOLATED database of the configured dialect (see migration_testdb_helper_test.go):
//
//   - the documents' columns, short_name unique, the draft and retired_at nullable, every string
//     column pinned case-sensitive and the Markdown unbounded;
//   - the versions' columns, all NOT NULL, one version of each number per document, and a foreign
//     key to the document with no cascade, so a document with a version cannot be deleted;
//   - nothing else in the schema changes, and the down migration drops both tables.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000075_LegalDocuments
func TestMigration000075_LegalDocuments(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(ctx, 74), "migrate to 74")
	before := listTables(t, h)
	assert.NotContains(t, before, "legal_documents")
	assert.NotContains(t, before, "legal_document_versions")

	require.NoError(t, h.Migrator.Migrate(ctx, 75), "apply 000075")
	assertLegalDocumentsShape(t, h, "after apply")
	assertLegalDocumentsBehaviour(t, h, "after apply")
	assert.ElementsMatch(t, append(append([]string{}, before...), "legal_documents", "legal_document_versions"),
		listTables(t, h), "000075 must add the two tables and no other")

	require.NoError(t, h.Migrator.Migrate(ctx, 74), "roll back to 74")
	assert.Equal(t, before, listTables(t, h), "the down migration must drop both tables and nothing else")

	require.NoError(t, h.Migrator.Migrate(ctx, 75), "apply 000075 again")
	assertLegalDocumentsShape(t, h, "after down then up")
	assertLegalDocumentsBehaviour(t, h, "after down then up")
}

func assertLegalDocumentsShape(t *testing.T, h *isolatedDB, when string) {
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
	intType := map[data.Dialect]string{
		data.MySQL: "int", data.Postgres: "integer", data.MSSQL: "int", data.SQLite: "INTEGER",
	}[engine]
	collation := map[data.Dialect]string{
		data.MySQL: "utf8mb4_0900_as_cs", data.MSSQL: "Latin1_General_100_CS_AS_KS_WS_SC_UTF8", data.Postgres: "default", data.SQLite: "BINARY",
	}[engine]

	type want struct {
		typ      string
		nullable bool
		text     bool
	}
	check := func(shape tableShape, table string, columns map[string]want) {
		t.Helper()
		assert.Lenf(t, shape.Columns, len(columns), "%s has exactly its columns %s", table, when)
		for name, w := range columns {
			c := shape.column(t, name)
			assert.Equalf(t, w.typ, c.Type, "%s.%s's type %s", table, name, when)
			if name != "id" || engine != data.SQLite {
				assert.Equalf(t, w.nullable, c.Nullable, "%s.%s's nullability %s", table, name, when)
			}
			if w.text {
				assert.Equalf(t, collation, c.Collation, "%s.%s compares case-sensitively %s", table, name, when)
			}
		}
		assert.Truef(t, shape.column(t, "id").Generated, "%s.id is generated %s", table, when)
	}

	documents := dumpTable(t, h, "legal_documents")
	check(documents, "legal_documents", map[string]want{
		"id":             {typ: idType},
		"created_at":     {typ: timeType, nullable: true},
		"updated_at":     {typ: timeType, nullable: true},
		"short_name":     {typ: stringType(64), text: true},
		"kind":           {typ: stringType(20), text: true},
		"draft_title":    {typ: stringType(200), nullable: true, text: true},
		"draft_markdown": {typ: unboundedType, nullable: true, text: true},
		"retired_at":     {typ: timeType, nullable: true},
	})
	shortName := documents.index("idx_legal_documents_short_name")
	assert.Truef(t, shortName.Exists && shortName.Unique, "short_name is unique %s: %v", when, documents.Indexes)
	assert.Equalf(t, []string{"short_name"}, shortName.Columns, "on short_name alone %s", when)
	assert.Emptyf(t, documents.ForeignKeys, "a document references nothing yet %s", when)

	versions := dumpTable(t, h, "legal_document_versions")
	check(versions, "legal_document_versions", map[string]want{
		"id":                {typ: idType},
		"published_at":      {typ: timeType},
		"legal_document_id": {typ: idType},
		"version_number":    {typ: intType},
		"title":             {typ: stringType(200), text: true},
		"markdown":          {typ: unboundedType, text: true},
	})
	number := versions.index("idx_legal_document_versions_document_version")
	assert.Truef(t, number.Exists && number.Unique, "one version of each number per document %s: %v", when, versions.Indexes)
	assert.Equalf(t, []string{"legal_document_id", "version_number"}, number.Columns, "keyed document first %s", when)
	for _, index := range versions.Indexes {
		if index.Origin == schemadump.OriginPrimaryKey || index.Name == number.Name {
			continue
		}
		assert.Failf(t, "an index the migration did not ask for", "%v %s: the unique index serves the foreign key, MySQL's included", index, when)
	}
	fk := versions.foreignKey(t, "legal_document_id")
	assert.Equalf(t, "legal_documents", fk.RefTable, "a version references its document %s", when)
	assert.Equalf(t, "id", fk.RefColumn, "by id %s", when)
	assert.Equalf(t, "NO ACTION", fk.OnDelete, "deleting a published document is refused, never cascaded %s", when)
	assert.Lenf(t, versions.ForeignKeys, 1, "the one foreign key %s", when)
}

// assertLegalDocumentsBehaviour holds the tables to what they do, in plain SQL with literals because
// the four dialects disagree on placeholder syntax and every value is test-controlled.
func assertLegalDocumentsBehaviour(t *testing.T, h *isolatedDB, when string) {
	t.Helper()
	ctx := context.Background()
	exec := func(query string, args ...any) error {
		_, err := h.SQL.ExecContext(ctx, fmt.Sprintf(query, args...))
		return err
	}
	scalar := func(query string, args ...any) int64 {
		var n int64
		require.NoError(t, h.SQL.QueryRowContext(ctx, fmt.Sprintf(query, args...)).Scan(&n))
		return n
	}
	now := "'2026-10-31 12:00:00'"

	require.NoErrorf(t, exec("INSERT INTO legal_documents (short_name, kind) VALUES ('privacy', 'for_information')"),
		"a document needs only its short name and kind %s", when)
	require.Errorf(t, exec("INSERT INTO legal_documents (short_name, kind) VALUES ('privacy', 'must_accept')"),
		"a second document with the same short name is refused %s", when)
	require.NoErrorf(t, exec("INSERT INTO legal_documents (short_name, kind) VALUES ('Privacy', 'must_accept')"),
		"another case is another short name %s", when)
	id := scalar("SELECT id FROM legal_documents WHERE short_name = 'privacy'")

	version := "INSERT INTO legal_document_versions (published_at, legal_document_id, version_number, title, markdown) VALUES (%s, %d, %d, 'Privacy', 'Text')"
	require.NoErrorf(t, exec(version, now, id, 1), "version 1 %s", when)
	require.NoErrorf(t, exec(version, now, id, 2), "version 2 %s", when)
	require.Errorf(t, exec(version, now, id, 2), "a second version 2 of one document is refused %s", when)
	require.Errorf(t, exec(version, now, id+1_000_000, 1), "a version naming no document is refused %s", when)

	require.Errorf(t, exec("DELETE FROM legal_documents WHERE id = %d", id),
		"a document with a published version cannot be deleted %s", when)
	assert.Equalf(t, int64(2), scalar("SELECT COUNT(*) FROM legal_document_versions WHERE legal_document_id = %d", id),
		"its versions stay %s", when)

	require.NoError(t, exec("DELETE FROM legal_document_versions"))
	require.NoError(t, exec("DELETE FROM legal_documents"))
}
