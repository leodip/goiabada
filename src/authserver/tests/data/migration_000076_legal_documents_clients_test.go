package datatests

import (
	"context"
	"fmt"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/schemadump"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Migration 000076 (#622, "Applies to") gives a legal document its Applies to on all four engines:
// legal_documents.applies_to_all_apps, and legal_documents_clients, the link table to the apps a
// document set to selected apps applies to. This holds the migration to the claims its comments
// make, against an ISOLATED database of the configured dialect (see
// migration_testdb_helper_test.go):
//
//   - applies_to_all_apps is a NOT NULL boolean defaulting to true, so a document written before
//     the migration, or without naming the column, applies to all apps;
//   - the link table's id is the key, created_at a microsecond datetime, legal_document_id and
//     client_id NOT NULL with the id columns' types;
//   - a document lists an app once, so the pair is unique;
//   - each side's foreign key cascades, so deleting a document or a client removes its links and
//     the other side stays;
//   - nothing else in the schema changes, and the down migration drops what it added.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000076_LegalDocumentsClients
func TestMigration000076_LegalDocumentsClients(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(ctx, 75), "migrate to 75")
	before := listTables(t, h)
	assert.NotContains(t, before, "legal_documents_clients",
		"the table must not exist before 000076, so what is found afterwards is what 000076 added")
	documentColumns := len(dumpTable(t, h, "legal_documents").Columns)

	// A document written before the migration, which must come out applying to all apps.
	_, err := h.SQL.ExecContext(ctx, "INSERT INTO legal_documents (short_name, kind) VALUES ('before-076', 'must_accept')")
	require.NoError(t, err)

	require.NoError(t, h.Migrator.Migrate(ctx, 76), "apply 000076")
	assert.True(t, appliesToAllApps(t, h, "before-076"), "a document written before 000076 applies to all apps")
	assertLegalDocumentsClientsShape(t, h, documentColumns, "after apply")
	assertLegalDocumentsClientsBehaviour(t, h, "after apply")
	assert.ElementsMatch(t, append(append([]string{}, before...), "legal_documents_clients"), listTables(t, h),
		"000076 must add the one table and no other")

	require.NoError(t, h.Migrator.Migrate(ctx, 75), "roll back to 75")
	assert.Equal(t, before, listTables(t, h), "the down migration must drop legal_documents_clients and nothing else")
	documents := dumpTable(t, h, "legal_documents")
	assert.Len(t, documents.Columns, documentColumns, "the down migration drops applies_to_all_apps")
	_, hasColumn := schemadump.TableShape(documents).Column("applies_to_all_apps")
	assert.False(t, hasColumn, "applies_to_all_apps is gone after the down migration")

	require.NoError(t, h.Migrator.Migrate(ctx, 76), "apply 000076 again")
	assertLegalDocumentsClientsShape(t, h, documentColumns, "after down then up")
	assertLegalDocumentsClientsBehaviour(t, h, "after down then up")

	_, err = h.SQL.ExecContext(ctx, "DELETE FROM legal_documents")
	require.NoError(t, err)
}

// appliesToAllApps reads one document's applies_to_all_apps by its short name.
func appliesToAllApps(t *testing.T, h *isolatedDB, shortName string) bool {
	t.Helper()
	var all bool
	require.NoError(t, h.SQL.QueryRowContext(context.Background(), fmt.Sprintf(
		"SELECT applies_to_all_apps FROM legal_documents WHERE short_name = '%s'", shortName)).Scan(&all))
	return all
}

func assertLegalDocumentsClientsShape(t *testing.T, h *isolatedDB, documentColumnsBefore int, when string) {
	t.Helper()
	engine := dbType()
	idType := map[data.Dialect]string{
		data.MySQL: "bigint unsigned", data.Postgres: "bigint", data.MSSQL: "bigint", data.SQLite: "INTEGER",
	}[engine]
	createdAtType := map[data.Dialect]string{
		data.MySQL: "datetime(6)", data.Postgres: "timestamp(6) without time zone", data.MSSQL: "datetime2(6)", data.SQLite: "DATETIME",
	}[engine]
	boolType := map[data.Dialect]string{
		data.MySQL: "tinyint(1)", data.Postgres: "boolean", data.MSSQL: "bit", data.SQLite: "numeric",
	}[engine]

	documents := dumpTable(t, h, "legal_documents")
	assert.Lenf(t, documents.Columns, documentColumnsBefore+1, "legal_documents gains one column %s", when)
	all := documents.column(t, "applies_to_all_apps")
	assert.Equalf(t, boolType, all.Type, "applies_to_all_apps is the engine's boolean %s", when)
	assert.Falsef(t, all.Nullable, "applies_to_all_apps is NOT NULL %s", when)
	assert.Truef(t, all.HasDefault, "applies_to_all_apps has a default %s", when)

	shape := dumpTable(t, h, "legal_documents_clients")
	assert.Lenf(t, shape.Columns, 4, "id, created_at, legal_document_id and client_id %s", when)

	id := shape.column(t, "id")
	assert.Equalf(t, idType, id.Type, "id's type %s", when)
	assert.Truef(t, id.Generated, "id is generated %s", when)

	assert.Equalf(t, createdAtType, shape.column(t, "created_at").Type, "created_at keeps the microseconds Go writes %s", when)

	for _, column := range []string{"legal_document_id", "client_id"} {
		c := shape.column(t, column)
		assert.Equalf(t, idType, c.Type, "%s has the type of the id it names %s", column, when)
		assert.Falsef(t, c.Nullable, "%s is NOT NULL %s", column, when)
	}

	for column, table := range map[string]string{"legal_document_id": "legal_documents", "client_id": "clients"} {
		fk := shape.foreignKey(t, column)
		assert.Equalf(t, table, fk.RefTable, "%s references %s %s", column, table, when)
		assert.Equalf(t, "id", fk.RefColumn, "by id %s", when)
		assert.Equalf(t, "CASCADE", fk.OnDelete, "deleting the %s row removes its links %s", table, when)
	}
	assert.Lenf(t, shape.ForeignKeys, 2, "the two foreign keys and no more %s", when)

	pair := shape.index("idx_legal_documents_clients_document_client")
	require.Truef(t, pair.Exists, "the pair's unique index %s; indexes read: %v", when, shape.Indexes)
	assert.Truef(t, pair.Unique, "a document lists an app once %s", when)
	assert.Equalf(t, []string{"legal_document_id", "client_id"}, pair.Columns, "over the pair, document first %s", when)
	assert.NotEqualf(t, schemadump.OriginPrimaryKey, pair.Origin, "and it is not the key %s", when)

	client := shape.index("idx_legal_documents_clients_client_id")
	require.Truef(t, client.Exists, "the client side's index, for a client's documents and its cascade %s; indexes read: %v", when, shape.Indexes)
	assert.Falsef(t, client.Unique, "many documents list one app %s", when)
	assert.Equalf(t, []string{"client_id"}, client.Columns, "over client_id alone %s", when)
}

// assertLegalDocumentsClientsBehaviour holds the default, the key and the cascades to what they do.
// The client is written through the isolated handle's own data layer; the documents, the links and
// the deletions are plain SQL on the tables under test, with literals because the four dialects
// disagree on placeholder syntax, and every value here is test-controlled.
func assertLegalDocumentsClientsBehaviour(t *testing.T, h *isolatedDB, when string) {
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
	newDocument := func() int64 {
		shortName := "applies-" + fake.LetterN(8)
		require.NoError(t, exec("INSERT INTO legal_documents (short_name, kind) VALUES ('%s', 'must_accept')", shortName))
		assert.Truef(t, appliesToAllApps(t, h, shortName), "a document written without the column applies to all apps %s", when)
		return scalar("SELECT id FROM legal_documents WHERE short_name = '%s'", shortName)
	}
	newClient := func() int64 {
		client := &record.Client{ClientIdentifier: "applies-client-" + fake.LetterN(8)}
		require.NoError(t, h.DB.CreateClient(ctx, nil, client), "CreateClient")
		return client.Id
	}
	links := func(column string, id int64) int64 {
		return scalar("SELECT COUNT(*) FROM legal_documents_clients WHERE %s = %d", column, id)
	}

	documentId := newDocument()
	clientId := newClient()
	otherClientId := newClient()

	link := "INSERT INTO legal_documents_clients (legal_document_id, client_id) VALUES (%d, %d)"
	require.NoErrorf(t, exec(link, documentId, clientId), "the first link is accepted %s", when)
	require.Errorf(t, exec(link, documentId, clientId), "a second link of the pair is refused by the key %s", when)
	assert.Equalf(t, int64(1), links("legal_document_id", documentId), "and writes nothing %s", when)
	require.Errorf(t, exec(link, documentId, clientId+1_000_000), "a link to no client is refused %s", when)
	require.Errorf(t, exec(link, documentId+1_000_000, clientId), "a link from no document is refused %s", when)
	require.NoError(t, exec(link, documentId, otherClientId))

	require.NoError(t, exec("DELETE FROM clients WHERE id = %d", clientId))
	assert.Equalf(t, int64(1), links("legal_document_id", documentId),
		"deleting a client removed its link and left the document's other app %s", when)
	assert.Equalf(t, int64(1), scalar("SELECT COUNT(*) FROM legal_documents WHERE id = %d", documentId),
		"the document stays %s", when)

	require.NoError(t, exec("DELETE FROM legal_documents WHERE id = %d", documentId))
	assert.Equalf(t, int64(0), links("client_id", otherClientId), "deleting the document removed its links %s", when)
	assert.Equalf(t, int64(1), scalar("SELECT COUNT(*) FROM clients WHERE id = %d", otherClientId),
		"the client stays %s", when)

	require.NoError(t, exec("DELETE FROM clients WHERE id = %d", otherClientId))
}
