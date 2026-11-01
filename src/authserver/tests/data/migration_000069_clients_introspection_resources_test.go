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

// Migration 000069 (#676 decisions 5 and 14) creates clients_introspection_resources on all four
// engines, the link table between clients and the resources whose tokens each may introspect. This
// holds the migration to the claims its comments make, against an ISOLATED database of the
// configured dialect (see migration_testdb_helper_test.go):
//
//   - id is the key, created_at a microsecond datetime, client_id and resource_id NOT NULL with the
//     id columns' types;
//   - a client lists a resource once, so the pair is unique;
//   - each side's foreign key cascades, so deleting a client or a resource removes its links;
//   - nothing else in the schema changes, and the down migration drops the table it created.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000069_ClientsIntrospectionResources
func TestMigration000069_ClientsIntrospectionResources(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(ctx, 68), "migrate to 68")
	before := listTables(t, h)
	assert.NotContains(t, before, "clients_introspection_resources",
		"the table must not exist before 000069, so what is found afterwards is what 000069 added")

	require.NoError(t, h.Migrator.Migrate(ctx, 69), "apply 000069")
	assertClientsIntrospectionResourcesShape(t, h, "after apply")
	assertClientsIntrospectionResourcesBehaviour(t, h, "after apply")
	assert.ElementsMatch(t, append(append([]string{}, before...), "clients_introspection_resources"), listTables(t, h),
		"000069 must add the one table and no other")

	require.NoError(t, h.Migrator.Migrate(ctx, 68), "roll back to 68")
	assert.Equal(t, before, listTables(t, h), "the down migration must drop clients_introspection_resources and nothing else")

	require.NoError(t, h.Migrator.Migrate(ctx, 69), "apply 000069 again")
	assertClientsIntrospectionResourcesShape(t, h, "after down then up")
	assertClientsIntrospectionResourcesBehaviour(t, h, "after down then up")
}

func assertClientsIntrospectionResourcesShape(t *testing.T, h *isolatedDB, when string) {
	t.Helper()
	idType := map[data.Dialect]string{
		data.MySQL: "bigint unsigned", data.Postgres: "bigint", data.MSSQL: "bigint", data.SQLite: "INTEGER",
	}
	createdAtType := map[data.Dialect]string{
		data.MySQL: "datetime(6)", data.Postgres: "timestamp(6) without time zone", data.MSSQL: "datetime2(6)", data.SQLite: "DATETIME",
	}
	engine := dbType()

	shape := dumpTable(t, h, "clients_introspection_resources")
	assert.Lenf(t, shape.Columns, 4, "id, created_at, client_id and resource_id %s", when)

	id := shape.column(t, "id")
	assert.Equalf(t, idType[engine], id.Type, "id's type %s", when)
	assert.Truef(t, id.Generated, "id is generated %s", when)

	createdAt := shape.column(t, "created_at")
	assert.Equalf(t, createdAtType[engine], createdAt.Type, "created_at keeps the microseconds Go writes %s", when)

	for _, column := range []string{"client_id", "resource_id"} {
		c := shape.column(t, column)
		assert.Equalf(t, idType[engine], c.Type, "%s has the type of the id it names %s", column, when)
		assert.Falsef(t, c.Nullable, "%s is NOT NULL %s", column, when)
	}

	for column, table := range map[string]string{"client_id": "clients", "resource_id": "resources"} {
		fk := shape.foreignKey(t, column)
		assert.Equalf(t, table, fk.RefTable, "%s references %s %s", column, table, when)
		assert.Equalf(t, "id", fk.RefColumn, "by id %s", when)
		assert.Equalf(t, "CASCADE", fk.OnDelete, "deleting the %s row removes its links %s", table, when)
	}
	assert.Lenf(t, shape.ForeignKeys, 2, "the two foreign keys and no more %s", when)

	pair := shape.index("idx_clients_introspection_resources_client_resource")
	require.Truef(t, pair.Exists, "the pair's unique index %s; indexes read: %v", when, shape.Indexes)
	assert.Truef(t, pair.Unique, "a client lists a resource once %s", when)
	assert.Equalf(t, []string{"client_id", "resource_id"}, pair.Columns, "over the pair, client first %s", when)
	assert.NotEqualf(t, schemadump.OriginPrimaryKey, pair.Origin, "and it is not the key %s", when)

	resource := shape.index("idx_clients_introspection_resources_resource_id")
	require.Truef(t, resource.Exists, "the resource side's index, for its cascade %s; indexes read: %v", when, shape.Indexes)
	assert.Falsef(t, resource.Unique, "many clients list one resource %s", when)
	assert.Equalf(t, []string{"resource_id"}, resource.Columns, "over resource_id alone %s", when)
}

// assertClientsIntrospectionResourcesBehaviour holds the key and the cascades to what they do. The
// resource is written through the isolated handle's own data layer and the client by seedClient;
// the links and the deletions are plain SQL on the table under test.
// Literals rather than placeholders because the four dialects disagree on placeholder syntax, and
// every value here is test-controlled.
func assertClientsIntrospectionResourcesBehaviour(t *testing.T, h *isolatedDB, when string) {
	t.Helper()
	ctx := context.Background()
	exec := func(query string, args ...any) error {
		_, err := h.SQL.ExecContext(ctx, fmt.Sprintf(query, args...))
		return err
	}
	newResource := func() int64 {
		resource := &record.Resource{ResourceIdentifier: "intro-resource-" + fake.LetterN(8)}
		require.NoError(t, h.DB.CreateResource(ctx, nil, resource), "CreateResource")
		return resource.Id
	}
	// Seeded in SQL: the data layer writes every column the record carries at head, which a
	// database at 000069 lacks (migration_seed_sql_test.go).
	client := &record.Client{Id: seedClient(t, h, "intro-client-"+fake.LetterN(8))}
	resourceId := newResource()
	count := func() int64 {
		var n int64
		require.NoError(t, h.SQL.QueryRowContext(ctx, fmt.Sprintf(
			"SELECT COUNT(*) FROM clients_introspection_resources WHERE client_id = %d", client.Id)).Scan(&n))
		return n
	}

	link := "INSERT INTO clients_introspection_resources (client_id, resource_id) VALUES (%d, %d)"
	require.NoErrorf(t, exec(link, client.Id, resourceId), "the first link is accepted %s", when)
	require.Errorf(t, exec(link, client.Id, resourceId), "a second link of the pair is refused by the key %s", when)
	assert.Equalf(t, int64(1), count(), "and writes nothing %s", when)
	require.Errorf(t, exec(link, client.Id, resourceId+1_000_000), "a link to no resource is refused %s", when)

	require.NoError(t, exec("DELETE FROM resources WHERE id = %d", resourceId))
	assert.Equalf(t, int64(0), count(), "deleting the resource removed the link %s", when)

	resourceId = newResource()
	require.NoError(t, exec(link, client.Id, resourceId))
	require.NoError(t, exec("DELETE FROM clients WHERE id = %d", client.Id))
	assert.Equalf(t, int64(0), count(), "deleting the client removed the link %s", when)

	require.NoError(t, exec("DELETE FROM resources WHERE id = %d", resourceId))
}
