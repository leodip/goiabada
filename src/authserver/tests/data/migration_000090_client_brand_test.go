package datatests

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/data/schemadump"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two versions migration 000090 sits between. Literals: nothing in production code names this
// number.
const (
	beforeClientBrand000090 = 89
	clientBrand000090       = 90
)

// TestMigration000090_ClientBrand exercises the migration that gives every client a brand of its
// own (#812 decision 1), against a real engine of the configured dialect.
//
//  1. clients.brand_id is absent at 000089, and once 000090 has run it is the only thing about
//     clients that moved: a nullable column with no default, a foreign key to brands(id) with no
//     cascade, and an index over it alone.
//  2. Nothing is backfilled: a client that predates the column has no brand of its own, and is
//     drawn in the default.
//  3. A save the previous release makes during a rolling upgrade, naming no brand_id, leaves it.
//  4. The foreign key refuses deleting a brand a client names, and a brand_id naming no brand.
//  5. The down migration restores clients to exactly the shape 000089 built, and 000090 applies
//     again after it.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000090_ClientBrand
func TestMigration000090_ClientBrand(t *testing.T) {
	ctx := context.Background()
	h, def := brandsIsolatedDB(t)

	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeClientBrand000090), "roll back to 000089 on %s", dbType())
	before := dumpTable(t, h, "clients")
	_, exists := schemadump.TableShape(before).Column("brand_id")
	require.Falsef(t, exists, "1. clients.brand_id must not exist at 000089 on %s", dbType())

	// A client that predates the column, inserted in SQL because the data layer at head names it.
	existing := "predates_brand_" + fake.LetterN(6)
	insertClientWithoutDPoP000087(t, h, existing)

	require.NoErrorf(t, h.Migrator.Migrate(ctx, clientBrand000090), "apply 000090 on %s", dbType())
	assertClientBrandShape000090(t, h, before, "after apply")

	// 2.
	predating, err := h.DB.GetClientByClientIdentifier(ctx, nil, existing)
	require.NoError(t, err)
	require.NotNil(t, predating)
	assert.Equalf(t, sql.NullInt64{}, predating.BrandId, "2. a client that predates 000090 has no brand of its own on %s", dbType())
	// The data layer's brand reads name the columns of later migrations, so this one is read at head.
	if upErr := h.Migrator.Up(ctx); upErr != nil && !errors.Is(upErr, migrator.ErrNoChange) {
		require.NoErrorf(t, upErr, "migrate to head on %s", dbType())
	}
	drawnIn, err := h.DB.GetClientPageBrand(ctx, nil, existing)
	require.NoError(t, err)
	require.NotNilf(t, drawnIn, "2. a client that predates 000090 is drawn in the default on %s", dbType())
	assert.Equal(t, def.Id, drawnIn.Id)
	require.NoErrorf(t, h.Migrator.Migrate(ctx, clientBrand000090), "roll back to 000090 on %s", dbType())

	// 3. The brand and the assignment in SQL, for the same reason.
	otherId := insertBrand000091(t, h, "Other", "dark", "plum")
	_, err = h.SQL.Exec(fmt.Sprintf("UPDATE clients SET brand_id = %d WHERE id = %d", otherId, predating.Id))
	require.NoErrorf(t, err, "give the client a brand on %s", dbType())
	_, err = h.SQL.Exec(fmt.Sprintf("UPDATE clients SET description = 'Previous release' WHERE id = %d", predating.Id))
	require.NoErrorf(t, err, "save the client as the previous release does on %s", dbType())
	assert.Equalf(t, sql.NullInt64{Int64: otherId, Valid: true}, clientBrandIdOf(t, h, predating.Id),
		"3. the previous release's save leaves the client's brand on %s", dbType())

	// 4.
	_, err = h.SQL.Exec(fmt.Sprintf("DELETE FROM brands WHERE id = %d", otherId))
	require.Errorf(t, err, "4. the foreign key refuses deleting a brand a client names on %s", dbType())
	_, err = h.SQL.Exec(fmt.Sprintf("UPDATE clients SET brand_id = %d WHERE id = %d", otherId+1_000, predating.Id))
	require.Errorf(t, err, "4. the foreign key refuses a brand_id naming no brand on %s", dbType())

	// 5.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeClientBrand000090), "roll back 000090 on %s", dbType())
	assert.Equalf(t, before, dumpTable(t, h, "clients"),
		"5. 000090's down must restore clients to the shape 000089 built on %s", dbType())
	require.NoErrorf(t, h.Migrator.Migrate(ctx, clientBrand000090), "re-apply 000090 on %s", dbType())
	assertClientBrandShape000090(t, h, before, "after a down/up round trip")
	assert.Equalf(t, sql.NullInt64{}, clientBrandIdOf(t, h, predating.Id),
		"5. a round trip leaves the client with no brand of its own on %s", dbType())
}

// assertClientBrandShape000090 holds clients to the shape 000089 built plus the column, its
// foreign key and its index, and nothing else.
func assertClientBrandShape000090(t *testing.T, h *isolatedDB, before tableShape, phase string) {
	t.Helper()
	after := dumpTable(t, h, "clients")

	column := after.column(t, "brand_id")
	assert.Truef(t, column.Nullable, "[%s] clients.brand_id is nullable: NULL follows the default, on %s", phase, dbType())
	assert.Falsef(t, column.HasDefault, "[%s] clients.brand_id has no default on %s", phase, dbType())
	idColumn := dumpTable(t, h, "brands").column(t, "id")
	assert.Equalf(t, idColumn.Type, column.Type, "[%s] clients.brand_id has brands.id's type on %s", phase, dbType())

	fk := after.foreignKey(t, "brand_id")
	assert.Equalf(t, "brands", fk.RefTable, "[%s] clients.brand_id references brands on %s", phase, dbType())
	assert.Equalf(t, "id", fk.RefColumn, "[%s] by id on %s", phase, dbType())
	assert.Containsf(t, []string{"NO ACTION", "RESTRICT"}, fk.OnDelete,
		"[%s] the foreign key has no cascade: a brand's deletion moves its clients itself, on %s", phase, dbType())

	byBrand := after.index("idx_clients_brand_id")
	require.Truef(t, byBrand.Exists, "[%s] the brand's index on %s; indexes read: %v", phase, dbType(), after.Indexes)
	assert.Falsef(t, byBrand.Unique, "[%s] many clients share a brand on %s", phase, dbType())
	assert.Equalf(t, []string{"brand_id"}, byBrand.Columns, "[%s] over brand_id alone on %s", phase, dbType())

	withoutAdded := after
	withoutAdded.Columns = slices.DeleteFunc(slices.Clone(after.Columns),
		func(c schemadump.ColumnShape) bool { return c.Name == "brand_id" })
	withoutAdded.Indexes = slices.DeleteFunc(slices.Clone(after.Indexes),
		func(i schemadump.IndexShape) bool { return i.Name == "idx_clients_brand_id" })
	withoutAdded.ForeignKeys = slices.DeleteFunc(slices.Clone(after.ForeignKeys),
		func(f schemadump.ForeignKeyShape) bool { return f.Column == "brand_id" })
	if len(withoutAdded.ForeignKeys) == 0 && before.ForeignKeys == nil {
		// clients had no foreign key before on this engine, which the dump reads as none at all.
		withoutAdded.ForeignKeys = nil
	}
	assert.Equalf(t, before, withoutAdded,
		"[%s] 000090 must add the column, its foreign key and its index and touch nothing else of clients on %s",
		phase, dbType())
}
