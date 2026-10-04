package datatests

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/schemadump"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two versions migration 000056 sits between. Literals, as for 000048: nothing in production
// code names this number.
const (
	beforeDropPreRegistrationPasswordHash000056 = 55
	dropPreRegistrationPasswordHash000056       = 56
)

// TestMigration000056_DropPreRegistrationPasswordHash exercises the migration that removes
// pre_registrations.password_hash (#207 decision 2), against a REAL engine of the configured
// dialect (see migration_testdb_helper_test.go). The password is chosen at activation now, so
// nothing writes or reads the column.
//
// The properties, in order:
//
//  1. The column is gone from the catalog once 000056 has run, and it is the only thing about the
//     table that moved. Read from the engine's own catalog rather than from a query failing.
//
//  2. A pending registration written BEFORE the drop reads back afterwards through the data layer
//     with its address and code hash intact, so a registration in progress at upgrade can still be
//     activated: its link resolves the row by that hash.
//
//  3. The down migration restores the table to exactly the shape 000055 built, the column's type,
//     nullability, collation and the absence of a default included, and fills the rows it finds
//     with an empty string. The shape comes back, never the values. Compared against the shape
//     read before the drop on this same engine rather than against a per-engine literal, as
//     000048's test does.
//
//  4. 000056 applies again after a round trip, which on SQL Server says the down left no default
//     constraint behind to block the drop.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000056_DropPreRegistrationPasswordHash
func TestMigration000056_DropPreRegistrationPasswordHash(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	// FORWARD to 000055 from an empty database, never down to it, so that `before` is what the
	// chain built and not what 000056's own down wrote (see 000048's test for the measured case).
	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeDropPreRegistrationPasswordHash000056),
		"migrate an empty database up to 000055 on %s", dbType())

	before := dumpTable(t, h, "pre_registrations")
	_, ok := schemadump.TableShape(before).Column("password_hash")
	require.Truef(t, ok,
		"pre_registrations.password_hash must exist at 000055 on %s, or this migration has nothing to drop and every assertion below is vacuous",
		dbType())

	// Seeded with SQL rather than through the data layer: the record carries no password field
	// any more, and the column is NOT NULL with no default at 000055.
	email := fake.UUID() + "@example.com"
	codeHash := hashutil.HashString(fake.UUID())
	_, err := h.SQL.Exec(fmt.Sprintf(
		`INSERT INTO pre_registrations (email, password_hash, verification_code_hash) VALUES ('%s', '%s', '%s')`,
		email, "a-stored-password-hash", codeHash))
	require.NoErrorf(t, err, "seed a pending registration at 000055 on %s", dbType())

	require.NoErrorf(t, h.Migrator.Migrate(ctx, dropPreRegistrationPasswordHash000056), "apply 000056 on %s", dbType())

	// 1. Gone, and nothing else moved.
	afterDrop := schemadump.TableShape(dumpTable(t, h, "pre_registrations"))
	_, stillThere := afterDrop.Column("password_hash")
	assert.Falsef(t, stillThere,
		"pre_registrations.password_hash is still in the catalog on %s after 000056", dbType())

	wantAfterDrop := schemadump.TableShape(before)
	wantAfterDrop.Columns = slices.DeleteFunc(slices.Clone(wantAfterDrop.Columns),
		func(c schemadump.ColumnShape) bool { return c.Name == "password_hash" })
	assert.Equalf(t, wantAfterDrop, afterDrop,
		"000056 must drop pre_registrations.password_hash and touch nothing else of the table on %s", dbType())

	// 2. The pending registration survives, found the way its link finds it.
	got, err := h.DB.GetPreRegistrationByVerificationCodeHash(ctx, nil, codeHash)
	require.NoErrorf(t, err, "read the pending registration back after the drop on %s", dbType())
	require.NotNilf(t, got, "the pending registration is gone on %s; this migration deletes no rows", dbType())
	assert.Equal(t, email, got.Email)
	assert.Equal(t, codeHash, got.VerificationCodeHash)

	// 3. Roll back: the table 000055 built, and the row's restored column holds an empty string,
	// never the hash it held before.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeDropPreRegistrationPasswordHash000056),
		"roll back 000056 on %s", dbType())

	assert.Equalf(t, before, dumpTable(t, h, "pre_registrations"),
		"000056's down must restore pre_registrations to the shape 000055 built on %s: the column's "+
			"type, nullability and collation, no default left behind, and every index", dbType())

	var restored string
	require.NoErrorf(t, h.SQL.QueryRow(fmt.Sprintf(
		`SELECT password_hash FROM pre_registrations WHERE email = '%s'`, email)).Scan(&restored),
		"read the restored column on %s", dbType())
	assert.Equalf(t, "", restored,
		"000056's down restores the shape, never the values: the row reads an empty string on %s", dbType())

	rolledBack, err := h.DB.GetPreRegistrationByVerificationCodeHash(ctx, nil, codeHash)
	require.NoErrorf(t, err, "read the pending registration back after the roll back on %s", dbType())
	require.NotNilf(t, rolledBack, "the roll back must keep the pending registration on %s", dbType())
	assert.Equal(t, email, rolledBack.Email)

	// 4. Forward again, which is what an operator who rolled back and retried does.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, dropPreRegistrationPasswordHash000056),
		"re-apply 000056 on %s after a down/up round trip", dbType())
	_, thereAgain := schemadump.TableShape(dumpTable(t, h, "pre_registrations")).Column("password_hash")
	assert.Falsef(t, thereAgain, "000056 must drop the column again after a round trip on %s", dbType())
}
