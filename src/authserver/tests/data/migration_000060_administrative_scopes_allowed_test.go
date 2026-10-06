package datatests

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/data/schemadump"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two versions migration 000060 sits between. Literals, as for 000059: nothing in production
// code names this number.
const (
	beforeAdministrativeScopesAllowed000060 = 59
	administrativeScopesAllowed000060       = 60
)

// TestMigration000060_AdministrativeScopesAllowed exercises the migration that adds a client's
// allowance to request the administrative scopes (#499 decisions 3 and 8), against a REAL engine
// of the configured dialect (see migration_testdb_helper_test.go).
//
// The properties, in order:
//
//  1. clients.administrative_scopes_allowed is absent at 000059, and once 000060 has run it is the
//     only thing about the table that moved: NOT NULL, defaulting to false, with the very shape
//     created_via_dcr has on the same engine, the other yes/no column 000029 added to this table.
//     A default of true would allow every client a later writer forgets to set.
//
//  2. The backfill, against rows that predate the column. After an upgrade the admin console's
//     client, matched by its built-in identifier, is allowed and no other client is: not one
//     differing from it only by case or by a suffix, and not an ordinary client, which the seed
//     below stores as allowed at head so that the not-allowed it reads afterwards is the
//     migration's doing rather than the seed's.
//
//  3. The down migration restores the table to exactly the shape 000059 built, and 000060
//     applies again after it with the same backfill.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000060_AdministrativeScopesAllowed
func TestMigration000060_AdministrativeScopesAllowed(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	// FORWARD to 000059 from an empty database, never down to it, so that `before` is what the
	// chain built and not what 000060's own down wrote.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeAdministrativeScopesAllowed000060),
		"migrate an empty database up to 000059 on %s", dbType())

	// 1. Absent before, then the one column added.
	before := dumpTable(t, h, "clients")
	_, exists := schemadump.TableShape(before).Column("administrative_scopes_allowed")
	require.Falsef(t, exists, "clients.administrative_scopes_allowed must not exist at 000059 on %s", dbType())

	require.NoErrorf(t, h.Migrator.Migrate(ctx, administrativeScopesAllowed000060), "apply 000060 on %s", dbType())
	assertAdministrativeScopesAllowedShape000060(t, h, before, "after apply")

	// 2. The backfill, against rows that predate the column. Seeded through the ORM at head, then
	// carried down to 000059 and back up, as 000029's test does and for its reason: the ORM writes
	// every column the record carries, so seeding at 000060 would break the moment a later
	// migration adds one.
	if err := h.Migrator.Up(ctx); err != nil && !errors.Is(err, migrator.ErrNoChange) {
		require.NoError(t, err, "migrate to head before seeding through the ORM")
	}

	random := fake.LetterN(6)
	cases := []struct {
		identifier   string
		storedAtHead bool
		want         bool
		why          string
	}{
		{"admin-console-client", false, true,
			"the admin console's client, by its built-in identifier, is the one client allowed after an upgrade"},
		{"Admin-Console-Client", false, false,
			"client identifiers are case-sensitive (RFC 6749 section 1.9), so this is another client"},
		{"admin-console-client-" + random, false, false,
			"the match is the whole identifier, not a prefix"},
		{"reporting_" + random, true, false,
			"every other client starts not allowed, whatever it held before the column was re-added"},
	}

	ids := make([]int64, len(cases))
	for i, c := range cases {
		client := &record.Client{
			ClientIdentifier:            c.identifier,
			Description:                 "Migration 000060 test client",
			AdministrativeScopesAllowed: c.storedAtHead,
		}
		require.NoErrorf(t, h.DB.CreateClient(ctx, nil, client), "seed client %s on %s", c.identifier, dbType())
		ids[i] = client.Id
	}

	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeAdministrativeScopesAllowed000060), "roll back to 000059 on %s", dbType())

	// 3. Down restores the shape 000059 built, and the clients are still there.
	assert.Equalf(t, before, dumpTable(t, h, "clients"),
		"000060's down must restore clients to the shape 000059 built on %s", dbType())

	require.NoErrorf(t, h.Migrator.Migrate(ctx, administrativeScopesAllowed000060), "re-apply 000060 on %s", dbType())
	assertAdministrativeScopesAllowedShape000060(t, h, before, "after a down/up round trip")

	for i, c := range cases {
		assert.Equalf(t, c.want, readAdministrativeScopesAllowed000060(t, h, ids[i]),
			"%s: administrative_scopes_allowed on %s, because %s", c.identifier, dbType(), c.why)
	}
}

// assertAdministrativeScopesAllowedShape000060 holds clients to the shape 000059 built plus one
// column, and that column to created_via_dcr's type, nullability and default on the same engine:
// both are a yes/no defaulting to no, and comparing against the engine's own spelling of one is
// what keeps this from carrying four per-engine literals.
func assertAdministrativeScopesAllowedShape000060(t *testing.T, h *isolatedDB, before tableShape, phase string) {
	t.Helper()
	after := schemadump.TableShape(dumpTable(t, h, "clients"))

	added, ok := after.Column("administrative_scopes_allowed")
	require.Truef(t, ok, "[%s] clients.administrative_scopes_allowed must exist on %s", phase, dbType())
	sibling, ok := after.Column("created_via_dcr")
	require.Truef(t, ok, "[%s] clients.created_via_dcr must exist on %s", phase, dbType())

	assert.Falsef(t, added.Nullable, "[%s] clients.administrative_scopes_allowed must be NOT NULL on %s", phase, dbType())
	assert.Equalf(t, sibling.Type, added.Type, "[%s] type on %s", phase, dbType())
	assert.Truef(t, added.HasDefault, "[%s] clients.administrative_scopes_allowed must carry a default on %s", phase, dbType())
	assert.Equalf(t, sibling.Default, added.Default,
		"[%s] clients.administrative_scopes_allowed must default to false, as created_via_dcr does, on %s", phase, dbType())

	withoutAdded := after
	withoutAdded.Columns = slices.DeleteFunc(slices.Clone(after.Columns),
		func(c schemadump.ColumnShape) bool { return c.Name == "administrative_scopes_allowed" })
	assert.Equalf(t, schemadump.TableShape(before), withoutAdded,
		"[%s] 000060 must add the one column and touch nothing else of clients on %s", phase, dbType())
}

func readAdministrativeScopesAllowed000060(t *testing.T, h *isolatedDB, clientId int64) bool {
	t.Helper()
	var allowed bool
	q := fmt.Sprintf("SELECT administrative_scopes_allowed FROM clients WHERE id = %d", clientId)
	require.NoErrorf(t, h.SQL.QueryRow(q).Scan(&allowed), "read clients.administrative_scopes_allowed on %s", dbType())
	return allowed
}
