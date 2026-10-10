package datatests

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two versions migration 000061 sits between. Literals, as for 000060: nothing in production
// code names this number.
const (
	beforeDCRLegacyFlowsOff000061 = 60
	dcrLegacyFlowsOff000061       = 61
)

// TestMigration000061_DCRClientsLegacyFlowsOff exercises the backfill that turns the two legacy
// flows off on self-registered clients registered before the registration handler started writing
// them off, against a REAL engine of the configured dialect (see migration_testdb_helper_test.go).
// Until it ran, such a client's NULL switches followed the global settings, so turning implicit or
// ROPC on under Admin, General handed it to every self-registered client (#542 review).
//
// The properties:
//
//  1. A self-registered client with both switches NULL ends with both off.
//  2. A value an administrator chose on a self-registered client, on or off, is kept.
//  3. A client created in the admin console keeps its NULLs: for it NULL means "follow the global
//     setting", which the console offers.
//  4. The down migration changes nothing, and 000061 applies again after it.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000061_DCRClientsLegacyFlowsOff
func TestMigration000061_DCRClientsLegacyFlowsOff(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	// Seeded through the ORM at head, then carried down to 000060 and back up, as 000060's test
	// does and for its reason: the ORM writes every column the record carries, so seeding at
	// 000060 would break the moment a later migration adds one. 000061's down is a no-op, so the
	// rows keep what the seed wrote until the up runs again.
	if err := h.Migrator.Up(ctx); err != nil && !errors.Is(err, migrator.ErrNoChange) {
		require.NoError(t, err, "migrate to head before seeding through the ORM")
	}

	on, off := true, false
	random := fake.LetterN(6)
	cases := []struct {
		identifier   string
		createdByDCR bool
		implicit     *bool
		ropc         *bool
		wantImplicit sql.NullBool
		wantROPC     sql.NullBool
		why          string
	}{
		{"dcr_unset_" + random, true, nil, nil,
			sql.NullBool{Valid: true, Bool: false}, sql.NullBool{Valid: true, Bool: false},
			"a self-registered client registered before the fix gets both legacy flows off"},
		{"dcr_implicit_on_" + random, true, &on, nil,
			sql.NullBool{Valid: true, Bool: true}, sql.NullBool{Valid: true, Bool: false},
			"an administrator who turned implicit on for a reviewed client keeps it; the unset ROPC goes off"},
		{"dcr_ropc_off_" + random, true, nil, &off,
			sql.NullBool{Valid: true, Bool: false}, sql.NullBool{Valid: true, Bool: false},
			"an explicit off stays off"},
		{"console_" + random, false, nil, nil,
			sql.NullBool{}, sql.NullBool{},
			"a client created in the admin console keeps following the global settings"},
	}

	ids := make([]int64, len(cases))
	for i, c := range cases {
		client := &record.Client{
			ClientIdentifier:                        c.identifier,
			Description:                             "Migration 000061 test client",
			CreatedViaDCR:                           c.createdByDCR,
			ImplicitGrantEnabled:                    c.implicit,
			ResourceOwnerPasswordCredentialsEnabled: c.ropc,
		}
		require.NoErrorf(t, h.DB.CreateClient(ctx, nil, client), "seed client %s on %s", c.identifier, dbType())
		ids[i] = client.Id
	}

	// 4. Down to 000060 changes nothing: the seeded values are still what the seed wrote.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeDCRLegacyFlowsOff000061), "roll back to 000060 on %s", dbType())
	for i, c := range cases {
		implicit, ropc := readLegacyFlowSwitches000061(t, h, ids[i])
		assert.Equalf(t, nullBoolOf(c.implicit), implicit, "%s: implicit after the no-op down on %s", c.identifier, dbType())
		assert.Equalf(t, nullBoolOf(c.ropc), ropc, "%s: ROPC after the no-op down on %s", c.identifier, dbType())
	}

	// 1 to 3. The up's backfill.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, dcrLegacyFlowsOff000061), "apply 000061 on %s", dbType())
	for i, c := range cases {
		implicit, ropc := readLegacyFlowSwitches000061(t, h, ids[i])
		assert.Equalf(t, c.wantImplicit, implicit, "%s: implicit_grant_enabled on %s, because %s", c.identifier, dbType(), c.why)
		assert.Equalf(t, c.wantROPC, ropc, "%s: resource_owner_password_credentials_enabled on %s, because %s", c.identifier, dbType(), c.why)
	}
}

func nullBoolOf(b *bool) sql.NullBool {
	if b == nil {
		return sql.NullBool{}
	}
	return sql.NullBool{Valid: true, Bool: *b}
}

func readLegacyFlowSwitches000061(t *testing.T, h *isolatedDB, clientId int64) (sql.NullBool, sql.NullBool) {
	t.Helper()
	var implicit, ropc sql.NullBool
	q := fmt.Sprintf("SELECT implicit_grant_enabled, resource_owner_password_credentials_enabled FROM clients WHERE id = %d", clientId)
	require.NoErrorf(t, h.SQL.QueryRow(q).Scan(&implicit, &ropc), "read the legacy flow switches on %s", dbType())
	return implicit, ropc
}
