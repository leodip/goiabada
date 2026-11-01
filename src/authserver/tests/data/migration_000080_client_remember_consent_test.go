package datatests

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/data/schemadump"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two versions migration 000080 sits between. Literals: nothing in production code names this
// number.
const (
	beforeClientRememberConsent000080 = 79
	clientRememberConsent000080       = 80
)

// TestMigration000080_ClientRememberConsent exercises the migration that gives every client its
// Remember consent setting (#711 decisions 4 and 7), against a real engine of the configured
// dialect.
//
//  1. clients.remember_consent is absent at 000079, and once 000080 has run it is the only thing
//     about clients that moved: NOT NULL, defaulting to off, with the shape created_via_dcr has on
//     the same engine. A default of on would let a public row inserted without the column skip the
//     consent screen.
//  2. The backfill, against rows that predate the column: every confidential client is on and every
//     public client is off, whatever each held before. The seed below stores the opposite of the
//     expected value at head, so the value read afterwards is the migration's doing.
//  3. A row inserted without the column reads off.
//  4. The down migration restores clients to exactly the shape 000079 built, and 000080 applies
//     again after it with the same backfill.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000080_ClientRememberConsent
func TestMigration000080_ClientRememberConsent(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	// Forward to 000079 from an empty database, so that `before` is what the chain built and not
	// what 000080's own down wrote.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeClientRememberConsent000080),
		"migrate an empty database up to 000079 on %s", dbType())

	before := dumpTable(t, h, "clients")
	_, exists := schemadump.TableShape(before).Column("remember_consent")
	require.Falsef(t, exists, "clients.remember_consent must not exist at 000079 on %s", dbType())

	require.NoErrorf(t, h.Migrator.Migrate(ctx, clientRememberConsent000080), "apply 000080 on %s", dbType())
	assertClientRememberConsentShape000080(t, h, before, "after apply")

	// Seeded through the data layer at head, then carried down to 000079 and back up: the data
	// layer writes every column the record carries, so seeding at 000080 would break the moment a
	// later migration adds one.
	if err := h.Migrator.Up(ctx); err != nil && !errors.Is(err, migrator.ErrNoChange) {
		require.NoError(t, err, "migrate to head before seeding through the data layer")
	}

	random := fake.LetterN(6)
	cases := []struct {
		identifier   string
		isPublic     bool
		storedAtHead bool
		want         bool
		why          string
	}{
		{"confidential_" + random, false, false, true,
			"a confidential client's earlier consent skips the screen as before the upgrade"},
		{"admin-console-client", false, false, true,
			"the admin console's client is confidential and is set on with every other confidential client"},
		{"public_" + random, true, true, false,
			"a public client cannot prove its identity, so every existing one starts off (RFC 8252 section 8.6)"},
		{"public_off_" + random, true, false, false,
			"a public client already off stays off"},
	}

	ids := make([]int64, len(cases))
	for i, c := range cases {
		client := &record.Client{
			ClientIdentifier: c.identifier,
			Description:      "Migration 000080 test client",
			IsPublic:         c.isPublic,
			RememberConsent:  c.storedAtHead,
		}
		require.NoErrorf(t, h.DB.CreateClient(ctx, nil, client), "seed client %s on %s", c.identifier, dbType())
		ids[i] = client.Id
	}

	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeClientRememberConsent000080), "roll back to 000079 on %s", dbType())
	assert.Equalf(t, before, dumpTable(t, h, "clients"),
		"000080's down must restore clients to the shape 000079 built on %s", dbType())

	require.NoErrorf(t, h.Migrator.Migrate(ctx, clientRememberConsent000080), "re-apply 000080 on %s", dbType())
	assertClientRememberConsentShape000080(t, h, before, "after a down/up round trip")

	for i, c := range cases {
		assert.Equalf(t, c.want, readClientRememberConsent000080(t, h, ids[i]),
			"%s: remember_consent on %s, because %s", c.identifier, dbType(), c.why)
	}

	// A row inserted without the column fails closed for a public client: it reads off.
	identifier := "public_unset_" + random
	_, err := h.SQL.Exec(fmt.Sprintf(
		"INSERT INTO clients (client_identifier, description, display_name, enabled, consent_required, "+
			"is_public, authorization_code_enabled, client_credentials_enabled, token_expiration_in_seconds, "+
			"refresh_token_offline_idle_timeout_in_seconds, refresh_token_offline_max_lifetime_in_seconds, "+
			"include_open_id_connect_claims_in_access_token, include_open_id_connect_claims_in_id_token, "+
			"default_acr_level) VALUES ('%s', '', '', %s, %s, %s, %s, %s, 0, 0, 0, 'default', 'default', '')",
		identifier, sqlBool000080(true), sqlBool000080(false), sqlBool000080(true), sqlBool000080(true),
		sqlBool000080(false)))
	require.NoErrorf(t, err, "insert a public client without remember_consent on %s", dbType())
	inserted, err := h.DB.GetClientByClientIdentifier(ctx, nil, identifier)
	require.NoError(t, err)
	require.NotNil(t, inserted)
	assert.Falsef(t, inserted.RememberConsent,
		"a row inserted without remember_consent must default to off on %s", dbType())
}

// assertClientRememberConsentShape000080 holds clients to the shape 000079 built plus one column,
// and that column to created_via_dcr's type, nullability and default on the same engine: both are
// a yes/no defaulting to no.
func assertClientRememberConsentShape000080(t *testing.T, h *isolatedDB, before tableShape, phase string) {
	t.Helper()
	after := schemadump.TableShape(dumpTable(t, h, "clients"))

	added, ok := after.Column("remember_consent")
	require.Truef(t, ok, "[%s] clients.remember_consent must exist on %s", phase, dbType())
	sibling, ok := after.Column("created_via_dcr")
	require.Truef(t, ok, "[%s] clients.created_via_dcr must exist on %s", phase, dbType())

	assert.Falsef(t, added.Nullable, "[%s] clients.remember_consent must be NOT NULL on %s", phase, dbType())
	assert.Equalf(t, sibling.Type, added.Type, "[%s] type on %s", phase, dbType())
	assert.Truef(t, added.HasDefault, "[%s] clients.remember_consent must carry a default on %s", phase, dbType())
	assert.Equalf(t, sibling.Default, added.Default,
		"[%s] clients.remember_consent must default to off, as created_via_dcr does, on %s", phase, dbType())

	withoutAdded := after
	withoutAdded.Columns = slices.DeleteFunc(slices.Clone(after.Columns),
		func(c schemadump.ColumnShape) bool { return c.Name == "remember_consent" })
	assert.Equalf(t, schemadump.TableShape(before), withoutAdded,
		"[%s] 000080 must add the one column and touch nothing else of clients on %s", phase, dbType())
}

func readClientRememberConsent000080(t *testing.T, h *isolatedDB, clientId int64) bool {
	t.Helper()
	var remember bool
	q := fmt.Sprintf("SELECT remember_consent FROM clients WHERE id = %d", clientId)
	require.NoErrorf(t, h.SQL.QueryRow(q).Scan(&remember), "read clients.remember_consent on %s", dbType())
	return remember
}

// sqlBool000080 spells a boolean literal every engine accepts for its yes/no column type.
func sqlBool000080(v bool) string {
	if dbType() == data.Postgres {
		if v {
			return "true"
		}
		return "false"
	}
	if v {
		return "1"
	}
	return "0"
}
