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

// The two versions migration 000087 sits between. Literals: nothing in production code names this
// number.
const (
	beforeClientDPoP000087 = 86
	clientDPoP000087       = 87
)

// TestMigration000087_ClientDPoPBoundAccessTokens exercises the migration that gives every client
// its "Require DPoP for token requests" setting (#42 decision 12, RFC 9449 section 5.2's
// dpop_bound_access_tokens), against a real engine of the configured dialect.
//
//  1. clients.dpop_bound_access_tokens is absent at 000086, and once 000087 has run it is the only
//     thing about clients that moved: NOT NULL, defaulting to off, with remember_consent's type and
//     default on the same engine. A default of on would refuse every existing client's token
//     requests without a proof.
//  2. A client that predates the column reads off, and so does a row inserted without it.
//  3. CreateClient writes it and every reader of a client row reads it back, both ways round;
//     SetClientDPoPBoundAccessTokens switches it on the one client it names, and the whole-row
//     UpdateClient writes it in neither direction.
//  4. The down migration restores clients to exactly the shape 000086 built, and 000087 applies
//     again after it.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000087_ClientDPoPBoundAccessTokens
func TestMigration000087_ClientDPoPBoundAccessTokens(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeClientDPoP000087),
		"migrate an empty database up to 000086 on %s", dbType())

	before := dumpTable(t, h, "clients")
	_, exists := schemadump.TableShape(before).Column("dpop_bound_access_tokens")
	require.Falsef(t, exists, "clients.dpop_bound_access_tokens must not exist at 000086 on %s", dbType())

	// A client that predates the column, inserted in SQL because the data layer at head names it.
	existing := "predates_dpop_" + fake.LetterN(6)
	insertClientWithoutDPoP000087(t, h, existing)

	require.NoErrorf(t, h.Migrator.Migrate(ctx, clientDPoP000087), "apply 000087 on %s", dbType())
	assertClientDPoPShape000087(t, h, before, "after apply")

	// The round trips write through the data layer, which writes every column the record carries,
	// so they run at head.
	if err := h.Migrator.Up(ctx); err != nil && !errors.Is(err, migrator.ErrNoChange) {
		require.NoError(t, err, "migrate to head for the round trips")
	}

	predating, err := h.DB.GetClientByClientIdentifier(ctx, nil, existing)
	require.NoError(t, err)
	require.NotNil(t, predating)
	assert.False(t, predating.DPoPBoundAccessTokens, "a client that predates 000087 does not require DPoP")

	insertedWithout := "inserted_without_dpop_" + fake.LetterN(6)
	insertClientWithoutDPoP000087(t, h, insertedWithout)
	without, err := h.DB.GetClientByClientIdentifier(ctx, nil, insertedWithout)
	require.NoError(t, err)
	require.NotNil(t, without)
	assert.False(t, without.DPoPBoundAccessTokens, "a row inserted without the column does not require DPoP")

	requiring := &record.Client{ClientIdentifier: "requires_dpop_" + fake.LetterN(6), DefaultAcrLevel: record.AcrLevel1,
		DPoPBoundAccessTokens: true}
	notRequiring := &record.Client{ClientIdentifier: "no_dpop_" + fake.LetterN(6), DefaultAcrLevel: record.AcrLevel1}
	require.NoError(t, h.DB.CreateClient(ctx, nil, requiring))
	require.NoError(t, h.DB.CreateClient(ctx, nil, notRequiring))
	want := map[int64]bool{requiring.Id: true, notRequiring.Id: false}

	for id, w := range want {
		byId, readErr := h.DB.GetClientById(ctx, nil, id)
		require.NoError(t, readErr)
		require.NotNil(t, byId)
		assert.Equalf(t, w, byId.DPoPBoundAccessTokens, "GetClientById(%d)", id)
		byIdentifier, readErr := h.DB.GetClientByClientIdentifier(ctx, nil, byId.ClientIdentifier)
		require.NoError(t, readErr)
		require.NotNil(t, byIdentifier)
		assert.Equalf(t, w, byIdentifier.DPoPBoundAccessTokens, "GetClientByClientIdentifier(%q)", byId.ClientIdentifier)
	}
	byIds, err := h.DB.GetClientsByIds(ctx, nil, []int64{requiring.Id, notRequiring.Id})
	require.NoError(t, err)
	require.Len(t, byIds, 2)
	for _, c := range byIds {
		assert.Equalf(t, want[c.Id], c.DPoPBoundAccessTokens, "GetClientsByIds, client %d", c.Id)
	}
	all, err := h.DB.GetAllClients(ctx, nil)
	require.NoError(t, err)
	seen := 0
	for _, c := range all {
		if w, ok := want[c.Id]; ok {
			seen++
			assert.Equalf(t, w, c.DPoPBoundAccessTokens, "GetAllClients, client %d", c.Id)
		}
	}
	assert.Equal(t, 2, seen, "GetAllClients answers both clients")

	// The whole-row save carries it in neither direction: the other client saves write the row
	// from a copy read earlier in their request, which would write back a setting switched since.
	for _, stored := range []*record.Client{requiring, notRequiring} {
		read, readErr := h.DB.GetClientById(ctx, nil, stored.Id)
		require.NoError(t, readErr)
		read.DPoPBoundAccessTokens = !want[stored.Id]
		read.Description = "rewritten_" + fake.LetterN(6)
		require.NoError(t, h.DB.UpdateClient(ctx, nil, read))
		updated, readErr := h.DB.GetClientById(ctx, nil, stored.Id)
		require.NoError(t, readErr)
		assert.Equalf(t, want[stored.Id], updated.DPoPBoundAccessTokens, "UpdateClient must not write dpop_bound_access_tokens")
		assert.Equal(t, read.Description, updated.Description, "and still writes the ordinary columns")
	}

	// The setter switches the one client it names, both ways, and nothing else of it.
	for _, on := range []bool{true, false, false, true} {
		require.NoError(t, h.DB.SetClientDPoPBoundAccessTokens(ctx, nil, notRequiring.Id, on))
		got, readErr := h.DB.GetClientById(ctx, nil, notRequiring.Id)
		require.NoError(t, readErr)
		assert.Equalf(t, on, got.DPoPBoundAccessTokens, "the target after switching to %v", on)
		assert.Equal(t, notRequiring.ClientIdentifier, got.ClientIdentifier)
		bystander, readErr := h.DB.GetClientById(ctx, nil, requiring.Id)
		require.NoError(t, readErr)
		assert.True(t, bystander.DPoPBoundAccessTokens, "the client not switched is left as it was")
	}

	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeClientDPoP000087), "roll back to 000086 on %s", dbType())
	assert.Equalf(t, before, dumpTable(t, h, "clients"),
		"000087's down must restore clients to the shape 000086 built on %s", dbType())

	require.NoErrorf(t, h.Migrator.Migrate(ctx, clientDPoP000087), "re-apply 000087 on %s", dbType())
	assertClientDPoPShape000087(t, h, before, "after a down/up round trip")
}

// assertClientDPoPShape000087 holds clients to the shape 000086 built plus the one column, with
// remember_consent's type, collation and default (false) on the same engine, the default named on
// SQL Server.
func assertClientDPoPShape000087(t *testing.T, h *isolatedDB, before tableShape, phase string) {
	t.Helper()
	after := schemadump.TableShape(dumpTable(t, h, "clients"))

	sibling, ok := after.Column("remember_consent")
	require.Truef(t, ok, "[%s] clients.remember_consent must exist on %s", phase, dbType())
	column, ok := after.Column("dpop_bound_access_tokens")
	require.Truef(t, ok, "[%s] clients.dpop_bound_access_tokens must exist on %s", phase, dbType())
	assert.Falsef(t, column.Nullable, "[%s] dpop_bound_access_tokens must be NOT NULL on %s", phase, dbType())
	assert.Equalf(t, sibling.Type, column.Type, "[%s] dpop_bound_access_tokens type on %s", phase, dbType())
	assert.Equalf(t, sibling.Collation, column.Collation, "[%s] dpop_bound_access_tokens collation on %s", phase, dbType())
	assert.Truef(t, column.HasDefault, "[%s] dpop_bound_access_tokens must carry a default on %s", phase, dbType())
	assert.Equalf(t, sibling.Default, column.Default, "[%s] dpop_bound_access_tokens must default to false on %s", phase, dbType())
	if dbType() == data.MSSQL {
		assert.Equalf(t, "df_clients_dpop_bound_access_tokens", column.DefaultName,
			"[%s] the default constraint is named, so the down can drop it", phase)
	}

	withoutAdded := after
	withoutAdded.Columns = slices.DeleteFunc(slices.Clone(after.Columns),
		func(c schemadump.ColumnShape) bool { return c.Name == "dpop_bound_access_tokens" })
	assert.Equalf(t, schemadump.TableShape(before), withoutAdded,
		"[%s] 000087 must add the one column and touch nothing else of clients on %s", phase, dbType())
}

// insertClientWithoutDPoP000087 inserts a client in SQL, naming none of the columns that have a
// default, dpop_bound_access_tokens among them.
func insertClientWithoutDPoP000087(t *testing.T, h *isolatedDB, identifier string) {
	t.Helper()
	falseValue, trueValue := sqlBool000080(false), sqlBool000080(true)
	_, err := h.SQL.Exec(fmt.Sprintf(
		"INSERT INTO clients (client_identifier, description, display_name, enabled, consent_required, "+
			"is_public, authorization_code_enabled, client_credentials_enabled, token_expiration_in_seconds, "+
			"refresh_token_offline_idle_timeout_in_seconds, refresh_token_offline_max_lifetime_in_seconds, "+
			"include_open_id_connect_claims_in_access_token, include_open_id_connect_claims_in_id_token, "+
			"default_acr_level) VALUES ('%s', '', '', %s, %s, %s, %s, %s, 0, 0, 0, 'default', 'default', '')",
		identifier, trueValue, falseValue, falseValue, trueValue, falseValue))
	require.NoErrorf(t, err, "insert a client without dpop_bound_access_tokens on %s", dbType())
}
