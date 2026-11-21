package datatests

import (
	"context"
	"database/sql"
	"errors"
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

// The two versions migration 000096 sits between. Literals: nothing in production code names this
// number.
const (
	beforeClientAuthMethod000096 = 95
	clientAuthMethod000096       = 96
)

// TestMigration000096_ClientTokenEndpointAuthMethod exercises the migration that stores the
// token_endpoint_auth_method a confidential client registered through dynamic client registration
// (#708 decision 3), against a real engine of the configured dialect.
//
//  1. clients.token_endpoint_auth_method is absent at 000095, and once 000096 has run it is the
//     only thing about clients that moved: NOT NULL, defaulting to the empty string, a client not
//     held to one method, with website_url's collation and default on the same engine.
//  2. A client that predates the column reads the empty string: nothing is backfilled.
//  3. CreateClient writes it and every reader of a client row reads it back; the whole-row
//     UpdateClient writes it in neither direction.
//  4. The switch to public clears it in the same write, on the transition only, and on the one
//     client switched; the switch back to confidential, a whole-row save, leaves it empty.
//  5. The down migration restores clients to exactly the shape 000095 built, and 000096 applies
//     again after it.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000096_ClientTokenEndpointAuthMethod
func TestMigration000096_ClientTokenEndpointAuthMethod(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeClientAuthMethod000096),
		"migrate an empty database up to 000095 on %s", dbType())

	before := dumpTable(t, h, "clients")
	_, exists := schemadump.TableShape(before).Column("token_endpoint_auth_method")
	require.Falsef(t, exists, "clients.token_endpoint_auth_method must not exist at 000095 on %s", dbType())

	// A client that predates the column, inserted in SQL because the data layer at head names it.
	existing := "predates_auth_method_" + fake.LetterN(6)
	insertClientWithoutDPoP000087(t, h, existing)

	require.NoErrorf(t, h.Migrator.Migrate(ctx, clientAuthMethod000096), "apply 000096 on %s", dbType())
	assertClientAuthMethodShape000096(t, h, before, "after apply")

	// The round trips write through the data layer, which writes every column the record carries,
	// so they run at head.
	if err := h.Migrator.Up(ctx); err != nil && !errors.Is(err, migrator.ErrNoChange) {
		require.NoError(t, err, "migrate to head for the round trips")
	}

	predating, err := h.DB.GetClientByClientIdentifier(ctx, nil, existing)
	require.NoError(t, err)
	require.NotNil(t, predating)
	assert.Empty(t, predating.TokenEndpointAuthMethod, "a client that predates 000096 is not held to one method")

	basic := createAuthMethodClient000096(t, h, false, "client_secret_basic")
	post := createAuthMethodClient000096(t, h, false, "client_secret_post")
	either := createAuthMethodClient000096(t, h, false, "")
	want := map[int64]string{basic.ID: "client_secret_basic", post.ID: "client_secret_post", either.ID: ""}

	for id, w := range want {
		byID, readErr := h.DB.GetClientByID(ctx, nil, id)
		require.NoError(t, readErr)
		require.NotNil(t, byID)
		assert.Equalf(t, w, byID.TokenEndpointAuthMethod, "GetClientByID(%d)", id)
		byIdentifier, readErr := h.DB.GetClientByClientIdentifier(ctx, nil, byID.ClientIdentifier)
		require.NoError(t, readErr)
		require.NotNil(t, byIdentifier)
		assert.Equalf(t, w, byIdentifier.TokenEndpointAuthMethod, "GetClientByClientIdentifier(%q)", byID.ClientIdentifier)
	}
	byIDs, err := h.DB.GetClientsByIDs(ctx, nil, []int64{basic.ID, post.ID, either.ID})
	require.NoError(t, err)
	require.Len(t, byIDs, 3)
	for _, c := range byIDs {
		assert.Equalf(t, want[c.ID], c.TokenEndpointAuthMethod, "GetClientsByIDs, client %d", c.ID)
	}
	all, err := h.DB.GetAllClients(ctx, nil)
	require.NoError(t, err)
	seen := 0
	for _, c := range all {
		if w, ok := want[c.ID]; ok {
			seen++
			assert.Equalf(t, w, c.TokenEndpointAuthMethod, "GetAllClients, client %d", c.ID)
		}
	}
	assert.Equal(t, 3, seen, "GetAllClients answers the three clients")

	// The whole-row save carries it in neither direction: the other client saves write the row
	// from a copy read earlier in their request, which would write back a method cleared since.
	carried := map[int64]string{basic.ID: "", post.ID: "client_secret_basic", either.ID: "client_secret_post"}
	for id, other := range carried {
		read, readErr := h.DB.GetClientByID(ctx, nil, id)
		require.NoError(t, readErr)
		read.TokenEndpointAuthMethod = other
		read.Description = "rewritten_" + fake.LetterN(6)
		require.NoError(t, h.DB.UpdateClient(ctx, nil, read))
		updated, readErr := h.DB.GetClientByID(ctx, nil, id)
		require.NoError(t, readErr)
		assert.Equalf(t, want[id], updated.TokenEndpointAuthMethod,
			"UpdateClient must not write token_endpoint_auth_method: stored %q, the save carried %q", want[id], other)
		assert.Equal(t, read.Description, updated.Description, "and still writes the ordinary columns")
	}

	// The switch to public clears it in the write that makes the client public, and on that
	// client alone.
	becamePublic := makeClientPublic000096(t, h, post.ID)
	assert.True(t, becamePublic, "a confidential client switched to public is the transition")
	switched, err := h.DB.GetClientByID(ctx, nil, post.ID)
	require.NoError(t, err)
	assert.True(t, switched.IsPublic)
	assert.Empty(t, switched.TokenEndpointAuthMethod, "the switch to public clears the registered method")
	bystander, err := h.DB.GetClientByID(ctx, nil, basic.ID)
	require.NoError(t, err)
	assert.Equal(t, "client_secret_basic", bystander.TokenEndpointAuthMethod, "the client not switched keeps its method")

	// Switched back to confidential, by the whole-row save the authentication save makes, the
	// method stays empty: the client authenticates either way from then on.
	switched.IsPublic = false
	switched.ClientSecretEncrypted = []byte("a-new-secret")
	switched.TokenEndpointAuthMethod = "client_secret_post"
	require.NoError(t, h.DB.UpdateClient(ctx, nil, switched))
	back, err := h.DB.GetClientByID(ctx, nil, post.ID)
	require.NoError(t, err)
	assert.False(t, back.IsPublic)
	assert.Empty(t, back.TokenEndpointAuthMethod, "a client switched back to confidential is not held to one method")

	// A save of a client already public is no transition and writes nothing of it. No writer gives
	// a public client a method, so the row is made here to show the clearing is the transition's.
	alreadyPublic := createAuthMethodClient000096(t, h, true, "client_secret_basic")
	assert.False(t, makeClientPublic000096(t, h, alreadyPublic.ID), "an already-public client is no transition")
	kept, err := h.DB.GetClientByID(ctx, nil, alreadyPublic.ID)
	require.NoError(t, err)
	assert.Equal(t, "client_secret_basic", kept.TokenEndpointAuthMethod, "only the transition clears the method")

	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeClientAuthMethod000096), "roll back to 000095 on %s", dbType())
	assert.Equalf(t, before, dumpTable(t, h, "clients"),
		"000096's down must restore clients to the shape 000095 built on %s", dbType())

	require.NoErrorf(t, h.Migrator.Migrate(ctx, clientAuthMethod000096), "re-apply 000096 on %s", dbType())
	assertClientAuthMethodShape000096(t, h, before, "after a down/up round trip")
}

// assertClientAuthMethodShape000096 holds clients to the shape 000095 built plus the one column: a
// short NOT NULL text column with website_url's collation and empty default on the same engine, the
// default named on SQL Server.
func assertClientAuthMethodShape000096(t *testing.T, h *isolatedDB, before tableShape, phase string) {
	t.Helper()
	after := schemadump.TableShape(dumpTable(t, h, "clients"))

	wantType := map[data.Dialect]string{
		data.SQLite:   "TEXT",
		data.MySQL:    "varchar(64)",
		data.Postgres: "character varying(64)",
		data.MSSQL:    "nvarchar(64)",
	}[dbType()]

	sibling, ok := after.Column("website_url")
	require.Truef(t, ok, "[%s] clients.website_url must exist on %s", phase, dbType())
	column, ok := after.Column("token_endpoint_auth_method")
	require.Truef(t, ok, "[%s] clients.token_endpoint_auth_method must exist on %s", phase, dbType())
	assert.Falsef(t, column.Nullable, "[%s] token_endpoint_auth_method must be NOT NULL on %s", phase, dbType())
	assert.Equalf(t, wantType, column.Type, "[%s] token_endpoint_auth_method type on %s", phase, dbType())
	assert.Equalf(t, sibling.Collation, column.Collation, "[%s] token_endpoint_auth_method collation on %s", phase, dbType())
	assert.Truef(t, column.HasDefault, "[%s] token_endpoint_auth_method must carry a default on %s", phase, dbType())
	if dbType() == data.Postgres {
		assert.Equalf(t, "''::character varying", column.Default, "[%s] token_endpoint_auth_method must default to empty", phase)
	} else {
		assert.Equalf(t, sibling.Default, column.Default, "[%s] token_endpoint_auth_method must default to empty on %s", phase, dbType())
	}
	if dbType() == data.MSSQL {
		assert.Equalf(t, "df_clients_token_endpoint_auth_method", column.DefaultName,
			"[%s] the default constraint is named, so the down can drop it", phase)
	}

	withoutAdded := after
	withoutAdded.Columns = slices.DeleteFunc(slices.Clone(after.Columns),
		func(c schemadump.ColumnShape) bool { return c.Name == "token_endpoint_auth_method" })
	assert.Equalf(t, schemadump.TableShape(before), withoutAdded,
		"[%s] 000096 must add the one column and touch nothing else of clients on %s", phase, dbType())
}

func createAuthMethodClient000096(t *testing.T, h *isolatedDB, isPublic bool, method string) *record.Client {
	t.Helper()
	client := &record.Client{
		ClientIdentifier:        "auth_method_" + fake.LetterN(8),
		DefaultACRLevel:         record.ACRLevel1,
		IsPublic:                isPublic,
		TokenEndpointAuthMethod: method,
	}
	require.NoError(t, h.DB.CreateClient(context.Background(), nil, client))
	return client
}

func makeClientPublic000096(t *testing.T, h *isolatedDB, clientID int64) bool {
	t.Helper()
	var becamePublic bool
	require.NoError(t, h.DB.RunInTransaction(context.Background(), func(tx *sql.Tx) error {
		var err error
		becamePublic, err = h.DB.SetClientPublic(context.Background(), tx, clientID)
		return err
	}))
	return becamePublic
}
