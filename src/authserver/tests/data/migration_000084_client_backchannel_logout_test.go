package datatests

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/data/schemadump"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two versions migration 000084 sits between. Literals: nothing in production code names this
// number.
const (
	beforeClientBackchannelLogout000084 = 83
	clientBackchannelLogout000084       = 84
)

// columns000084 are the two columns 000084 adds to clients (#784 decision 14).
var columns000084 = []string{"backchannel_logout_uri", "backchannel_logout_session_required"}

// TestMigration000084_ClientBackchannelLogout exercises the migration that gives a client its
// back-channel logout URI and whether it requires the session identifier (#784 decision 14),
// against a real engine of the configured dialect.
//
//  1. Both columns are absent at 000083, and once 000084 has run they are the only thing about
//     clients that moved: each NOT NULL with a default. The URI takes the empty string, with the
//     type and collation of post_logout_redirect_uris.uri on the same engine, the 2048-wide URI it
//     is bounded like; the flag defaults to false, with remember_consent's type and default.
//  2. A client written without them reads back neither, and one written with them reads them back
//     byte for byte through CreateClient and GetClientById, at 2048 bytes. SetClientBackchannelLogout
//     changes both on the one client, and the whole-row UpdateClient writes neither.
//  3. The down migration restores clients to exactly the shape 000083 built, and 000084 applies
//     again after it.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000084_ClientBackchannelLogout
func TestMigration000084_ClientBackchannelLogout(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeClientBackchannelLogout000084),
		"migrate an empty database up to 000083 on %s", dbType())

	before := dumpTable(t, h, "clients")
	for _, column := range columns000084 {
		_, exists := schemadump.TableShape(before).Column(column)
		require.Falsef(t, exists, "clients.%s must not exist at 000083 on %s", column, dbType())
	}

	require.NoErrorf(t, h.Migrator.Migrate(ctx, clientBackchannelLogout000084), "apply 000084 on %s", dbType())
	assertClientBackchannelLogoutShape000084(t, h, before, "after apply")

	// The round trips write through the ORM, which writes every column the record carries, so they
	// run at head.
	if err := h.Migrator.Up(ctx); err != nil && !errors.Is(err, migrator.ErrNoChange) {
		require.NoError(t, err, "migrate to head for the round trips")
	}

	without := &record.Client{ClientIdentifier: "no-backchannel-" + fake.LetterN(6), DefaultAcrLevel: record.AcrLevel1}
	require.NoError(t, h.DB.CreateClient(ctx, nil, without))
	read, err := h.DB.GetClientById(ctx, nil, without.Id)
	require.NoError(t, err)
	require.NotNil(t, read)
	assert.Empty(t, read.BackchannelLogoutURI, "a client written without a back-channel logout URI reads back none")
	assert.False(t, read.BackchannelLogoutSessionRequired, "a client written without the flag reads it back off")

	// 2048 bytes, the bound, with a query kept as registered.
	prefix := "https://app.example.com/backchannel-logout?tenant=a&x="
	uri := prefix + strings.Repeat("y", 2048-len(prefix))
	with := &record.Client{
		ClientIdentifier:                 "with-backchannel-" + fake.LetterN(6),
		DefaultAcrLevel:                  record.AcrLevel1,
		BackchannelLogoutURI:             uri,
		BackchannelLogoutSessionRequired: true,
	}
	require.NoError(t, h.DB.CreateClient(ctx, nil, with))
	read, err = h.DB.GetClientById(ctx, nil, with.Id)
	require.NoError(t, err)
	require.NotNil(t, read)
	assert.Equal(t, uri, read.BackchannelLogoutURI)
	assert.True(t, read.BackchannelLogoutSessionRequired)

	// The whole-row save carries neither, in either direction.
	read.BackchannelLogoutURI = "http://app.internal:3000/written-back"
	read.BackchannelLogoutSessionRequired = false
	read.Description = "rewritten-" + fake.LetterN(6)
	require.NoError(t, h.DB.UpdateClient(ctx, nil, read))
	updated, err := h.DB.GetClientById(ctx, nil, with.Id)
	require.NoError(t, err)
	assert.Equal(t, uri, updated.BackchannelLogoutURI, "UpdateClient must not write backchannel_logout_uri")
	assert.True(t, updated.BackchannelLogoutSessionRequired, "UpdateClient must not write backchannel_logout_session_required")
	assert.Equal(t, read.Description, updated.Description, "and still writes the ordinary columns")

	// The setter changes both on its client, and leaves the other client alone.
	require.NoError(t, h.DB.SetClientBackchannelLogout(ctx, nil, without.Id, "https://other.example.com/bcl", true))
	require.NoError(t, h.DB.SetClientBackchannelLogout(ctx, nil, with.Id, "", false))
	cleared, err := h.DB.GetClientById(ctx, nil, with.Id)
	require.NoError(t, err)
	assert.Empty(t, cleared.BackchannelLogoutURI, "SetClientBackchannelLogout clears the URI")
	assert.False(t, cleared.BackchannelLogoutSessionRequired, "SetClientBackchannelLogout turns the flag off")
	assert.Equal(t, updated.Description, cleared.Description, "SetClientBackchannelLogout writes nothing else")
	other, err := h.DB.GetClientById(ctx, nil, without.Id)
	require.NoError(t, err)
	assert.Equal(t, "https://other.example.com/bcl", other.BackchannelLogoutURI)
	assert.True(t, other.BackchannelLogoutSessionRequired)

	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeClientBackchannelLogout000084), "roll back to 000083 on %s", dbType())
	assert.Equalf(t, before, dumpTable(t, h, "clients"),
		"000084's down must restore clients to the shape 000083 built on %s", dbType())

	require.NoErrorf(t, h.Migrator.Migrate(ctx, clientBackchannelLogout000084), "re-apply 000084 on %s", dbType())
	assertClientBackchannelLogoutShape000084(t, h, before, "after a down/up round trip")
}

// assertClientBackchannelLogoutShape000084 holds clients to the shape 000083 built plus the two
// columns: the URI to post_logout_redirect_uris.uri's type and collation, defaulting to ” as
// website_url does, and the flag to remember_consent's type and default (false) on the same engine,
// each default named on SQL Server.
func assertClientBackchannelLogoutShape000084(t *testing.T, h *isolatedDB, before tableShape, phase string) {
	t.Helper()
	after := schemadump.TableShape(dumpTable(t, h, "clients"))

	uriSibling, ok := schemadump.TableShape(dumpTable(t, h, "post_logout_redirect_uris")).Column("uri")
	require.Truef(t, ok, "[%s] post_logout_redirect_uris.uri must exist on %s", phase, dbType())
	emptyDefault, ok := after.Column("website_url")
	require.Truef(t, ok, "[%s] clients.website_url must exist on %s", phase, dbType())
	flagSibling, ok := after.Column("remember_consent")
	require.Truef(t, ok, "[%s] clients.remember_consent must exist on %s", phase, dbType())

	uri, ok := after.Column("backchannel_logout_uri")
	require.Truef(t, ok, "[%s] clients.backchannel_logout_uri must exist on %s", phase, dbType())
	assert.Falsef(t, uri.Nullable, "[%s] backchannel_logout_uri must be NOT NULL on %s", phase, dbType())
	assert.Equalf(t, uriSibling.Type, uri.Type, "[%s] backchannel_logout_uri type on %s", phase, dbType())
	assert.Equalf(t, uriSibling.Collation, uri.Collation, "[%s] backchannel_logout_uri collation on %s", phase, dbType())
	assert.Truef(t, uri.HasDefault, "[%s] backchannel_logout_uri must carry a default on %s", phase, dbType())
	assert.Equalf(t, emptyDefault.Default, uri.Default, "[%s] backchannel_logout_uri must default to '' on %s", phase, dbType())

	flag, ok := after.Column("backchannel_logout_session_required")
	require.Truef(t, ok, "[%s] clients.backchannel_logout_session_required must exist on %s", phase, dbType())
	assert.Falsef(t, flag.Nullable, "[%s] backchannel_logout_session_required must be NOT NULL on %s", phase, dbType())
	assert.Equalf(t, flagSibling.Type, flag.Type, "[%s] backchannel_logout_session_required type on %s", phase, dbType())
	assert.Truef(t, flag.HasDefault, "[%s] backchannel_logout_session_required must carry a default on %s", phase, dbType())
	assert.Equalf(t, flagSibling.Default, flag.Default, "[%s] backchannel_logout_session_required must default to false on %s", phase, dbType())
	assert.Equalf(t, flagSibling.Collation, flag.Collation, "[%s] backchannel_logout_session_required collation on %s", phase, dbType())

	if dbType() == data.MSSQL {
		for _, column := range columns000084 {
			added, _ := after.Column(column)
			assert.Equalf(t, "df_clients_"+column, added.DefaultName,
				"[%s] clients.%s's default constraint is named, so the down can drop it", phase, column)
		}
	}

	withoutAdded := after
	withoutAdded.Columns = slices.DeleteFunc(slices.Clone(after.Columns),
		func(c schemadump.ColumnShape) bool { return slices.Contains(columns000084, c.Name) })
	assert.Equalf(t, schemadump.TableShape(before), withoutAdded,
		"[%s] 000084 must add the two columns and touch nothing else of clients on %s", phase, dbType())
}
