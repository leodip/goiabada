package datatests

import (
	"context"
	"errors"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two versions migration 000072 sits between. Literals, as for 000060: nothing in production
// code names this number.
const (
	beforeAdminConsoleSignOutRedirectURI000072 = 71
	adminConsoleSignOutRedirectURI000072       = 72
)

// TestMigration000072_AdminConsoleSignOutRedirectURI holds the upgrade that moves the admin
// console's base URL from its redirect URIs to its sign-out redirect URIs (#147 decision 8), against
// a REAL engine of the configured dialect (see migration_testdb_helper_test.go).
//
// For the client admin-console-client, a redirect URI moves when that URI followed by
// /auth/callback is also one of the client's redirect URIs, which is the shape the first start
// writes. It catches the old and the new URL after a URL change made as the docs describe. Nothing
// else moves: not the callback, not an unrelated row, not a partner differing in case or by a
// trailing space, and not another client's identical pair. The down migration moves the rows back,
// and 000072 applies again after it with the same result.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000072_AdminConsoleSignOutRedirectURI
func TestMigration000072_AdminConsoleSignOutRedirectURI(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	// Seeded through the data layer at head, then carried down to 000071, as 000060's test does: the
	// data layer writes every column the record carries, so seeding at 000071 would break the moment
	// a later migration adds one. Only redirect URIs are seeded, so 000072's own down, run on the way
	// to 000071, has nothing to move back.
	if err := h.Migrator.Up(ctx); err != nil && !errors.Is(err, migrator.ErrNoChange) {
		require.NoError(t, err, "migrate to head before seeding through the data layer")
	}

	console := &record.Client{ClientIdentifier: "admin-console-client"}
	require.NoError(t, h.DB.CreateClient(ctx, nil, console))
	other := &record.Client{ClientIdentifier: "portal-000072"}
	require.NoError(t, h.DB.CreateClient(ctx, nil, other))

	consoleRows := []string{
		"https://admin.example.com",
		"https://admin.example.com/auth/callback",
		// The URL before a change made as the docs describe: the old pair stays registered.
		"https://old-admin.example.com",
		"https://old-admin.example.com/auth/callback",
		// Added by an operator for another purpose, with no /auth/callback partner.
		"https://admin.example.com/landing",
		// Partners only when compared without case.
		"https://admin.example.com/Case",
		"https://admin.example.com/case/auth/callback",
		// Partners only when SQL Server pads the comparison.
		"https://padded.example.com",
		"https://padded.example.com/auth/callback ",
	}
	for _, uri := range consoleRows {
		require.NoError(t, h.DB.CreateRedirectURI(ctx, nil, &record.RedirectURI{ClientId: console.Id, URI: uri}))
	}
	for _, uri := range []string{"https://admin.example.com", "https://admin.example.com/auth/callback"} {
		require.NoError(t, h.DB.CreateRedirectURI(ctx, nil, &record.RedirectURI{ClientId: other.Id, URI: uri}))
	}

	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeAdminConsoleSignOutRedirectURI000072), "roll back to 000071 on %s", dbType())
	unmoved := map[int64][]string{console.Id: consoleRows, other.Id: {"https://admin.example.com", "https://admin.example.com/auth/callback"}}
	assertAdminConsoleRows000072(t, h, console.Id, other.Id, unmoved, map[int64][]string{}, "at 000071")

	moved := map[int64][]string{
		console.Id: {
			"https://admin.example.com/auth/callback",
			"https://old-admin.example.com/auth/callback",
			"https://admin.example.com/landing",
			"https://admin.example.com/Case",
			"https://admin.example.com/case/auth/callback",
			"https://padded.example.com",
			"https://padded.example.com/auth/callback ",
		},
		other.Id: {"https://admin.example.com", "https://admin.example.com/auth/callback"},
	}
	signOut := map[int64][]string{console.Id: {"https://admin.example.com", "https://old-admin.example.com"}}

	require.NoErrorf(t, h.Migrator.Migrate(ctx, adminConsoleSignOutRedirectURI000072), "apply 000072 on %s", dbType())
	assertAdminConsoleRows000072(t, h, console.Id, other.Id, moved, signOut, "after apply")

	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeAdminConsoleSignOutRedirectURI000072), "roll back to 000071 on %s", dbType())
	assertAdminConsoleRows000072(t, h, console.Id, other.Id, unmoved, map[int64][]string{}, "after the down migration")

	require.NoErrorf(t, h.Migrator.Migrate(ctx, adminConsoleSignOutRedirectURI000072), "re-apply 000072 on %s", dbType())
	assertAdminConsoleRows000072(t, h, console.Id, other.Id, moved, signOut, "after a down/up round trip")
}

// assertAdminConsoleRows000072 holds both clients' redirect URIs and sign-out redirect URIs to the
// lists given, by client id, in any order. A client missing from a map has no rows in that table.
func assertAdminConsoleRows000072(t *testing.T, h *isolatedDB, consoleId, otherId int64,
	redirectURIs, signOutRedirectURIs map[int64][]string, when string) {
	t.Helper()
	ctx := context.Background()
	for _, clientId := range []int64{consoleId, otherId} {
		gotRedirect, err := h.DB.GetRedirectURIsByClientId(ctx, nil, clientId)
		require.NoError(t, err)
		uris := []string{}
		for _, row := range gotRedirect {
			uris = append(uris, row.URI)
		}
		assert.ElementsMatchf(t, append([]string{}, redirectURIs[clientId]...), uris,
			"client %d's redirect URIs %s on %s", clientId, when, dbType())

		gotSignOut, err := h.DB.GetPostLogoutRedirectURIsByClientId(ctx, nil, clientId)
		require.NoError(t, err)
		uris = []string{}
		for _, row := range gotSignOut {
			uris = append(uris, row.URI)
		}
		assert.ElementsMatchf(t, append([]string{}, signOutRedirectURIs[clientId]...), uris,
			"client %d's sign-out redirect URIs %s on %s", clientId, when, dbType())
	}
}
