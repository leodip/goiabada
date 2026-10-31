package datatests

import (
	"context"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A client's sign-out redirect URIs (#147 decision 2): the addresses a sign-out may send the browser
// back to, kept in post_logout_redirect_uris apart from the client's redirect URIs.

func createTestPostLogoutRedirectURI(t *testing.T, clientId int64, uri string) *record.PostLogoutRedirectURI {
	t.Helper()
	signOutURI := &record.PostLogoutRedirectURI{URI: uri, ClientId: clientId}
	require.NoError(t, database.CreatePostLogoutRedirectURI(context.Background(), nil, signOutURI), "CreatePostLogoutRedirectURI")
	return signOutURI
}

// storedPostLogoutRedirectURIs is the URIs a client's stored sign-out list holds, in no particular order.
func storedPostLogoutRedirectURIs(t *testing.T, clientId int64) []string {
	t.Helper()
	rows, err := database.GetPostLogoutRedirectURIsByClientId(context.Background(), nil, clientId)
	require.NoError(t, err, "GetPostLogoutRedirectURIsByClientId")
	uris := []string{}
	for _, row := range rows {
		assert.Equal(t, clientId, row.ClientId, "a client's rows name that client")
		uris = append(uris, row.URI)
	}
	return uris
}

// clientIdentifiersHolding is the identifiers of the clients the lookup answers for uri, in its order.
func clientIdentifiersHolding(t *testing.T, uri string) []string {
	t.Helper()
	clients, err := database.GetClientsByPostLogoutRedirectURI(context.Background(), nil, uri)
	require.NoError(t, err, "GetClientsByPostLogoutRedirectURI")
	identifiers := []string{}
	for _, client := range clients {
		identifiers = append(identifiers, client.ClientIdentifier)
	}
	return identifiers
}

func TestCreatePostLogoutRedirectURI(t *testing.T) {
	client := createTestClient(t)

	signOutURI := createTestPostLogoutRedirectURI(t, client.Id, "https://app.example/signed-out")
	assert.NotZero(t, signOutURI.Id, "the row's id is set")
	require.True(t, signOutURI.CreatedAt.Valid, "created_at is set")
	createTestPostLogoutRedirectURI(t, client.Id, "com.example.app:/signed-out?state=fixed")

	assert.ElementsMatch(t, []string{"https://app.example/signed-out", "com.example.app:/signed-out?state=fixed"},
		storedPostLogoutRedirectURIs(t, client.Id))

	rows, err := database.GetPostLogoutRedirectURIsByClientId(context.Background(), nil, client.Id)
	require.NoError(t, err)
	for _, row := range rows {
		if row.URI == "https://app.example/signed-out" {
			assert.Equal(t, signOutURI.Id, row.Id, "the row read back is the row written")
			assert.WithinDuration(t, signOutURI.CreatedAt.Time, row.CreatedAt.Time, time.Millisecond, "with its created_at")
		}
	}

	assert.Empty(t, storedPostLogoutRedirectURIs(t, createTestClient(t).Id), "another client lists nothing")
}

func TestCreatePostLogoutRedirectURI_RefusesAZeroClientId(t *testing.T) {
	err := database.CreatePostLogoutRedirectURI(context.Background(), nil,
		&record.PostLogoutRedirectURI{URI: "https://app.example/signed-out", ClientId: 0})
	require.Error(t, err, "a sign-out redirect URI of no client is refused")
}

// The list is kept apart from the redirect URIs: a row of one is never a row of the other.
func TestCreatePostLogoutRedirectURI_IsNotARedirectURI(t *testing.T) {
	client := createTestClient(t)
	createTestPostLogoutRedirectURI(t, client.Id, "https://app.example/signed-out")
	require.NoError(t, database.CreateRedirectURI(context.Background(), nil,
		&record.RedirectURI{URI: "https://app.example/callback", ClientId: client.Id}))

	redirectURIs, err := database.GetRedirectURIsByClientId(context.Background(), nil, client.Id)
	require.NoError(t, err)
	require.Len(t, redirectURIs, 1, "the sign-out redirect URI is not among the redirect URIs")
	assert.Equal(t, "https://app.example/callback", redirectURIs[0].URI)

	assert.Equal(t, []string{"https://app.example/signed-out"}, storedPostLogoutRedirectURIs(t, client.Id),
		"and the redirect URI is not among the sign-out redirect URIs")
}

// The column is as wide as redirect_uris.uri, and the admin API and registration bound an entry with
// the same byte bound (#147 decision 2).
func TestCreatePostLogoutRedirectURI_AURIAtTheBoundRoundTrips(t *testing.T) {
	for _, tc := range redirectURIsAtTheBound(t) {
		t.Run(tc.name, func(t *testing.T) {
			client := createTestClient(t)
			createTestPostLogoutRedirectURI(t, client.Id, tc.value)
			assert.Equal(t, []string{tc.value}, storedPostLogoutRedirectURIs(t, client.Id),
				"the sign-out redirect URI did not round-trip unchanged")
		})
	}
}

func TestDeletePostLogoutRedirectURI(t *testing.T) {
	client := createTestClient(t)
	other := createTestClient(t)
	createTestPostLogoutRedirectURI(t, client.Id, "https://app.example/kept")
	removed := createTestPostLogoutRedirectURI(t, client.Id, "https://app.example/removed")
	createTestPostLogoutRedirectURI(t, other.Id, "https://app.example/removed")

	require.NoError(t, database.DeletePostLogoutRedirectURI(context.Background(), nil, removed.Id))

	assert.Equal(t, []string{"https://app.example/kept"}, storedPostLogoutRedirectURIs(t, client.Id), "only that row went")
	assert.Equal(t, []string{"https://app.example/removed"}, storedPostLogoutRedirectURIs(t, other.Id),
		"another client's row of the same URI stays")
}

func TestClientLoadPostLogoutRedirectURIs(t *testing.T) {
	client := createTestClient(t)
	first := createTestPostLogoutRedirectURI(t, client.Id, "https://app.example/one")
	second := createTestPostLogoutRedirectURI(t, client.Id, "https://app.example/two")
	createTestPostLogoutRedirectURI(t, createTestClient(t).Id, "https://app.example/another-clients")

	require.NoError(t, database.ClientLoadPostLogoutRedirectURIs(context.Background(), nil, client))

	ids := []int64{}
	uris := []string{}
	for _, row := range client.PostLogoutRedirectURIs {
		ids = append(ids, row.Id)
		uris = append(uris, row.URI)
	}
	assert.ElementsMatch(t, []int64{first.Id, second.Id}, ids, "the client's own rows are loaded")
	assert.ElementsMatch(t, []string{"https://app.example/one", "https://app.example/two"}, uris)
	assert.Empty(t, client.RedirectURIs, "and the redirect URIs are left alone")

	require.NoError(t, database.ClientLoadPostLogoutRedirectURIs(context.Background(), nil, nil), "a nil client loads nothing")
}

func TestClientLoadPostLogoutRedirectURIs_AnEmptyListLoadsEmpty(t *testing.T) {
	client := createTestClient(t)
	client.PostLogoutRedirectURIs = []record.PostLogoutRedirectURI{{URI: "https://stale.example/"}}

	require.NoError(t, database.ClientLoadPostLogoutRedirectURIs(context.Background(), nil, client))
	assert.Empty(t, client.PostLogoutRedirectURIs, "a client with no sign-out redirect URIs loads none")
}

func TestPostLogoutRedirectURIs_CascadeWithTheirClient(t *testing.T) {
	client := createTestClient(t)
	other := createTestClient(t)
	createTestPostLogoutRedirectURI(t, client.Id, "https://app.example/signed-out")
	createTestPostLogoutRedirectURI(t, other.Id, "https://app.example/signed-out")

	require.NoError(t, database.DeleteClient(context.Background(), nil, client.Id))

	assert.Empty(t, storedPostLogoutRedirectURIs(t, client.Id), "post_logout_redirect_uris must cascade from clients")
	assert.Equal(t, []string{"https://app.example/signed-out"}, storedPostLogoutRedirectURIs(t, other.Id),
		"and only the deleted client's rows go")
}

// The lookup the prepared sign-out runs when the caller names no client (#147 decision 10): the
// clients whose sign-out list holds the URI, found in one query and matched exactly.
func TestGetClientsByPostLogoutRedirectURI(t *testing.T) {
	random := fake.LetterN(8)
	uri := "https://lookup-" + random + ".example/signed-out"

	t.Run("no client holds it", func(t *testing.T) {
		assert.Empty(t, clientIdentifiersHolding(t, uri))
	})

	first := createTestClient(t)
	createTestPostLogoutRedirectURI(t, first.Id, uri)
	createTestPostLogoutRedirectURI(t, first.Id, "https://lookup-"+random+".example/other")

	t.Run("one client holds it", func(t *testing.T) {
		clients, err := database.GetClientsByPostLogoutRedirectURI(context.Background(), nil, uri)
		require.NoError(t, err)
		require.Len(t, clients, 1)
		assert.Equal(t, first.Id, clients[0].Id)
		assert.Equal(t, first.ClientIdentifier, clients[0].ClientIdentifier)
		assert.Equal(t, "Test Client", clients[0].Description, "the whole client is read")
	})

	second := createTestClient(t)
	createTestPostLogoutRedirectURI(t, second.Id, uri)

	t.Run("several clients hold it, each once, in id order", func(t *testing.T) {
		assert.Equal(t, []string{first.ClientIdentifier, second.ClientIdentifier}, clientIdentifiersHolding(t, uri))
	})

	t.Run("a client holding it twice is answered once", func(t *testing.T) {
		createTestPostLogoutRedirectURI(t, second.Id, uri)
		assert.Equal(t, []string{first.ClientIdentifier, second.ClientIdentifier}, clientIdentifiersHolding(t, uri))
	})
}

// A redirect URI is not a sign-out redirect URI, so the lookup does not find a client by one.
func TestGetClientsByPostLogoutRedirectURI_ARedirectURIIsNotFound(t *testing.T) {
	uri := "https://lookup-" + fake.LetterN(8) + ".example/callback"
	client := createTestClient(t)
	require.NoError(t, database.CreateRedirectURI(context.Background(), nil, &record.RedirectURI{URI: uri, ClientId: client.Id}))

	assert.Empty(t, clientIdentifiersHolding(t, uri))
}

// The match is exact on every engine. SQL Server pads for `=`, and SQL Server and MySQL compare an
// NFC character equal to its decomposed spelling under every collation, so the engine's answer is
// rechecked in Go (see engineFoldedTheMatch). Case is compared by the pinned collation.
func TestGetClientsByPostLogoutRedirectURI_TheMatchIsExact(t *testing.T) {
	base := "https://lookup-" + fake.LetterN(8) + ".example/"
	for _, tc := range []struct {
		name   string
		stored string
		asked  string
	}{
		{"a trailing space asked", base + "bye", base + "bye "},
		{"a trailing space stored", base + "padded ", base + "padded"},
		{"another case", base + "Shout", base + "shout"},
		{"a decomposed accent asked", base + "caf\u00e9", base + "cafe\u0301"},
		{"a composed accent asked", base + "de\u0301cor", base + "d\u00e9cor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := createTestClient(t)
			createTestPostLogoutRedirectURI(t, client.Id, tc.stored)

			assert.Empty(t, clientIdentifiersHolding(t, tc.asked), "%q does not match %q", tc.asked, tc.stored)
			assert.Equal(t, []string{client.ClientIdentifier}, clientIdentifiersHolding(t, tc.stored),
				"while the stored value finds its client")
		})
	}
}

// Of two clients holding URIs that differ by a trailing space, each finds only its own.
func TestGetClientsByPostLogoutRedirectURI_ATrailingSpaceIsAnotherURI(t *testing.T) {
	uri := "https://lookup-" + fake.LetterN(8) + ".example/signed-out"
	bare := createTestClient(t)
	padded := createTestClient(t)
	createTestPostLogoutRedirectURI(t, bare.Id, uri)
	createTestPostLogoutRedirectURI(t, padded.Id, uri+" ")

	assert.Equal(t, []string{bare.ClientIdentifier}, clientIdentifiersHolding(t, uri))
	assert.Equal(t, []string{padded.ClientIdentifier}, clientIdentifiersHolding(t, uri+" "))
}
