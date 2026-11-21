package integration

import (
	"context"
	"net/http"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/require"
)

// Every access token names the client row it was issued to in client_internal_id, and is refused
// once another client holds the identifier its client_id names (#710 decisions 8 and 9). A token of
// the client credentials grant or the implicit flow has no grant a rename revokes, and a client
// created before the token passes the creation-time rule, so without the binding an older client
// renamed to the identifier a rename gave up would pass the earlier client's tokens as its own.
//
// Each test shows the token working first, then refused for its liveness: inactive at
// introspection and answered as an invalid token at the bearer guard, which a refusal for
// insufficient scope is not.

// createOlderClient creates an enabled confidential client, before the token of the test is
// issued, to take another client's identifier later; it is removed when the test ends.
func createOlderClient(t *testing.T) *record.Client {
	t.Helper()
	client := &record.Client{
		ClientIdentifier: "older-client-" + fake.LetterN(8),
		Enabled:          true,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.ID) })
	return client
}

// assertNamesClientRow asserts the access token names the client's row in client_internal_id.
func assertNamesClientRow(t *testing.T, accessToken string, client *record.Client) {
	t.Helper()
	claims := decodeJWTPayload(t, accessToken)
	require.Equal(t, client.ClientIdentifier, claims["client_id"])
	clientInternalID, ok := claims["client_internal_id"].(float64)
	require.True(t, ok, "the token carries client_internal_id as a number")
	require.Equal(t, client.ID, int64(clientInternalID), "the token names its client's row")
}

func TestClientRowBinding_AClientCredentialsTokenIsRefusedOnceAnOlderClientTakesItsIdentifier(t *testing.T) {
	manager, _ := createAdminClientWithToken(t)
	older := createOlderClient(t)
	accessToken, original, _ := createAdminClientWithTokenAndSecret(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, original.ID) })
	observer := authserverAPI(t)
	const target = "/api/v1/admin/resources"
	assertNamesClientRow(t, accessToken, original)
	assertAPIAdmitsToken(t, target, accessToken)
	assertActive(t, observer.introspect(t, accessToken))

	saveClientSettings(t, manager, original.ID, renamedIdentifier())
	saveClientSettings(t, manager, older.ID, original.ClientIdentifier)

	assertAPIRefusesToken(t, target, accessToken)
	assertInactive(t, observer.introspect(t, accessToken))
}

func TestClientRowBinding_AClientCredentialsTokenIsRefusedOnceANewClientTakesItsIdentifier(t *testing.T) {
	manager, _ := createAdminClientWithToken(t)
	accessToken, original, _ := createAdminClientWithTokenAndSecret(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, original.ID) })
	observer := authserverAPI(t)
	const target = "/api/v1/admin/resources"
	assertNamesClientRow(t, accessToken, original)
	assertAPIAdmitsToken(t, target, accessToken)
	assertActive(t, observer.introspect(t, accessToken))

	saveClientSettings(t, manager, original.ID, renamedIdentifier())
	recreateThroughAdminAPI(t, manager, original)

	assertAPIRefusesToken(t, target, accessToken)
	assertInactive(t, observer.introspect(t, accessToken))
}

// UserInfo serves no client's token, so a user's token from the implicit flow stands for it: it has
// no grant either.
func TestClientRowBinding_AnImplicitFlowTokenIsRefusedOnceAnOlderClientTakesItsIdentifier(t *testing.T) {
	manager, _ := createAdminClientWithToken(t)
	enableImplicitFlowGlobally(t)
	older := createOlderClient(t)
	implicitEnabled := true
	client, redirectURI := createImplicitFlowClient(t, &implicitEnabled)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.ID) })
	user, password := createTestUserForImplicit(t)
	resp := signInToIssue(t, createHTTPClient(t),
		implicitModeAuthorizeURL(client, redirectURI.URI, "token", "", fake.LetterN(12), ""), user, password)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	accessToken := getTokensFromFragment(t, resp)["access_token"]
	require.NotEmpty(t, accessToken)
	require.NotContains(t, decodeJWTPayload(t, accessToken), "grant_id", "an implicit-flow token has no grant")
	assertNamesClientRow(t, accessToken, client)
	observer := authserverAPI(t)
	assertUserinfoAdmits(t, accessToken, user.Subject)
	assertActive(t, observer.introspect(t, accessToken))

	saveClientSettings(t, manager, client.ID, renamedIdentifier())
	saveClientSettings(t, manager, older.ID, client.ClientIdentifier)

	assertUserinfoRefusesTheToken(t, accessToken)
	assertInactive(t, observer.introspect(t, accessToken))
}

// A client renamed away from an identifier and back is still the row its tokens name: they are
// refused while no client holds the identifier and work again once it does again.
func TestClientRowBinding_AClientRenamedAwayAndBackKeepsItsOwnToken(t *testing.T) {
	manager, _ := createAdminClientWithToken(t)
	accessToken, original, _ := createAdminClientWithTokenAndSecret(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, original.ID) })
	observer := authserverAPI(t)
	const target = "/api/v1/admin/resources"
	assertAPIAdmitsToken(t, target, accessToken)

	saveClientSettings(t, manager, original.ID, renamedIdentifier())
	assertAPIRefusesToken(t, target, accessToken)
	assertInactive(t, observer.introspect(t, accessToken))

	saveClientSettings(t, manager, original.ID, original.ClientIdentifier)
	assertAPIAdmitsToken(t, target, accessToken)
	assertActive(t, observer.introspect(t, accessToken))
}
