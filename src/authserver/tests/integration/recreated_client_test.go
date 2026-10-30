package integration

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/require"
)

// A deleted client's tokens never work again (#676 decision 6), a new client taking its identifier
// included. An access token names its client only by client_id, and a token of the client
// credentials grant or the implicit flow has no grant whose deletion would end it, so without the
// recorded deletion the token would work again, with its old scopes, under the new client. Both
// tokens below are obtained, the client deleted and recreated through the admin API within the same
// second as a rule, and the token then refused at the bearer guard and inactive at introspection.

// recreateThroughAdminAPI creates a client with the identifier through the admin API, as a new
// client taking a deleted one's identifier, and returns it, removed when the test ends.
func recreateThroughAdminAPI(t *testing.T, adminToken string, deleted *record.Client) *record.Client {
	t.Helper()
	resp := makeAPIRequest(t, http.MethodPost, appConfig.AuthServer.BaseURL+"/api/v1/admin/clients", adminToken,
		api.CreateClientRequest{ClientIdentifier: deleted.ClientIdentifier, AuthorizationCodeEnabled: true})
	_ = resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	replacement, err := database.GetClientByClientIdentifier(context.Background(), nil, deleted.ClientIdentifier)
	require.NoError(t, err)
	require.NotNil(t, replacement)
	require.NotEqual(t, deleted.Id, replacement.Id, "the replacement is another client")
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, replacement.Id) })
	return replacement
}

func TestRecreatedClient_AClientCredentialsTokenOfTheDeletedClientStaysRefused(t *testing.T) {
	manager, _ := createAdminClientWithToken(t)
	accessToken, original, _ := createAdminClientWithTokenAndSecret(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, original.Id) })
	observer := authserverAPI(t)
	const target = "/api/v1/admin/resources"
	assertAPIAdmitsToken(t, target, accessToken)
	assertActive(t, observer.introspect(t, accessToken))

	deleteThroughAdminAPI(t, manager, fmt.Sprintf("/api/v1/admin/clients/%d", original.Id))
	assertAPIRefusesToken(t, target, accessToken)
	assertInactive(t, observer.introspect(t, accessToken))

	recreateThroughAdminAPI(t, manager, original)

	assertAPIRefusesToken(t, target, accessToken)
	assertInactive(t, observer.introspect(t, accessToken))
}

func TestRecreatedClient_AnImplicitFlowTokenOfTheDeletedClientStaysRefused(t *testing.T) {
	manager, _ := createAdminClientWithToken(t)
	enableImplicitFlowGlobally(t)
	implicitEnabled := true
	client, redirectUri := createImplicitFlowClient(t, &implicitEnabled)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	user, password := createTestUserForImplicit(t)
	resp := signInToIssue(t, createHttpClient(t),
		implicitModeAuthorizeURL(client, redirectUri.URI, "token", "", fake.LetterN(12), ""), user, password)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	accessToken := getTokensFromFragment(t, resp)["access_token"]
	require.NotEmpty(t, accessToken)
	require.NotContains(t, decodeJWTPayload(t, accessToken), "grant_id", "an implicit-flow token has no grant")
	observer := authserverAPI(t)
	assertUserinfoAdmits(t, accessToken, user.Subject)
	assertActive(t, observer.introspect(t, accessToken))

	deleteThroughAdminAPI(t, manager, fmt.Sprintf("/api/v1/admin/clients/%d", client.Id))
	assertUserinfoRefusesTheToken(t, accessToken)
	assertInactive(t, observer.introspect(t, accessToken))

	recreateThroughAdminAPI(t, manager, client)

	assertUserinfoRefusesTheToken(t, accessToken)
	assertInactive(t, observer.introspect(t, accessToken))
}
