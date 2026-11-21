package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clientJSONMembers is the "client" object of an admin API answer as raw JSON members, so a test
// tells a member that is absent from one that is empty.
func clientJSONMembers(t *testing.T, resp *http.Response) map[string]interface{} {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var answer struct {
		Client map[string]interface{} `json:"client"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&answer))
	require.NotNil(t, answer.Client)
	return answer.Client
}

// tokenEndpointAuthMethodOf is the tokenEndpointAuthMethod member of the admin API's client detail,
// failing the test when the member is absent or not a string.
func tokenEndpointAuthMethodOf(t *testing.T, accessToken string, clientID int64) string {
	t.Helper()
	client := clientJSONMembers(t, makeAPIRequest(t, http.MethodGet,
		appConfig.AuthServer.BaseURL+"/api/v1/admin/clients/"+strconv.FormatInt(clientID, 10), accessToken, nil))
	return stringMember(t, client)
}

func stringMember(t *testing.T, client map[string]interface{}) string {
	t.Helper()
	value, present := client["tokenEndpointAuthMethod"]
	require.True(t, present, "the client response carries tokenEndpointAuthMethod: %v", client)
	method, isString := value.(string)
	require.True(t, isString, "tokenEndpointAuthMethod is a string: %v", value)
	return method
}

// selfRegisteredClientID is the id of the client a registration created.
func selfRegisteredClientID(t *testing.T, clientIdentifier string) int64 {
	t.Helper()
	client, err := database.GetClientByClientIdentifier(context.Background(), nil, clientIdentifier)
	require.NoError(t, err)
	require.NotNil(t, client)
	return client.ID
}

// The admin API's client response carries the method a self-registered confidential client is
// held to, client_secret_basic, the default, or client_secret_post, and the empty string for a
// client not held to one: a self-registered public client and a client an administrator created
// (#708 decision 5).
func TestAPIClient_TokenEndpointAuthMethodIsTheRegisteredOne(t *testing.T) {
	enableDCR(t)
	accessToken, _ := createAdminClientWithToken(t)

	for _, row := range []struct {
		named string
		want  string
	}{
		{"client_secret_basic", "client_secret_basic"},
		{"client_secret_post", "client_secret_post"},
		{"", "client_secret_basic"},
	} {
		t.Run("registered naming "+row.named, func(t *testing.T) {
			clientIdentifier, _ := registerConfidentialClient(t, row.named)
			assert.Equal(t, row.want, tokenEndpointAuthMethodOf(t, accessToken, selfRegisteredClientID(t, clientIdentifier)))
		})
	}

	t.Run("a self-registered public client", func(t *testing.T) {
		resp := makeDCRRequest(t, oidc.DynamicClientRegistrationRequest{
			TokenEndpointAuthMethod: "none",
			RedirectURIs:            []string{"http://127.0.0.1:8765/callback"},
			ClientName:              "Public, held to no method",
		})
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		var registered oidc.DynamicClientRegistrationResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&registered))
		clientID := selfRegisteredClientID(t, registered.ClientID)
		t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, clientID) })

		assert.Empty(t, tokenEndpointAuthMethodOf(t, accessToken, clientID))
	})

	t.Run("a client an administrator created", func(t *testing.T) {
		resp := makeAPIRequest(t, http.MethodPost, appConfig.AuthServer.BaseURL+"/api/v1/admin/clients", accessToken,
			api.CreateClientRequest{ClientIdentifier: "admin-created-" + strings.ToLower(fake.LetterN(8)),
				Description: "created by an administrator", ClientCredentialsEnabled: true})
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		var created api.CreateClientResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
		t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, created.Client.ID) })

		assert.Empty(t, tokenEndpointAuthMethodOf(t, accessToken, created.Client.ID))
	})
}

// The clients list carries the method too: it is the same client response.
func TestAPIClients_ListCarriesTheRegisteredMethod(t *testing.T) {
	enableDCR(t)
	accessToken, _ := createAdminClientWithToken(t)
	clientIdentifier, _ := registerConfidentialClient(t, "client_secret_post")

	resp := makeAPIRequest(t, http.MethodGet, appConfig.AuthServer.BaseURL+"/api/v1/admin/clients", accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var list struct {
		Clients []map[string]interface{} `json:"clients"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&list))
	for _, client := range list.Clients {
		if client["clientIdentifier"] == clientIdentifier {
			assert.Equal(t, "client_secret_post", stringMember(t, client))
			return
		}
	}
	t.Fatalf("the list holds no client %s", clientIdentifier)
}

// A self-registered client switched to public through the admin API is answered with the empty
// method, by the switch itself and by every read after it, switched back to confidential included
// (#708 decision 5, Assumed: the switch to public clears it).
func TestAPIClient_TheSwitchToPublicClearsTheMethodShown(t *testing.T) {
	enableDCR(t)
	accessToken, _ := createAdminClientWithToken(t)
	clientIdentifier, _ := registerConfidentialClient(t, "client_secret_post")
	clientID := selfRegisteredClientID(t, clientIdentifier)
	require.Equal(t, "client_secret_post", tokenEndpointAuthMethodOf(t, accessToken, clientID))
	authenticationURL := appConfig.AuthServer.BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(clientID, 10) + "/authentication"

	switched := clientJSONMembers(t, makeAPIRequest(t, http.MethodPut, authenticationURL, accessToken,
		api.UpdateClientAuthenticationRequest{IsPublic: true}))
	assert.Empty(t, stringMember(t, switched), "the switch's own answer")
	assert.Empty(t, tokenEndpointAuthMethodOf(t, accessToken, clientID), "a read after the switch")

	back := clientJSONMembers(t, makeAPIRequest(t, http.MethodPut, authenticationURL, accessToken,
		api.UpdateClientAuthenticationRequest{IsPublic: false, ClientSecret: strings.Repeat("s", 60)}))
	assert.Empty(t, stringMember(t, back), "switched back to confidential")
}
