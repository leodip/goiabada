package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/securerandom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The refusals of a client held to the method it registered (#708 decision 2), as the agreement
// words them.
const (
	registeredForBasicDescription = "Client authentication failed: this client is registered for client_secret_basic. Send the client_secret in the Authorization header."
	registeredForPostDescription  = "Client authentication failed: this client is registered for client_secret_post. Send the client_secret in the request body."
)

// clientAuthenticatingEndpoint is one of the three endpoints a client authenticates at, with the
// request that, once the client is authenticated, gets the answer accepted describes.
type clientAuthenticatingEndpoint struct {
	path string
	form url.Values
	// accepted is the status of an authenticated request, and description, when not empty, the
	// error_description it carries: a refusal that comes only after client authentication.
	accepted    int
	description string
}

// The token endpoint is asked to refresh without a refresh token: the refresh grant authenticates
// the client first, so the missing parameter is answered only once it is authenticated, whatever
// flows the client has. The revocation and introspection endpoints are given a string that is no
// token, which they answer 200 once the client is authenticated (RFC 7009 section 2.2, RFC 7662
// section 2.2).
var probeEndpoints = []clientAuthenticatingEndpoint{
	{path: "/auth/token/", form: url.Values{"grant_type": {"refresh_token"}},
		accepted: http.StatusBadRequest, description: "Missing required refresh_token parameter."},
	{path: "/auth/revoke", form: url.Values{"token": {"not-a-token"}}, accepted: http.StatusOK},
	{path: "/auth/introspect", form: url.Values{"token": {"not-a-token"}}, accepted: http.StatusOK},
}

// endpointAnswer is what an endpoint answered, the challenge and the error members included.
type endpointAnswer struct {
	status      int
	challenge   string
	errorCode   string
	description string
	body        string
}

// presentClientSecret posts form to path as the client, its secret in the Authorization header when
// basic is set and in the body otherwise.
func presentClientSecret(t *testing.T, path string, form url.Values, clientIdentifier, secret string, basic bool) endpointAnswer {
	t.Helper()
	values := url.Values{}
	for name, value := range form {
		values[name] = value
	}
	if !basic {
		values.Set("client_id", clientIdentifier)
		values.Set("client_secret", secret)
	}
	destURL := appConfig.AuthServer.BaseURL + path
	req, err := http.NewRequest(http.MethodPost, destURL, strings.NewReader(values.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", destURL)
	req.Header.Set("Origin", appConfig.AuthServer.BaseURL)
	if basic {
		req.SetBasicAuth(url.QueryEscape(clientIdentifier), url.QueryEscape(secret))
	}
	resp, err := createHTTPClient(t).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	answer := endpointAnswer{status: resp.StatusCode, challenge: resp.Header.Get("WWW-Authenticate"), body: string(raw)}
	var members map[string]interface{}
	if json.Unmarshal(raw, &members) == nil {
		answer.errorCode, _ = members["error"].(string)
		answer.description, _ = members["error_description"].(string)
	}
	return answer
}

// assertAuthenticated asserts the endpoint authenticated the client: the answer an authenticated
// request gets.
func assertAuthenticated(t *testing.T, endpoint clientAuthenticatingEndpoint, answer endpointAnswer) {
	t.Helper()
	require.Equal(t, endpoint.accepted, answer.status, "%s: %s", endpoint.path, answer.body)
	assert.Equal(t, endpoint.description, answer.description, endpoint.path)
}

// assertRefusedForTheMethod asserts the endpoint refused the client for the method it used: 401
// invalid_client with the Basic challenge and description.
func assertRefusedForTheMethod(t *testing.T, endpoint clientAuthenticatingEndpoint, answer endpointAnswer, description string) {
	t.Helper()
	require.Equal(t, http.StatusUnauthorized, answer.status, "%s: %s", endpoint.path, answer.body)
	assert.Equal(t, `Basic realm="goiabada"`, answer.challenge, endpoint.path)
	assert.Equal(t, "invalid_client", answer.errorCode, endpoint.path)
	assert.Equal(t, description, answer.description, endpoint.path)
}

// assertBothMethodsAuthenticate asserts the client is not held to one method: its secret
// authenticates it by the header and by the body at all three endpoints.
func assertBothMethodsAuthenticate(t *testing.T, clientIdentifier, secret string) {
	t.Helper()
	for _, endpoint := range probeEndpoints {
		for _, basic := range []bool{true, false} {
			assertAuthenticated(t, endpoint,
				presentClientSecret(t, endpoint.path, endpoint.form, clientIdentifier, secret, basic))
		}
	}
}

// registerConfidentialClient registers a confidential client for the client credentials grant,
// naming authMethod, or no method when it is empty, and returns its identifier and secret.
func registerConfidentialClient(t *testing.T, authMethod string) (string, string) {
	t.Helper()
	resp := makeDCRRequest(t, oidc.DynamicClientRegistrationRequest{
		TokenEndpointAuthMethod: authMethod,
		GrantTypes:              []string{"client_credentials"},
		ClientName:              "Held to " + authMethod,
	})
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var response oidc.DynamicClientRegistrationResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&response))
	require.NotEmpty(t, response.ClientSecret)
	t.Cleanup(func() {
		client, err := database.GetClientByClientIdentifier(context.Background(), nil, response.ClientID)
		if err == nil && client != nil {
			_ = database.DeleteClient(context.Background(), nil, client.ID)
		}
	})
	return response.ClientID, response.ClientSecret
}

// A confidential client that registered itself authenticates by the method it registered only,
// client_secret_basic when it named none, at the token, revocation and introspection endpoints. A
// secret sent the other way is refused 401 invalid_client with the Basic challenge, and the refusal
// is the same whether the secret is right or wrong, since it is never compared (#708 decisions 1
// and 2).
func TestDCR_AConfidentialClientIsHeldToTheMethodItRegistered(t *testing.T) {
	enableDCR(t)

	rows := []struct {
		name string
		// named is the method the registration names; empty names none.
		named string
		// basic is whether the registered method is the Authorization header.
		basic   bool
		refusal string
	}{
		{"client_secret_basic", "client_secret_basic", true, registeredForBasicDescription},
		{"client_secret_post", "client_secret_post", false, registeredForPostDescription},
		{"no method named, so client_secret_basic", "", true, registeredForBasicDescription},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			clientIdentifier, secret := registerConfidentialClient(t, row.named)

			for _, endpoint := range probeEndpoints {
				t.Run(endpoint.path, func(t *testing.T) {
					assertAuthenticated(t, endpoint,
						presentClientSecret(t, endpoint.path, endpoint.form, clientIdentifier, secret, row.basic))
					assertRefusedForTheMethod(t, endpoint,
						presentClientSecret(t, endpoint.path, endpoint.form, clientIdentifier, secret, !row.basic), row.refusal)
					assertRefusedForTheMethod(t, endpoint,
						presentClientSecret(t, endpoint.path, endpoint.form, clientIdentifier, "not-the-secret", !row.basic), row.refusal)
				})
			}
		})
	}
}

// The registered method gets a real token: a client held to client_secret_post is issued one by
// the client credentials grant with its secret in the body, and refused it by the header.
func TestDCR_AClientHeldToItsMethodIsIssuedATokenByIt(t *testing.T) {
	enableDCR(t)
	clientIdentifier, secret := registerConfidentialClient(t, "client_secret_post")
	client, err := database.GetClientByClientIdentifier(context.Background(), nil, clientIdentifier)
	require.NoError(t, err)
	resource := createResource(t)
	permission := createPermission(t, resource.ID)
	require.NoError(t, database.CreateClientPermission(context.Background(), nil,
		&record.ClientPermission{ClientID: client.ID, PermissionID: permission.ID}))
	form := url.Values{"grant_type": {"client_credentials"},
		"scope": {resource.ResourceIdentifier + ":" + permission.PermissionIdentifier}}

	issued := presentClientSecret(t, "/auth/token/", form, clientIdentifier, secret, false)
	require.Equal(t, http.StatusOK, issued.status, issued.body)
	assert.Contains(t, issued.body, `"access_token"`)

	refused := presentClientSecret(t, "/auth/token/", form, clientIdentifier, secret, true)
	assertRefusedForTheMethod(t, clientAuthenticatingEndpoint{path: "/auth/token/"}, refused, registeredForPostDescription)
}

// Clients not held to one method accept both at all three endpoints: a client an administrator
// created through the admin API, and the admin console's own client (#708, Done when).
func TestClientAuthentication_ClientsNotHeldToOneMethodAcceptBoth(t *testing.T) {
	t.Run("a client an administrator created", func(t *testing.T) {
		accessToken, _ := createAdminClientWithToken(t)
		resp := makeAPIRequest(t, http.MethodPost, appConfig.AuthServer.BaseURL+"/api/v1/admin/clients", accessToken,
			api.CreateClientRequest{ClientIdentifier: "admin-created-" + strings.ToLower(fake.LetterN(8)),
				Description: "created by an administrator", ClientCredentialsEnabled: true})
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		var created api.CreateClientResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
		t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, created.Client.ID) })

		assertBothMethodsAuthenticate(t, created.Client.ClientIdentifier, clientSecretThroughTheAdminAPI(t, accessToken, created.Client.ID))
	})

	t.Run("the admin console's client", func(t *testing.T) {
		client, err := database.GetClientByClientIdentifier(context.Background(), nil, "admin-console-client")
		require.NoError(t, err)
		require.NotNil(t, client)
		secret, err := dataCipher.Decrypt(client.ClientSecretEncrypted)
		require.NoError(t, err)

		assertBothMethodsAuthenticate(t, client.ClientIdentifier, secret)
	})
}

// A self-registered confidential client switched to public through the admin API loses its
// registered method, and switched back to confidential is not held to one: it accepts both (#708,
// Done when).
func TestDCR_AClientSwitchedToPublicAndBackAcceptsBoth(t *testing.T) {
	enableDCR(t)
	clientIdentifier, _ := registerConfidentialClient(t, "client_secret_post")
	client, err := database.GetClientByClientIdentifier(context.Background(), nil, clientIdentifier)
	require.NoError(t, err)
	accessToken, _ := createAdminClientWithToken(t)
	authenticationURL := appConfig.AuthServer.BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.ID, 10) + "/authentication"

	toPublic := makeAPIRequest(t, http.MethodPut, authenticationURL, accessToken, api.UpdateClientAuthenticationRequest{IsPublic: true})
	_ = toPublic.Body.Close()
	require.Equal(t, http.StatusOK, toPublic.StatusCode)

	newSecret := securerandom.String(60)
	toConfidential := makeAPIRequest(t, http.MethodPut, authenticationURL, accessToken,
		api.UpdateClientAuthenticationRequest{IsPublic: false, ClientSecret: newSecret})
	_ = toConfidential.Body.Close()
	require.Equal(t, http.StatusOK, toConfidential.StatusCode)

	assertBothMethodsAuthenticate(t, clientIdentifier, newSecret)
}

// clientSecretThroughTheAdminAPI is the client's secret, as the admin API's secret route answers it.
func clientSecretThroughTheAdminAPI(t *testing.T, accessToken string, clientID int64) string {
	t.Helper()
	resp := makeAPIRequest(t, http.MethodGet,
		appConfig.AuthServer.BaseURL+"/api/v1/admin/clients/"+strconv.FormatInt(clientID, 10)+"/secret", accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var secret api.GetClientSecretResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&secret))
	require.NotEmpty(t, secret.ClientSecret)
	return secret.ClientSecret
}
