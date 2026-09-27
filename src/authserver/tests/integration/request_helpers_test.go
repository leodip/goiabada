package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/leodip/goiabada/core/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createUserAccessTokenWithScope issues an access token for a user making sure requested
// custom scopes are granted to that user before the flow. Returns (accessToken, *user).
func createUserAccessTokenWithScope(t *testing.T, scope string) (string, *models.User) {
	data, code, _, _ := userTokenResponseWithScope(t, scope, nil)
	accessToken, ok := data["access_token"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, accessToken)
	return accessToken, &code.User
}

// userTokenResponseWithScope is createUserAccessTokenWithScope for a caller that needs the whole
// token response, the code it redeemed, and the client to refresh with. beforeExchange, when set,
// runs on the user after the code is issued and before it is redeemed, which is where a fixture
// changes what the token will carry: issuance reads the user's groups at the exchange.
func userTokenResponseWithScope(t *testing.T, scope string, beforeExchange func(user *models.User)) (
	map[string]interface{}, *models.Code, *http.Client, string) {
	clientSecret := fake.LetterN(32)
	httpClient, code := createAuthCodeEnsuringUserScope(t, clientSecret, scope)
	if beforeExchange != nil {
		beforeExchange(&code.User)
	}

	// Exchange code for tokens
	tokenEndpoint := config.GetAuthServer().BaseURL + "/auth/token/"
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
	}
	data := postToTokenEndpoint(t, httpClient, tokenEndpoint, form)
	return data, code, httpClient, clientSecret
}

func postToTokenEndpoint(t *testing.T, client *http.Client, url string, formData url.Values) map[string]interface{} {
	formDataString := formData.Encode()
	requestBody := strings.NewReader(formDataString)
	request, err := http.NewRequest("POST", url, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Referer", url)
	request.Header.Set("Origin", config.GetAuthServer().BaseURL)

	resp, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	var data interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		// Include the status and the body: the token endpoint renders an HTML
		// error page on an internal failure, and the bare json error ("invalid
		// character '<'") says nothing about what actually went wrong.
		t.Fatalf("token endpoint did not return JSON: %v (status %d, body: %s)",
			err, resp.StatusCode, string(body))
	}

	return data.(map[string]interface{})
}

// postToTokenEndpointWithBasicAuth sends a POST request to the token endpoint using HTTP Basic authentication
func postToTokenEndpointWithBasicAuth(t *testing.T, client *http.Client, url string, formData url.Values, clientId, clientSecret string) map[string]interface{} {
	formDataString := formData.Encode()
	requestBody := strings.NewReader(formDataString)
	request, err := http.NewRequest("POST", url, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Referer", url)
	request.Header.Set("Origin", config.GetAuthServer().BaseURL)
	request.SetBasicAuth(clientId, clientSecret)

	resp, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	var data interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		t.Fatal(err)
	}

	return data.(map[string]interface{})
}

func dumpResponseBody(t *testing.T, response *http.Response) {
	t.Log("Response body:")
	byteArr, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	response.Body = io.NopCloser(bytes.NewReader(byteArr))
	content := string(byteArr)
	t.Log(content)
}

// createAdminClientWithToken creates a client with admin permissions and returns an access token
func createAdminClientWithToken(t *testing.T) (string, *models.Client) {
	// Generate client secret
	clientSecret := fake.Password(32)
	clientSecretEncrypted, err := encryption.EncryptData(clientSecret)
	assert.NoError(t, err)

	// Create client with admin permissions
	client := &models.Client{
		ClientIdentifier:         "admin-test-client-" + fake.LetterN(8),
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		IsPublic:                 false,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}
	err = database.CreateClient(context.Background(), nil, client)
	assert.NoError(t, err)

	// Get authserver resource and permission
	authServerResource, err := database.GetResourceByResourceIdentifier(context.Background(), nil, constants.AuthServerResourceIdentifier)
	assert.NoError(t, err)

	permissions, err := database.GetPermissionsByResourceId(context.Background(), nil, authServerResource.Id)
	assert.NoError(t, err)

	var adminPermission *models.Permission
	for idx, permission := range permissions {
		if permission.PermissionIdentifier == constants.ManagePermissionIdentifier {
			adminPermission = &permissions[idx]
			break
		}
	}
	assert.NotNil(t, adminPermission, "Should find manage permission")

	// Assign admin permission to client
	err = database.CreateClientPermission(context.Background(), nil, &models.ClientPermission{
		ClientId:     client.Id,
		PermissionId: adminPermission.Id,
	})
	assert.NoError(t, err)

	// Get access token using client credentials flow
	httpClient := createHttpClient(t)
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"scope":         {constants.AuthServerResourceIdentifier + ":" + constants.ManagePermissionIdentifier},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)
	accessToken, ok := data["access_token"].(string)
	assert.True(t, ok, "access_token should be a string")
	assert.NotEmpty(t, accessToken, "access_token should not be empty")

	return accessToken, client
}

// makeAPIRequest makes an authenticated API request
// The error checks below are require, not assert: a non-fatal assert would let
// the helper return a nil *http.Response, and the caller then dereferences it,
// turning a plain connectivity failure into a SIGSEGV that aborts the whole
// package. require stops at the real cause.
func makeAPIRequest(t *testing.T, method, url, accessToken string, body interface{}) *http.Response {
	var reqBody *bytes.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		require.NoError(t, err)
		reqBody = bytes.NewReader(jsonBody)
	} else {
		reqBody = bytes.NewReader([]byte{})
	}

	req, err := http.NewRequest(method, url, reqBody)
	require.NoError(t, err)

	req.Header.Set("Authorization", "Bearer "+accessToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)

	return resp
}
