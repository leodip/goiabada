package integrationtests

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
)

func TestAPIClientCreate_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	ident := "client-" + strings.ToLower(fake.LetterN(8))
	reqBody := api.CreateClientRequest{
		ClientIdentifier:         ident,
		Description:              "  Test client  ",
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients"
	resp := makeAPIRequest(t, "POST", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Decode generically to avoid tight coupling
	var response map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	client := response["client"].(map[string]interface{})
	assert.Equal(t, reqBody.ClientIdentifier, client["clientIdentifier"])
	assert.Equal(t, true, client["enabled"])
	assert.Equal(t, reqBody.AuthorizationCodeEnabled, client["authorizationCodeEnabled"])
	assert.Equal(t, reqBody.ClientCredentialsEnabled, client["clientCredentialsEnabled"])
	assert.Equal(t, "Test client", client["description"]) // sanitized trimming
}

func TestAPIClientCreate_Validation(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients"

	testCases := []struct {
		name           string
		requestData    map[string]interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name: "Empty client identifier",
			requestData: map[string]interface{}{
				"clientIdentifier":         "",
				"description":              "Test Description",
				"authorizationCodeEnabled": true,
				"clientCredentialsEnabled": false,
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Client identifier is required",
		},
		{
			name: "Client identifier too short",
			requestData: map[string]interface{}{
				"clientIdentifier":         "ab",
				"description":              "Test Description",
				"authorizationCodeEnabled": true,
				"clientCredentialsEnabled": false,
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "at least 3 characters",
		},
		{
			name: "Client identifier too long",
			requestData: map[string]interface{}{
				"clientIdentifier":         strings.Repeat("a", 39),
				"description":              "Test Description",
				"authorizationCodeEnabled": true,
				"clientCredentialsEnabled": false,
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "maximum length of 38 characters",
		},
		{
			name: "Invalid client identifier characters",
			requestData: map[string]interface{}{
				"clientIdentifier":         "invalid@client!",
				"description":              "Test Description",
				"authorizationCodeEnabled": true,
				"clientCredentialsEnabled": false,
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid identifier format",
		},
		{
			name: "Description too long",
			requestData: map[string]interface{}{
				"clientIdentifier":         "valid-client",
				"description":              strings.Repeat("a", 101),
				"authorizationCodeEnabled": true,
				"clientCredentialsEnabled": false,
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "maximum length of 100 characters",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := makeAPIRequest(t, "POST", url, accessToken, tc.requestData)
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, tc.expectedStatus, resp.StatusCode)

			var response map[string]interface{}
			err := json.NewDecoder(resp.Body).Decode(&response)
			assert.NoError(t, err)
			assert.Contains(t, response["error_description"].(string), tc.expectedError)
		})
	}
}

func TestAPIClientCreate_Duplicate(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	ident := "client-" + strings.ToLower(fake.LetterN(8))
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients"

	first := api.CreateClientRequest{ClientIdentifier: ident, Description: "first"}
	resp := makeAPIRequest(t, "POST", url, accessToken, first)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	// Try again with same identifier
	second := api.CreateClientRequest{ClientIdentifier: ident, Description: "second"}
	resp = makeAPIRequest(t, "POST", url, accessToken, second)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&errResp)
	assert.NoError(t, err)
	assert.Equal(t, "VALIDATION_ERROR", errResp["error_code"])
	assert.Contains(t, errResp["error_description"].(string), "already in use")
}

func TestAPIClientCreate_Unauthorized(t *testing.T) {
	reqBody := api.CreateClientRequest{ClientIdentifier: "unauth-client", Description: "x"}
	b, _ := json.Marshal(reqBody)

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients"
	httpClient := createHttpClient(t)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(b))
	assert.NoError(t, err)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPIClientCreate_InsufficientScope(t *testing.T) {
	// A valid token whose only scope is one no route grants, so the route answers 403
	accessToken := createClientCredentialsTokenWithoutRouteScope(t)

	// Attempt to create client with token lacking required scope
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients"
	reqBody := api.CreateClientRequest{ClientIdentifier: "noadmin-" + strings.ToLower(fake.LetterN(8)), Description: "x"}
	resp := makeAPIRequest(t, "POST", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestAPIClientCreate_WithDisplayName(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	ident := "client-" + strings.ToLower(fake.LetterN(8))
	reqBody := api.CreateClientRequest{
		ClientIdentifier:         ident,
		DisplayName:              "My App",
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients"
	resp := makeAPIRequest(t, "POST", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var response map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	client := response["client"].(map[string]interface{})
	assert.Equal(t, "My App", client["displayName"])
	assert.Equal(t, true, client["showDisplayName"])
}

func TestAPIClientCreate_EmptyDisplayName(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	ident := "client-" + strings.ToLower(fake.LetterN(8))
	reqBody := api.CreateClientRequest{
		ClientIdentifier:         ident,
		DisplayName:              "",
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients"
	resp := makeAPIRequest(t, "POST", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var response map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	client := response["client"].(map[string]interface{})
	assert.Equal(t, "", client["displayName"])
	assert.Equal(t, false, client["showDisplayName"])
}

func TestAPIClientCreate_DisplayNameTooLong(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	ident := "client-" + strings.ToLower(fake.LetterN(8))
	reqBody := api.CreateClientRequest{
		ClientIdentifier:         ident,
		DisplayName:              strings.Repeat("a", 101),
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients"
	resp := makeAPIRequest(t, "POST", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var response map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	assert.Contains(t, response["error_description"].(string), "maximum length of 100 characters")
}

func TestAPIClientCreate_DisplayNameTrimmed(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	ident := "client-" + strings.ToLower(fake.LetterN(8))
	reqBody := api.CreateClientRequest{
		ClientIdentifier:         ident,
		DisplayName:              "  My App  ",
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients"
	resp := makeAPIRequest(t, "POST", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var response map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	client := response["client"].(map[string]interface{})
	assert.Equal(t, "My App", client["displayName"])
	assert.Equal(t, true, client["showDisplayName"])
}

// TestAPIClientCreate_AngleBracketsRejected pins that a display name or a description holding "<"
// or ">" is refused rather than rewritten. This used to store "<script>alert(1)</script>" as the
// empty string and create the client anyway, which is the silent rewrite #275 removed.
func TestAPIClientCreate_AngleBracketsRejected(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients"

	cases := []struct {
		name     string
		body     api.CreateClientRequest
		wantCode string
	}{
		{"display name", api.CreateClientRequest{
			ClientIdentifier:         "client-" + strings.ToLower(fake.LetterN(8)),
			DisplayName:              "<script>alert(1)</script>",
			AuthorizationCodeEnabled: true,
		}, "validator.display_name.angle_brackets"},
		{"description", api.CreateClientRequest{
			ClientIdentifier:         "client-" + strings.ToLower(fake.LetterN(8)),
			Description:              "a > b",
			AuthorizationCodeEnabled: true,
		}, "validator.description.angle_brackets"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := makeAPIRequest(t, "POST", url, accessToken, tc.body)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			var errResp api.ErrorResponse
			_ = json.NewDecoder(resp.Body).Decode(&errResp)
			assert.Equal(t, tc.wantCode, errResp.ErrorCode)

			// Nothing was created.
			stored, err := database.GetClientByClientIdentifier(context.Background(), nil, tc.body.ClientIdentifier)
			assert.NoError(t, err)
			assert.Nil(t, stored)
		})
	}
}

// TestAPIClientCreate_AmpersandsAndQuotesStoredVerbatim is the accepted twin of the case above:
// what is not refused is stored exactly as it was sent.
func TestAPIClientCreate_AmpersandsAndQuotesStoredVerbatim(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	ident := "client-" + strings.ToLower(fake.LetterN(8))
	reqBody := api.CreateClientRequest{
		ClientIdentifier:         ident,
		Description:              `Tom & Jerry said "hi"`,
		DisplayName:              `AT&T "Wireless"`,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients"
	resp := makeAPIRequest(t, "POST", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var response map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	client := response["client"].(map[string]interface{})
	assert.Equal(t, `Tom & Jerry said "hi"`, client["description"])
	assert.Equal(t, `AT&T "Wireless"`, client["displayName"])
	assert.Equal(t, true, client["showDisplayName"])

	stored, err := database.GetClientByClientIdentifier(context.Background(), nil, ident)
	assert.NoError(t, err)
	assert.NotNil(t, stored)
	assert.Equal(t, `Tom & Jerry said "hi"`, stored.Description)
	assert.Equal(t, `AT&T "Wireless"`, stored.DisplayName)
	_ = database.DeleteClient(context.Background(), nil, stored.Id)
}

func TestAPIClientCreate_DescriptionOnlyBackwardCompat(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	ident := "client-" + strings.ToLower(fake.LetterN(8))
	reqBody := api.CreateClientRequest{
		ClientIdentifier:         ident,
		Description:              "some desc",
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients"
	resp := makeAPIRequest(t, "POST", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var response map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	client := response["client"].(map[string]interface{})
	assert.Equal(t, "some desc", client["description"])
	assert.Equal(t, false, client["showDisplayName"])
}

func TestAPIClientCreate_BothDescriptionAndDisplayName(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	ident := "client-" + strings.ToLower(fake.LetterN(8))
	reqBody := api.CreateClientRequest{
		ClientIdentifier:         ident,
		Description:              "some desc",
		DisplayName:              "My App",
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients"
	resp := makeAPIRequest(t, "POST", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var response map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	client := response["client"].(map[string]interface{})
	assert.Equal(t, "some desc", client["description"])
	assert.Equal(t, "My App", client["displayName"])
	assert.Equal(t, true, client["showDisplayName"])
}
