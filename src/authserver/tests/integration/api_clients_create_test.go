package integrationtests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

func TestAPIClientCreate_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	ident := "client-" + strings.ToLower(gofakeit.LetterN(8))
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
			assert.Contains(t, response["error"].(map[string]interface{})["message"].(string), tc.expectedError)
		})
	}
}

func TestAPIClientCreate_Duplicate(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	ident := "client-" + strings.ToLower(gofakeit.LetterN(8))
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
	errObj := errResp["error"].(map[string]interface{})
	assert.Equal(t, "VALIDATION_ERROR", errObj["code"])
	assert.Contains(t, errObj["message"].(string), "already in use")
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
	// Create a client with a different permission (auth-server:userinfo) and request a token for that scope
	// Then call the admin endpoint and expect 403
	// Setup client
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	assert.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "inscope-client-" + strings.ToLower(gofakeit.LetterN(8)),
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		IsPublic:                 false,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}
	err = database.CreateClient(nil, client)
	assert.NoError(t, err)

	// Grant auth-server:userinfo permission
	authRes, err := database.GetResourceByResourceIdentifier(nil, constants.AuthServerResourceIdentifier)
	assert.NoError(t, err)
	perms, err := database.GetPermissionsByResourceId(nil, authRes.Id)
	assert.NoError(t, err)
	var userinfoPerm *models.Permission
	for i := range perms {
		if perms[i].PermissionIdentifier == constants.UserinfoPermissionIdentifier {
			userinfoPerm = &perms[i]
			break
		}
	}
	assert.NotNil(t, userinfoPerm)
	err = database.CreateClientPermission(nil, &models.ClientPermission{ClientId: client.Id, PermissionId: userinfoPerm.Id})
	assert.NoError(t, err)

	// Get token with only auth-server:userinfo scope
	httpClient := createHttpClient(t)
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"
	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"scope":         {constants.AuthServerResourceIdentifier + ":" + constants.UserinfoPermissionIdentifier},
	}
	data := postToTokenEndpoint(t, httpClient, destUrl, formData)
	accessToken, ok := data["access_token"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, accessToken)

	// Attempt to create client with token lacking required scope
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients"
	reqBody := api.CreateClientRequest{ClientIdentifier: "noadmin-" + strings.ToLower(gofakeit.LetterN(8)), Description: "x"}
	resp := makeAPIRequest(t, "POST", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}
