package integrationtests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/stretchr/testify/assert"
)

// TestDCR_Disabled_Returns403 verifies that DCR returns 403 when feature is disabled (RFC 7591 §3)
func TestDCR_Disabled_Returns403(t *testing.T) {
	// Ensure DCR is disabled
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	originalDCREnabled := settings.DynamicClientRegistrationEnabled
	settings.DynamicClientRegistrationEnabled = false
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() {
		// Restore original setting
		settings.DynamicClientRegistrationEnabled = originalDCREnabled
		database.UpdateSettings(nil, settings)
	}()

	// Attempt to register a client
	reqBody := api.DynamicClientRegistrationRequest{
		RedirectURIs: []string{"http://localhost:3000/callback"},
		ClientName:   "Test Client",
	}

	resp := makeDCRRequest(t, reqBody)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	var errorResp api.DynamicClientRegistrationError
	err = json.NewDecoder(resp.Body).Decode(&errorResp)
	assert.NoError(t, err)
	assert.Equal(t, "access_denied", errorResp.Error)
	assert.Contains(t, errorResp.ErrorDescription, "not enabled")
}

// TestDCR_PublicClient_MCP_UseCase_Success tests the happy path for MCP public clients (RFC 7591 §3)
func TestDCR_PublicClient_MCP_UseCase_Success(t *testing.T) {
	enableDCR(t)
	defer disableDCR(t)

	// MCP client registration request
	reqBody := api.DynamicClientRegistrationRequest{
		RedirectURIs:            []string{"http://localhost:8080/callback"},
		TokenEndpointAuthMethod: "none", // Public client
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ClientName:              "MCP Remote Client",
	}

	resp := makeDCRRequest(t, reqBody)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	assert.Equal(t, "no-cache", resp.Header.Get("Pragma"))

	var response api.DynamicClientRegistrationResponse
	err := json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)

	// Verify response (RFC 7591 §3.2.1)
	assert.NotEmpty(t, response.ClientID)
	assert.True(t, strings.HasPrefix(response.ClientID, "dcr_"))
	assert.Empty(t, response.ClientSecret, "Public clients should not receive a client_secret")
	assert.Greater(t, response.ClientIDIssuedAt, int64(0))
	assert.Equal(t, int64(0), response.ClientSecretExpiresAt, "Secret never expires")
	assert.Equal(t, reqBody.RedirectURIs, response.RedirectURIs)
	assert.Equal(t, "none", response.TokenEndpointAuthMethod)
	assert.Equal(t, reqBody.GrantTypes, response.GrantTypes)
	assert.Equal(t, "MCP Remote Client", response.ClientName)

	// Verify database state
	client, err := database.GetClientByClientIdentifier(nil, response.ClientID)
	assert.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, "MCP Remote Client", client.Description)
	assert.True(t, client.IsPublic)
	assert.True(t, client.Enabled)
	assert.False(t, client.ConsentRequired)
	assert.True(t, client.AuthorizationCodeEnabled)
	assert.False(t, client.ClientCredentialsEnabled)
	assert.Nil(t, client.ClientSecretEncrypted)

	// Verify redirect URIs saved
	redirectURIs, err := database.GetRedirectURIsByClientId(nil, client.Id)
	assert.NoError(t, err)
	assert.Len(t, redirectURIs, 1)
	assert.Equal(t, "http://localhost:8080/callback", redirectURIs[0].URI)
}

// TestDCR_ConfidentialClient_Success tests confidential client registration with client_secret
func TestDCR_ConfidentialClient_Success(t *testing.T) {
	enableDCR(t)
	defer disableDCR(t)

	reqBody := api.DynamicClientRegistrationRequest{
		RedirectURIs:            []string{"https://app.example.com/callback"},
		TokenEndpointAuthMethod: "client_secret_post",
		GrantTypes:              []string{"authorization_code", "client_credentials", "refresh_token"},
		ClientName:              "Confidential App",
	}

	resp := makeDCRRequest(t, reqBody)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var response api.DynamicClientRegistrationResponse
	err := json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)

	// Confidential clients MUST receive a client_secret (RFC 7591 §3.2.1)
	assert.NotEmpty(t, response.ClientSecret)
	assert.Greater(t, len(response.ClientSecret), 30, "Secret should be sufficiently long")
	assert.Equal(t, "client_secret_post", response.TokenEndpointAuthMethod)

	// Verify database state
	client, err := database.GetClientByClientIdentifier(nil, response.ClientID)
	assert.NoError(t, err)
	assert.False(t, client.IsPublic)
	assert.True(t, client.AuthorizationCodeEnabled)
	assert.True(t, client.ClientCredentialsEnabled)
	assert.NotNil(t, client.ClientSecretEncrypted)

	// Verify secret can be decrypted and matches
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	decryptedSecret, err := encryption.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
	assert.NoError(t, err)
	assert.Equal(t, response.ClientSecret, decryptedSecret)
}

// TestDCR_DefaultValues_Applied tests RFC 7591 §2 default values
func TestDCR_DefaultValues_Applied(t *testing.T) {
	enableDCR(t)
	defer disableDCR(t)

	// Minimal request - no token_endpoint_auth_method, no grant_types
	reqBody := api.DynamicClientRegistrationRequest{
		RedirectURIs: []string{"https://app.example.com/callback"},
		ClientName:   "Minimal Client",
	}

	resp := makeDCRRequest(t, reqBody)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var response api.DynamicClientRegistrationResponse
	err := json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)

	// Verify defaults (RFC 7591 §2)
	assert.Equal(t, "client_secret_basic", response.TokenEndpointAuthMethod, "Default auth method")
	assert.Equal(t, []string{"authorization_code"}, response.GrantTypes, "Default grant type")
	assert.NotEmpty(t, response.ClientSecret, "Confidential client receives secret")

	// Verify database
	client, err := database.GetClientByClientIdentifier(nil, response.ClientID)
	assert.NoError(t, err)
	assert.False(t, client.IsPublic)
	assert.True(t, client.AuthorizationCodeEnabled)
	assert.False(t, client.ClientCredentialsEnabled)
}

// TestDCR_RedirectURI_Validation tests RFC 7591 §5 redirect URI validation
func TestDCR_RedirectURI_Validation(t *testing.T) {
	enableDCR(t)
	defer disableDCR(t)

	testCases := []struct {
		name           string
		authMethod     string
		redirectURIs   []string
		grantTypes     []string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "Public client - localhost HTTP allowed",
			authMethod:     "none",
			redirectURIs:   []string{"http://localhost:3000/callback"},
			grantTypes:     []string{"authorization_code"},
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "Public client - 127.0.0.1 HTTP allowed",
			authMethod:     "none",
			redirectURIs:   []string{"http://127.0.0.1:8080/callback"},
			grantTypes:     []string{"authorization_code"},
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "Public client - IPv6 localhost allowed",
			authMethod:     "none",
			redirectURIs:   []string{"http://[::1]:9000/callback"},
			grantTypes:     []string{"authorization_code"},
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "Public client - custom scheme allowed",
			authMethod:     "none",
			redirectURIs:   []string{"myapp://callback"},
			grantTypes:     []string{"authorization_code"},
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "Public client - HTTPS rejected (security)",
			authMethod:     "none",
			redirectURIs:   []string{"https://app.example.com/callback"},
			grantTypes:     []string{"authorization_code"},
			expectedStatus: http.StatusBadRequest,
			expectedError:  api.DCRErrorInvalidRedirectURI,
		},
		{
			name:           "Public client - non-localhost HTTP rejected",
			authMethod:     "none",
			redirectURIs:   []string{"http://example.com/callback"},
			grantTypes:     []string{"authorization_code"},
			expectedStatus: http.StatusBadRequest,
			expectedError:  api.DCRErrorInvalidRedirectURI,
		},
		{
			name:           "Confidential client - HTTPS allowed",
			authMethod:     "client_secret_post",
			redirectURIs:   []string{"https://app.example.com/callback"},
			grantTypes:     []string{"authorization_code"},
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "Confidential client - localhost HTTP allowed",
			authMethod:     "client_secret_post",
			redirectURIs:   []string{"http://localhost:3000/callback"},
			grantTypes:     []string{"authorization_code"},
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "Confidential client - non-localhost HTTP rejected",
			authMethod:     "client_secret_post",
			redirectURIs:   []string{"http://example.com/callback"},
			grantTypes:     []string{"authorization_code"},
			expectedStatus: http.StatusBadRequest,
			expectedError:  api.DCRErrorInvalidRedirectURI,
		},
		{
			name:           "Missing redirect_uris for authorization_code",
			authMethod:     "client_secret_post",
			redirectURIs:   []string{},
			grantTypes:     []string{"authorization_code"},
			expectedStatus: http.StatusBadRequest,
			expectedError:  api.DCRErrorInvalidRedirectURI,
		},
		{
			name:           "Client credentials - no redirect_uris required",
			authMethod:     "client_secret_post",
			redirectURIs:   []string{},
			grantTypes:     []string{"client_credentials"},
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "Invalid URI format",
			authMethod:     "client_secret_post",
			redirectURIs:   []string{"not a valid uri"},
			grantTypes:     []string{"authorization_code"},
			expectedStatus: http.StatusBadRequest,
			expectedError:  api.DCRErrorInvalidRedirectURI,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqBody := api.DynamicClientRegistrationRequest{
				RedirectURIs:            tc.redirectURIs,
				TokenEndpointAuthMethod: tc.authMethod,
				GrantTypes:              tc.grantTypes,
				ClientName:              tc.name,
			}

			resp := makeDCRRequest(t, reqBody)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)

			if tc.expectedStatus == http.StatusBadRequest {
				var errorResp api.DynamicClientRegistrationError
				err := json.NewDecoder(resp.Body).Decode(&errorResp)
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedError, errorResp.Error)
			}
		})
	}
}

// TestDCR_GrantType_Validation tests grant type validation
func TestDCR_GrantType_Validation(t *testing.T) {
	enableDCR(t)
	defer disableDCR(t)

	testCases := []struct {
		name           string
		grantTypes     []string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "Valid grant types",
			grantTypes:     []string{"authorization_code", "client_credentials", "refresh_token"},
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "Unsupported grant type",
			grantTypes:     []string{"password"},
			expectedStatus: http.StatusBadRequest,
			expectedError:  api.DCRErrorInvalidClientMetadata,
		},
		{
			name:           "Unsupported implicit grant",
			grantTypes:     []string{"implicit"},
			expectedStatus: http.StatusBadRequest,
			expectedError:  api.DCRErrorInvalidClientMetadata,
		},
		{
			name:           "Mixed valid and invalid",
			grantTypes:     []string{"authorization_code", "password"},
			expectedStatus: http.StatusBadRequest,
			expectedError:  api.DCRErrorInvalidClientMetadata,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqBody := api.DynamicClientRegistrationRequest{
				RedirectURIs:            []string{"https://app.example.com/callback"},
				TokenEndpointAuthMethod: "client_secret_post",
				GrantTypes:              tc.grantTypes,
				ClientName:              tc.name,
			}

			resp := makeDCRRequest(t, reqBody)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)

			if tc.expectedStatus == http.StatusBadRequest {
				var errorResp api.DynamicClientRegistrationError
				err := json.NewDecoder(resp.Body).Decode(&errorResp)
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedError, errorResp.Error)
			}
		})
	}
}

// TestDCR_TokenEndpointAuthMethod_Validation tests auth method validation
func TestDCR_TokenEndpointAuthMethod_Validation(t *testing.T) {
	enableDCR(t)
	defer disableDCR(t)

	testCases := []struct {
		name           string
		authMethod     string
		expectedStatus int
	}{
		{
			name:           "none - public client",
			authMethod:     "none",
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "client_secret_basic",
			authMethod:     "client_secret_basic",
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "client_secret_post",
			authMethod:     "client_secret_post",
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "Unsupported method",
			authMethod:     "client_secret_jwt",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Unsupported private_key_jwt",
			authMethod:     "private_key_jwt",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqBody := api.DynamicClientRegistrationRequest{
				RedirectURIs:            []string{"http://localhost:3000/callback"},
				TokenEndpointAuthMethod: tc.authMethod,
				GrantTypes:              []string{"authorization_code"},
				ClientName:              tc.name,
			}

			resp := makeDCRRequest(t, reqBody)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

// TestDCR_ClientName_Validation tests client name validation
func TestDCR_ClientName_Validation(t *testing.T) {
	enableDCR(t)
	defer disableDCR(t)

	testCases := []struct {
		name           string
		clientName     string
		expectedStatus int
	}{
		{
			name:           "Normal name",
			clientName:     "My Application",
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "Empty name allowed",
			clientName:     "",
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "Max length (128 chars)",
			clientName:     strings.Repeat("a", 128),
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "Too long (129 chars)",
			clientName:     strings.Repeat("a", 129),
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqBody := api.DynamicClientRegistrationRequest{
				RedirectURIs:            []string{"http://localhost:3000/callback"},
				TokenEndpointAuthMethod: "none",
				GrantTypes:              []string{"authorization_code"},
				ClientName:              tc.clientName,
			}

			resp := makeDCRRequest(t, reqBody)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

// TestDCR_WellKnown_Metadata tests that registration endpoint appears in discovery when enabled
func TestDCR_WellKnown_Metadata(t *testing.T) {
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	originalDCREnabled := settings.DynamicClientRegistrationEnabled

	t.Run("DCR enabled - registration_endpoint present", func(t *testing.T) {
		settings.DynamicClientRegistrationEnabled = true
		err = database.UpdateSettings(nil, settings)
		assert.NoError(t, err)

		httpClient := createHttpClient(t)
		wellKnownURL := config.GetAuthServer().BaseURL + "/.well-known/openid-configuration"

		resp, err := httpClient.Get(wellKnownURL)
		assert.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var metadata map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&metadata)
		assert.NoError(t, err)

		registrationEndpoint, ok := metadata["registration_endpoint"].(string)
		assert.True(t, ok, "registration_endpoint should be present")
		assert.Equal(t, config.GetAuthServer().BaseURL+"/connect/register", registrationEndpoint)
	})

	t.Run("DCR disabled - registration_endpoint absent", func(t *testing.T) {
		settings.DynamicClientRegistrationEnabled = false
		err = database.UpdateSettings(nil, settings)
		assert.NoError(t, err)

		httpClient := createHttpClient(t)
		wellKnownURL := config.GetAuthServer().BaseURL + "/.well-known/openid-configuration"

		resp, err := httpClient.Get(wellKnownURL)
		assert.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var metadata map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&metadata)
		assert.NoError(t, err)

		_, ok := metadata["registration_endpoint"]
		assert.False(t, ok, "registration_endpoint should be absent when DCR disabled")
	})

	// Restore original setting
	settings.DynamicClientRegistrationEnabled = originalDCREnabled
	database.UpdateSettings(nil, settings)
}

// TestDCR_MultipleRedirectURIs tests registering multiple redirect URIs
func TestDCR_MultipleRedirectURIs(t *testing.T) {
	enableDCR(t)
	defer disableDCR(t)

	reqBody := api.DynamicClientRegistrationRequest{
		RedirectURIs: []string{
			"http://localhost:3000/callback",
			"http://localhost:3001/callback",
			"http://127.0.0.1:8080/auth",
		},
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{"authorization_code"},
		ClientName:              "Multi-URI Client",
	}

	resp := makeDCRRequest(t, reqBody)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var response api.DynamicClientRegistrationResponse
	err := json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)

	assert.Len(t, response.RedirectURIs, 3)

	// Verify all URIs saved in database
	client, err := database.GetClientByClientIdentifier(nil, response.ClientID)
	assert.NoError(t, err)

	redirectURIs, err := database.GetRedirectURIsByClientId(nil, client.Id)
	assert.NoError(t, err)
	assert.Len(t, redirectURIs, 3)

	uris := make([]string, len(redirectURIs))
	for i, uri := range redirectURIs {
		uris[i] = uri.URI
	}
	assert.ElementsMatch(t, reqBody.RedirectURIs, uris)
}

// TestDCR_ConfidentialClient_DefaultAcrLevel tests that DCR clients get sensible defaults
func TestDCR_ConfidentialClient_DefaultAcrLevel(t *testing.T) {
	enableDCR(t)
	defer disableDCR(t)

	reqBody := api.DynamicClientRegistrationRequest{
		RedirectURIs:            []string{"https://app.example.com/callback"},
		TokenEndpointAuthMethod: "client_secret_post",
		GrantTypes:              []string{"authorization_code"},
		ClientName:              "Default ACR Test",
	}

	resp := makeDCRRequest(t, reqBody)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var response api.DynamicClientRegistrationResponse
	err := json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)

	// Verify database defaults
	client, err := database.GetClientByClientIdentifier(nil, response.ClientID)
	assert.NoError(t, err)

	assert.Equal(t, enums.AcrLevel2Optional, client.DefaultAcrLevel, "Should default to level 2 optional")

	// Verify token expiration uses global settings
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	assert.Equal(t, settings.TokenExpirationInSeconds, client.TokenExpirationInSeconds)
	assert.Equal(t, settings.RefreshTokenOfflineIdleTimeoutInSeconds, client.RefreshTokenOfflineIdleTimeoutInSeconds)
	assert.Equal(t, settings.RefreshTokenOfflineMaxLifetimeInSeconds, client.RefreshTokenOfflineMaxLifetimeInSeconds)
}

// Helper functions

// makeDCRRequest makes a DCR POST request without authentication (open registration)
func makeDCRRequest(t *testing.T, body api.DynamicClientRegistrationRequest) *http.Response {
	jsonBody, err := json.Marshal(body)
	assert.NoError(t, err)

	url := config.GetAuthServer().BaseURL + "/connect/register"
	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonBody))
	assert.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)

	return resp
}

// enableDCR enables Dynamic Client Registration for a test
func enableDCR(t *testing.T) {
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	settings.DynamicClientRegistrationEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
}

// disableDCR disables Dynamic Client Registration after a test
func disableDCR(t *testing.T) {
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	settings.DynamicClientRegistrationEnabled = false
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
}
