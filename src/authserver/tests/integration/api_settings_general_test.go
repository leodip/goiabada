package integrationtests

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/stretchr/testify/assert"
)

// GET /api/v1/admin/settings/general
func TestAPISettingsGeneralGet_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Fetch current settings directly from DB for expected values
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	assert.NotNil(t, settings)

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/general"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body api.SettingsGeneralResponse
	err = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, err)

	assert.Equal(t, settings.AppName, body.AppName)
	assert.Equal(t, settings.Issuer, body.Issuer)
	assert.Equal(t, settings.SelfRegistrationEnabled, body.SelfRegistrationEnabled)
	assert.Equal(t, settings.SelfRegistrationRequiresEmailVerification, body.SelfRegistrationRequiresEmailVerification)
	assert.Equal(t, settings.PasswordPolicy.String(), body.PasswordPolicy)
}

// PUT /api/v1/admin/settings/general - success cases
func TestAPISettingsGeneralPut_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Build update request with URI issuer and toggles
	req := api.UpdateSettingsGeneralRequest{
		AppName:                 "  My New App  ",
		Issuer:                  "https://example.org",
		SelfRegistrationEnabled: true,
		SelfRegistrationRequiresEmailVerification: true,
		PasswordPolicy: "low",
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/general"
	resp := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body api.SettingsGeneralResponse
	err := json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, err)

	// App name should be trimmed by sanitizer
	assert.Equal(t, "My New App", body.AppName)
	assert.Equal(t, req.Issuer, body.Issuer)
	assert.Equal(t, true, body.SelfRegistrationEnabled)
	assert.Equal(t, true, body.SelfRegistrationRequiresEmailVerification)
	assert.Equal(t, strings.ToLower(req.PasswordPolicy), strings.ToLower(body.PasswordPolicy))

	// Verify DB persisted
	settings, err2 := database.GetSettingsById(nil, 1)
	assert.NoError(t, err2)
	assert.Equal(t, "My New App", settings.AppName)
	assert.Equal(t, req.Issuer, settings.Issuer)
	assert.Equal(t, true, settings.SelfRegistrationEnabled)
	assert.Equal(t, true, settings.SelfRegistrationRequiresEmailVerification)
}

// PUT: disabling self-registration should force RequiresEmailVerification to false
func TestAPISettingsGeneralPut_DisableSelfRegForcesVerificationFalse(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// First enable both
	preReq := api.UpdateSettingsGeneralRequest{
		AppName:                 "App X",
		Issuer:                  "issuer-" + gofakeit.LetterN(6),
		SelfRegistrationEnabled: true,
		SelfRegistrationRequiresEmailVerification: true,
		PasswordPolicy: "low",
	}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/general"
	resp1 := makeAPIRequest(t, "PUT", url, accessToken, preReq)
	defer func() { _ = resp1.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp1.StatusCode)

	// Now disable self-registration but send verification flag as true to verify server overrides to false
	req := api.UpdateSettingsGeneralRequest{
		AppName:                 "App X",
		Issuer:                  preReq.Issuer,
		SelfRegistrationEnabled: false,
		SelfRegistrationRequiresEmailVerification: true, // should be ignored
		PasswordPolicy: "low",
	}
	resp2 := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	var body api.SettingsGeneralResponse
	_ = json.NewDecoder(resp2.Body).Decode(&body)
	assert.Equal(t, false, body.SelfRegistrationEnabled)
	assert.Equal(t, false, body.SelfRegistrationRequiresEmailVerification)

	// Also verify DB persisted override
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	assert.Equal(t, false, settings.SelfRegistrationEnabled)
	assert.Equal(t, false, settings.SelfRegistrationRequiresEmailVerification)
}

func TestAPISettingsGeneralPut_ValidationErrors(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/general"

	// App name too long (>30)
	resp1 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsGeneralRequest{
		AppName:        strings.Repeat("a", 31),
		Issuer:         "issuer-valid",
		PasswordPolicy: "low",
	})
	defer func() { _ = resp1.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp1.StatusCode)
	var err1 api.ErrorResponse
	_ = json.NewDecoder(resp1.Body).Decode(&err1)
	assert.Equal(t, "App name is too long. The maximum length is 30 characters.", err1.Error.Message)

	// Issuer contains ':' but invalid URI
	resp2 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsGeneralRequest{
		AppName:        "App",
		Issuer:         "http://",
		PasswordPolicy: "low",
	})
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
	var err2 api.ErrorResponse
	_ = json.NewDecoder(resp2.Body).Decode(&err2)
	assert.Equal(t, "Invalid issuer. Please enter a valid URI.", err2.Error.Message)

	// Issuer invalid identifier format
	resp3 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsGeneralRequest{
		AppName:        "App",
		Issuer:         "invalid issuer",
		PasswordPolicy: "low",
	})
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp3.StatusCode)
	var err3 api.ErrorResponse
	_ = json.NewDecoder(resp3.Body).Decode(&err3)
	assert.Equal(t, "Invalid issuer. It must start with a letter, can include letters, numbers, dashes, and underscores, but cannot end with a dash or underscore, or have two consecutive dashes or underscores.", err3.Error.Message)

	// Issuer with consecutive dashes
	resp4 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsGeneralRequest{
		AppName:        "App",
		Issuer:         "aa--bb",
		PasswordPolicy: "low",
	})
	defer func() { _ = resp4.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp4.StatusCode)
	var err4 api.ErrorResponse
	_ = json.NewDecoder(resp4.Body).Decode(&err4)
	assert.Equal(t, "Invalid issuer. It must start with a letter, can include letters, numbers, dashes, and underscores, but cannot end with a dash or underscore, or have two consecutive dashes or underscores.", err4.Error.Message)

	// Issuer too short (<3)
	resp5 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsGeneralRequest{
		AppName:        "App",
		Issuer:         "aa",
		PasswordPolicy: "low",
	})
	defer func() { _ = resp5.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp5.StatusCode)
	var err5 api.ErrorResponse
	_ = json.NewDecoder(resp5.Body).Decode(&err5)
	assert.Equal(t, "Issuer is too short. The minimum length is 3 characters.", err5.Error.Message)

	// Issuer too long (>60)
	resp6 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsGeneralRequest{
		AppName:        "App",
		Issuer:         strings.Repeat("a", 61),
		PasswordPolicy: "low",
	})
	defer func() { _ = resp6.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp6.StatusCode)
	var err6 api.ErrorResponse
	_ = json.NewDecoder(resp6.Body).Decode(&err6)
	assert.Equal(t, "Issuer is too long. The maximum length is 60 characters.", err6.Error.Message)

	// Invalid password policy
	resp7 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsGeneralRequest{
		AppName:        "App",
		Issuer:         "issuer-valid",
		PasswordPolicy: "invalid-policy",
	})
	defer func() { _ = resp7.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp7.StatusCode)
	var err7 api.ErrorResponse
	_ = json.NewDecoder(resp7.Body).Decode(&err7)
	assert.Equal(t, "Invalid password policy", err7.Error.Message)
}

// Test implicit flow enabled setting
func TestAPISettingsGeneralPut_ImplicitFlowEnabled(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Save original settings
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	originalImplicitFlow := settings.ImplicitFlowEnabled
	defer func() {
		settings.ImplicitFlowEnabled = originalImplicitFlow
		_ = database.UpdateSettings(nil, settings)
	}()

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/general"

	// Enable implicit flow
	req := api.UpdateSettingsGeneralRequest{
		AppName:             settings.AppName,
		Issuer:              settings.Issuer,
		PasswordPolicy:      settings.PasswordPolicy.String(),
		PKCERequired:        settings.PKCERequired,
		ImplicitFlowEnabled: true,
	}
	resp := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body api.SettingsGeneralResponse
	err = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, err)
	assert.True(t, body.ImplicitFlowEnabled, "ImplicitFlowEnabled should be true in response")

	// Verify DB persisted
	updatedSettings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	assert.True(t, updatedSettings.ImplicitFlowEnabled, "ImplicitFlowEnabled should be true in DB")

	// Now disable implicit flow
	req.ImplicitFlowEnabled = false
	resp2 := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp2.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	var body2 api.SettingsGeneralResponse
	err = json.NewDecoder(resp2.Body).Decode(&body2)
	assert.NoError(t, err)
	assert.False(t, body2.ImplicitFlowEnabled, "ImplicitFlowEnabled should be false in response")

	// Verify DB persisted
	updatedSettings2, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	assert.False(t, updatedSettings2.ImplicitFlowEnabled, "ImplicitFlowEnabled should be false in DB")
}

func TestAPISettingsGeneralGet_IncludesImplicitFlowEnabled(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Get current settings
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/general"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body api.SettingsGeneralResponse
	err = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, err)

	// Verify ImplicitFlowEnabled matches database value
	assert.Equal(t, settings.ImplicitFlowEnabled, body.ImplicitFlowEnabled, "ImplicitFlowEnabled should match DB value")
	// Verify PKCERequired is also included
	assert.Equal(t, settings.PKCERequired, body.PKCERequired, "PKCERequired should match DB value")
}

// Test ROPC enabled setting
func TestAPISettingsGeneralPut_ResourceOwnerPasswordCredentialsEnabled(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Save original settings
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	originalROPC := settings.ResourceOwnerPasswordCredentialsEnabled
	defer func() {
		settings.ResourceOwnerPasswordCredentialsEnabled = originalROPC
		_ = database.UpdateSettings(nil, settings)
	}()

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/general"

	// Enable ROPC
	req := api.UpdateSettingsGeneralRequest{
		AppName:                                 settings.AppName,
		Issuer:                                  settings.Issuer,
		PasswordPolicy:                          settings.PasswordPolicy.String(),
		PKCERequired:                            settings.PKCERequired,
		ImplicitFlowEnabled:                     settings.ImplicitFlowEnabled,
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	resp := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body api.SettingsGeneralResponse
	err = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, err)
	assert.True(t, body.ResourceOwnerPasswordCredentialsEnabled, "ResourceOwnerPasswordCredentialsEnabled should be true in response")

	// Verify DB persisted
	updatedSettings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	assert.True(t, updatedSettings.ResourceOwnerPasswordCredentialsEnabled, "ResourceOwnerPasswordCredentialsEnabled should be true in DB")

	// Now disable ROPC
	req.ResourceOwnerPasswordCredentialsEnabled = false
	resp2 := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp2.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	var body2 api.SettingsGeneralResponse
	err = json.NewDecoder(resp2.Body).Decode(&body2)
	assert.NoError(t, err)
	assert.False(t, body2.ResourceOwnerPasswordCredentialsEnabled, "ResourceOwnerPasswordCredentialsEnabled should be false in response")

	// Verify DB persisted
	updatedSettings2, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	assert.False(t, updatedSettings2.ResourceOwnerPasswordCredentialsEnabled, "ResourceOwnerPasswordCredentialsEnabled should be false in DB")
}

func TestAPISettingsGeneralGet_IncludesROPCEnabled(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Get current settings
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/general"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body api.SettingsGeneralResponse
	err = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, err)

	// Verify ResourceOwnerPasswordCredentialsEnabled matches database value
	assert.Equal(t, settings.ResourceOwnerPasswordCredentialsEnabled, body.ResourceOwnerPasswordCredentialsEnabled, "ResourceOwnerPasswordCredentialsEnabled should match DB value")
}

func TestAPISettingsGeneral_UnauthorizedAndScope(t *testing.T) {
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/general"

	// No token - GET
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	// Assert error text
	bodyBytes, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"))
	assert.Equal(t, "Access token required", strings.TrimSpace(string(bodyBytes)))

	// Invalid token - GET
	resp2 := makeAPIRequest(t, "GET", url, "invalid-token", nil)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
	bodyBytes2, _ := io.ReadAll(resp2.Body)
	assert.Equal(t, "Access token required", strings.TrimSpace(string(bodyBytes2)))

	// Insufficient scope
	tok := createClientCredentialsTokenWithScope(t, constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
	resp3 := makeAPIRequest(t, "GET", url, tok, nil)
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp3.StatusCode)
	bodyBytes3, _ := io.ReadAll(resp3.Body)
	assert.Equal(t, "Insufficient scope", strings.TrimSpace(string(bodyBytes3)))

	// Also test PUT unauthorized
	req2, err := http.NewRequest("PUT", url, nil)
	assert.NoError(t, err)
	resp4, err := httpClient.Do(req2)
	assert.NoError(t, err)
	defer func() { _ = resp4.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp4.StatusCode)
}
