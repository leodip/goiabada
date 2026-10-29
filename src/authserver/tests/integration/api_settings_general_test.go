package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GET /api/v1/admin/settings/general
func TestAPISettingsGeneralGet_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Fetch current settings directly from DB for expected values
	settings, err := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)
	assert.NotNil(t, settings)

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/settings/general"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body api.SettingsGeneralResponse
	err = json.NewDecoder(resp.Body).Decode(&body)
	require.NoError(t, err)

	assert.Equal(t, settings.AppName, body.AppName)
	assert.Equal(t, settings.Issuer, body.Issuer)
	assert.Equal(t, settings.SelfRegistrationEnabled, body.SelfRegistrationEnabled)
	assert.Equal(t, settings.SelfRegistrationRequiresEmailVerification, body.SelfRegistrationRequiresEmailVerification)
	assert.Equal(t, settings.PasswordPolicy.String(), body.PasswordPolicy)
}

// PUT /api/v1/admin/settings/general - success cases
func TestAPISettingsGeneralPut_Success(t *testing.T) {
	restoreSettings(t)
	accessToken, _ := createAdminClientWithToken(t)

	// Build update request with URI issuer and toggles
	req := api.UpdateSettingsGeneralRequest{
		AppName:                 "  My New App  ",
		Issuer:                  "https://example.org",
		SelfRegistrationEnabled: true,
		SelfRegistrationRequiresEmailVerification: true,
		PasswordPolicy: "low",
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/settings/general"
	resp := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body api.SettingsGeneralResponse
	err := json.NewDecoder(resp.Body).Decode(&body)
	require.NoError(t, err)

	// App name should be trimmed
	assert.Equal(t, "My New App", body.AppName)
	assert.Equal(t, req.Issuer, body.Issuer)
	assert.True(t, body.SelfRegistrationEnabled)
	assert.True(t, body.SelfRegistrationRequiresEmailVerification)
	assert.Equal(t, strings.ToLower(req.PasswordPolicy), strings.ToLower(body.PasswordPolicy))

	// Verify DB persisted
	settings, err2 := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err2)
	assert.Equal(t, "My New App", settings.AppName)
	assert.Equal(t, req.Issuer, settings.Issuer)
	assert.True(t, settings.SelfRegistrationEnabled)
	assert.True(t, settings.SelfRegistrationRequiresEmailVerification)
}

// PUT: disabling self-registration keeps the email verification choice, as sent. It used to be
// forced to false, so turning self-registration off and on again lost email verification and made
// which addresses have an account discoverable, with nothing on the page saying so. The choice does
// nothing while self-registration is off, the registration page being a 404 then.
func TestAPISettingsGeneralPut_DisablingSelfRegKeepsTheVerificationChoice(t *testing.T) {
	restoreSettings(t)
	accessToken, _ := createAdminClientWithToken(t)

	// First enable both
	preReq := api.UpdateSettingsGeneralRequest{
		AppName:                 "App X",
		Issuer:                  "https://issuer-" + strings.ToLower(fake.LetterN(6)) + ".example.org",
		SelfRegistrationEnabled: true,
		SelfRegistrationRequiresEmailVerification: true,
		PasswordPolicy: "low",
	}
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/settings/general"
	resp1 := makeAPIRequest(t, "PUT", url, accessToken, preReq)
	defer func() { _ = resp1.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp1.StatusCode)
	// The issuer changed, and with it every access token issued under the old one is refused, so
	// the second save takes a token issued under the new one.
	accessToken, _ = createAdminClientWithToken(t)

	// Now disable self-registration, keeping the verification flag on
	req := api.UpdateSettingsGeneralRequest{
		AppName:                 "App X",
		Issuer:                  preReq.Issuer,
		SelfRegistrationEnabled: false,
		SelfRegistrationRequiresEmailVerification: true,
		PasswordPolicy: "low",
	}
	resp2 := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	var body api.SettingsGeneralResponse
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&body))
	assert.False(t, body.SelfRegistrationEnabled)
	assert.True(t, body.SelfRegistrationRequiresEmailVerification)

	// And the database holds it, so turning self-registration back on brings it back
	settings, err := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)
	assert.False(t, settings.SelfRegistrationEnabled)
	assert.True(t, settings.SelfRegistrationRequiresEmailVerification)
}

func TestAPISettingsGeneralPut_ValidationErrors(t *testing.T) {
	restoreSettings(t)
	accessToken, _ := createAdminClientWithToken(t)
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/settings/general"

	// App name too long (>30)
	resp1 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsGeneralRequest{
		AppName:        strings.Repeat("a", 31),
		Issuer:         "https://example.org",
		PasswordPolicy: "low",
	})
	defer func() { _ = resp1.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp1.StatusCode)
	var err1 api.ErrorResponse
	_ = json.NewDecoder(resp1.Body).Decode(&err1)
	assert.Equal(t, "App name is too long. The maximum length is 30 characters.", err1.ErrorDescription)

	// The issuer is an https URL with no query, fragment or user info, or the base URL (#576
	// decision 3): a URL with no host, a plain name, an identifier with a space and an http URL
	// other than the base URL are each refused with the sentence stating the rule.
	const issuerRule = "Invalid issuer. Enter an https URL with no query, fragment or user info, or the auth server's base URL."
	for _, issuer := range []string{"http://", "https://", "goiabada", "invalid issuer", "http://auth.example.org", "https://example.org?tenant=a"} {
		resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsGeneralRequest{
			AppName:        "App",
			Issuer:         issuer,
			PasswordPolicy: "low",
		})
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, issuer)
		var errResp api.ErrorResponse
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		_ = resp.Body.Close()
		assert.Equal(t, "handler.settings_general.issuer_uri_invalid", errResp.ErrorCode, issuer)
		assert.Equal(t, issuerRule, errResp.ErrorDescription, issuer)
	}

	// Issuer too long (>60)
	resp6 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsGeneralRequest{
		AppName:        "App",
		Issuer:         "https://example.org/" + strings.Repeat("a", 41),
		PasswordPolicy: "low",
	})
	defer func() { _ = resp6.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp6.StatusCode)
	var err6 api.ErrorResponse
	_ = json.NewDecoder(resp6.Body).Decode(&err6)
	assert.Equal(t, "Issuer is too long. The maximum length is 60 characters.", err6.ErrorDescription)

	// Invalid password policy
	resp7 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsGeneralRequest{
		AppName:        "App",
		Issuer:         "https://example.org",
		PasswordPolicy: "invalid-policy",
	})
	defer func() { _ = resp7.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp7.StatusCode)
	var err7 api.ErrorResponse
	_ = json.NewDecoder(resp7.Body).Decode(&err7)
	assert.Equal(t, "Invalid password policy", err7.ErrorDescription)
}

// PUT: the base URL is the one issuer the rule accepts whatever its scheme, since discovery is
// fetched under it and a new install seeds it, http on a deployment with no TLS (#576 decision 3).
func TestAPISettingsGeneralPut_TheBaseURLIsAnAcceptedIssuer(t *testing.T) {
	changeSettings(t, func(settings *record.Settings) { settings.Issuer = "https://before.example.org" })
	accessToken, _ := createAdminClientWithToken(t)
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/settings/general"

	resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsGeneralRequest{
		AppName:        "App",
		Issuer:         appConfig.AuthServer.BaseURL,
		PasswordPolicy: "low",
	})
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	stored, err := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)
	assert.Equal(t, appConfig.AuthServer.BaseURL, stored.Issuer)
}

// PUT: a stored issuer the rule refuses stands until the operator changes it, and the other
// general settings save around it, because the rule applies only to an issuer that differs from
// the stored one (#576 decision 4). Changing it to another value the rule refuses is refused.
func TestAPISettingsGeneralPut_AStoredIssuerTheRuleRefusesStandsUntilChanged(t *testing.T) {
	const legacyIssuer = "goiabada"
	before := changeSettings(t, func(settings *record.Settings) { settings.Issuer = legacyIssuer })
	accessToken, _ := createAdminClientWithToken(t)
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/settings/general"

	resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsGeneralRequest{
		AppName:                 "Saved around the issuer",
		Issuer:                  legacyIssuer,
		SelfRegistrationEnabled: !before.SelfRegistrationEnabled,
		PasswordPolicy:          "low",
	})
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	stored, err := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)
	assert.Equal(t, legacyIssuer, stored.Issuer)
	assert.Equal(t, "Saved around the issuer", stored.AppName)
	assert.Equal(t, !before.SelfRegistrationEnabled, stored.SelfRegistrationEnabled)

	resp2 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsGeneralRequest{
		AppName:        "Saved around the issuer",
		Issuer:         legacyIssuer + "-changed",
		PasswordPolicy: "low",
	})
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)

	stored, err = database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)
	assert.Equal(t, legacyIssuer, stored.Issuer)
}

// Test implicit flow enabled setting
func TestAPISettingsGeneralPut_ImplicitFlowEnabled(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	settings := restoreSettings(t)

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/settings/general"

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
	err := json.NewDecoder(resp.Body).Decode(&body)
	require.NoError(t, err)
	assert.True(t, body.ImplicitFlowEnabled, "ImplicitFlowEnabled should be true in response")

	// Verify DB persisted
	updatedSettings, err := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)
	assert.True(t, updatedSettings.ImplicitFlowEnabled, "ImplicitFlowEnabled should be true in DB")

	// Now disable implicit flow
	req.ImplicitFlowEnabled = false
	resp2 := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp2.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	var body2 api.SettingsGeneralResponse
	err = json.NewDecoder(resp2.Body).Decode(&body2)
	require.NoError(t, err)
	assert.False(t, body2.ImplicitFlowEnabled, "ImplicitFlowEnabled should be false in response")

	// Verify DB persisted
	updatedSettings2, err := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)
	assert.False(t, updatedSettings2.ImplicitFlowEnabled, "ImplicitFlowEnabled should be false in DB")
}

func TestAPISettingsGeneralGet_IncludesImplicitFlowEnabled(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Get current settings
	settings, err := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/settings/general"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body api.SettingsGeneralResponse
	err = json.NewDecoder(resp.Body).Decode(&body)
	require.NoError(t, err)

	// Verify ImplicitFlowEnabled matches database value
	assert.Equal(t, settings.ImplicitFlowEnabled, body.ImplicitFlowEnabled, "ImplicitFlowEnabled should match DB value")
	// Verify PKCERequired is also included
	assert.Equal(t, settings.PKCERequired, body.PKCERequired, "PKCERequired should match DB value")
}

// Test ROPC enabled setting
func TestAPISettingsGeneralPut_ResourceOwnerPasswordCredentialsEnabled(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	settings := restoreSettings(t)

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/settings/general"

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
	err := json.NewDecoder(resp.Body).Decode(&body)
	require.NoError(t, err)
	assert.True(t, body.ResourceOwnerPasswordCredentialsEnabled, "ResourceOwnerPasswordCredentialsEnabled should be true in response")

	// Verify DB persisted
	updatedSettings, err := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)
	assert.True(t, updatedSettings.ResourceOwnerPasswordCredentialsEnabled, "ResourceOwnerPasswordCredentialsEnabled should be true in DB")

	// Now disable ROPC
	req.ResourceOwnerPasswordCredentialsEnabled = false
	resp2 := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp2.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	var body2 api.SettingsGeneralResponse
	err = json.NewDecoder(resp2.Body).Decode(&body2)
	require.NoError(t, err)
	assert.False(t, body2.ResourceOwnerPasswordCredentialsEnabled, "ResourceOwnerPasswordCredentialsEnabled should be false in response")

	// Verify DB persisted
	updatedSettings2, err := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)
	assert.False(t, updatedSettings2.ResourceOwnerPasswordCredentialsEnabled, "ResourceOwnerPasswordCredentialsEnabled should be false in DB")
}

func TestAPISettingsGeneralGet_IncludesROPCEnabled(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Get current settings
	settings, err := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/settings/general"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body api.SettingsGeneralResponse
	err = json.NewDecoder(resp.Body).Decode(&body)
	require.NoError(t, err)

	// Verify ResourceOwnerPasswordCredentialsEnabled matches database value
	assert.Equal(t, settings.ResourceOwnerPasswordCredentialsEnabled, body.ResourceOwnerPasswordCredentialsEnabled, "ResourceOwnerPasswordCredentialsEnabled should match DB value")
}

func TestAPISettingsGeneral_UnauthorizedAndScope(t *testing.T) {
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/settings/general"

	// No token - GET
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(t, err)
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	// Assert error text
	bodyBytes, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Contains(t, string(bodyBytes), "Access token required.")

	// Invalid token - GET
	resp2 := makeAPIRequest(t, "GET", url, "invalid-token", nil)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
	bodyBytes2, _ := io.ReadAll(resp2.Body)
	assert.Contains(t, string(bodyBytes2), "The access token is invalid.")

	// Insufficient scope
	tok := createClientCredentialsTokenWithoutRouteScope(t)
	resp3 := makeAPIRequest(t, "GET", url, tok, nil)
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp3.StatusCode)
	bodyBytes3, _ := io.ReadAll(resp3.Body)
	assert.Contains(t, string(bodyBytes3), "Insufficient scope.")

	// Also test PUT unauthorized
	req2, err := http.NewRequest("PUT", url, nil)
	require.NoError(t, err)
	resp4, err := httpClient.Do(req2)
	require.NoError(t, err)
	defer func() { _ = resp4.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp4.StatusCode)
}

// TestAPISettingsGeneralPut_AngleBracketsRejected covers the two checks this endpoint carries. The
// issuer rule accepts "<" in an https URL's path or host, so an issuer holding markup would reach
// the iss claim of every token without the issuer's own check (#275).
func TestAPISettingsGeneralPut_AngleBracketsRejected(t *testing.T) {
	before := restoreSettings(t)
	accessToken, _ := createAdminClientWithToken(t)
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/settings/general"

	cases := []struct {
		name     string
		body     api.UpdateSettingsGeneralRequest
		wantCode string
	}{
		{"app name", api.UpdateSettingsGeneralRequest{
			AppName:        "Acme <the third>",
			Issuer:         "https://example.org",
			PasswordPolicy: "low",
		}, "validator.settings.app_name_angle_brackets"},
		{"issuer", api.UpdateSettingsGeneralRequest{
			AppName:        "Acme",
			Issuer:         "https://example.org/<b>",
			PasswordPolicy: "low",
		}, "validator.settings.issuer_angle_brackets"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := makeAPIRequest(t, "PUT", url, accessToken, tc.body)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			var errResp api.ErrorResponse
			_ = json.NewDecoder(resp.Body).Decode(&errResp)
			assert.Equal(t, tc.wantCode, errResp.ErrorCode)

			stored, err := database.GetSettingsById(context.Background(), nil, 1)
			require.NoError(t, err)
			assert.Equal(t, before.AppName, stored.AppName)
			assert.Equal(t, before.Issuer, stored.Issuer)
		})
	}
}

// PUT: an App name that is empty once trimmed is refused with its own code and nothing is written,
// and the name is measured once trimmed, so 30 characters with spaces around them are stored
// trimmed (#646 decisions 3 and 7).
func TestAPISettingsGeneralPut_TheAppNameIsRequiredAndMeasuredTrimmed(t *testing.T) {
	before := restoreSettings(t)
	accessToken, _ := createAdminClientWithToken(t)
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/settings/general"

	for _, appName := range []string{"", "    "} {
		resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsGeneralRequest{
			AppName:        appName,
			Issuer:         "https://example.org",
			PasswordPolicy: "low",
		})
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "%q", appName)
		var errResp api.ErrorResponse
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		_ = resp.Body.Close()
		assert.Equal(t, "handler.settings_general.app_name_required", errResp.ErrorCode, "%q", appName)
		assert.Equal(t, "App name is required.", errResp.ErrorDescription, "%q", appName)

		stored, err := database.GetSettingsById(context.Background(), nil, 1)
		require.NoError(t, err)
		assert.Equal(t, before.AppName, stored.AppName, "nothing is written for %q", appName)
		assert.Equal(t, before.Issuer, stored.Issuer, "nothing is written for %q", appName)
	}

	thirty := strings.Repeat("é", 30)
	resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsGeneralRequest{
		AppName:        "   " + thirty + "  ",
		Issuer:         before.Issuer,
		PasswordPolicy: "low",
	})
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body api.SettingsGeneralResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, thirty, body.AppName)
	stored, err := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)
	assert.Equal(t, thirty, stored.AppName)
}

// TestAPISettingsGeneralPut_AmpersandsAndQuotesStoredVerbatim is the accepted twin.
func TestAPISettingsGeneralPut_AmpersandsAndQuotesStoredVerbatim(t *testing.T) {
	restoreSettings(t)
	accessToken, _ := createAdminClientWithToken(t)
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/settings/general"

	req := api.UpdateSettingsGeneralRequest{
		AppName:        `  R&D "labs"  `,
		Issuer:         "https://example.org",
		PasswordPolicy: "low",
	}
	resp := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body api.SettingsGeneralResponse
	err := json.NewDecoder(resp.Body).Decode(&body)
	require.NoError(t, err)
	assert.Equal(t, `R&D "labs"`, body.AppName)

	stored, err := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)
	assert.Equal(t, `R&D "labs"`, stored.AppName)
}
