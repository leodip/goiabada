package integrationtests

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/stretchr/testify/assert"
)

// GET /api/v1/admin/settings/email
func TestAPISettingsEmailGet_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Read current settings from DB for comparison
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	assert.NotNil(t, settings)

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/email"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body api.SettingsEmailResponse
	err = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, err)

	assert.Equal(t, settings.SMTPEnabled, body.SMTPEnabled)
	assert.Equal(t, settings.SMTPHost, body.SMTPHost)
	assert.Equal(t, settings.SMTPPort, body.SMTPPort)
	assert.Equal(t, settings.SMTPUsername, body.SMTPUsername)
	assert.Equal(t, settings.SMTPEncryption, body.SMTPEncryption)
	assert.Equal(t, settings.SMTPFromName, body.SMTPFromName)
	assert.Equal(t, settings.SMTPFromEmail, body.SMTPFromEmail)
	assert.Equal(t, len(settings.SMTPPasswordEncrypted) > 0, body.HasSMTPPassword)
}

// PUT /api/v1/admin/settings/email - enable and persist
func TestAPISettingsEmailPut_EnableSuccess(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	req := api.UpdateSettingsEmailRequest{
		SMTPEnabled:    true,
		SMTPHost:       "mailpit",
		SMTPPort:       1025,
		SMTPUsername:   "",
		SMTPPassword:   "secret123",
		SMTPEncryption: "starttls",
		SMTPFromName:   "Goiabada QA",
		SMTPFromEmail:  "qa@goiabada.dev",
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/email"
	resp := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body api.SettingsEmailResponse
	err := json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, err)

	assert.Equal(t, true, body.SMTPEnabled)
	assert.Equal(t, req.SMTPHost, body.SMTPHost)
	assert.Equal(t, req.SMTPPort, body.SMTPPort)
	assert.Equal(t, req.SMTPUsername, body.SMTPUsername)
	assert.Equal(t, strings.ToLower(req.SMTPEncryption), strings.ToLower(body.SMTPEncryption))
	assert.Equal(t, req.SMTPFromName, body.SMTPFromName)
	assert.Equal(t, strings.ToLower(req.SMTPFromEmail), strings.ToLower(body.SMTPFromEmail))
	assert.Equal(t, true, body.HasSMTPPassword)

	// Verify DB persisted
	settings, err2 := database.GetSettingsById(nil, 1)
	assert.NoError(t, err2)
	assert.True(t, settings.SMTPEnabled)
	assert.Equal(t, req.SMTPHost, settings.SMTPHost)
	assert.Equal(t, req.SMTPPort, settings.SMTPPort)
	assert.Equal(t, req.SMTPUsername, settings.SMTPUsername)
	assert.Equal(t, strings.ToLower(req.SMTPEncryption), strings.ToLower(settings.SMTPEncryption))
	assert.Equal(t, req.SMTPFromName, settings.SMTPFromName)
	assert.Equal(t, strings.ToLower(req.SMTPFromEmail), strings.ToLower(settings.SMTPFromEmail))
	assert.Greater(t, len(settings.SMTPPasswordEncrypted), 0)
}

// PUT: disable should reset fields
func TestAPISettingsEmailPut_DisableResetsFields(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// First enable with a password
	pre := api.UpdateSettingsEmailRequest{
		SMTPEnabled:    true,
		SMTPHost:       "mailpit",
		SMTPPort:       1025,
		SMTPUsername:   "user",
		SMTPPassword:   "p@ss",
		SMTPEncryption: "none",
		SMTPFromName:   "Goiabada",
		SMTPFromEmail:  "noreply@goiabada.dev",
	}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/email"
	_ = makeAPIRequest(t, "PUT", url, accessToken, pre)

	// Now disable
	req := api.UpdateSettingsEmailRequest{SMTPEnabled: false}
	resp := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify DB reset
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	assert.False(t, settings.SMTPEnabled)
	assert.Equal(t, "", settings.SMTPHost)
	assert.Equal(t, 0, settings.SMTPPort)
	assert.Equal(t, "none", strings.ToLower(settings.SMTPEncryption))
	assert.Equal(t, "", settings.SMTPUsername)
	assert.Nil(t, settings.SMTPPasswordEncrypted)
	assert.Equal(t, "", settings.SMTPFromName)
	assert.Equal(t, "", settings.SMTPFromEmail)
}

// PUT: validation errors
func TestAPISettingsEmailPut_ValidationErrors(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/email"

	// Missing host
	resp1 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsEmailRequest{
		SMTPEnabled:   true,
		SMTPHost:      "",
		SMTPPort:      1025,
		SMTPFromEmail: "noreply@goiabada.dev",
	})
	defer func() { _ = resp1.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp1.StatusCode)
	var err1 api.ErrorResponse
	_ = json.NewDecoder(resp1.Body).Decode(&err1)
	assert.Equal(t, "SMTP host is required.", err1.Error.Message)

	// Missing port
	resp2 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsEmailRequest{
		SMTPEnabled:   true,
		SMTPHost:      "mailpit",
		SMTPFromEmail: "noreply@goiabada.dev",
	})
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
	var err2 api.ErrorResponse
	_ = json.NewDecoder(resp2.Body).Decode(&err2)
	assert.Equal(t, "SMTP port is required.", err2.Error.Message)

	// Port out of range
	resp3 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsEmailRequest{
		SMTPEnabled:   true,
		SMTPHost:      "mailpit",
		SMTPPort:      70000,
		SMTPFromEmail: "noreply@goiabada.dev",
	})
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp3.StatusCode)
	var err3 api.ErrorResponse
	_ = json.NewDecoder(resp3.Body).Decode(&err3)
	assert.Equal(t, "SMTP port must be between 1 and 65535.", err3.Error.Message)

	// Host too long
	resp4 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsEmailRequest{
		SMTPEnabled:   true,
		SMTPHost:      strings.Repeat("a", 121),
		SMTPPort:      1025,
		SMTPFromEmail: "noreply@goiabada.dev",
	})
	defer func() { _ = resp4.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp4.StatusCode)
	var err4 api.ErrorResponse
	_ = json.NewDecoder(resp4.Body).Decode(&err4)
	assert.Equal(t, "SMTP host must be less than 120 characters.", err4.Error.Message)

	// Invalid encryption
	resp5 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsEmailRequest{
		SMTPEnabled:    true,
		SMTPHost:       "mailpit",
		SMTPPort:       1025,
		SMTPFromEmail:  "noreply@goiabada.dev",
		SMTPEncryption: "invalid",
	})
	defer func() { _ = resp5.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp5.StatusCode)
	var err5 api.ErrorResponse
	_ = json.NewDecoder(resp5.Body).Decode(&err5)
	assert.Equal(t, "Invalid SMTP encryption.", err5.Error.Message)
}

// PUT: TCP connectivity failure
func TestAPISettingsEmailPut_TCPConnectionFailure(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/email"

	req := api.UpdateSettingsEmailRequest{
		SMTPEnabled:    true,
		SMTPHost:       "127.0.0.1",
		SMTPPort:       65534, // likely closed
		SMTPFromEmail:  "noreply@goiabada.dev",
		SMTPEncryption: "none",
	}
	resp := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errBody api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errBody)
	assert.True(t, strings.HasPrefix(errBody.Error.Message, "Unable to connect to the SMTP server:"))
}

// PUT: password set and clear lifecycle
func TestAPISettingsEmailPut_PasswordLifecycle(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/email"

	// Set password
	req1 := api.UpdateSettingsEmailRequest{
		SMTPEnabled:    true,
		SMTPHost:       "mailpit",
		SMTPPort:       1025,
		SMTPFromEmail:  "noreply@goiabada.dev",
		SMTPEncryption: "none",
		SMTPPassword:   "abc123",
	}
	resp1 := makeAPIRequest(t, "PUT", url, accessToken, req1)
	defer func() { _ = resp1.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp1.StatusCode)
	// GET should show has password true
	respGet := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = respGet.Body.Close() }()
	var body api.SettingsEmailResponse
	_ = json.NewDecoder(respGet.Body).Decode(&body)
	assert.Equal(t, true, body.HasSMTPPassword)

	// Clear password (send empty)
	req2 := api.UpdateSettingsEmailRequest{
		SMTPEnabled:    true,
		SMTPHost:       "mailpit",
		SMTPPort:       1025,
		SMTPFromEmail:  "noreply@goiabada.dev",
		SMTPEncryption: "none",
		SMTPPassword:   "",
	}
	resp2 := makeAPIRequest(t, "PUT", url, accessToken, req2)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	// DB should have password cleared
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(settings.SMTPPasswordEncrypted))

	// GET should show has password false
	respGet2 := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = respGet2.Body.Close() }()
	var body2 api.SettingsEmailResponse
	_ = json.NewDecoder(respGet2.Body).Decode(&body2)
	assert.Equal(t, false, body2.HasSMTPPassword)
}

// POST /api/v1/admin/settings/email/send-test
func TestAPISettingsEmailSendTest_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Ensure SMTP is enabled and pointing to mailpit
	_ = makeAPIRequest(t, "PUT", config.GetAuthServer().BaseURL+"/api/v1/admin/settings/email", accessToken, api.UpdateSettingsEmailRequest{
		SMTPEnabled:    true,
		SMTPHost:       "mailpit",
		SMTPPort:       1025,
		SMTPFromEmail:  "noreply@goiabada.dev",
		SMTPEncryption: "none",
	})

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/email/send-test"
	resp := makeAPIRequest(t, "POST", url, accessToken, api.SendTestEmailRequest{To: "someone@example.com"})
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var okBody struct {
		Success bool `json:"success"`
	}
	err := json.NewDecoder(resp.Body).Decode(&okBody)
	assert.NoError(t, err)
	assert.True(t, okBody.Success)
}

func TestAPISettingsEmailSendTest_SMTPDisabled(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Disable SMTP
	_ = makeAPIRequest(t, "PUT", config.GetAuthServer().BaseURL+"/api/v1/admin/settings/email", accessToken, api.UpdateSettingsEmailRequest{SMTPEnabled: false})

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/email/send-test"
	resp := makeAPIRequest(t, "POST", url, accessToken, api.SendTestEmailRequest{To: "someone@example.com"})
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errBody api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errBody)
	assert.Equal(t, "SMTP is not enabled", errBody.Error.Message)
}

// Unauthorized scenarios
func TestAPISettingsEmail_Unauthorized(t *testing.T) {
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/email"
	httpClient := createHttpClient(t)

	// No token - GET
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	bodyBytes, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "Access token required", strings.TrimSpace(string(bodyBytes)))

	// No token - PUT
	req2, _ := http.NewRequest("PUT", url, nil)
	resp2, err := httpClient.Do(req2)
	assert.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
}
