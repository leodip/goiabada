package integrationtests

import (
	"net/url"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/validators"
	"github.com/stretchr/testify/assert"
)

// Helper function to create a client with ROPC enabled
func createROPCClient(t *testing.T, clientSecret string, isPublic bool) *models.Client {
	ropcEnabled := true
	client := &models.Client{
		ClientIdentifier: "ropc-client-" + gofakeit.LetterN(8),
		Enabled:          true,
		IsPublic:         isPublic,
		// Off deliberately, so this is an ROPC-ONLY client. With the authorization code flow
		// also on, no test here can observe whether the token endpoint gates a refresh on the
		// switch of the flow that issued the token: both answers look the same. That is how a
		// refresh arm refusing every ROPC token on !AuthorizationCodeEnabled survived five
		// releases with a green suite (#250). A test that genuinely wants both flows sets the
		// field after this call, as the two inline clients further down this file do.
		AuthorizationCodeEnabled:                false,
		ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
		DefaultAcrLevel:                         enums.AcrLevel1,
	}

	if !isPublic && clientSecret != "" {
		clientSecretEncrypted, err := encryption.EncryptData(clientSecret)
		assert.Nil(t, err)
		client.ClientSecretEncrypted = clientSecretEncrypted
	}

	err := database.CreateClient(nil, client)
	assert.Nil(t, err)

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}
	err = database.CreateRedirectURI(nil, redirectUri)
	assert.Nil(t, err)

	return client
}

// Helper function to create a user for ROPC tests
func createROPCUser(t *testing.T, password string) *models.User {
	passwordHashed, err := hashutil.HashPassword(password)
	assert.Nil(t, err)

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
		GivenName:    gofakeit.FirstName(),
		FamilyName:   gofakeit.LastName(),
	}

	err = database.CreateUser(nil, user)
	assert.Nil(t, err)

	return user
}

// TestROPC_Success tests a successful ROPC flow with a public client
func TestROPC_Success(t *testing.T) {
	// Enable ROPC globally
	settings, err := database.GetSettingsById(nil, 1)
	assert.Nil(t, err)
	originalROPCSetting := settings.ResourceOwnerPasswordCredentialsEnabled
	settings.ResourceOwnerPasswordCredentialsEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.Nil(t, err)
	defer func() {
		settings.ResourceOwnerPasswordCredentialsEnabled = originalROPCSetting
		_ = database.UpdateSettings(nil, settings)
	}()

	// Create client and user
	password := gofakeit.Password(true, true, true, true, false, 12)
	client := createROPCClient(t, "", true) // public client
	user := createROPCUser(t, password)

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"
	httpClient := createHttpClient(t)

	formData := url.Values{
		"grant_type": {"password"},
		"client_id":  {client.ClientIdentifier},
		"username":   {user.Email},
		"password":   {password},
		"scope":      {"openid"},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	// Verify successful response
	assert.NotEmpty(t, data["access_token"])
	assert.NotEmpty(t, data["refresh_token"])
	assert.NotEmpty(t, data["id_token"])
	assert.Equal(t, "Bearer", data["token_type"])
	assert.NotNil(t, data["expires_in"])
}

// TestROPC_ConfidentialClient tests ROPC with a confidential client
func TestROPC_ConfidentialClient(t *testing.T) {
	// Enable ROPC globally
	settings, err := database.GetSettingsById(nil, 1)
	assert.Nil(t, err)
	originalROPCSetting := settings.ResourceOwnerPasswordCredentialsEnabled
	settings.ResourceOwnerPasswordCredentialsEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.Nil(t, err)
	defer func() {
		settings.ResourceOwnerPasswordCredentialsEnabled = originalROPCSetting
		_ = database.UpdateSettings(nil, settings)
	}()

	// Create confidential client and user
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	password := gofakeit.Password(true, true, true, true, false, 12)
	client := createROPCClient(t, clientSecret, false) // confidential client
	user := createROPCUser(t, password)

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"
	httpClient := createHttpClient(t)

	formData := url.Values{
		"grant_type":    {"password"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"username":      {user.Email},
		"password":      {password},
		"scope":         {"openid"},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	// Verify successful response
	assert.NotEmpty(t, data["access_token"])
	assert.NotEmpty(t, data["refresh_token"])
	assert.NotEmpty(t, data["id_token"])
	assert.Equal(t, "Bearer", data["token_type"])
}

// TestROPC_GlobalDisabled tests that ROPC fails when globally disabled
func TestROPC_GlobalDisabled(t *testing.T) {
	// Ensure ROPC is globally disabled
	settings, err := database.GetSettingsById(nil, 1)
	assert.Nil(t, err)
	originalROPCSetting := settings.ResourceOwnerPasswordCredentialsEnabled
	settings.ResourceOwnerPasswordCredentialsEnabled = false
	err = database.UpdateSettings(nil, settings)
	assert.Nil(t, err)
	defer func() {
		settings.ResourceOwnerPasswordCredentialsEnabled = originalROPCSetting
		_ = database.UpdateSettings(nil, settings)
	}()

	// Create client with ROPC set to nil (follows global setting) and user
	password := gofakeit.Password(true, true, true, true, false, 12)
	client := &models.Client{
		ClientIdentifier:                        "ropc-client-" + gofakeit.LetterN(8),
		Enabled:                                 true,
		IsPublic:                                true,
		AuthorizationCodeEnabled:                true,
		ResourceOwnerPasswordCredentialsEnabled: nil, // Follow global setting
		DefaultAcrLevel:                         enums.AcrLevel1,
	}
	err = database.CreateClient(nil, client)
	assert.Nil(t, err)
	user := createROPCUser(t, password)

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"
	httpClient := createHttpClient(t)

	formData := url.Values{
		"grant_type": {"password"},
		"client_id":  {client.ClientIdentifier},
		"username":   {user.Email},
		"password":   {password},
		"scope":      {"openid"},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "unauthorized_client", data["error"])
	// Error message describes that ROPC is not authorized for this client
	assert.Contains(t, data["error_description"], "not authorized to use the resource owner password credentials grant")
}

// TestROPC_ClientOverrideDisabled tests that client-level override can disable ROPC
func TestROPC_ClientOverrideDisabled(t *testing.T) {
	// Enable ROPC globally
	settings, err := database.GetSettingsById(nil, 1)
	assert.Nil(t, err)
	originalROPCSetting := settings.ResourceOwnerPasswordCredentialsEnabled
	settings.ResourceOwnerPasswordCredentialsEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.Nil(t, err)
	defer func() {
		settings.ResourceOwnerPasswordCredentialsEnabled = originalROPCSetting
		_ = database.UpdateSettings(nil, settings)
	}()

	// Create client with ROPC disabled at client level
	ropcDisabled := false
	client := &models.Client{
		ClientIdentifier:                        "ropc-disabled-client-" + gofakeit.LetterN(8),
		Enabled:                                 true,
		IsPublic:                                true,
		AuthorizationCodeEnabled:                true,
		ResourceOwnerPasswordCredentialsEnabled: &ropcDisabled,
		DefaultAcrLevel:                         enums.AcrLevel1,
	}
	err = database.CreateClient(nil, client)
	assert.Nil(t, err)

	password := gofakeit.Password(true, true, true, true, false, 12)
	user := createROPCUser(t, password)

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"
	httpClient := createHttpClient(t)

	formData := url.Values{
		"grant_type": {"password"},
		"client_id":  {client.ClientIdentifier},
		"username":   {user.Email},
		"password":   {password},
		"scope":      {"openid"},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "unauthorized_client", data["error"])
	// Error message describes that ROPC is not authorized for this client
	assert.Contains(t, data["error_description"], "not authorized to use the resource owner password credentials grant")
}

// TestROPC_MissingUsername tests that missing username returns error
func TestROPC_MissingUsername(t *testing.T) {
	// Enable ROPC globally
	settings, err := database.GetSettingsById(nil, 1)
	assert.Nil(t, err)
	originalROPCSetting := settings.ResourceOwnerPasswordCredentialsEnabled
	settings.ResourceOwnerPasswordCredentialsEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.Nil(t, err)
	defer func() {
		settings.ResourceOwnerPasswordCredentialsEnabled = originalROPCSetting
		_ = database.UpdateSettings(nil, settings)
	}()

	client := createROPCClient(t, "", true)

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"
	httpClient := createHttpClient(t)

	formData := url.Values{
		"grant_type": {"password"},
		"client_id":  {client.ClientIdentifier},
		"password":   {"somepassword"},
		"scope":      {"openid"},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Contains(t, data["error_description"], "username")
}

// TestROPC_MissingPassword tests that missing password returns error
func TestROPC_MissingPassword(t *testing.T) {
	// Enable ROPC globally
	settings, err := database.GetSettingsById(nil, 1)
	assert.Nil(t, err)
	originalROPCSetting := settings.ResourceOwnerPasswordCredentialsEnabled
	settings.ResourceOwnerPasswordCredentialsEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.Nil(t, err)
	defer func() {
		settings.ResourceOwnerPasswordCredentialsEnabled = originalROPCSetting
		_ = database.UpdateSettings(nil, settings)
	}()

	client := createROPCClient(t, "", true)
	user := createROPCUser(t, "somepassword")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"
	httpClient := createHttpClient(t)

	formData := url.Values{
		"grant_type": {"password"},
		"client_id":  {client.ClientIdentifier},
		"username":   {user.Email},
		"scope":      {"openid"},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Contains(t, data["error_description"], "password")
}

// TestROPC_InvalidCredentials tests that invalid password returns error
func TestROPC_InvalidCredentials(t *testing.T) {
	// Enable ROPC globally
	settings, err := database.GetSettingsById(nil, 1)
	assert.Nil(t, err)
	originalROPCSetting := settings.ResourceOwnerPasswordCredentialsEnabled
	settings.ResourceOwnerPasswordCredentialsEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.Nil(t, err)
	defer func() {
		settings.ResourceOwnerPasswordCredentialsEnabled = originalROPCSetting
		_ = database.UpdateSettings(nil, settings)
	}()

	password := gofakeit.Password(true, true, true, true, false, 12)
	client := createROPCClient(t, "", true)
	user := createROPCUser(t, password)

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"
	httpClient := createHttpClient(t)

	formData := url.Values{
		"grant_type": {"password"},
		"client_id":  {client.ClientIdentifier},
		"username":   {user.Email},
		"password":   {"wrongpassword"},
		"scope":      {"openid"},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_grant", data["error"])
	assert.Contains(t, data["error_description"], "credentials")
}

// TestROPC_UserNotFound tests that non-existent user returns error
// Note: For security reasons, the error message doesn't reveal whether the user exists
func TestROPC_UserNotFound(t *testing.T) {
	// Enable ROPC globally
	settings, err := database.GetSettingsById(nil, 1)
	assert.Nil(t, err)
	originalROPCSetting := settings.ResourceOwnerPasswordCredentialsEnabled
	settings.ResourceOwnerPasswordCredentialsEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.Nil(t, err)
	defer func() {
		settings.ResourceOwnerPasswordCredentialsEnabled = originalROPCSetting
		_ = database.UpdateSettings(nil, settings)
	}()

	client := createROPCClient(t, "", true)

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"
	httpClient := createHttpClient(t)

	formData := url.Values{
		"grant_type": {"password"},
		"client_id":  {client.ClientIdentifier},
		"username":   {"nonexistent@example.com"},
		"password":   {"somepassword"},
		"scope":      {"openid"},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_grant", data["error"])
	// For security, same error message as invalid password (doesn't reveal user existence)
	assert.Contains(t, data["error_description"], "Invalid resource owner credentials")
}

// TestROPC_DisabledUser tests that disabled user cannot authenticate
func TestROPC_DisabledUser(t *testing.T) {
	// Enable ROPC globally
	settings, err := database.GetSettingsById(nil, 1)
	assert.Nil(t, err)
	originalROPCSetting := settings.ResourceOwnerPasswordCredentialsEnabled
	settings.ResourceOwnerPasswordCredentialsEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.Nil(t, err)
	defer func() {
		settings.ResourceOwnerPasswordCredentialsEnabled = originalROPCSetting
		_ = database.UpdateSettings(nil, settings)
	}()

	password := gofakeit.Password(true, true, true, true, false, 12)
	client := createROPCClient(t, "", true)

	// Create disabled user
	passwordHashed, err := hashutil.HashPassword(password)
	assert.Nil(t, err)
	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      false, // Disabled
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}
	err = database.CreateUser(nil, user)
	assert.Nil(t, err)

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"
	httpClient := createHttpClient(t)

	formData := url.Values{
		"grant_type": {"password"},
		"client_id":  {client.ClientIdentifier},
		"username":   {user.Email},
		"password":   {password},
		"scope":      {"openid"},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_grant", data["error"])
	assert.Contains(t, data["error_description"], "disabled")
}

// TestROPC_WithOfflineAccess tests ROPC with offline_access scope
func TestROPC_WithOfflineAccess(t *testing.T) {
	// Enable ROPC globally
	settings, err := database.GetSettingsById(nil, 1)
	assert.Nil(t, err)
	originalROPCSetting := settings.ResourceOwnerPasswordCredentialsEnabled
	settings.ResourceOwnerPasswordCredentialsEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.Nil(t, err)
	defer func() {
		settings.ResourceOwnerPasswordCredentialsEnabled = originalROPCSetting
		_ = database.UpdateSettings(nil, settings)
	}()

	password := gofakeit.Password(true, true, true, true, false, 12)
	client := createROPCClient(t, "", true)
	user := createROPCUser(t, password)

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"
	httpClient := createHttpClient(t)

	formData := url.Values{
		"grant_type": {"password"},
		"client_id":  {client.ClientIdentifier},
		"username":   {user.Email},
		"password":   {password},
		"scope":      {"openid offline_access"},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	// Verify successful response with offline_access
	assert.NotEmpty(t, data["access_token"])
	assert.NotEmpty(t, data["refresh_token"])
	assert.NotEmpty(t, data["id_token"])
	assert.Equal(t, "Bearer", data["token_type"])

	// Verify scope includes offline_access
	scope, ok := data["scope"].(string)
	assert.True(t, ok)
	assert.Contains(t, scope, "offline_access")
}

// TestROPC_ConfidentialClient_MissingSecret tests that confidential client requires secret
func TestROPC_ConfidentialClient_MissingSecret(t *testing.T) {
	// Enable ROPC globally
	settings, err := database.GetSettingsById(nil, 1)
	assert.Nil(t, err)
	originalROPCSetting := settings.ResourceOwnerPasswordCredentialsEnabled
	settings.ResourceOwnerPasswordCredentialsEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.Nil(t, err)
	defer func() {
		settings.ResourceOwnerPasswordCredentialsEnabled = originalROPCSetting
		_ = database.UpdateSettings(nil, settings)
	}()

	// Create confidential client
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	password := gofakeit.Password(true, true, true, true, false, 12)
	client := createROPCClient(t, clientSecret, false) // confidential client
	user := createROPCUser(t, password)

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"
	httpClient := createHttpClient(t)

	// Don't include client_secret
	formData := url.Values{
		"grant_type": {"password"},
		"client_id":  {client.ClientIdentifier},
		"username":   {user.Email},
		"password":   {password},
		"scope":      {"openid"},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	// RFC 6749 Section 5.2: invalid_client for missing client credentials
	assert.Equal(t, "invalid_client", data["error"])
	assert.Contains(t, data["error_description"], "client_secret")
}

// TestROPC_ConfidentialClient_InvalidSecret tests that invalid client secret fails
func TestROPC_ConfidentialClient_InvalidSecret(t *testing.T) {
	// Enable ROPC globally
	settings, err := database.GetSettingsById(nil, 1)
	assert.Nil(t, err)
	originalROPCSetting := settings.ResourceOwnerPasswordCredentialsEnabled
	settings.ResourceOwnerPasswordCredentialsEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.Nil(t, err)
	defer func() {
		settings.ResourceOwnerPasswordCredentialsEnabled = originalROPCSetting
		_ = database.UpdateSettings(nil, settings)
	}()

	// Create confidential client
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	password := gofakeit.Password(true, true, true, true, false, 12)
	client := createROPCClient(t, clientSecret, false)
	user := createROPCUser(t, password)

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"
	httpClient := createHttpClient(t)

	// Use wrong client_secret
	formData := url.Values{
		"grant_type":    {"password"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {"wrongsecret"},
		"username":      {user.Email},
		"password":      {password},
		"scope":         {"openid"},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_client", data["error"])
	assert.Contains(t, data["error_description"], "Client authentication failed")
}

// TestROPC_UserWith2FAEnabled tests that users with 2FA enabled cannot use ROPC
// This is a security feature - ROPC cannot securely support a second authentication factor
func TestROPC_UserWith2FAEnabled(t *testing.T) {
	// Enable ROPC globally
	settings, err := database.GetSettingsById(nil, 1)
	assert.Nil(t, err)
	originalROPCSetting := settings.ResourceOwnerPasswordCredentialsEnabled
	settings.ResourceOwnerPasswordCredentialsEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.Nil(t, err)
	defer func() {
		settings.ResourceOwnerPasswordCredentialsEnabled = originalROPCSetting
		_ = database.UpdateSettings(nil, settings)
	}()

	password := gofakeit.Password(true, true, true, true, false, 12)
	client := createROPCClient(t, "", true)

	// Create user with 2FA (OTP) enabled
	passwordHashed, err := hashutil.HashPassword(password)
	assert.Nil(t, err)
	user := &models.User{
		Subject:            uuid.New(),
		Enabled:            true,
		Email:              gofakeit.Email(),
		PasswordHash:       passwordHashed,
		OTPEnabled:         true,               // 2FA enabled
		OTPSecret:          "JBSWY3DPEHPK3PXP", // Dummy OTP secret
		OTPSecretEncrypted: encryptOTPSecretForTest(t, "JBSWY3DPEHPK3PXP"),
	}
	err = database.CreateUser(nil, user)
	assert.Nil(t, err)

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"
	httpClient := createHttpClient(t)

	formData := url.Values{
		"grant_type": {"password"},
		"client_id":  {client.ClientIdentifier},
		"username":   {user.Email},
		"password":   {password},
		"scope":      {"openid"},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	// Should fail with invalid_grant error explaining 2FA users cannot use ROPC
	assert.Equal(t, "invalid_grant", data["error"])
	assert.Contains(t, data["error_description"], "two-factor authentication enabled")
	assert.Contains(t, data["error_description"], "authorization code flow")
}

// TestROPC_WithResourcePermissions tests ROPC with resource permissions
func TestROPC_WithResourcePermissions(t *testing.T) {
	// Enable ROPC globally
	settings, err := database.GetSettingsById(nil, 1)
	assert.Nil(t, err)
	originalROPCSetting := settings.ResourceOwnerPasswordCredentialsEnabled
	settings.ResourceOwnerPasswordCredentialsEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.Nil(t, err)
	defer func() {
		settings.ResourceOwnerPasswordCredentialsEnabled = originalROPCSetting
		_ = database.UpdateSettings(nil, settings)
	}()

	// Create resource and permission
	resource := createResourceWithId(t, "testapi-"+gofakeit.LetterN(8))
	permission := createPermissionWithId(t, resource.Id, "read")

	password := gofakeit.Password(true, true, true, true, false, 12)
	client := createROPCClient(t, "", true)
	user := createROPCUser(t, password)

	// Assign permission to user
	assignPermissionToUser(t, user.Id, permission.Id)

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"
	httpClient := createHttpClient(t)

	formData := url.Values{
		"grant_type": {"password"},
		"client_id":  {client.ClientIdentifier},
		"username":   {user.Email},
		"password":   {password},
		"scope":      {"openid " + resource.ResourceIdentifier + ":" + permission.PermissionIdentifier},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	// Verify successful response with resource permission
	assert.NotEmpty(t, data["access_token"])
	assert.NotEmpty(t, data["refresh_token"])
	assert.Equal(t, "Bearer", data["token_type"])

	// Verify scope includes the resource permission
	scope, ok := data["scope"].(string)
	assert.True(t, ok)
	assert.Contains(t, scope, resource.ResourceIdentifier+":"+permission.PermissionIdentifier)
}

// TestROPC_RefreshToken_OpenIdOnly covers the case that was broken outright: an ROPC token
// requesting `openid` and nothing else could not be refreshed.
//
// generateAccessTokenCore appends authserver:userinfo to any token carrying an OIDC scope so the
// token can reach /userinfo. The ROPC refresh token used to record that appended scope as though
// it were the grant, and on refresh the validator re-checked every non-OIDC scope in it against
// the user's permissions, so the server rejected a scope it had injected itself.
//
// The four ROPC tests above assert only that a refresh token comes back and never redeem one,
// which is why this shipped. `openid` alone is deliberate: it is the normal ROPC request, needs no
// permission grants, and is exactly the case that failed. A test that also requested a resource
// scope could pass for the wrong reason if the user happened to hold it.
func TestROPC_RefreshToken_OpenIdOnly(t *testing.T) {
	settings, err := database.GetSettingsById(nil, 1)
	assert.Nil(t, err)
	originalROPCSetting := settings.ResourceOwnerPasswordCredentialsEnabled
	settings.ResourceOwnerPasswordCredentialsEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.Nil(t, err)
	defer func() {
		settings.ResourceOwnerPasswordCredentialsEnabled = originalROPCSetting
		_ = database.UpdateSettings(nil, settings)
	}()

	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	password := gofakeit.Password(true, true, true, true, false, 12)
	client := createROPCClient(t, clientSecret, false)
	user := createROPCUser(t, password)

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"
	httpClient := createHttpClient(t)

	userInfoScope := constants.AuthServerResourceIdentifier + ":" + constants.UserinfoPermissionIdentifier

	data := postToTokenEndpoint(t, httpClient, destUrl, url.Values{
		"grant_type":    {"password"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"username":      {user.Email},
		"password":      {password},
		"scope":         {"openid"},
	})

	refreshToken, ok := data["refresh_token"].(string)
	assert.True(t, ok, "ROPC should return a refresh token: %v", data)

	// The ACCESS token carries the injected scope: that is the feature, and it must survive.
	accessScope, ok := data["scope"].(string)
	assert.True(t, ok)
	assert.Contains(t, accessScope, userInfoScope,
		"the issued access token should still carry the injected userinfo scope")

	// The REFRESH token must record the grant instead, so it carries no injected scope. Assert on
	// both the claim and the persisted row, because the row is what the validator consults.
	refreshClaims := decodeJWTPayload(t, refreshToken)
	refreshScopeClaim, ok := refreshClaims["scope"].(string)
	assert.True(t, ok, "refresh token should carry a scope claim")
	assert.Equal(t, "openid", refreshScopeClaim,
		"the refresh token should record the granted scope, not the decorated one")

	jti, ok := refreshClaims["jti"].(string)
	assert.True(t, ok)
	persisted, err := database.GetRefreshTokenByJti(nil, jti)
	assert.NoError(t, err)
	if assert.NotNil(t, persisted, "the refresh token should be persisted") {
		assert.Equal(t, "openid", persisted.Scope,
			"the persisted refresh token row should record the granted scope")
		assert.NotContains(t, persisted.Scope, userInfoScope)
	}

	// Redeeming it is the point. The user holds no permissions at all, which before the fix was
	// enough to make this fail with invalid_grant.
	refreshed := postToTokenEndpoint(t, httpClient, destUrl, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"refresh_token": {refreshToken},
	})

	assert.Nil(t, refreshed["error"], "refresh should succeed: %v", refreshed)
	newAccessToken, ok := refreshed["access_token"].(string)
	assert.True(t, ok, "refresh should return a new access token: %v", refreshed)
	assert.NotEmpty(t, newAccessToken)

	// The reissued access token is re-decorated, so /userinfo access is unchanged by the fix.
	// This pair is the whole point: the scope left the refresh token record without leaving the
	// issued token.
	newAccessClaims := decodeJWTPayload(t, newAccessToken)
	newAccessScope, ok := newAccessClaims["scope"].(string)
	assert.True(t, ok)
	assert.Contains(t, newAccessScope, userInfoScope,
		"the reissued access token should still carry the injected userinfo scope")
}

// TestROPC_RefreshToken_StopsWhenROPCDisabled is the breaking half of this change, end to end:
// turning ROPC off stops refresh tokens ALREADY ISSUED, not merely new logins. Before this the
// switch governed issuance only, so an operator who turned it off left every outstanding offline
// grant refreshing indefinitely with nothing saying so (#250).
//
// Two subtests, differing only in which switch is turned off: the per-client override, and the
// global with the client left inheriting. The second is the one an operator actually reaches for,
// and it is the only one that fails if the gate reads the override alone.
func TestROPC_RefreshToken_StopsWhenROPCDisabled(t *testing.T) {
	testCases := []struct {
		name string
		// disable turns ROPC off the way this case is about, and returns a restore func.
		disable func(t *testing.T, client *models.Client) func()
	}{
		{
			name: "the client's own override is turned off",
			disable: func(t *testing.T, client *models.Client) func() {
				ropcDisabled := false
				client.ResourceOwnerPasswordCredentialsEnabled = &ropcDisabled
				assert.Nil(t, database.UpdateClient(nil, client))
				return func() {}
			},
		},
		{
			name: "the client inherits and the global switch is turned off",
			disable: func(t *testing.T, client *models.Client) func() {
				client.ResourceOwnerPasswordCredentialsEnabled = nil
				assert.Nil(t, database.UpdateClient(nil, client))

				settings, err := database.GetSettingsById(nil, 1)
				assert.Nil(t, err)
				settings.ResourceOwnerPasswordCredentialsEnabled = false
				assert.Nil(t, database.UpdateSettings(nil, settings))
				return func() {
					settings.ResourceOwnerPasswordCredentialsEnabled = true
					_ = database.UpdateSettings(nil, settings)
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			settings, err := database.GetSettingsById(nil, 1)
			assert.Nil(t, err)
			originalROPCSetting := settings.ResourceOwnerPasswordCredentialsEnabled
			settings.ResourceOwnerPasswordCredentialsEnabled = true
			err = database.UpdateSettings(nil, settings)
			assert.Nil(t, err)
			defer func() {
				current, err := database.GetSettingsById(nil, 1)
				if err == nil {
					current.ResourceOwnerPasswordCredentialsEnabled = originalROPCSetting
					_ = database.UpdateSettings(nil, current)
				}
			}()

			clientSecret := gofakeit.Password(true, true, true, true, false, 32)
			password := gofakeit.Password(true, true, true, true, false, 12)
			client := createROPCClient(t, clientSecret, false)
			user := createROPCUser(t, password)

			destUrl := config.GetAuthServer().BaseURL + "/auth/token/"
			httpClient := createHttpClient(t)

			data := postToTokenEndpoint(t, httpClient, destUrl, url.Values{
				"grant_type":    {"password"},
				"client_id":     {client.ClientIdentifier},
				"client_secret": {clientSecret},
				"username":      {user.Email},
				"password":      {password},
				"scope":         {"openid"},
			})

			// Reassigned from every response on purpose. Rotation retires a refresh token the
			// moment it is redeemed, so presenting the password grant's token a second time
			// would be a REPLAY: it would be contained and answered invalid_grant whatever the
			// ROPC switch says, and this test would report a refusal while proving nothing
			// about a live token. The successor is what must still be live when the switch
			// goes off.
			refreshToken, ok := data["refresh_token"].(string)
			assert.True(t, ok, "ROPC should return a refresh token: %v", data)

			// Establish that it works while ROPC is on, so the refusal below is attributable to
			// the switch and to nothing else.
			refreshed := postToTokenEndpoint(t, httpClient, destUrl, url.Values{
				"grant_type":    {"refresh_token"},
				"client_id":     {client.ClientIdentifier},
				"client_secret": {clientSecret},
				"refresh_token": {refreshToken},
			})
			assert.Nil(t, refreshed["error"], "the refresh should succeed while ROPC is on: %v", refreshed)
			refreshToken, ok = refreshed["refresh_token"].(string)
			assert.True(t, ok, "the rotation should return a successor refresh token: %v", refreshed)

			restore := tc.disable(t, client)
			defer restore()

			stopped := postToTokenEndpoint(t, httpClient, destUrl, url.Values{
				"grant_type":    {"refresh_token"},
				"client_id":     {client.ClientIdentifier},
				"client_secret": {clientSecret},
				"refresh_token": {refreshToken},
			})

			assert.Equal(t, "unauthorized_client", stopped["error"],
				"a live ROPC refresh token must stop the moment ROPC is turned off: %v", stopped)
			assert.Equal(t, validators.ROPCNotAuthorizedErrorMsg, stopped["error_description"],
				"the refusal must name the grant that was actually refused: %v", stopped)
			assert.Nil(t, stopped["access_token"], "nothing may be minted: %v", stopped)
		})
	}
}
