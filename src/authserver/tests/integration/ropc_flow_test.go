package integrationtests

import (
	"net/url"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// Helper function to create a client with ROPC enabled
func createROPCClient(t *testing.T, clientSecret string, isPublic bool) *models.Client {
	ropcEnabled := true
	client := &models.Client{
		ClientIdentifier:                        "ropc-client-" + gofakeit.LetterN(8),
		Enabled:                                 true,
		IsPublic:                                isPublic,
		AuthorizationCodeEnabled:                true,
		ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
		DefaultAcrLevel:                         enums.AcrLevel1,
	}

	if !isPublic && clientSecret != "" {
		settings, err := database.GetSettingsById(nil, 1)
		assert.Nil(t, err)
		clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
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
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
		OTPEnabled:   true, // 2FA enabled
		OTPSecret:    "JBSWY3DPEHPK3PXP", // Dummy OTP secret
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
