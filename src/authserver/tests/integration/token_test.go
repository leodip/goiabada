package integrationtests

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
)

func TestToken_ClientIdIsMissing(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	httpClient := createHttpClient(t)

	formData := url.Values{}
	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "Missing required client_id parameter.", data["error_description"])
}

func TestToken_ClientDoesNotExist(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	httpClient := createHttpClient(t)

	formData := url.Values{
		"client_id": {"invalid"},
	}
	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "Client does not exist.", data["error_description"])
}

func TestToken_InvalidGrantType(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: true,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
	}
	err := database.CreateClient(nil, client)
	assert.Nil(t, err)

	httpClient := createHttpClient(t)

	formData := url.Values{
		"grant_type": {"invalid_grant_type"},
		"client_id":  {client.ClientIdentifier},
	}
	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "unsupported_grant_type", data["error"])
	assert.Equal(t, "Unsupported grant_type.", data["error_description"])
}

func TestToken_AuthCode_MissingCode(t *testing.T) {
	httpClient, code := createAuthCode(t, gofakeit.LetterN(32), "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {gofakeit.LetterN(43)},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "Missing required code parameter.", data["error_description"])
}

func TestToken_AuthCode_MissingRedirectURI(t *testing.T) {
	httpClient, code := createAuthCode(t, gofakeit.LetterN(32), "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"code_verifier": {gofakeit.LetterN(43)},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "Missing required redirect_uri parameter.", data["error_description"])
}

func TestToken_AuthCode_MissingCodeVerifier(t *testing.T) {
	clientSecret := gofakeit.LetterN(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"client_secret": {clientSecret},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "Missing required code_verifier parameter.", data["error_description"])
}

func TestToken_AuthCode_ClientDoesNotExist(t *testing.T) {
	httpClient, code := createAuthCode(t, gofakeit.LetterN(32), "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"non-existent-client"},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {gofakeit.LetterN(43)},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "Client does not exist.", data["error_description"])
}

func TestToken_AuthCode_CodeIsInvalid(t *testing.T) {
	httpClient, code := createAuthCode(t, gofakeit.LetterN(32), "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {"invalid_code"},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {gofakeit.LetterN(43)},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_grant", data["error"])
	assert.Equal(t, "Code is invalid.", data["error_description"])
}

func TestToken_AuthCode_RedirectURIIsInvalid(t *testing.T) {
	httpClient, code := createAuthCode(t, gofakeit.LetterN(32), "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {"https://invalid-redirect-uri.com"},
		"code_verifier": {gofakeit.LetterN(43)},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_grant", data["error"])
	assert.Equal(t, "Invalid redirect_uri.", data["error_description"])
}

func TestToken_AuthCode_WrongClient(t *testing.T) {
	httpClient, code := createAuthCode(t, gofakeit.LetterN(32), "openid profile email")

	// Create a new client to use as the wrong client
	wrongClient := &models.Client{
		ClientIdentifier:         "wrong-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
	}
	err := database.CreateClient(nil, wrongClient)
	assert.NoError(t, err)

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {wrongClient.ClientIdentifier}, // Use the wrong client ID
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {gofakeit.LetterN(43)},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_grant", data["error"])
	assert.Equal(t, "The client_id provided does not match the client_id from code.", data["error_description"])
}

func TestToken_AuthCode_ConfidentialClient_NoClientSecret(t *testing.T) {
	httpClient, code := createAuthCode(t, gofakeit.LetterN(32), "openid profile email")

	// Ensure the client is not public (confidential)
	code.Client.IsPublic = false
	err := database.UpdateClient(nil, &code.Client)
	assert.NoError(t, err)

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {gofakeit.LetterN(43)},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	// RFC 6749 Section 5.2: invalid_client for missing client credentials
	assert.Equal(t, "invalid_client", data["error"])
	assert.Equal(t, "This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed.", data["error_description"])
}

func TestToken_AuthCode_ConfidentialClient_ClientAuthFailed(t *testing.T) {
	clientSecret := gofakeit.LetterN(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	// Ensure the client is confidential (not public)
	code.Client.IsPublic = false
	err := database.UpdateClient(nil, &code.Client)
	assert.NoError(t, err)

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {gofakeit.LetterN(43)},
		"client_secret": {"incorrect_secret"}, // Provide an incorrect client secret
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	// RFC 6749 Section 5.2: invalid_client for failed client authentication
	assert.Equal(t, "invalid_client", data["error"])
	assert.Equal(t, "Client authentication failed. Please review your client_secret.", data["error_description"])
}

func TestToken_AuthCode_InvalidCodeVerifier(t *testing.T) {
	clientSecret := gofakeit.LetterN(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	code.Client.IsPublic = false
	err := database.UpdateClient(nil, &code.Client)
	assert.NoError(t, err)

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"invalid_code_verifier"}, // Using an invalid code verifier
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_grant", data["error"])
	assert.Equal(t, "Invalid code_verifier (PKCE).", data["error_description"])
}

func TestToken_AuthCode_SuccessPath(t *testing.T) {
	clientSecret := gofakeit.LetterN(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
		"client_secret": {clientSecret},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.NotNil(t, data["access_token"])
	assert.NotNil(t, data["token_type"])
	assert.Equal(t, "Bearer", data["token_type"])
	assert.NotNil(t, data["expires_in"])
	assert.NotNil(t, data["id_token"])

	// Verify that the code has been marked as used
	usedCode, err := database.GetCodeById(nil, code.Id)
	assert.NoError(t, err)
	assert.True(t, usedCode.Used)
}

// ============================================================================
// client_secret_basic tests (HTTP Basic Authentication)
// ============================================================================

func TestToken_AuthCode_ClientSecretBasic_Success(t *testing.T) {
	clientSecret := gofakeit.LetterN(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	// Use Basic auth instead of client_secret in form body
	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
	}

	data := postToTokenEndpointWithBasicAuth(t, httpClient, destUrl, formData, code.Client.ClientIdentifier, clientSecret)

	assert.NotNil(t, data["access_token"])
	assert.NotNil(t, data["token_type"])
	assert.Equal(t, "Bearer", data["token_type"])
	assert.NotNil(t, data["expires_in"])
	assert.NotNil(t, data["id_token"])

	// Verify that the code has been marked as used
	usedCode, err := database.GetCodeById(nil, code.Id)
	assert.NoError(t, err)
	assert.True(t, usedCode.Used)
}

func TestToken_AuthCode_ClientSecretBasic_WrongSecret(t *testing.T) {
	clientSecret := gofakeit.LetterN(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
	}

	// Use wrong secret in Basic auth
	data := postToTokenEndpointWithBasicAuth(t, httpClient, destUrl, formData, code.Client.ClientIdentifier, "wrong_secret")

	// RFC 6749 Section 5.2: invalid_client for failed client authentication
	assert.Equal(t, "invalid_client", data["error"])
	assert.Equal(t, "Client authentication failed. Please review your client_secret.", data["error_description"])
}

func TestToken_AuthCode_ClientSecretBasic_BothMethodsProvided(t *testing.T) {
	clientSecret := gofakeit.LetterN(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	// Provide client_secret in BOTH Basic auth header AND form body
	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
		"client_secret": {clientSecret}, // Also in form body
	}

	data := postToTokenEndpointWithBasicAuth(t, httpClient, destUrl, formData, code.Client.ClientIdentifier, clientSecret)

	// Should be rejected per RFC 6749
	assert.Equal(t, "invalid_request", data["error"])
	assert.Contains(t, data["error_description"].(string), "multiple authentication methods")
}

func TestToken_ClientCred_ClientSecretBasic_Success(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)

	clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	assert.NoError(t, err)

	// Create resources and permissions with random identifiers
	resourceIdentifier := "backend-svc-" + gofakeit.LetterN(8)
	resource := createResourceWithId(t, resourceIdentifier)
	permissionIdentifier := "read-data-" + gofakeit.LetterN(8)
	permission := createPermissionWithId(t, resource.Id, permissionIdentifier)

	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
		IsPublic:                 false,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}
	err = database.CreateClient(nil, client)
	assert.NoError(t, err)

	// Assign permission to the client
	err = database.CreateClientPermission(nil, &models.ClientPermission{
		ClientId:     client.Id,
		PermissionId: permission.Id,
	})
	assert.NoError(t, err)

	httpClient := createHttpClient(t)

	// Use Basic auth - no client_id or client_secret in form body
	formData := url.Values{
		"grant_type": {"client_credentials"},
	}
	data := postToTokenEndpointWithBasicAuth(t, httpClient, destUrl, formData, client.ClientIdentifier, clientSecret)

	assert.NotNil(t, data["access_token"])
	assert.Equal(t, "Bearer", data["token_type"])
	assert.NotNil(t, data["expires_in"])
}

func TestToken_ClientCred_ClientSecretBasic_WrongSecret(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)

	clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	assert.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
		IsPublic:                 false,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}
	err = database.CreateClient(nil, client)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)

	formData := url.Values{
		"grant_type": {"client_credentials"},
	}
	data := postToTokenEndpointWithBasicAuth(t, httpClient, destUrl, formData, client.ClientIdentifier, "wrong_secret")

	assert.Equal(t, "invalid_client", data["error"])
	assert.Equal(t, "Client authentication failed.", data["error_description"])
}

func TestToken_Refresh_ClientSecretBasic_Success(t *testing.T) {
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	// First, get tokens using Basic auth
	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
	}

	data := postToTokenEndpointWithBasicAuth(t, httpClient, destUrl, formData, code.Client.ClientIdentifier, clientSecret)

	assert.NotNil(t, data["refresh_token"])
	refreshToken := data["refresh_token"].(string)

	// Now refresh using Basic auth
	formData = url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}

	data = postToTokenEndpointWithBasicAuth(t, httpClient, destUrl, formData, code.Client.ClientIdentifier, clientSecret)

	assert.NotNil(t, data["access_token"])
	assert.NotNil(t, data["refresh_token"])
	assert.Equal(t, "Bearer", data["token_type"])
	assert.NotNil(t, data["expires_in"])
}

func TestToken_Refresh_ClientSecretBasic_WrongSecret(t *testing.T) {
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	// First, get tokens using Basic auth
	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
	}

	data := postToTokenEndpointWithBasicAuth(t, httpClient, destUrl, formData, code.Client.ClientIdentifier, clientSecret)

	assert.NotNil(t, data["refresh_token"])
	refreshToken := data["refresh_token"].(string)

	// Now try to refresh with wrong secret
	formData = url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}

	data = postToTokenEndpointWithBasicAuth(t, httpClient, destUrl, formData, code.Client.ClientIdentifier, "wrong_secret")

	// RFC 6749 Section 5.2: invalid_client for failed client authentication
	assert.Equal(t, "invalid_client", data["error"])
	assert.Equal(t, "Client authentication failed. Please review your client_secret.", data["error_description"])
}

// ============================================================================
// Original client_credentials tests
// ============================================================================

func TestToken_ClientCred_FlowIsNotEnabled(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false, // Client credentials flow is not enabled
		DefaultAcrLevel:          enums.AcrLevel2Optional,
	}
	err := database.CreateClient(nil, client)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)

	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {gofakeit.Password(true, true, true, true, false, 32)},
	}
	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "unauthorized_client", data["error"])
	assert.Equal(t, "The client associated with the provided client_id does not support client credentials flow.", data["error_description"])
}

func TestToken_ClientCred_ClientSecretIsMissing(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: true,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
		IsPublic:                 false, // Set to false to require a client secret
	}
	err := database.CreateClient(nil, client)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)

	formData := url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {client.ClientIdentifier},
		// Intentionally omitting client_secret
	}
	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	// RFC 6749 Section 5.2: invalid_client for missing client credentials
	assert.Equal(t, "invalid_client", data["error"])
	assert.Equal(t, "This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed.", data["error_description"])
}

func TestToken_ClientCred_ClientAuthFailed(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)

	clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	assert.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: true,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
		IsPublic:                 false,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}
	err = database.CreateClient(nil, client)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)

	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {"incorrect_secret"}, // Intentionally using an incorrect secret
	}
	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_client", data["error"])
	assert.Equal(t, "Client authentication failed.", data["error_description"])
}

func TestToken_ClientCred_InvalidScope(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	// Create a client for testing
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)

	clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	assert.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
		IsPublic:                 false,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}
	err = database.CreateClient(nil, client)
	assert.NoError(t, err)

	// Create a resource and permission for the last test cases
	resourceIdentifier := "backend-svcA-" + gofakeit.LetterN(8)
	permissionIdentifier := "read-product-" + gofakeit.LetterN(8)
	resource := createResourceWithId(t, resourceIdentifier)
	createPermissionWithId(t, resource.Id, permissionIdentifier)

	testCases := []struct {
		scope            string
		errorCode        string
		errorDescription string
	}{
		{
			scope:            "openid",
			errorCode:        "invalid_request",
			errorDescription: "Id token scopes (such as 'openid') are not supported in the client credentials flow. Please use scopes in the format 'resource:permission' (e.g., 'backendA:read'). Multiple scopes can be specified, separated by spaces.",
		},
		{
			scope:            "groups",
			errorCode:        "invalid_request",
			errorDescription: "Id token scopes (such as 'groups') are not supported in the client credentials flow. Please use scopes in the format 'resource:permission' (e.g., 'backendA:read'). Multiple scopes can be specified, separated by spaces.",
		},
		{
			scope:            "aaa",
			errorCode:        "invalid_scope",
			errorDescription: "Invalid scope format: 'aaa'. Scopes must adhere to the resource-identifier:permission-identifier format. For instance: backend-service:create-product.",
		},
		{
			scope:            "invalid:perm",
			errorCode:        "invalid_scope",
			errorDescription: "Invalid scope: 'invalid:perm'. Could not find a resource with identifier 'invalid'.",
		},
		{
			scope:            resourceIdentifier + ":perm",
			errorCode:        "invalid_scope",
			errorDescription: fmt.Sprintf("Scope '%s:perm' is not recognized. The resource identified by '%s' doesn't grant the 'perm' permission.", resourceIdentifier, resourceIdentifier),
		},
		{
			scope:            resourceIdentifier + ":" + permissionIdentifier,
			errorCode:        "invalid_scope",
			errorDescription: fmt.Sprintf("Permission to access scope '%s:%s' is not granted to the client.", resourceIdentifier, permissionIdentifier),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.scope, func(t *testing.T) {
			httpClient := createHttpClient(t)

			formData := url.Values{
				"grant_type":    {"client_credentials"},
				"client_id":     {client.ClientIdentifier},
				"client_secret": {clientSecret},
				"scope":         {testCase.scope},
			}
			data := postToTokenEndpoint(t, httpClient, destUrl, formData)

			assert.Equal(t, testCase.errorCode, data["error"])
			assert.Equal(t, testCase.errorDescription, data["error_description"])
		})
	}
}

func TestToken_ClientCred_NoScopesGiven(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	// Create a client for testing
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)

	clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	assert.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
		IsPublic:                 false,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}
	err = database.CreateClient(nil, client)
	assert.NoError(t, err)

	// Create resources and permissions with random identifiers
	resourceAIdentifier := "backend-svcA-" + gofakeit.LetterN(8)
	resourceA := createResourceWithId(t, resourceAIdentifier)
	permissionAIdentifier := "create-product-" + gofakeit.LetterN(8)
	permissionA := createPermissionWithId(t, resourceA.Id, permissionAIdentifier)

	resourceBIdentifier := "backend-svcB-" + gofakeit.LetterN(8)
	resourceB := createResourceWithId(t, resourceBIdentifier)
	permissionBIdentifier := "read-info-" + gofakeit.LetterN(8)
	permissionB := createPermissionWithId(t, resourceB.Id, permissionBIdentifier)

	// Assign permissions to the client
	err = database.CreateClientPermission(nil, &models.ClientPermission{
		ClientId:     client.Id,
		PermissionId: permissionA.Id,
	})
	assert.NoError(t, err)
	err = database.CreateClientPermission(nil, &models.ClientPermission{
		ClientId:     client.Id,
		PermissionId: permissionB.Id,
	})
	assert.NoError(t, err)

	httpClient := createHttpClient(t)

	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
	}
	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	// When no scopes are required, it should include all scopes that the client has access to
	assert.NotNil(t, data["access_token"])
	assert.Equal(t, "Bearer", data["token_type"])
	assert.NotNil(t, data["expires_in"])

	scope, ok := data["scope"].(string)
	assert.True(t, ok, "scope should be a string")
	parts := strings.Split(scope, " ")
	assert.Equal(t, 2, len(parts))
	expectedScopeA := fmt.Sprintf("%s:%s", resourceAIdentifier, permissionAIdentifier)
	expectedScopeB := fmt.Sprintf("%s:%s", resourceBIdentifier, permissionBIdentifier)
	assert.Contains(t, parts, expectedScopeA)
	assert.Contains(t, parts, expectedScopeB)
}

func TestToken_ClientCred_SpecificScope(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	// Create a client for testing
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)

	clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	assert.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
		IsPublic:                 false,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}
	err = database.CreateClient(nil, client)
	assert.NoError(t, err)

	// Create resources and permissions with random identifiers
	resourceAIdentifier := "backend-svcA-" + gofakeit.LetterN(8)
	resourceA := createResourceWithId(t, resourceAIdentifier)
	permissionAIdentifier := "create-product-" + gofakeit.LetterN(8)
	permissionA := createPermissionWithId(t, resourceA.Id, permissionAIdentifier)

	resourceBIdentifier := "backend-svcB-" + gofakeit.LetterN(8)
	resourceB := createResourceWithId(t, resourceBIdentifier)
	permissionBIdentifier := "read-info-" + gofakeit.LetterN(8)
	permissionB := createPermissionWithId(t, resourceB.Id, permissionBIdentifier)

	// Assign permissions to the client
	err = database.CreateClientPermission(nil, &models.ClientPermission{
		ClientId:     client.Id,
		PermissionId: permissionA.Id,
	})
	assert.NoError(t, err)
	err = database.CreateClientPermission(nil, &models.ClientPermission{
		ClientId:     client.Id,
		PermissionId: permissionB.Id,
	})
	assert.NoError(t, err)

	httpClient := createHttpClient(t)

	// Request only one specific scope
	requestedScope := fmt.Sprintf("%s:%s", resourceAIdentifier, permissionAIdentifier)
	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"scope":         {requestedScope},
	}
	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	// Verify the response
	assert.NotNil(t, data["access_token"])
	assert.Equal(t, "Bearer", data["token_type"])
	assert.NotNil(t, data["expires_in"])

	scope, ok := data["scope"].(string)
	assert.True(t, ok, "scope should be a string")
	assert.Equal(t, requestedScope, scope, "Returned scope should match the requested scope")

	// Ensure the other scope is not present in the returned scope
	unrequestedScope := fmt.Sprintf("%s:%s", resourceBIdentifier, permissionBIdentifier)
	assert.NotContains(t, scope, unrequestedScope, "Returned scope should not contain the unrequested scope")
}

func TestToken_Refresh_ClientSecretIsMissing(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)

	clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	assert.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
		IsPublic:                 false,
		AuthorizationCodeEnabled: true,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}
	err = database.CreateClient(nil, client)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)

	formData := url.Values{
		"grant_type": {"refresh_token"},
		"client_id":  {client.ClientIdentifier},
	}
	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	// RFC 6749 Section 5.2: invalid_client for missing client credentials
	assert.Equal(t, "invalid_client", data["error"])
	assert.Equal(t, "This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed.", data["error_description"])
}

func TestToken_Refresh_ClientAuthFailed(t *testing.T) {
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	// Get the token using the authorization code
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
		"client_secret": {clientSecret},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.NotNil(t, data["refresh_token"])
	refreshToken := data["refresh_token"].(string)

	// Now try to refresh the token with an incorrect client secret
	formData = url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {code.Client.ClientIdentifier},
		"refresh_token": {refreshToken},
		"client_secret": {"incorrect_secret"},
	}

	data = postToTokenEndpoint(t, httpClient, destUrl, formData)

	// RFC 6749 Section 5.2: invalid_client for failed client authentication
	assert.Equal(t, "invalid_client", data["error"])
	assert.Equal(t, "Client authentication failed. Please review your client_secret.", data["error_description"])
}

func TestToken_Refresh_MissingRefreshToken(t *testing.T) {
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	// First, get a valid refresh token
	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
		"client_secret": {clientSecret},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.NotNil(t, data["refresh_token"])

	// Now, attempt to refresh without providing the refresh_token
	formData = url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {code.Client.ClientIdentifier},
		"client_secret": {clientSecret},
	}

	data = postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "Missing required refresh_token parameter.", data["error_description"])
}

func TestToken_Refresh_TokenWithBadSignature(t *testing.T) {
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	// First, get a valid refresh token
	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
		"client_secret": {clientSecret},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.NotNil(t, data["refresh_token"])
	validRefreshToken := data["refresh_token"].(string)

	// Parse the valid refresh token
	token, _, err := new(jwt.Parser).ParseUnverified(validRefreshToken, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	// Get the claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("Failed to get claims from token")
	}

	// Create a new key pair for signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Create a new token with the same claims but signed with the new key
	newToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	invalidRefreshToken, err := newToken.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign new token: %v", err)
	}

	// Now try to use the invalid refresh token
	formData = url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {code.Client.ClientIdentifier},
		"refresh_token": {invalidRefreshToken},
		"client_secret": {clientSecret},
	}

	data = postToTokenEndpoint(t, httpClient, destUrl, formData)

	// Assert that the token endpoint rejects the invalid token
	assert.Equal(t, "invalid_grant", data["error"])
	assert.Contains(t, data["error_description"].(string), "token signature is invalid")
}

func TestToken_Refresh_TokenExpired(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/token"

	httpClient := createHttpClient(t)

	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 false,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
	}

	clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	assert.NoError(t, err)
	client.ClientSecretEncrypted = clientSecretEncrypted

	err = database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	claims := make(jwt.MapClaims)

	now := time.Now().UTC()

	jti := uuid.New().String()
	exp := now.AddDate(-5, 0, 0)
	claims["iss"] = settings.Issuer
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	claims["jti"] = jti
	claims["aud"] = settings.Issuer
	claims["typ"] = "Refresh"
	claims["exp"] = exp.Unix()
	claims["sub"] = uuid.New().String()

	keyPair, err := database.GetCurrentSigningKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyPair.PrivateKeyPEM)
	if err != nil {
		t.Fatal("unable to parse private key from PEM")
	}
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privKey)
	if err != nil {
		t.Fatal("unable to sign refresh_token")
	}

	formData := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"refresh_token": {refreshToken},
	}
	respData := postToTokenEndpoint(t, httpClient, destUrl, formData)
	assert.Equal(t, "invalid_grant", respData["error"])
	assert.Contains(t, respData["error_description"], "token is expired")
}

func TestToken_Refresh_WrongClient(t *testing.T) {
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	// First, get a valid refresh token
	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
		"client_secret": {clientSecret},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.NotNil(t, data["refresh_token"])
	refreshToken := data["refresh_token"].(string)

	// Create a new client
	wrongClientSecret := gofakeit.Password(true, true, true, true, false, 32)
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)

	wrongClientSecretEncrypted, err := encryption.EncryptText(wrongClientSecret, settings.AESEncryptionKey)
	assert.NoError(t, err)

	wrongClient := &models.Client{
		ClientIdentifier:         "wrong-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 false,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
		ClientSecretEncrypted:    wrongClientSecretEncrypted,
	}
	err = database.CreateClient(nil, wrongClient)
	assert.NoError(t, err)

	// Now try to use the refresh token with the wrong client
	formData = url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {wrongClient.ClientIdentifier},
		"refresh_token": {refreshToken},
		"client_secret": {wrongClientSecret},
	}

	data = postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "The refresh token is invalid because it does not belong to the client.", data["error_description"])
}

func TestToken_Refresh_WithAdditionalScope(t *testing.T) {
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	// First, get the initial access token and refresh token
	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
		"client_secret": {clientSecret},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.NotNil(t, data["refresh_token"])
	refreshToken := data["refresh_token"].(string)

	// Create a new resource and permission with randomized identifiers
	resourceIdentifier := "additional-resource-" + gofakeit.LetterN(8)
	permissionIdentifier := "read-" + gofakeit.LetterN(8)
	resource := createResourceWithId(t, resourceIdentifier)
	permission := createPermissionWithId(t, resource.Id, permissionIdentifier)

	// Assign the new permission to the user
	assignPermissionToUser(t, code.UserId, permission.Id)

	// Now, attempt to refresh the token with an additional scope
	newScope := fmt.Sprintf("%s:%s", resourceIdentifier, permissionIdentifier)
	formData = url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {code.Client.ClientIdentifier},
		"refresh_token": {refreshToken},
		"client_secret": {clientSecret},
		"scope":         {"openid profile email " + newScope},
	}

	data = postToTokenEndpoint(t, httpClient, destUrl, formData)

	// Check that the request was denied due to the additional scope
	assert.Equal(t, "invalid_grant", data["error"])
	assert.Contains(t, data["error_description"], fmt.Sprintf("Scope '%s' is not recognized. The original access token does not grant the '%s' permission.", newScope, newScope))

	// Now, try again with only the original scopes
	formData.Set("scope", "openid profile email")
	data = postToTokenEndpoint(t, httpClient, destUrl, formData)

	// This time, the refresh should be successful
	assert.NotNil(t, data["access_token"])
	assert.NotNil(t, data["refresh_token"])
	assert.Equal(t, "Bearer", data["token_type"])
	assert.NotNil(t, data["expires_in"])

	// authserver:userinfo is always included when there's an openid scope
	assert.Equal(t, "openid profile email authserver:userinfo", data["scope"])
}

func TestToken_Refresh_ConsentRemoved(t *testing.T) {
	// Create a client with consent required

	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)

	clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	assert.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          true,
		DefaultAcrLevel:          enums.AcrLevel1,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}
	err = database.CreateClient(nil, client)
	assert.NoError(t, err)

	// Create a redirect URI for the client
	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}
	err = database.CreateRedirectURI(nil, redirectUri)
	assert.NoError(t, err)

	// Create a user
	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	assert.NoError(t, err)
	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}
	err = database.CreateUser(nil, user)
	assert.NoError(t, err)

	// Create a resource and permission, and assign it to the user
	resource := createResource(t)
	permission := createPermission(t, resource.Id)
	assignPermissionToUser(t, user.Id, permission.Id)

	// Set up the request scope
	requestScope := "openid profile email " + resource.ResourceIdentifier + ":" + permission.PermissionIdentifier

	// Start the authorization flow
	httpClient := createHttpClient(t)
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + oauth.GeneratePKCECodeChallenge("code-verifier") +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + gofakeit.LetterN(8) +
		"&nonce=" + gofakeit.LetterN(8)

	resp, err := httpClient.Get(destUrl)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Follow redirects and authenticate
	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)
	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// Provide consent
	csrf = getCsrfValue(t, resp)
	resp = postConsent(t, httpClient, redirectLocation, []int{0, 1, 2, 3}, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// Get the authorization code
	codeVal, _ := getCodeAndStateFromUrl(t, resp)

	// Exchange the code for tokens
	tokenUrl := config.GetAuthServer().BaseURL + "/auth/token"
	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {codeVal},
		"redirect_uri":  {redirectUri.URI},
		"client_id":     {client.ClientIdentifier},
		"code_verifier": {"code-verifier"},
		"client_secret": {clientSecret},
	}

	tokenResp := postToTokenEndpoint(t, httpClient, tokenUrl, formData)

	assert.NotNil(t, tokenResp["refresh_token"])
	refreshToken := tokenResp["refresh_token"].(string)

	// Remove the consent
	consent, err := database.GetConsentByUserIdAndClientId(nil, user.Id, client.Id)
	assert.NoError(t, err)
	assert.NotNil(t, consent)

	err = database.DeleteUserConsent(nil, consent.Id)
	assert.NoError(t, err)

	// Attempt to use the refresh token
	formData = url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
	}

	refreshResp := postToTokenEndpoint(t, httpClient, tokenUrl, formData)

	// Assert that the request failed due to removed consent
	assert.Equal(t, "invalid_grant", refreshResp["error"])
	assert.Equal(t, "The user has either not given consent to this client or the previously granted consent has been revoked.", refreshResp["error_description"])
}

func TestToken_Refresh_ConsentDoesNotIncludeScope(t *testing.T) {
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)

	clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	assert.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          true,
		DefaultAcrLevel:          enums.AcrLevel1,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}
	err = database.CreateClient(nil, client)
	assert.NoError(t, err)

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}
	err = database.CreateRedirectURI(nil, redirectUri)
	assert.NoError(t, err)

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	assert.NoError(t, err)
	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}
	err = database.CreateUser(nil, user)
	assert.NoError(t, err)

	resource := createResource(t)
	permission := createPermission(t, resource.Id)
	assignPermissionToUser(t, user.Id, permission.Id)

	initialScope := "openid profile email"
	additionalScope := resource.ResourceIdentifier + ":" + permission.PermissionIdentifier
	fullScope := initialScope + " " + additionalScope

	httpClient := createHttpClient(t)
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + oauth.GeneratePKCECodeChallenge("code-verifier") +
		"&scope=" + url.QueryEscape(initialScope) +
		"&state=" + gofakeit.LetterN(8) +
		"&nonce=" + gofakeit.LetterN(8)

	resp, err := httpClient.Get(destUrl)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)
	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)
	resp = postConsent(t, httpClient, redirectLocation, []int{0, 1, 2}, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, _ := getCodeAndStateFromUrl(t, resp)

	tokenUrl := config.GetAuthServer().BaseURL + "/auth/token"
	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {codeVal},
		"redirect_uri":  {redirectUri.URI},
		"client_id":     {client.ClientIdentifier},
		"code_verifier": {"code-verifier"},
		"client_secret": {clientSecret},
	}

	tokenResp := postToTokenEndpoint(t, httpClient, tokenUrl, formData)

	assert.NotNil(t, tokenResp["refresh_token"])
	refreshToken := tokenResp["refresh_token"].(string)

	formData = url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"scope":         {fullScope}, // Request the full scope including the additional resource permission
	}

	refreshResp := postToTokenEndpoint(t, httpClient, tokenUrl, formData)

	assert.Equal(t, "invalid_grant", refreshResp["error"])
	expectedErrorDescription := fmt.Sprintf("Scope '%s' is not recognized. The original access token does not grant the '%s' permission.",
		additionalScope, additionalScope)
	assert.Equal(t, expectedErrorDescription, refreshResp["error_description"])
}

func TestToken_Refresh_TokenMarkedAsUsed(t *testing.T) {
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	// First, exchange the authorization code for tokens
	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
		"client_secret": {clientSecret},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.NotNil(t, data["refresh_token"])
	refreshToken := data["refresh_token"].(string)

	// Now, use the refresh token to get a new access token
	formData = url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {code.Client.ClientIdentifier},
		"refresh_token": {refreshToken},
		"client_secret": {clientSecret},
	}

	data = postToTokenEndpoint(t, httpClient, destUrl, formData)

	// Verify that the refresh operation was successful
	assert.NotNil(t, data["access_token"])
	assert.NotNil(t, data["refresh_token"])
	assert.Equal(t, "Bearer", data["token_type"])
	assert.NotNil(t, data["expires_in"])

	// Extract the JTI from the original refresh token
	parts := strings.Split(refreshToken, ".")
	if len(parts) != 3 {
		t.Fatal("Invalid refresh token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("Failed to decode refresh token payload: %v", err)
	}

	var claims map[string]interface{}
	err = json.Unmarshal(payload, &claims)
	if err != nil {
		t.Fatalf("Failed to unmarshal refresh token claims: %v", err)
	}

	jti, ok := claims["jti"].(string)
	if !ok {
		t.Fatal("Failed to extract jti from refresh token claims")
	}

	// Verify that the original refresh token is now marked as used (revoked)
	revokedRefreshToken, err := database.GetRefreshTokenByJti(nil, jti)
	assert.NoError(t, err)
	assert.NotNil(t, revokedRefreshToken)
	assert.True(t, revokedRefreshToken.Revoked, "The original refresh token should be marked as revoked after use")

	// Attempt to use the same refresh token again, which should fail
	data = postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_grant", data["error"])
	assert.Equal(t, "This refresh token has been revoked.", data["error_description"])
}

// ============================================================================
// AMR (Authentication Methods Reference) format tests
// OIDC Core 1.0 Section 2 requires amr to be a JSON array of strings
// ============================================================================

// TestToken_AuthCode_AMR_IsArray verifies that AMR in tokens is a JSON array per OIDC spec
func TestToken_AuthCode_AMR_IsArray(t *testing.T) {
	clientSecret := gofakeit.LetterN(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
		"client_secret": {clientSecret},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	// Verify we got tokens
	assert.NotNil(t, data["access_token"])
	assert.NotNil(t, data["id_token"])

	// Decode and verify access_token AMR is an array
	accessToken := data["access_token"].(string)
	accessClaims := decodeJWTPayload(t, accessToken)

	amrAccess := accessClaims["amr"]
	assert.NotNil(t, amrAccess, "access_token must contain amr claim")
	amrArrayAccess, ok := amrAccess.([]interface{})
	assert.True(t, ok, "amr in access_token must be a JSON array, got %T", amrAccess)
	assert.GreaterOrEqual(t, len(amrArrayAccess), 1, "amr array must contain at least one method")

	// Decode and verify id_token AMR is an array
	idToken := data["id_token"].(string)
	idClaims := decodeJWTPayload(t, idToken)

	amrId := idClaims["amr"]
	assert.NotNil(t, amrId, "id_token must contain amr claim")
	amrArrayId, ok := amrId.([]interface{})
	assert.True(t, ok, "amr in id_token must be a JSON array, got %T", amrId)
	assert.GreaterOrEqual(t, len(amrArrayId), 1, "amr array must contain at least one method")

	// Verify the array contains "pwd" (password authentication)
	// Since this is a normal auth code flow, at minimum pwd should be present
	assert.Contains(t, amrArrayAccess, "pwd", "amr should contain 'pwd' for password authentication")
	assert.Contains(t, amrArrayId, "pwd", "amr should contain 'pwd' for password authentication")
}

// TestToken_Refresh_AMR_IsArray verifies AMR is preserved as array through refresh
func TestToken_Refresh_AMR_IsArray(t *testing.T) {
	clientSecret := gofakeit.LetterN(32)
	// Use "openid profile email" instead of "offline_access" to avoid consent flow
	// The auth code flow still returns a refresh token with these scopes
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	// First, get initial tokens
	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
		"client_secret": {clientSecret},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)
	assert.NotNil(t, data["refresh_token"])

	// Refresh the token
	refreshToken := data["refresh_token"].(string)
	refreshFormData := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {code.Client.ClientIdentifier},
		"refresh_token": {refreshToken},
		"client_secret": {clientSecret},
	}

	refreshData := postToTokenEndpoint(t, httpClient, destUrl, refreshFormData)
	assert.NotNil(t, refreshData["access_token"])

	// Verify AMR is still an array after refresh
	accessToken := refreshData["access_token"].(string)
	accessClaims := decodeJWTPayload(t, accessToken)

	amrAccess := accessClaims["amr"]
	assert.NotNil(t, amrAccess, "access_token after refresh must contain amr claim")
	amrArrayAccess, ok := amrAccess.([]interface{})
	assert.True(t, ok, "amr in refreshed access_token must be a JSON array, got %T", amrAccess)
	assert.Contains(t, amrArrayAccess, "pwd", "amr should contain 'pwd' after refresh")
}

// decodeJWTPayload extracts and decodes the payload from a JWT
func decodeJWTPayload(t *testing.T, token string) map[string]interface{} {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("Invalid JWT format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("Failed to decode JWT payload: %v", err)
	}

	var claims map[string]interface{}
	err = json.Unmarshal(payload, &claims)
	if err != nil {
		t.Fatalf("Failed to unmarshal JWT claims: %v", err)
	}

	return claims
}
