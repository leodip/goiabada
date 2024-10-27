package integrationtests

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

func TestToken_ClientIdIsMissing(t *testing.T) {
	destUrl := config.Get().BaseURL + "/auth/token/"

	httpClient := createHttpClient(t)

	formData := url.Values{}
	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "Missing required client_id parameter.", data["error_description"])
}

func TestToken_ClientDoesNotExist(t *testing.T) {
	destUrl := config.Get().BaseURL + "/auth/token/"

	httpClient := createHttpClient(t)

	formData := url.Values{
		"client_id": {"invalid"},
	}
	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "Client does not exist.", data["error_description"])
}

func TestToken_InvalidGrantType(t *testing.T) {
	destUrl := config.Get().BaseURL + "/auth/token/"

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

	destUrl := config.Get().BaseURL + "/auth/token/"

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

	destUrl := config.Get().BaseURL + "/auth/token/"

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
	httpClient, code := createAuthCode(t, gofakeit.LetterN(32), "openid profile email")

	destUrl := config.Get().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":   {"authorization_code"},
		"client_id":    {code.Client.ClientIdentifier},
		"code":         {code.Code},
		"redirect_uri": {code.RedirectURI},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "Missing required code_verifier parameter.", data["error_description"])
}

func TestToken_AuthCode_ClientDoesNotExist(t *testing.T) {
	httpClient, code := createAuthCode(t, gofakeit.LetterN(32), "openid profile email")

	destUrl := config.Get().BaseURL + "/auth/token/"

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

	destUrl := config.Get().BaseURL + "/auth/token/"

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

	destUrl := config.Get().BaseURL + "/auth/token/"

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

	destUrl := config.Get().BaseURL + "/auth/token/"

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

	destUrl := config.Get().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {gofakeit.LetterN(43)},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed.", data["error_description"])
}

func TestToken_AuthCode_ConfidentialClient_ClientAuthFailed(t *testing.T) {
	clientSecret := gofakeit.LetterN(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	// Ensure the client is confidential (not public)
	code.Client.IsPublic = false
	err := database.UpdateClient(nil, &code.Client)
	assert.NoError(t, err)

	destUrl := config.Get().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {gofakeit.LetterN(43)},
		"client_secret": {"incorrect_secret"}, // Provide an incorrect client secret
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_grant", data["error"])
	assert.Equal(t, "Client authentication failed. Please review your client_secret.", data["error_description"])
}

func TestToken_AuthCode_InvalidCodeVerifier(t *testing.T) {
	clientSecret := gofakeit.LetterN(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")

	code.Client.IsPublic = false
	err := database.UpdateClient(nil, &code.Client)
	assert.NoError(t, err)

	destUrl := config.Get().BaseURL + "/auth/token/"

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

	destUrl := config.Get().BaseURL + "/auth/token/"

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

func TestToken_ClientCred_FlowIsNotEnabled(t *testing.T) {
	destUrl := config.Get().BaseURL + "/auth/token/"

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
	destUrl := config.Get().BaseURL + "/auth/token/"

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

	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed.", data["error_description"])
}

func TestToken_ClientCred_ClientAuthFailed(t *testing.T) {
	destUrl := config.Get().BaseURL + "/auth/token/"

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
			scope:            "backend-svcA:perm",
			errorCode:        "invalid_scope",
			errorDescription: "Scope 'backend-svcA:perm' is not recognized. The resource identified by 'backend-svcA' doesn't grant the 'perm' permission.",
		},
		{
			scope:            "backend-svcA:read-product",
			errorCode:        "invalid_scope",
			errorDescription: "Permission to access scope 'backend-svcA:read-product' is not granted to the client.",
		},
	}

	destUrl := config.Get().BaseURL + "/auth/token/"

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

	// Create a resource and permission for the last test case
	resource := createResourceWithId(t, "backend-svcA")
	createPermissionWithId(t, resource.Id, "read-product")

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
	destUrl := config.Get().BaseURL + "/auth/token/"

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
	destUrl := config.Get().BaseURL + "/auth/token/"

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
