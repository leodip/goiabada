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
