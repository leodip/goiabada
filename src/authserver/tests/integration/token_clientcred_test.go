package integrationtests

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
)

func TestToken_ClientCred_ClientSecretBasic_Success(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	clientSecretEncrypted, err := encryption.EncryptData(clientSecret)
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
	clientSecretEncrypted, err := encryption.EncryptData(clientSecret)
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
	clientSecretEncrypted, err := encryption.EncryptData(clientSecret)
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
	clientSecretEncrypted, err := encryption.EncryptData(clientSecret)
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
	clientSecretEncrypted, err := encryption.EncryptData(clientSecret)
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
	clientSecretEncrypted, err := encryption.EncryptData(clientSecret)
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

// TestToken_ClientCred_CrossResourcePermissionCollision covers #104: permission
// identifiers are scoped to their resource, so a grant on one resource must convey
// nothing about a same-named permission on another. Before the fix the ownership check
// compared only the bare identifier against the client's permissions across every
// resource, so the denied leg below returned a token.
//
// Both resources deliberately define the SAME permission identifier. The client is
// granted resource A's permission only.
func TestToken_ClientCred_CrossResourcePermissionCollision(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	clientSecretEncrypted, err := encryption.EncryptData(clientSecret)
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

	// One permission identifier, defined on two different resources.
	sharedPermissionIdentifier := "read-product-" + gofakeit.LetterN(8)

	resourceAIdentifier := "billing-api-" + gofakeit.LetterN(8)
	resourceA := createResourceWithId(t, resourceAIdentifier)
	permissionA := createPermissionWithId(t, resourceA.Id, sharedPermissionIdentifier)

	resourceBIdentifier := "reports-api-" + gofakeit.LetterN(8)
	resourceB := createResourceWithId(t, resourceBIdentifier)
	createPermissionWithId(t, resourceB.Id, sharedPermissionIdentifier)

	// The client holds resource A's permission and nothing else.
	err = database.CreateClientPermission(nil, &models.ClientPermission{
		ClientId:     client.Id,
		PermissionId: permissionA.Id,
	})
	assert.NoError(t, err)

	scopeA := fmt.Sprintf("%s:%s", resourceAIdentifier, sharedPermissionIdentifier)
	scopeB := fmt.Sprintf("%s:%s", resourceBIdentifier, sharedPermissionIdentifier)

	// Denied leg: same permission identifier, different resource. Client credentials
	// consumes no one-shot resource, so the two legs may run in either order.
	t.Run("the same identifier on an ungranted resource is denied", func(t *testing.T) {
		httpClient := createHttpClient(t)
		data := postToTokenEndpoint(t, httpClient, destUrl, url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {client.ClientIdentifier},
			"client_secret": {clientSecret},
			"scope":         {scopeB},
		})

		assert.Equal(t, "invalid_scope", data["error"])
		assert.Equal(t,
			fmt.Sprintf("Permission to access scope '%s' is not granted to the client.", scopeB),
			data["error_description"])
		assert.Nil(t, data["access_token"], "no token may be issued for an ungranted resource")
	})

	// Granted leg: the positive control. Without it the test above would also pass
	// against an implementation that rejected everything.
	t.Run("the granted resource still works", func(t *testing.T) {
		httpClient := createHttpClient(t)
		data := postToTokenEndpoint(t, httpClient, destUrl, url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {client.ClientIdentifier},
			"client_secret": {clientSecret},
			"scope":         {scopeA},
		})

		assert.NotNil(t, data["access_token"])
		scope, ok := data["scope"].(string)
		assert.True(t, ok, "scope should be a string")
		assert.Equal(t, scopeA, scope)
	})
}

// TestToken_ClientCred_AuthServerScopeNotReachableByCollision is the escalation case
// from #104, against the REAL authserver resource and its real built-in "manage"
// permission as seeded at startup, rather than a fixture that resembles them.
//
// "manage" is exactly the kind of generic identifier the docs encourage on a custom
// resource, and authserver:manage is full Admin API access. Before the fix, a client
// holding <custom>:manage received a token carrying authserver:manage.
func TestToken_ClientCred_AuthServerScopeNotReachableByCollision(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	clientSecretEncrypted, err := encryption.EncryptData(clientSecret)
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

	// A custom resource whose permission identifier collides with the built-in one.
	customResourceIdentifier := "billing-api-" + gofakeit.LetterN(8)
	customResource := createResourceWithId(t, customResourceIdentifier)
	customManage := createPermissionWithId(t, customResource.Id, constants.ManagePermissionIdentifier)

	err = database.CreateClientPermission(nil, &models.ClientPermission{
		ClientId:     client.Id,
		PermissionId: customManage.Id,
	})
	assert.NoError(t, err)

	// Confirm the collision really exists against the seeded authserver resource,
	// otherwise this test could pass because there was nothing to collide with.
	authserverResource, err := database.GetResourceByResourceIdentifier(nil, constants.AuthServerResourceIdentifier)
	assert.NoError(t, err)
	assert.NotNil(t, authserverResource)
	authserverPermissions, err := database.GetPermissionsByResourceId(nil, authserverResource.Id)
	assert.NoError(t, err)
	foundBuiltInManage := false
	for _, perm := range authserverPermissions {
		if perm.PermissionIdentifier == constants.ManagePermissionIdentifier {
			foundBuiltInManage = true
			assert.NotEqual(t, customManage.Id, perm.Id,
				"the fixture must be two distinct permission rows sharing one identifier")
			break
		}
	}
	assert.True(t, foundBuiltInManage,
		"the authserver resource must define the built-in 'manage' permission for this test to mean anything")

	escalatedScope := constants.AuthServerResourceIdentifier + ":" + constants.ManagePermissionIdentifier

	httpClient := createHttpClient(t)
	data := postToTokenEndpoint(t, httpClient, destUrl, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"scope":         {escalatedScope},
	})

	assert.Equal(t, "invalid_scope", data["error"])
	assert.Equal(t,
		fmt.Sprintf("Permission to access scope '%s' is not granted to the client.", escalatedScope),
		data["error_description"])
	assert.Nil(t, data["access_token"], "an admin-capable token must not be issued")

	// The client's genuine grant is unaffected.
	genuineScope := fmt.Sprintf("%s:%s", customResourceIdentifier, constants.ManagePermissionIdentifier)
	data = postToTokenEndpoint(t, httpClient, destUrl, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"scope":         {genuineScope},
	})
	assert.NotNil(t, data["access_token"])
	assert.Equal(t, genuineScope, data["scope"])
}

// TestToken_ClientCred_TabSeparatedScopeIsNormalized is the end-to-end half of the scope
// normalization work, and the only step that shows the defect is actually fixed.
//
// The token endpoint used to collapse whitespace onto a local copy and never assign it back, so the
// caller's raw string was carried onward. A tab-separated request passed scope validation, which
// collapses whitespace before checking, and then failed with a **500**: the issuer re-parses the
// scope, splits on spaces alone, and the tab-joined string arrives as one element whose colon-split
// yields three parts. Measured by reverting the handler to pass the raw scope, where this test fails
// with server_error and the server logs `invalid scope: <the tab-joined string>`.
//
// So no token was issued with silently unmatchable scopes; the issuer rejected first.
//
// Asserting string equality on the response alone would not prove the fix, because the assertion
// and the bug could share the same expectation. So this drives the real HasScope, the same matcher
// the Admin API middleware uses, over the claim as decoded from the issued token.
func TestToken_ClientCred_TabSeparatedScopeIsNormalized(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	clientSecretEncrypted, err := encryption.EncryptData(clientSecret)
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

	resourceIdentifier := "billing-api-" + gofakeit.LetterN(8)
	resource := createResourceWithId(t, resourceIdentifier)
	readPermission := createPermissionWithId(t, resource.Id, "read-"+gofakeit.LetterN(6))
	writePermission := createPermissionWithId(t, resource.Id, "write-"+gofakeit.LetterN(6))

	for _, permission := range []*models.Permission{readPermission, writePermission} {
		err = database.CreateClientPermission(nil, &models.ClientPermission{
			ClientId:     client.Id,
			PermissionId: permission.Id,
		})
		assert.NoError(t, err)
	}

	readScope := resourceIdentifier + ":" + readPermission.PermissionIdentifier
	writeScope := resourceIdentifier + ":" + writePermission.PermissionIdentifier

	// A TAB between two genuinely granted scopes.
	data := postToTokenEndpoint(t, createHttpClient(t), destUrl, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"scope":         {readScope + "\t" + writeScope},
	})

	assert.Nil(t, data["error"], "the request should succeed: %v", data)

	responseScope, ok := data["scope"].(string)
	assert.True(t, ok, "scope should be a string")
	assert.Equal(t, readScope+" "+writeScope, responseScope,
		"the response scope should be space-separated")
	assert.NotContains(t, responseScope, "\t")

	accessToken, ok := data["access_token"].(string)
	assert.True(t, ok)

	// The claim as the client receives it, matched with production's own matcher.
	claims := decodeJWTPayload(t, accessToken)
	jwtToken := oauth.JwtToken{Claims: claims}
	assert.True(t, jwtToken.HasScope(readScope),
		"HasScope must match %q in claim %q", readScope, claims["scope"])
	assert.True(t, jwtToken.HasScope(writeScope),
		"HasScope must match %q in claim %q", writeScope, claims["scope"])
}

// TestToken_ClientCred_InvalidScopeWithEmoji_DescriptionIsConformed proves the token endpoint's
// error_description carries no byte RFC 6749 forbids, even when the description interpolates the
// caller's own text.
//
// RFC 6749 Appendix A.8 gives error-description = 1*NQSCHAR (%x20-21 / %x23-5B / %x5D-7E), and
// section 5.2 is one of the sections that production governs. The scope below is deliberately not a
// bare emoji: the ASCII either side of the offending rune must survive, which is what proves the
// filter replaces rather than drops and so still tells the integrator which scope was refused
// (#213).
//
// Thin on purpose. The character set itself is owned by TestConformErrorDescription in
// src/core/customerrors; what is left for this tier is only that the filter is on the path.
func TestToken_ClientCred_InvalidScopeWithEmoji_DescriptionIsConformed(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	clientSecretEncrypted, err := encryption.EncryptData(clientSecret)
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
		"scope":      {"emoji💣scope"},
	}
	data := postToTokenEndpointWithBasicAuth(t, httpClient, destUrl, formData, client.ClientIdentifier, clientSecret)

	assert.Equal(t, "invalid_scope", data["error"])
	assert.Equal(t,
		"Invalid scope format: 'emoji?scope'. Scopes must adhere to the resource-identifier:permission-identifier format. For instance: backend-service:create-product.",
		data["error_description"])
}
