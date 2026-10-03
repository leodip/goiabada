package protocolvalidation

import (
	"context"
	"fmt"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_protocolvalidation "github.com/leodip/goiabada/authserver/internal/protocolvalidation/mocks"
)

// The separator rule is pinned once, in core/oauth's own tables; these are the four validator
// paths' consumer rows, one table shared by all four, which is what #116 asked for. Each path splits
// with oidc.SplitScope, on the space alone (#244).
//
// A scope is held to its grammar where it enters: ValidateScopes judges the authorization request's
// scope as sent, and the token endpoint judges its own before normalizing it for the three token
// paths below (parseTokenRequest), so a run of spaces or one at an edge never reaches them. What does
// reach them is a character that is not a separator: it joins two scopes into one value, which each
// path refuses by name. A tab, a newline, a form feed and a carriage return used to separate, and the
// four paths granted both scopes (#244).
const (
	whitespaceScopeA = "billing-api:read"
	whitespaceScopeB = "billing-api:write"
)

// singleSpaceSpelling is the control every refused row varies from: one space between the two.
const singleSpaceSpelling = whitespaceScopeA + " " + whitespaceScopeB

// oneElementSpellings join the two scopes with a character that is not a separator, so every path
// reads one value holding two colons and refuses it by name.
var oneElementSpellings = []struct {
	name  string
	scope string
}{
	{"tab", whitespaceScopeA + "\t" + whitespaceScopeB},
	{"newline", whitespaceScopeA + "\n" + whitespaceScopeB},
	{"carriage return and newline", whitespaceScopeA + "\r\n" + whitespaceScopeB},
	{"form feed", whitespaceScopeA + "\f" + whitespaceScopeB},
	{"U+00A0", whitespaceScopeA + "\u00a0" + whitespaceScopeB},
}

var billingResource = models.Resource{Id: 1, ResourceIdentifier: "billing-api"}

var billingPermissions = []models.Permission{
	{Id: 10, PermissionIdentifier: "read", ResourceId: 1, Resource: billingResource},
	{Id: 11, PermissionIdentifier: "write", ResourceId: 1, Resource: billingResource},
}

func expectBillingResolution(mockDB *mocks_data.Database) {
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "billing-api").
		Return(&billingResource, nil)
	mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(1)).
		Return(billingPermissions, nil)
}

func assertRefusedAsOneElement(t *testing.T, err error, description string) {
	t.Helper()
	var customErr *oauth.ErrorDetail
	require.ErrorAs(t, err, &customErr)
	assert.Equal(t, "invalid_scope", customErr.Code())
	assert.Equal(t, description, customErr.Description())
}

func TestValidateScopes_ScopeWhitespace(t *testing.T) {
	t.Run("one space separates", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		expectBillingResolution(mockDB)

		assert.NoError(t, NewAuthorizeValidator(mockDB).ValidateScopes(context.Background(), singleSpaceSpelling))
	})

	// The strict database registers nothing, so a lookup made before the refusal fails the case.
	for _, tc := range []struct{ name, scope string }{
		{"double space", whitespaceScopeA + "  " + whitespaceScopeB},
		{"leading and trailing space", " " + singleSpaceSpelling + " "},
	} {
		t.Run(tc.name+" is malformed", func(t *testing.T) {
			err := NewAuthorizeValidator(mocks_data.NewDatabase(t)).ValidateScopes(context.Background(), tc.scope)

			assertRefusedAsOneElement(t, err, malformedText("scope"))
		})
	}

	for _, tc := range oneElementSpellings {
		t.Run(tc.name+" is not a separator", func(t *testing.T) {
			err := NewAuthorizeValidator(mocks_data.NewDatabase(t)).ValidateScopes(context.Background(), tc.scope)

			assertRefusedAsOneElement(t, err, fmt.Sprintf("Invalid scope format: '%v'. Scopes must adhere to the resource-identifier:permission-identifier format. For instance: backend-service:create-product.", tc.scope))
		})
	}
}

func TestValidateTokenRequest_RefreshToken_ScopeWhitespace(t *testing.T) {
	grant := storedGrant{ropc: true, scope: singleSpaceSpelling}

	t.Run("one space separates", func(t *testing.T) {
		validator, mockPermissionChecker, settings, input := newStoredGrantRefresh(t, grant, singleSpaceSpelling, true)
		// Each value asked about on its own is what shows the re-check split the request.
		mockPermissionChecker.On("UserHasScopePermission", mock.Anything, int64(1), whitespaceScopeA).Return(true, nil).Once()
		mockPermissionChecker.On("UserHasScopePermission", mock.Anything, int64(1), whitespaceScopeB).Return(true, nil).Once()

		result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

		require.NoError(t, err)
		assert.NotNil(t, result)
	})

	for _, tc := range oneElementSpellings {
		t.Run(tc.name+" is not a separator", func(t *testing.T) {
			validator, mockPermissionChecker, settings, input := newStoredGrantRefresh(t, grant, tc.scope, false)

			result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

			assert.Nil(t, result)
			assertRefusedAsOneElement(t, err, fmt.Sprintf("Scope '%v' is not recognized. The original access token does not grant the '%v' permission.", tc.scope, tc.scope))
			mockPermissionChecker.AssertNotCalled(t, "UserHasScopePermission", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

func newWhitespaceClientCredentials(t *testing.T, scope string) (*TokenValidator, *mocks_data.Database, *ValidateTokenRequestInput) {
	t.Helper()
	mockDB := mocks_data.NewDatabase(t)
	validator := NewTokenValidator(mockDB, mocks_protocolvalidation.NewTokenParser(t), mocks_protocolvalidation.NewPermissionChecker(t), testDataCipher)

	clientSecretEncrypted, err := testDataCipher.Encrypt("valid_secret")
	require.NoError(t, err)
	client := &models.Client{
		ClientIdentifier:         "cc_client",
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		ClientSecretEncrypted:    clientSecretEncrypted,
		Permissions:              billingPermissions,
	}
	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "cc_client").Return(client, nil).Once()
	mockDB.On("ClientLoadPermissions", mock.Anything, mock.Anything, client).Return(nil).Once()
	mockDB.On("PermissionsLoadResources", mock.Anything, mock.Anything, mock.AnythingOfType("[]models.Permission")).Return(nil).Once()

	return validator, mockDB, &ValidateTokenRequestInput{
		GrantType:    "client_credentials",
		ClientId:     "cc_client",
		ClientSecret: "valid_secret",
		Scope:        scope,
	}
}

func TestValidateTokenRequest_ClientCredentials_ScopeWhitespace(t *testing.T) {
	settings := &models.Settings{}
	ctx := context.Background()

	t.Run("one space separates", func(t *testing.T) {
		validator, mockDB, input := newWhitespaceClientCredentials(t, singleSpaceSpelling)
		expectBillingResolution(mockDB)

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		require.NoError(t, err)
		assert.NotNil(t, result)
	})

	for _, tc := range oneElementSpellings {
		t.Run(tc.name+" is not a separator", func(t *testing.T) {
			validator, _, input := newWhitespaceClientCredentials(t, tc.scope)

			result, err := validator.ValidateTokenRequest(ctx, settings, input)

			assert.Nil(t, result)
			assertRefusedAsOneElement(t, err, fmt.Sprintf("Invalid scope format: '%v'. Scopes must adhere to the resource-identifier:permission-identifier format. For instance: backend-service:create-product.", tc.scope))
		})
	}
}

func newWhitespaceROPC(t *testing.T, scope string) (*TokenValidator, *mocks_data.Database, *mocks_protocolvalidation.PermissionChecker, *models.Settings, *ValidateTokenRequestInput) {
	t.Helper()
	mockDB := mocks_data.NewDatabase(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)
	validator := NewTokenValidator(mockDB, mocks_protocolvalidation.NewTokenParser(t), mockPermissionChecker, testDataCipher)
	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}

	passwordHash, err := passwordhash.Hash("correctpassword")
	require.NoError(t, err)
	user := &models.User{Id: 1, Email: "user@example.com", PasswordHash: passwordHash, Enabled: true}
	ropcEnabled := true
	client := &models.Client{
		ClientIdentifier:                        "ropc-client",
		Enabled:                                 true,
		IsPublic:                                true,
		ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
	}
	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc-client").Return(client, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, mock.Anything, "user@example.com").Return(user, nil).Once()
	mockDB.On("UserLoadPermissions", mock.Anything, mock.Anything, user).Return(nil).Once()
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(nil).Once()

	return validator, mockDB, mockPermissionChecker, settings, &ValidateTokenRequestInput{
		GrantType: "password",
		ClientId:  "ropc-client",
		Username:  "user@example.com",
		Password:  "correctpassword",
		Scope:     scope,
	}
}

func TestValidateTokenRequest_ROPC_ScopeWhitespace(t *testing.T) {
	t.Run("one space separates", func(t *testing.T) {
		validator, mockDB, mockPermissionChecker, settings, input := newWhitespaceROPC(t, singleSpaceSpelling)
		expectBillingResolution(mockDB)
		mockPermissionChecker.On("UserHasScopePermission", mock.Anything, int64(1), whitespaceScopeA).Return(true, nil).Once()
		mockPermissionChecker.On("UserHasScopePermission", mock.Anything, int64(1), whitespaceScopeB).Return(true, nil).Once()

		result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, singleSpaceSpelling, grantAs[*PasswordGrant](t, result).Scope)
	})

	for _, tc := range oneElementSpellings {
		t.Run(tc.name+" is not a separator", func(t *testing.T) {
			validator, _, mockPermissionChecker, settings, input := newWhitespaceROPC(t, tc.scope)

			result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

			assert.Nil(t, result)
			assertRefusedAsOneElement(t, err, fmt.Sprintf("Invalid scope format: '%v'. Scopes must be either OIDC scopes (openid, profile, email, address, phone, groups, attributes) or resource-identifier:permission-identifier format.", tc.scope))
			mockPermissionChecker.AssertNotCalled(t, "UserHasScopePermission", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}
