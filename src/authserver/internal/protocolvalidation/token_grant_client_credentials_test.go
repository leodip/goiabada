package protocolvalidation

import (
	"context"
	"net/http"
	"testing"

	"errors"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation/mocks"
)

func TestValidateTokenRequest_ClientCredentials(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
	mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &record.Settings{}
	ctx := context.Background()

	t.Run("Client credentials flow not enabled", func(t *testing.T) {
		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "client1",
			ClientSecret: "secret",
		}

		client := &record.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			ClientCredentialsEnabled: false,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "unauthorized_client", customErr.Code())
		assert.Equal(t, "The client associated with the provided client_id does not support client credentials flow.", customErr.Description())
		assert.Equal(t, 400, customErr.HTTPStatus())
	})

	t.Run("Public client not eligible for client credentials", func(t *testing.T) {
		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "client1",
			ClientSecret: "secret",
		}

		client := &record.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			IsPublic:                 true,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "unauthorized_client", customErr.Code())
		assert.Equal(t, "A public client is not eligible for the client credentials flow. Please review the client configuration.", customErr.Description())
		assert.Equal(t, 400, customErr.HTTPStatus())
	})

	t.Run("Missing client secret", func(t *testing.T) {
		input := &ValidateTokenRequestInput{
			GrantType: "client_credentials",
			ClientId:  "client1",
			// ClientSecret is intentionally left empty
		}

		client := &record.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			IsPublic:                 false,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		// RFC 6749 Section 5.2: invalid_client for missing client credentials
		assert.Equal(t, "invalid_client", customErr.Code())
		assert.Equal(t, "This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed.", customErr.Description())
		assert.Equal(t, http.StatusUnauthorized, customErr.HTTPStatus())
	})

	t.Run("Valid client credentials request", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		subtestCtx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "valid_client",
			ClientSecret: "valid_secret",
			Scope:        "resource:permission",
		}

		clientSecret := "valid_secret"
		clientSecretEncrypted, _ := testDataCipher.Encrypt(clientSecret)

		client := &record.Client{
			ClientIdentifier:         "valid_client",
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
			// Ids are load-bearing: ownership is decided by resource-scoped permission id,
			// so a fixture leaving them zero matches every other zero and passes whether the
			// check is right, wrong, or absent. Do not tidy these back to bare identifiers.
			Permissions: []record.Permission{{Id: 10, PermissionIdentifier: "permission", ResourceId: 1}},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "valid_client").Return(client, nil)
		mockDB.On("ClientLoadPermissions", mock.Anything, mock.Anything, client).Return(nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, mock.Anything, mock.AnythingOfType("[]record.Permission")).Return(nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "resource").Return(&record.Resource{Id: 1, ResourceIdentifier: "resource"}, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(1)).Return([]record.Permission{{Id: 10, PermissionIdentifier: "permission", ResourceId: 1}}, nil)

		result, err := validator.ValidateTokenRequest(subtestCtx, settings, input)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, client, grantAs[*ClientCredentialsGrant](t, result).Client)
		assert.Equal(t, "resource:permission", grantAs[*ClientCredentialsGrant](t, result).Scope)
	})

	t.Run("Invalid client secret", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		subtestCtx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "valid_client",
			ClientSecret: "invalid_secret",
		}

		clientSecret := "valid_secret"
		clientSecretEncrypted, _ := testDataCipher.Encrypt(clientSecret)

		client := &record.Client{
			ClientIdentifier:         "valid_client",
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "valid_client").Return(client, nil)

		result, err := validator.ValidateTokenRequest(subtestCtx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_client", customErr.Code())
		assert.Equal(t, "Client authentication failed. Please review your client_secret.", customErr.Description())
	})

	t.Run("Valid scope", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		subtestCtx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "valid_client",
			ClientSecret: "valid_secret",
			Scope:        "resource1:read resource2:write",
		}

		clientSecret := "valid_secret"
		clientSecretEncrypted, _ := testDataCipher.Encrypt(clientSecret)

		client := &record.Client{
			ClientIdentifier:         "valid_client",
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
			// Ids are load-bearing, see "Valid client credentials request" above.
			Permissions: []record.Permission{
				{Id: 10, PermissionIdentifier: "read", ResourceId: 1},
				{Id: 20, PermissionIdentifier: "write", ResourceId: 2},
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "valid_client").Return(client, nil)
		mockDB.On("ClientLoadPermissions", mock.Anything, mock.Anything, client).Return(nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, mock.Anything, mock.AnythingOfType("[]record.Permission")).Return(nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "resource1").Return(&record.Resource{Id: 1, ResourceIdentifier: "resource1"}, nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "resource2").Return(&record.Resource{Id: 2, ResourceIdentifier: "resource2"}, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(1)).Return([]record.Permission{{Id: 10, PermissionIdentifier: "read", ResourceId: 1}}, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(2)).Return([]record.Permission{{Id: 20, PermissionIdentifier: "write", ResourceId: 2}}, nil)

		result, err := validator.ValidateTokenRequest(subtestCtx, settings, input)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "resource1:read resource2:write", grantAs[*ClientCredentialsGrant](t, result).Scope)
	})

	t.Run("Invalid scope format", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		subtestCtx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "valid_client",
			ClientSecret: "valid_secret",
			Scope:        "invalid_scope",
		}

		clientSecret := "valid_secret"
		clientSecretEncrypted, _ := testDataCipher.Encrypt(clientSecret)

		client := &record.Client{
			ClientIdentifier:         "valid_client",
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "valid_client").Return(client, nil)
		mockDB.On("ClientLoadPermissions", mock.Anything, mock.Anything, client).Return(nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, mock.Anything, mock.AnythingOfType("[]record.Permission")).Return(nil)

		result, err := validator.ValidateTokenRequest(subtestCtx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_scope", customErr.Code())
		assert.Contains(t, customErr.Description(), "Invalid scope format")
	})

	t.Run("Scope not granted to client", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		subtestCtx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "valid_client",
			ClientSecret: "valid_secret",
			Scope:        "resource:read",
		}

		clientSecret := "valid_secret"
		clientSecretEncrypted, _ := testDataCipher.Encrypt(clientSecret)

		client := &record.Client{
			ClientIdentifier:         "valid_client",
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
			Permissions:              []record.Permission{}, // Empty permissions
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "valid_client").Return(client, nil)
		mockDB.On("ClientLoadPermissions", mock.Anything, mock.Anything, client).Return(nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, mock.Anything, mock.AnythingOfType("[]record.Permission")).Return(nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "resource").Return(&record.Resource{Id: 1, ResourceIdentifier: "resource"}, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(1)).Return([]record.Permission{{PermissionIdentifier: "read"}}, nil)

		result, err := validator.ValidateTokenRequest(subtestCtx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_scope", customErr.Code())
		assert.Contains(t, customErr.Description(), "Permission to access scope 'resource:read' is not granted to the client")
	})

	t.Run("ID token scope in client credentials", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		subtestCtx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "valid_client",
			ClientSecret: "valid_secret",
			Scope:        "openid profile",
		}

		clientSecret := "valid_secret"
		clientSecretEncrypted, _ := testDataCipher.Encrypt(clientSecret)

		client := &record.Client{
			ClientIdentifier:         "valid_client",
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "valid_client").Return(client, nil)
		mockDB.On("ClientLoadPermissions", mock.Anything, mock.Anything, client).Return(nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, mock.Anything, mock.AnythingOfType("[]record.Permission")).Return(nil)

		result, err := validator.ValidateTokenRequest(subtestCtx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_scope", customErr.Code())
		assert.Contains(t, customErr.Description(), "Id token scopes (such as 'openid') are not supported in the client credentials flow")
	})

	t.Run("Non-existent resource in scope", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		subtestCtx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "valid_client",
			ClientSecret: "valid_secret",
			Scope:        "non_existent_resource:read",
		}

		clientSecret := "valid_secret"
		clientSecretEncrypted, _ := testDataCipher.Encrypt(clientSecret)

		client := &record.Client{
			ClientIdentifier:         "valid_client",
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "valid_client").Return(client, nil)
		mockDB.On("ClientLoadPermissions", mock.Anything, mock.Anything, client).Return(nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, mock.Anything, mock.AnythingOfType("[]record.Permission")).Return(nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "non_existent_resource").Return(nil, nil)

		result, err := validator.ValidateTokenRequest(subtestCtx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_scope", customErr.Code())
		assert.Contains(t, customErr.Description(), "Could not find a resource with identifier 'non_existent_resource'")
	})

	t.Run("Non-existent permission in scope", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		subtestCtx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "valid_client",
			ClientSecret: "valid_secret",
			Scope:        "resource:non_existent_permission",
		}

		clientSecret := "valid_secret"
		clientSecretEncrypted, _ := testDataCipher.Encrypt(clientSecret)

		client := &record.Client{
			ClientIdentifier:         "valid_client",
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "valid_client").Return(client, nil)
		mockDB.On("ClientLoadPermissions", mock.Anything, mock.Anything, client).Return(nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, mock.Anything, mock.AnythingOfType("[]record.Permission")).Return(nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "resource").Return(&record.Resource{Id: 1, ResourceIdentifier: "resource"}, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(1)).Return([]record.Permission{}, nil)

		result, err := validator.ValidateTokenRequest(subtestCtx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_scope", customErr.Code())
		assert.Contains(t, customErr.Description(), "The resource identified by 'resource' doesn't grant the 'non_existent_permission' permission")
	})

	t.Run("Multiple valid scopes", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		subtestCtx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "valid_client",
			ClientSecret: "valid_secret",
			Scope:        "resource1:read resource2:write resource3:delete",
		}

		clientSecret := "valid_secret"
		clientSecretEncrypted, _ := testDataCipher.Encrypt(clientSecret)

		client := &record.Client{
			ClientIdentifier:         "valid_client",
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
			// Ids are load-bearing, see "Valid client credentials request" above.
			Permissions: []record.Permission{
				{Id: 10, PermissionIdentifier: "read", ResourceId: 1},
				{Id: 20, PermissionIdentifier: "write", ResourceId: 2},
				{Id: 30, PermissionIdentifier: "delete", ResourceId: 3},
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "valid_client").Return(client, nil)
		mockDB.On("ClientLoadPermissions", mock.Anything, mock.Anything, client).Return(nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, mock.Anything, mock.AnythingOfType("[]record.Permission")).Return(nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "resource1").Return(&record.Resource{Id: 1, ResourceIdentifier: "resource1"}, nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "resource2").Return(&record.Resource{Id: 2, ResourceIdentifier: "resource2"}, nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "resource3").Return(&record.Resource{Id: 3, ResourceIdentifier: "resource3"}, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(1)).Return([]record.Permission{{Id: 10, PermissionIdentifier: "read", ResourceId: 1}}, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(2)).Return([]record.Permission{{Id: 20, PermissionIdentifier: "write", ResourceId: 2}}, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(3)).Return([]record.Permission{{Id: 30, PermissionIdentifier: "delete", ResourceId: 3}}, nil)

		result, err := validator.ValidateTokenRequest(subtestCtx, settings, input)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "resource1:read resource2:write resource3:delete", grantAs[*ClientCredentialsGrant](t, result).Scope)
	})

	// --- Resource-scoped permission ownership (#104) ---------------------------------
	//
	// permission_identifier is unique per resource, never globally, and the
	// docs steer users toward generic names ("read", "write", "manage"). The ownership
	// check used to compare the bare identifier against client.Permissions, which
	// ClientLoadPermissions populates across EVERY resource, so holding "read" on one
	// resource conveyed "read" on all of them, and holding "manage" on a custom
	// resource conveyed "authserver:manage" and with it the whole Admin API.
	//
	// The fixture below is built so identifier and id diverge: "read" exists on three
	// resources under three different ids, and "manage" on two. A test whose fixture
	// leaves ids at zero cannot tell the fixed code from the broken code.
	var (
		billingRead      = record.Permission{Id: 10, PermissionIdentifier: "read", ResourceId: 1}
		billingManage    = record.Permission{Id: 12, PermissionIdentifier: "manage", ResourceId: 1}
		reportsRead      = record.Permission{Id: 20, PermissionIdentifier: "read", ResourceId: 2}
		archiveRead      = record.Permission{Id: 30, PermissionIdentifier: "read", ResourceId: 3}
		authserverManage = record.Permission{Id: 40, PermissionIdentifier: "manage", ResourceId: 4}
	)

	ccSecretEncrypted, _ := testDataCipher.Encrypt("valid_secret")

	// Registered with .Maybe() because each case reaches only the lookups its own
	// scope string requires, and the assertion that matters is the outcome rather
	// than the call set. The two error-propagation subtests below register their own.
	registerCatalog := func(mockDB *datamocks.Database) {
		for _, r := range []struct {
			identifier string
			id         int64
			perms      []record.Permission
		}{
			{"billing-api", 1, []record.Permission{billingRead, billingManage}},
			{"reports-api", 2, []record.Permission{reportsRead}},
			{"archive-api", 3, []record.Permission{archiveRead}},
			{"authserver", 4, []record.Permission{authserverManage}},
		} {
			mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, r.identifier).
				Return(&record.Resource{Id: r.id, ResourceIdentifier: r.identifier}, nil).Maybe()
			mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, r.id).Return(r.perms, nil).Maybe()
		}
		// Anything not in the catalog resolves to nil, exercising the not-found branch.
		for _, unknown := range []string{"nope-api", ""} {
			mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, unknown).Return(nil, nil).Maybe()
		}
	}

	// runCC drives one client credentials request against the catalog above.
	// wantCode == "" means the request must be accepted with scope wantScope.
	runCC := func(t *testing.T, clientPerms []record.Permission, scope, wantCode, wantDesc, wantScope string) {
		t.Helper()

		mockDB := datamocks.NewDatabase(t)
		validator := NewTokenValidator(mockDB, protocolvalidationmocks.NewTokenParser(t), protocolvalidationmocks.NewPermissionChecker(t), testDataCipher)

		client := &record.Client{
			ClientIdentifier:         "cc_client",
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    ccSecretEncrypted,
			Permissions:              clientPerms,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "cc_client").Return(client, nil)
		mockDB.On("ClientLoadPermissions", mock.Anything, mock.Anything, client).Return(nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, mock.Anything, mock.AnythingOfType("[]record.Permission")).Return(nil)
		registerCatalog(mockDB)

		result, err := validator.ValidateTokenRequest(ctx, settings, &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "cc_client",
			ClientSecret: "valid_secret",
			Scope:        scope,
		})

		if wantCode == "" {
			assert.NoError(t, err)
			if assert.NotNil(t, result) {
				assert.Equal(t, wantScope, grantAs[*ClientCredentialsGrant](t, result).Scope)
			}
			return
		}

		assert.Nil(t, result)
		customErr, ok := err.(*oauth.ErrorDetail)
		if !assert.True(t, ok, "expected *oauth.ErrorDetail, got %T: %v", err, err) {
			return
		}
		assert.Equal(t, wantCode, customErr.Code())
		assert.Contains(t, customErr.Description(), wantDesc)
	}

	ownershipCases := []struct {
		name        string
		clientPerms []record.Permission
		scope       string
		wantCode    string
		wantDesc    string
		wantScope   string
	}{
		// The load-bearing pair. These two vary ONLY the resource, holding the
		// permission identifier, the client and the grant fixed, so nothing but the
		// ownership check can account for the difference in outcome. The first alone
		// would also pass against an implementation that over-rejected everything.
		{
			name:        "cross-resource read is denied",
			clientPerms: []record.Permission{billingRead},
			scope:       "reports-api:read",
			wantCode:    "invalid_scope",
			wantDesc:    "Permission to access scope 'reports-api:read' is not granted to the client.",
		},
		{
			name:        "same-resource read is allowed",
			clientPerms: []record.Permission{billingRead},
			scope:       "billing-api:read",
			wantScope:   "billing-api:read",
		},
		{
			name:        "cross-resource read is denied in the other direction",
			clientPerms: []record.Permission{reportsRead},
			scope:       "billing-api:read",
			wantCode:    "invalid_scope",
			wantDesc:    "Permission to access scope 'billing-api:read' is not granted to the client.",
		},
		{
			name:        "holding the identifier on two other resources does not help",
			clientPerms: []record.Permission{billingRead, archiveRead},
			scope:       "reports-api:read",
			wantCode:    "invalid_scope",
			wantDesc:    "Permission to access scope 'reports-api:read' is not granted to the client.",
		},
		// These two differ only in ordering. A short-circuit that accepted the whole
		// request on the first granted scope would pass one and fail the other.
		{
			name:        "a denied scope after a granted one is still denied",
			clientPerms: []record.Permission{billingRead},
			scope:       "billing-api:read reports-api:read",
			wantCode:    "invalid_scope",
			wantDesc:    "Permission to access scope 'reports-api:read' is not granted to the client.",
		},
		{
			name:        "a denied scope before a granted one is still denied",
			clientPerms: []record.Permission{billingRead},
			scope:       "reports-api:read billing-api:read",
			wantCode:    "invalid_scope",
			wantDesc:    "Permission to access scope 'reports-api:read' is not granted to the client.",
		},
		// The escalation the issue is really about: "manage" on a custom resource must
		// not reach the built-in "manage" on the system authserver resource, which is
		// full Admin API access.
		{
			name:        "custom manage does not reach authserver manage",
			clientPerms: []record.Permission{billingManage},
			scope:       "authserver:manage",
			wantCode:    "invalid_scope",
			wantDesc:    "Permission to access scope 'authserver:manage' is not granted to the client.",
		},
		{
			// Not redundant with "same-resource read is allowed": this is the grant
			// administrative tooling depends on, and it stops the case above passing
			// for the wrong reason.
			name:        "a genuine authserver manage grant still works",
			clientPerms: []record.Permission{authserverManage},
			scope:       "authserver:manage",
			wantScope:   "authserver:manage",
		},
		// Deduping (added in a later stage) must not be able to launder a denied
		// scope. Diverges from the old behaviour for two independent reasons at once,
		// so keep it even if deduping is ever reverted.
		{
			name:        "a repeated cross-resource scope is denied",
			clientPerms: []record.Permission{billingRead},
			scope:       "reports-api:read reports-api:read",
			wantCode:    "invalid_scope",
			wantDesc:    "Permission to access scope 'reports-api:read' is not granted to the client.",
		},
		// Paths that return before ownership is decided. These do not change
		// behaviour; they pin every early exit now that ownership depends on ids
		// resolved from the requested resource.
		{
			name:        "unknown resource",
			clientPerms: []record.Permission{billingRead},
			scope:       "nope-api:read",
			wantCode:    "invalid_scope",
			wantDesc:    "Could not find a resource with identifier 'nope-api'",
		},
		{
			name:        "permission does not exist on the requested resource",
			clientPerms: []record.Permission{billingRead},
			scope:       "billing-api:delete",
			wantCode:    "invalid_scope",
			wantDesc:    "doesn't grant the 'delete' permission",
		},
		{
			// The authserver resource has no userinfo permission since #449, so an explicit
			// request for it is refused as any unknown permission is.
			name:        "authserver:userinfo, a permission the authserver resource no longer has",
			clientPerms: []record.Permission{authserverManage},
			scope:       "authserver:userinfo",
			wantCode:    "invalid_scope",
			wantDesc:    "Scope 'authserver:userinfo' is not recognized. The resource identified by 'authserver' doesn't grant the 'userinfo' permission.",
		},
		{
			name:        "client holds no permissions at all",
			clientPerms: nil,
			scope:       "billing-api:read",
			wantCode:    "invalid_scope",
			wantDesc:    "Permission to access scope 'billing-api:read' is not granted to the client.",
		},
		{
			name:        "too many colon-separated parts",
			clientPerms: []record.Permission{billingRead},
			scope:       "billing-api:read:extra",
			wantCode:    "invalid_scope",
			wantDesc:    "Invalid scope format",
		},
		{
			name:        "empty permission part",
			clientPerms: []record.Permission{billingRead},
			scope:       "billing-api:",
			wantCode:    "invalid_scope",
			wantDesc:    "doesn't grant the '' permission",
		},
		{
			name:        "empty resource part",
			clientPerms: []record.Permission{billingRead},
			scope:       ":read",
			wantCode:    "invalid_scope",
			wantDesc:    "Could not find a resource with identifier ''",
		},
		{
			name:        "only colons",
			clientPerms: []record.Permission{billingRead},
			scope:       "::",
			wantCode:    "invalid_scope",
			wantDesc:    "Invalid scope format",
		},
		{
			name:        "no colon at all",
			clientPerms: []record.Permission{billingRead},
			scope:       "billing-api",
			wantCode:    "invalid_scope",
			wantDesc:    "Invalid scope format",
		},
		{
			name:        "openid is rejected for this grant",
			clientPerms: []record.Permission{billingRead},
			scope:       "openid",
			wantCode:    "invalid_scope",
			wantDesc:    "are not supported in the client credentials flow",
		},
		{
			name:        "offline_access is rejected for this grant",
			clientPerms: []record.Permission{billingRead},
			scope:       "offline_access",
			wantCode:    "invalid_scope",
			wantDesc:    "are not supported in the client credentials flow",
		},
		{
			name:        "an OIDC scope alongside a granted one is still rejected",
			clientPerms: []record.Permission{billingRead},
			scope:       "openid billing-api:read",
			wantCode:    "invalid_scope",
			wantDesc:    "are not supported in the client credentials flow",
		},
		// Scope values are case-sensitive (RFC 6749 section 3.3), so neither uppercase
		// spelling is an OIDC scope: both fall through to the format check. OFFLINE_ACCESS
		// used to be case-folded into offline_access here while every other site matched it
		// exactly; the two rows now agree, and the second is the one that fails if the
		// lenient match comes back (#425).
		{
			name:        "uppercase OPENID falls through to the format check",
			clientPerms: []record.Permission{billingRead},
			scope:       "OPENID",
			wantCode:    "invalid_scope",
			wantDesc:    "Invalid scope format",
		},
		{
			name:        "uppercase OFFLINE_ACCESS falls through to the format check",
			clientPerms: []record.Permission{billingRead},
			scope:       "OFFLINE_ACCESS",
			wantCode:    "invalid_scope",
			wantDesc:    "Invalid scope format",
		},
	}

	for _, tc := range ownershipCases {
		t.Run(tc.name, func(t *testing.T) {
			runCC(t, tc.clientPerms, tc.scope, tc.wantCode, tc.wantDesc, tc.wantScope)
		})
	}

	// A database failure must propagate as an error (a 500), not be swallowed into an
	// invalid_scope denial. The two are indistinguishable to a caller reading only the
	// status code, and a swallowed error would silently deny legitimate requests.
	for _, tc := range []struct {
		name  string
		setup func(*datamocks.Database)
	}{
		{
			name: "GetResourceByResourceIdentifier error propagates",
			setup: func(mockDB *datamocks.Database) {
				mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "billing-api").
					Return(nil, errors.New("database is down"))
			},
		},
		{
			name: "GetPermissionsByResourceId error propagates",
			setup: func(mockDB *datamocks.Database) {
				mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "billing-api").
					Return(&record.Resource{Id: 1, ResourceIdentifier: "billing-api"}, nil)
				mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(1)).
					Return(nil, errors.New("database is down"))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := datamocks.NewDatabase(t)
			validator := NewTokenValidator(mockDB, protocolvalidationmocks.NewTokenParser(t), protocolvalidationmocks.NewPermissionChecker(t), testDataCipher)

			client := &record.Client{
				ClientIdentifier:         "cc_client",
				Enabled:                  true,
				ClientCredentialsEnabled: true,
				IsPublic:                 false,
				ClientSecretEncrypted:    ccSecretEncrypted,
				Permissions:              []record.Permission{billingRead},
			}

			mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "cc_client").Return(client, nil)
			mockDB.On("ClientLoadPermissions", mock.Anything, mock.Anything, client).Return(nil)
			mockDB.On("PermissionsLoadResources", mock.Anything, mock.Anything, mock.AnythingOfType("[]record.Permission")).Return(nil)
			tc.setup(mockDB)

			result, err := validator.ValidateTokenRequest(ctx, settings, &ValidateTokenRequestInput{
				GrantType:    "client_credentials",
				ClientId:     "cc_client",
				ClientSecret: "valid_secret",
				Scope:        "billing-api:read",
			})

			assert.Nil(t, result)
			assert.EqualError(t, err, "database is down")
			_, isErrorDetail := err.(*oauth.ErrorDetail)
			assert.False(t, isErrorDetail, "a database failure must not be reported as an OAuth error")
		})
	}
}

// TestValidateTokenRequest_ClientCredentials_NoScopeGiven covers the "no scope was passed, grant
// everything the client holds" expansion, which had no unit coverage at all: of the client
// credentials cases above, none omits Scope. It was exercised only by an integration test.
//
// It also pins the removal of a redundant database round-trip. The expansion used to call
// GetResourceByResourceIdentifier for each granted permission and then use the identifier it had
// just passed in, even though PermissionsLoadResources had already populated perm.Resource.
//
// **The pin is the call COUNT, not the absence of a stub.** The issue-104 spec said the new cases
// "must not stub GetResourceByResourceIdentifier", which is wrong: validateClientCredentialsScopes
// runs on the expanded scope immediately afterwards and looks up each resource itself. So the stub
// is required, and .Once() is what makes the test fail if the expansion looks anything up: before
// the removal each resource was fetched twice per request, once expanding and once validating.
func TestValidateTokenRequest_ClientCredentials_NoScopeGiven(t *testing.T) {
	billingResource := record.Resource{Id: 1, ResourceIdentifier: "billing-api"}
	reportsResource := record.Resource{Id: 2, ResourceIdentifier: "reports-api"}

	billingRead := record.Permission{Id: 10, PermissionIdentifier: "read", ResourceId: 1, Resource: billingResource}
	reportsRead := record.Permission{Id: 20, PermissionIdentifier: "read", ResourceId: 2, Resource: reportsResource}

	testCases := []struct {
		name string
		// clientPerms carry a populated Resource, as PermissionsLoadResources would leave them.
		clientPerms []record.Permission
		wantScope   string
		// resourcesLookedUp is what the VALIDATION step then resolves, each expected exactly once.
		resourcesLookedUp []record.Resource
	}{
		{
			// Also confirms the expansion is resource-qualified: a client holding "read" on two
			// resources gets both "billing-api:read" and "reports-api:read", not one of them twice.
			// That distinction started mattering when the ownership check became resource-scoped.
			name:              "the same permission identifier on two resources yields both scopes",
			clientPerms:       []record.Permission{billingRead, reportsRead},
			wantScope:         "billing-api:read reports-api:read",
			resourcesLookedUp: []record.Resource{billingResource, reportsResource},
		},
		{
			name:              "a single grant yields a single scope",
			clientPerms:       []record.Permission{billingRead},
			wantScope:         "billing-api:read",
			resourcesLookedUp: []record.Resource{billingResource},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := datamocks.NewDatabase(t)
			validator := NewTokenValidator(mockDB, protocolvalidationmocks.NewTokenParser(t), protocolvalidationmocks.NewPermissionChecker(t), testDataCipher)
			settings := &record.Settings{}
			ctx := context.Background()

			clientSecretEncrypted, _ := testDataCipher.Encrypt("valid_secret")
			client := &record.Client{
				ClientIdentifier:         "cc_client",
				Enabled:                  true,
				ClientCredentialsEnabled: true,
				IsPublic:                 false,
				ClientSecretEncrypted:    clientSecretEncrypted,
				Permissions:              tc.clientPerms,
			}

			mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "cc_client").Return(client, nil)
			mockDB.On("ClientLoadPermissions", mock.Anything, mock.Anything, client).Return(nil)
			mockDB.On("PermissionsLoadResources", mock.Anything, mock.Anything, mock.AnythingOfType("[]record.Permission")).Return(nil)

			// .Once() is the assertion. Two calls per resource means the expansion is looking
			// resources up again instead of using the association already loaded above.
			for i := range tc.resourcesLookedUp {
				res := tc.resourcesLookedUp[i]
				mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, res.ResourceIdentifier).
					Return(&res, nil).Once()
				var perms []record.Permission
				for _, p := range tc.clientPerms {
					if p.ResourceId == res.Id {
						perms = append(perms, p)
					}
				}
				mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, res.Id).Return(perms, nil).Once()
			}

			// Scope deliberately omitted, which is what selects the expansion branch.
			result, err := validator.ValidateTokenRequest(ctx, settings, &ValidateTokenRequestInput{
				GrantType:    "client_credentials",
				ClientId:     "cc_client",
				ClientSecret: "valid_secret",
			})

			assert.NoError(t, err)
			if assert.NotNil(t, result) {
				assert.Equal(t, tc.wantScope, grantAs[*ClientCredentialsGrant](t, result).Scope)
			}
		})
	}
}

// TestValidateTokenRequest_ClientCredentials_NoScopeFromAClientHoldingNothingIsInvalidScope: with
// scope omitted the grant's default is every permission the client holds, so a client holding none
// has no default, and RFC 6749 section 3.3 says such a request fails as invalid_scope. It used to
// pass the validator with an empty scope and reach the issuer, which refused it as a plain error,
// answered 500 server_error. Nothing is resolved: the refusal comes before any scope is looked up.
func TestValidateTokenRequest_ClientCredentials_NoScopeFromAClientHoldingNothingIsInvalidScope(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	validator := NewTokenValidator(mockDB, protocolvalidationmocks.NewTokenParser(t), protocolvalidationmocks.NewPermissionChecker(t), testDataCipher)

	clientSecretEncrypted, err := testDataCipher.Encrypt("valid_secret")
	require.NoError(t, err)
	client := &record.Client{
		ClientIdentifier:         "cc_client",
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}
	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "cc_client").Return(client, nil)
	mockDB.On("ClientLoadPermissions", mock.Anything, mock.Anything, client).Return(nil)
	mockDB.On("PermissionsLoadResources", mock.Anything, mock.Anything, mock.AnythingOfType("[]record.Permission")).Return(nil)

	result, err := validator.ValidateTokenRequest(context.Background(), &record.Settings{}, &ValidateTokenRequestInput{
		GrantType:    "client_credentials",
		ClientId:     "cc_client",
		ClientSecret: "valid_secret",
	})

	assert.Nil(t, result)
	var detail *oauth.ErrorDetail
	require.True(t, errors.As(err, &detail), "the client's mistake is an OAuth error, not a server fault: %v", err)
	assert.Equal(t, "invalid_scope", detail.Code())
	assert.Equal(t, http.StatusBadRequest, detail.HTTPStatus())
	assert.Equal(t, "The client holds no permissions, so a request without a scope has nothing to grant.", detail.Description())
}
