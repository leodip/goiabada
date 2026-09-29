package protocolvalidation

import (
	"context"
	"net/http"
	"testing"

	"errors"

	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_protocolvalidation "github.com/leodip/goiabada/authserver/internal/protocolvalidation/mocks"
)

// =============================================================================
// ROPC (Resource Owner Password Credentials) Tests - RFC 6749 Section 4.3
// =============================================================================

func TestValidateTokenRequest_ROPC_Success(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.Background()

	passwordHash, _ := passwordhash.Hash("correctpassword")
	user := &models.User{
		Id:           1,
		Email:        "user@example.com",
		PasswordHash: passwordHash,
		Enabled:      true,
		OTPEnabled:   false,
	}

	ropcEnabled := true
	client := &models.Client{
		Id:                                      1,
		ClientIdentifier:                        "ropc-client",
		Enabled:                                 true,
		IsPublic:                                true,
		ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
	}

	input := &ValidateTokenRequestInput{
		GrantType: "password",
		ClientId:  "ropc-client",
		Username:  "user@example.com",
		Password:  "correctpassword",
		Scope:     "openid",
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc-client").Return(client, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, mock.Anything, "user@example.com").Return(user, nil).Once()
	mockDB.On("UserLoadPermissions", mock.Anything, mock.Anything, user).Return(nil).Once()
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, client, result.Client)
	assert.Equal(t, user, result.User)
	assert.Equal(t, "openid", result.Scope)
}

func TestValidateTokenRequest_ROPC_GlobalDisabled(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: false, // Globally disabled
	}
	ctx := context.Background()

	client := &models.Client{
		ClientIdentifier:                        "ropc-client",
		Enabled:                                 true,
		ResourceOwnerPasswordCredentialsEnabled: nil, // Inherit from global
	}

	input := &ValidateTokenRequestInput{
		GrantType: "password",
		ClientId:  "ropc-client",
		Username:  "user@example.com",
		Password:  "password",
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc-client").Return(client, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	assert.Nil(t, result)
	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "unauthorized_client", customErr.GetCode())
	assert.Contains(t, customErr.GetDescription(), "not authorized to use the resource owner password credentials")
	assert.Equal(t, 400, customErr.GetHttpStatusCode())
}

func TestValidateTokenRequest_ROPC_ClientOverrideEnabled(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: false, // Globally disabled
	}
	ctx := context.Background()

	passwordHash, _ := passwordhash.Hash("correctpassword")
	user := &models.User{
		Id:           1,
		Email:        "user@example.com",
		PasswordHash: passwordHash,
		Enabled:      true,
		OTPEnabled:   false,
	}

	ropcEnabled := true
	client := &models.Client{
		ClientIdentifier:                        "ropc-client",
		Enabled:                                 true,
		IsPublic:                                true,
		ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled, // Client overrides to enable
	}

	input := &ValidateTokenRequestInput{
		GrantType: "password",
		ClientId:  "ropc-client",
		Username:  "user@example.com",
		Password:  "correctpassword",
		Scope:     "openid",
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc-client").Return(client, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, mock.Anything, "user@example.com").Return(user, nil).Once()
	mockDB.On("UserLoadPermissions", mock.Anything, mock.Anything, user).Return(nil).Once()
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, client, result.Client)
	assert.Equal(t, user, result.User)
}

func TestValidateTokenRequest_ROPC_ClientOverrideDisabled(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true, // Globally enabled
	}
	ctx := context.Background()

	ropcDisabled := false
	client := &models.Client{
		ClientIdentifier:                        "ropc-client",
		Enabled:                                 true,
		ResourceOwnerPasswordCredentialsEnabled: &ropcDisabled, // Client overrides to disable
	}

	input := &ValidateTokenRequestInput{
		GrantType: "password",
		ClientId:  "ropc-client",
		Username:  "user@example.com",
		Password:  "password",
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc-client").Return(client, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	assert.Nil(t, result)
	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "unauthorized_client", customErr.GetCode())
}

func TestValidateTokenRequest_ROPC_MissingUsername(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.Background()

	ropcEnabled := true
	client := &models.Client{
		ClientIdentifier:                        "ropc-client",
		Enabled:                                 true,
		IsPublic:                                true,
		ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
	}

	input := &ValidateTokenRequestInput{
		GrantType: "password",
		ClientId:  "ropc-client",
		Username:  "", // Missing
		Password:  "password",
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc-client").Return(client, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	assert.Nil(t, result)
	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "invalid_request", customErr.GetCode())
	assert.Equal(t, "Missing required username parameter.", customErr.GetDescription())
	assert.Equal(t, 400, customErr.GetHttpStatusCode())
}

func TestValidateTokenRequest_ROPC_MissingPassword(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.Background()

	ropcEnabled := true
	client := &models.Client{
		ClientIdentifier:                        "ropc-client",
		Enabled:                                 true,
		IsPublic:                                true,
		ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
	}

	input := &ValidateTokenRequestInput{
		GrantType: "password",
		ClientId:  "ropc-client",
		Username:  "user@example.com",
		Password:  "", // Missing
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc-client").Return(client, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	assert.Nil(t, result)
	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "invalid_request", customErr.GetCode())
	assert.Equal(t, "Missing required password parameter.", customErr.GetDescription())
	assert.Equal(t, 400, customErr.GetHttpStatusCode())
}

func TestValidateTokenRequest_ROPC_PublicClientWithSecret_Fails(t *testing.T) {
	// Decision 11's symmetry, the password arm. Its own branch, independent of the
	// refresh_token arm's, so neutralising one leaves the other proving itself (#245).
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.Background()

	ropcEnabled := true
	client := &models.Client{
		ClientIdentifier:                        "ropc-client",
		Enabled:                                 true,
		IsPublic:                                true,
		ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
	}

	// Username and password are both present, so nothing above the rejection can answer.
	input := &ValidateTokenRequestInput{
		GrantType:    "password",
		ClientId:     "ropc-client",
		ClientSecret: "a_secret_this_client_does_not_have",
		Username:     "user@example.com",
		Password:     "the-password",
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc-client").Return(client, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	assert.Nil(t, result)
	customErr, ok := err.(*customerrors.ErrorDetail)
	if assert.True(t, ok, "expected *customerrors.ErrorDetail, got %T: %v", err, err) {
		assert.Equal(t, "invalid_request", customErr.GetCode())
		assert.Equal(t, http.StatusBadRequest, customErr.GetHttpStatusCode())
		assert.Contains(t, customErr.GetDescription(), "remove the client_secret from your request")
	}
	// The strict mock is the second assertion: the refusal answers before the resource
	// owner's credentials are ever looked up, so no rate-limited guess is spent on it.
}

func TestValidateTokenRequest_ROPC_UserNotFound(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.Background()

	ropcEnabled := true
	client := &models.Client{
		ClientIdentifier:                        "ropc-client",
		Enabled:                                 true,
		IsPublic:                                true,
		ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
	}

	input := &ValidateTokenRequestInput{
		GrantType: "password",
		ClientId:  "ropc-client",
		Username:  "nonexistent@example.com",
		Password:  "password",
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc-client").Return(client, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, mock.Anything, "nonexistent@example.com").Return(nil, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	assert.Nil(t, result)
	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "invalid_grant", customErr.GetCode())
	assert.Equal(t, "Invalid resource owner credentials.", customErr.GetDescription())
	assert.Equal(t, 400, customErr.GetHttpStatusCode())
}

// TestValidateTokenRequest_ROPC_UsernameNormalizedForLookup pins that the username
// reaches GetUserByEmail lowercased and trimmed, which is what the rate limiter's
// per-account key does. If the two spellings diverge, the limiter and the account it
// protects disagree about which account a request is and a case variant buys a fresh
// bucket. It is also the live cross-engine fix: mysql and mssql compare email
// case-insensitively and postgres and sqlite do not (#219).
//
// The mock's expectation is exact-argument, so with the normalization removed the
// lookup is called with "  Bob@Example.com  " and no expectation matches.
func TestValidateTokenRequest_ROPC_UsernameNormalizedForLookup(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.Background()

	ropcEnabled := true
	client := &models.Client{
		ClientIdentifier:                        "ropc-client",
		Enabled:                                 true,
		IsPublic:                                true,
		ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
	}

	input := &ValidateTokenRequestInput{
		GrantType: "password",
		ClientId:  "ropc-client",
		Username:  "  Bob@Example.com  ",
		Password:  "password",
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc-client").Return(client, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, mock.Anything, "bob@example.com").Return(nil, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	assert.Nil(t, result)
	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "invalid_grant", customErr.GetCode())
}

// TestValidateTokenRequest_ROPC_WhitespaceOnlyUsernameIsInvalidGrant pins the one
// place the normalization deliberately does not reach: the missing-username check
// stays on the raw value, so a whitespace-only username is a failed credential
// (invalid_grant) rather than a malformed request (invalid_request). The distinction
// is what the per-account failure counter keys on, so moving the trim above the check
// would silently stop counting a whole class of guess (#219 decision 7).
func TestValidateTokenRequest_ROPC_WhitespaceOnlyUsernameIsInvalidGrant(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.Background()

	ropcEnabled := true
	client := &models.Client{
		ClientIdentifier:                        "ropc-client",
		Enabled:                                 true,
		IsPublic:                                true,
		ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
	}

	input := &ValidateTokenRequestInput{
		GrantType: "password",
		ClientId:  "ropc-client",
		Username:  "   ",
		Password:  "password",
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc-client").Return(client, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, mock.Anything, "").Return(nil, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	assert.Nil(t, result)
	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "invalid_grant", customErr.GetCode())
}

func TestValidateTokenRequest_ROPC_InvalidPassword(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.Background()

	passwordHash, _ := passwordhash.Hash("correctpassword")
	user := &models.User{
		Id:           1,
		Email:        "user@example.com",
		PasswordHash: passwordHash,
		Enabled:      true,
	}

	ropcEnabled := true
	client := &models.Client{
		ClientIdentifier:                        "ropc-client",
		Enabled:                                 true,
		IsPublic:                                true,
		ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
	}

	input := &ValidateTokenRequestInput{
		GrantType: "password",
		ClientId:  "ropc-client",
		Username:  "user@example.com",
		Password:  "wrongpassword",
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc-client").Return(client, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, mock.Anything, "user@example.com").Return(user, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	assert.Nil(t, result)
	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "invalid_grant", customErr.GetCode())
	assert.Equal(t, "Invalid resource owner credentials.", customErr.GetDescription())
	assert.Equal(t, 400, customErr.GetHttpStatusCode())
}

func TestValidateTokenRequest_ROPC_UserDisabled(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.Background()

	passwordHash, _ := passwordhash.Hash("correctpassword")
	user := &models.User{
		Id:           1,
		Email:        "user@example.com",
		PasswordHash: passwordHash,
		Enabled:      false, // Disabled
	}

	ropcEnabled := true
	client := &models.Client{
		ClientIdentifier:                        "ropc-client",
		Enabled:                                 true,
		IsPublic:                                true,
		ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
	}

	input := &ValidateTokenRequestInput{
		GrantType: "password",
		ClientId:  "ropc-client",
		Username:  "user@example.com",
		Password:  "correctpassword",
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc-client").Return(client, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, mock.Anything, "user@example.com").Return(user, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	assert.Nil(t, result)
	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "invalid_grant", customErr.GetCode())
	assert.Equal(t, "The user account is disabled.", customErr.GetDescription())
	assert.Equal(t, 400, customErr.GetHttpStatusCode())
}

func TestValidateTokenRequest_ROPC_UserWith2FA(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.Background()

	passwordHash, _ := passwordhash.Hash("correctpassword")
	user := &models.User{
		Id:           1,
		Email:        "user@example.com",
		PasswordHash: passwordHash,
		Enabled:      true,
		OTPEnabled:   true, // 2FA enabled
	}

	ropcEnabled := true
	client := &models.Client{
		ClientIdentifier:                        "ropc-client",
		Enabled:                                 true,
		IsPublic:                                true,
		ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
	}

	input := &ValidateTokenRequestInput{
		GrantType: "password",
		ClientId:  "ropc-client",
		Username:  "user@example.com",
		Password:  "correctpassword",
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc-client").Return(client, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, mock.Anything, "user@example.com").Return(user, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	assert.Nil(t, result)
	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "invalid_grant", customErr.GetCode())
	assert.Contains(t, customErr.GetDescription(), "two-factor authentication")
	assert.Equal(t, 400, customErr.GetHttpStatusCode())
}

func TestValidateTokenRequest_ROPC_ConfidentialClient_MissingSecret(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.Background()

	ropcEnabled := true
	client := &models.Client{
		ClientIdentifier:                        "ropc-client",
		Enabled:                                 true,
		IsPublic:                                false, // Confidential client
		ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
	}

	input := &ValidateTokenRequestInput{
		GrantType:    "password",
		ClientId:     "ropc-client",
		ClientSecret: "", // Missing secret
		Username:     "user@example.com",
		Password:     "password",
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc-client").Return(client, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	assert.Nil(t, result)
	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	// RFC 6749 Section 5.2: invalid_client for missing client credentials
	assert.Equal(t, "invalid_client", customErr.GetCode())
	assert.Contains(t, customErr.GetDescription(), "client_secret")
	assert.Equal(t, http.StatusUnauthorized, customErr.GetHttpStatusCode())
}

func TestValidateTokenRequest_ROPC_ConfidentialClient_InvalidSecret(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	encryptedSecret, _ := testDataCipher.Encrypt("correct-secret")

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.Background()

	ropcEnabled := true
	client := &models.Client{
		ClientIdentifier:                        "ropc-client",
		Enabled:                                 true,
		IsPublic:                                false, // Confidential client
		ClientSecretEncrypted:                   encryptedSecret,
		ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
	}

	input := &ValidateTokenRequestInput{
		GrantType:    "password",
		ClientId:     "ropc-client",
		ClientSecret: "wrong-secret",
		Username:     "user@example.com",
		Password:     "password",
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc-client").Return(client, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	assert.Nil(t, result)
	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "invalid_client", customErr.GetCode())
	assert.Equal(t, "Client authentication failed.", customErr.GetDescription())
	assert.Equal(t, 401, customErr.GetHttpStatusCode())
}

// TestValidateTokenRequest_ROPC_ConfidentialClient_OpensTheSecretWithItsOwnCipher holds the client
// secret to the cipher the validator was built with, where it used to be opened with a process-wide
// key: the right secret, sealed under another key than the validator's, does not authenticate. The
// refusal is the decrypt failure itself, not an invalid_client answer, since the stored row cannot
// be read at all (#434).
func TestValidateTokenRequest_ROPC_ConfidentialClient_OpensTheSecretWithItsOwnCipher(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	otherCipher, err := encryption.NewDataCipher([]byte("fedcba9876543210fedcba9876543210"))
	require.NoError(t, err)
	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, otherCipher)

	encryptedSecret, err := testDataCipher.Encrypt("correct-secret")
	require.NoError(t, err)

	ropcEnabled := true
	client := &models.Client{
		ClientIdentifier:                        "ropc-client",
		Enabled:                                 true,
		IsPublic:                                false,
		ClientSecretEncrypted:                   encryptedSecret,
		ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
	}
	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc-client").Return(client, nil).Once()

	result, err := validator.ValidateTokenRequest(context.Background(),
		&models.Settings{ResourceOwnerPasswordCredentialsEnabled: true},
		&ValidateTokenRequestInput{
			GrantType:    "password",
			ClientId:     "ropc-client",
			ClientSecret: "correct-secret",
			Username:     "user@example.com",
			Password:     "password",
		})

	assert.Nil(t, result)
	require.Error(t, err)
	var errorDetail *customerrors.ErrorDetail
	assert.False(t, errors.As(err, &errorDetail), "a secret the cipher cannot open answered %v", err)
}

func TestValidateTokenRequest_ROPC_ConfidentialClient_Success(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	encryptedSecret, _ := testDataCipher.Encrypt("correct-secret")

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.Background()

	passwordHash, _ := passwordhash.Hash("userpassword")
	user := &models.User{
		Id:           1,
		Email:        "user@example.com",
		PasswordHash: passwordHash,
		Enabled:      true,
		OTPEnabled:   false,
	}

	ropcEnabled := true
	client := &models.Client{
		Id:                                      1,
		ClientIdentifier:                        "ropc-client",
		Enabled:                                 true,
		IsPublic:                                false, // Confidential client
		ClientSecretEncrypted:                   encryptedSecret,
		ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
	}

	input := &ValidateTokenRequestInput{
		GrantType:    "password",
		ClientId:     "ropc-client",
		ClientSecret: "correct-secret",
		Username:     "user@example.com",
		Password:     "userpassword",
		Scope:        "openid profile",
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc-client").Return(client, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, mock.Anything, "user@example.com").Return(user, nil).Once()
	mockDB.On("UserLoadPermissions", mock.Anything, mock.Anything, user).Return(nil).Once()
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, client, result.Client)
	assert.Equal(t, user, result.User)
	assert.Equal(t, "openid profile", result.Scope)
}

func TestValidateTokenRequest_ROPC_EmptyScope_DefaultsToOpenId(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.Background()

	passwordHash, _ := passwordhash.Hash("correctpassword")
	user := &models.User{
		Id:           1,
		Email:        "user@example.com",
		PasswordHash: passwordHash,
		Enabled:      true,
		OTPEnabled:   false,
	}

	ropcEnabled := true
	client := &models.Client{
		ClientIdentifier:                        "ropc-client",
		Enabled:                                 true,
		IsPublic:                                true,
		ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
	}

	input := &ValidateTokenRequestInput{
		GrantType: "password",
		ClientId:  "ropc-client",
		Username:  "user@example.com",
		Password:  "correctpassword",
		Scope:     "", // Empty scope
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc-client").Return(client, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, mock.Anything, "user@example.com").Return(user, nil).Once()
	mockDB.On("UserLoadPermissions", mock.Anything, mock.Anything, user).Return(nil).Once()
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "openid", result.Scope) // Should default to openid
}

func TestValidateTokenRequest_ROPC_WithOfflineAccess(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.Background()

	passwordHash, _ := passwordhash.Hash("correctpassword")
	user := &models.User{
		Id:           1,
		Email:        "user@example.com",
		PasswordHash: passwordHash,
		Enabled:      true,
		OTPEnabled:   false,
	}

	ropcEnabled := true
	client := &models.Client{
		ClientIdentifier:                        "ropc-client",
		Enabled:                                 true,
		IsPublic:                                true,
		ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
	}

	input := &ValidateTokenRequestInput{
		GrantType: "password",
		ClientId:  "ropc-client",
		Username:  "user@example.com",
		Password:  "correctpassword",
		Scope:     "openid offline_access",
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc-client").Return(client, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, mock.Anything, "user@example.com").Return(user, nil).Once()
	mockDB.On("UserLoadPermissions", mock.Anything, mock.Anything, user).Return(nil).Once()
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Contains(t, result.Scope, "offline_access")
}

// TestValidateTokenRequest_ROPC_ClaimScopesWithoutOpenid pins that a password grant asking for a
// claim scope without openid is admitted as it asked (#449 decision 2). OIDC Core 1.0 section 3.1.2.1
// leaves such a request "entirely unspecified", and the groups and attributes scopes put claims into
// the access token without openid, so refusing it would break a request that works. A claim scope is
// not a permission, so the checker is never asked.
func TestValidateTokenRequest_ROPC_ClaimScopesWithoutOpenid(t *testing.T) {
	for _, scope := range []string{"profile", "groups"} {
		t.Run(scope, func(t *testing.T) {
			mockDB := mocks_data.NewDatabase(t)
			mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
			mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

			validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

			settings := &models.Settings{
				ResourceOwnerPasswordCredentialsEnabled: true,
			}
			ctx := context.Background()

			passwordHash, err := passwordhash.Hash("correctpassword")
			require.NoError(t, err)
			user := &models.User{
				Id:           1,
				Email:        "user@example.com",
				PasswordHash: passwordHash,
				Enabled:      true,
			}

			ropcEnabled := true
			client := &models.Client{
				ClientIdentifier:                        "ropc-client",
				Enabled:                                 true,
				IsPublic:                                true,
				ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
			}

			input := &ValidateTokenRequestInput{
				GrantType: "password",
				ClientId:  "ropc-client",
				Username:  "user@example.com",
				Password:  "correctpassword",
				Scope:     scope,
			}

			mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc-client").Return(client, nil).Once()
			mockDB.On("GetUserByEmail", mock.Anything, mock.Anything, "user@example.com").Return(user, nil).Once()
			mockDB.On("UserLoadPermissions", mock.Anything, mock.Anything, user).Return(nil).Once()
			mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(nil).Once()

			result, err := validator.ValidateTokenRequest(ctx, settings, input)

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, scope, result.Scope)
			mockPermissionChecker.AssertNotCalled(t, "UserHasScopePermission", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

func TestValidateTokenRequest_ROPC_InvalidScopeFormat(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.Background()

	passwordHash, _ := passwordhash.Hash("correctpassword")
	user := &models.User{
		Id:           1,
		Email:        "user@example.com",
		PasswordHash: passwordHash,
		Enabled:      true,
		OTPEnabled:   false,
	}

	ropcEnabled := true
	client := &models.Client{
		ClientIdentifier:                        "ropc-client",
		Enabled:                                 true,
		IsPublic:                                true,
		ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
	}

	input := &ValidateTokenRequestInput{
		GrantType: "password",
		ClientId:  "ropc-client",
		Username:  "user@example.com",
		Password:  "correctpassword",
		Scope:     "openid invalid_scope_without_colon",
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc-client").Return(client, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, mock.Anything, "user@example.com").Return(user, nil).Once()
	mockDB.On("UserLoadPermissions", mock.Anything, mock.Anything, user).Return(nil).Once()
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	assert.Nil(t, result)
	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "invalid_scope", customErr.GetCode())
	assert.Contains(t, customErr.GetDescription(), "Invalid scope format")
	assert.Equal(t, 400, customErr.GetHttpStatusCode())
}

func TestValidateTokenRequest_ROPC_ResourcePermission_Success(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.Background()

	passwordHash, _ := passwordhash.Hash("correctpassword")
	user := &models.User{
		Id:           1,
		Email:        "user@example.com",
		PasswordHash: passwordHash,
		Enabled:      true,
		OTPEnabled:   false,
	}

	ropcEnabled := true
	client := &models.Client{
		ClientIdentifier:                        "ropc-client",
		Enabled:                                 true,
		IsPublic:                                true,
		ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
	}

	resource := &models.Resource{
		Id:                 1,
		ResourceIdentifier: "api",
	}

	permissions := []models.Permission{
		{Id: 1, PermissionIdentifier: "read", ResourceId: 1},
	}

	input := &ValidateTokenRequestInput{
		GrantType: "password",
		ClientId:  "ropc-client",
		Username:  "user@example.com",
		Password:  "correctpassword",
		Scope:     "openid api:read",
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc-client").Return(client, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, mock.Anything, "user@example.com").Return(user, nil).Once()
	mockDB.On("UserLoadPermissions", mock.Anything, mock.Anything, user).Return(nil).Once()
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(nil).Once()
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "api").Return(resource, nil).Once()
	mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(1)).Return(permissions, nil).Once()
	mockPermissionChecker.On("UserHasScopePermission", mock.Anything, int64(1), "api:read").Return(true, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Contains(t, result.Scope, "api:read")
}

func TestValidateTokenRequest_ROPC_ResourcePermission_UserLacksPermission(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.Background()

	passwordHash, _ := passwordhash.Hash("correctpassword")
	user := &models.User{
		Id:           1,
		Email:        "user@example.com",
		PasswordHash: passwordHash,
		Enabled:      true,
		OTPEnabled:   false,
	}

	ropcEnabled := true
	client := &models.Client{
		ClientIdentifier:                        "ropc-client",
		Enabled:                                 true,
		IsPublic:                                true,
		ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
	}

	resource := &models.Resource{
		Id:                 1,
		ResourceIdentifier: "api",
	}

	permissions := []models.Permission{
		{Id: 1, PermissionIdentifier: "read", ResourceId: 1},
	}

	input := &ValidateTokenRequestInput{
		GrantType: "password",
		ClientId:  "ropc-client",
		Username:  "user@example.com",
		Password:  "correctpassword",
		Scope:     "openid api:read",
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc-client").Return(client, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, mock.Anything, "user@example.com").Return(user, nil).Once()
	mockDB.On("UserLoadPermissions", mock.Anything, mock.Anything, user).Return(nil).Once()
	mockDB.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(nil).Once()
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "api").Return(resource, nil).Once()
	mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(1)).Return(permissions, nil).Once()
	mockPermissionChecker.On("UserHasScopePermission", mock.Anything, int64(1), "api:read").Return(false, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	assert.Nil(t, result)
	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "invalid_scope", customErr.GetCode())
	assert.Contains(t, customErr.GetDescription(), "does not have permission")
	assert.Equal(t, 400, customErr.GetHttpStatusCode())
}

// The two rejections ROPC reaches before the user's own permissions are consulted: a resource that
// does not exist, and a permission that does not exist on a resource that does. Each description is
// asserted in full rather than by substring, because ROPC's wording is not the authorize endpoint's
// for the same outcome - "is not recognized ... doesn't grant" here against "is invalid ... does not
// have" there - and the shared resolver behind all three sites (#124) returns an outcome precisely
// so each site keeps its own text. A resolver that grew a message would show up here first.
func TestValidateTokenRequest_ROPC_ResourcePermission_ResolutionFailures(t *testing.T) {
	for _, tc := range []struct {
		name     string
		scope    string
		setup    func(*mocks_data.Database)
		wantDesc string
	}{
		{
			name:  "unknown resource",
			scope: "openid nope-api:read",
			setup: func(mockDB *mocks_data.Database) {
				mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "nope-api").Return(nil, nil).Once()
			},
			wantDesc: "Invalid scope: 'nope-api:read'. Could not find a resource with identifier 'nope-api'.",
		},
		{
			name:  "permission does not exist on the requested resource",
			scope: "openid api:delete",
			setup: func(mockDB *mocks_data.Database) {
				mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "api").
					Return(&models.Resource{Id: 1, ResourceIdentifier: "api"}, nil).Once()
				mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(1)).
					Return([]models.Permission{{Id: 1, PermissionIdentifier: "read", ResourceId: 1}}, nil).Once()
			},
			wantDesc: "Scope 'api:delete' is not recognized. The resource identified by 'api' doesn't grant the 'delete' permission.",
		},
		{
			// The authserver resource has no userinfo permission since #449, so an explicit
			// request for it is refused as any unknown permission is.
			name:  "authserver:userinfo, a permission the authserver resource no longer has",
			scope: "openid authserver:userinfo",
			setup: func(mockDB *mocks_data.Database) {
				builtIns := make([]models.Permission, 0, len(coreconstants.BuiltInAuthServerPermissionIdentifiers))
				for i, identifier := range coreconstants.BuiltInAuthServerPermissionIdentifiers {
					builtIns = append(builtIns, models.Permission{Id: int64(40 + i), PermissionIdentifier: identifier, ResourceId: 4})
				}
				mockDB.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, coreconstants.AuthServerResourceIdentifier).
					Return(&models.Resource{Id: 4, ResourceIdentifier: coreconstants.AuthServerResourceIdentifier}, nil).Once()
				mockDB.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(4)).Return(builtIns, nil).Once()
			},
			wantDesc: "Scope 'authserver:userinfo' is not recognized. The resource identified by 'authserver' doesn't grant the 'userinfo' permission.",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := mocks_data.NewDatabase(t)
			validator := NewTokenValidator(mockDB, mocks_protocolvalidation.NewTokenParser(t), mocks_protocolvalidation.NewPermissionChecker(t), testDataCipher)

			settings := &models.Settings{ResourceOwnerPasswordCredentialsEnabled: true}
			ctx := context.Background()

			passwordHash, _ := passwordhash.Hash("correctpassword")
			user := &models.User{
				Id:           1,
				Email:        "user@example.com",
				PasswordHash: passwordHash,
				Enabled:      true,
			}

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
			tc.setup(mockDB)

			result, err := validator.ValidateTokenRequest(ctx, settings, &ValidateTokenRequestInput{
				GrantType: "password",
				ClientId:  "ropc-client",
				Username:  "user@example.com",
				Password:  "correctpassword",
				Scope:     tc.scope,
			})

			assert.Nil(t, result)
			customErr, ok := err.(*customerrors.ErrorDetail)
			require.True(t, ok, "expected an ErrorDetail, got %v", err)
			assert.Equal(t, "invalid_scope", customErr.GetCode())
			assert.Equal(t, tc.wantDesc, customErr.GetDescription())
			assert.Equal(t, 400, customErr.GetHttpStatusCode())
		})
	}
}
