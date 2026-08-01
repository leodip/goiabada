package validators

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_oauth "github.com/leodip/goiabada/core/oauth/mocks"
	mocks_user "github.com/leodip/goiabada/core/user/mocks"
)

func TestValidateTokenRequest(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

	t.Run("Missing required client_id", func(t *testing.T) {
		input := &ValidateTokenRequestInput{
			GrantType: "authorization_code",
			// ClientId is intentionally left empty
		}

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)
		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_request", customErr.GetCode())
		assert.Equal(t, "Missing required client_id parameter.", customErr.GetDescription())
		assert.Equal(t, 400, customErr.GetHttpStatusCode())
	})

	t.Run("Client does not exist", func(t *testing.T) {
		input := &ValidateTokenRequestInput{
			GrantType: "authorization_code",
			ClientId:  "non_existent_client",
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "non_existent_client").Return(nil, nil)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)
		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_request", customErr.GetCode())
		assert.Equal(t, "Client does not exist.", customErr.GetDescription())
		assert.Equal(t, 400, customErr.GetHttpStatusCode())
	})

	t.Run("Client is disabled", func(t *testing.T) {
		input := &ValidateTokenRequestInput{
			GrantType: "authorization_code",
			ClientId:  "disabled_client",
		}

		disabledClient := &models.Client{
			ClientIdentifier: "disabled_client",
			Enabled:          false,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "disabled_client").Return(disabledClient, nil)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)
		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.GetCode())
		assert.Equal(t, "Client is disabled.", customErr.GetDescription())
		assert.Equal(t, 400, customErr.GetHttpStatusCode())
	})
}

func TestValidateTokenRequest_AuthorizationCode(t *testing.T) {

	t.Run("Authorization code flow not enabled", func(t *testing.T) {

		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType: "authorization_code",
			ClientId:  "client1",
		}

		client := &models.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: false,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "unauthorized_client", customErr.GetCode())
		assert.Equal(t, "The client associated with the provided client_id does not support authorization code flow.", customErr.GetDescription())
		assert.Equal(t, 400, customErr.GetHttpStatusCode())
	})

	t.Run("Missing code parameter", func(t *testing.T) {

		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType: "authorization_code",
			ClientId:  "client1",
			// Code is intentionally left empty
		}

		client := &models.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_request", customErr.GetCode())
		assert.Equal(t, "Missing required code parameter.", customErr.GetDescription())
		assert.Equal(t, 400, customErr.GetHttpStatusCode())
	})

	t.Run("Missing redirect_uri parameter", func(t *testing.T) {

		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType: "authorization_code",
			ClientId:  "client1",
			Code:      "some_code",
			// RedirectURI is intentionally left empty
		}

		client := &models.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_request", customErr.GetCode())
		assert.Equal(t, "Missing required redirect_uri parameter.", customErr.GetDescription())
		assert.Equal(t, 400, customErr.GetHttpStatusCode())
	})

	t.Run("Missing code_verifier parameter when PKCE was used", func(t *testing.T) {
		// Now that PKCE is optional, code_verifier is only required if code_challenge was stored
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:   "authorization_code",
			ClientId:    "client1",
			Code:        "some_code",
			RedirectURI: "https://example.com/callback",
			// CodeVerifier is intentionally left empty
		}

		client := &models.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		// Code has a code_challenge stored, so code_verifier is required
		codeEntity := &models.Code{
			CodeHash:      "hash_of_some_code",
			RedirectURI:   "https://example.com/callback",
			CodeChallenge: sql.NullString{String: "stored_code_challenge", Valid: true},
			Client: models.Client{
				ClientIdentifier: "client1",
			},
			User: models.User{
				Enabled: true,
			},
			CreatedAt: sql.NullTime{
				Time:  time.Now().UTC(),
				Valid: true,
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, codeEntity).Return(nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_request", customErr.GetCode())
		assert.Equal(t, "Missing required code_verifier parameter.", customErr.GetDescription())
		assert.Equal(t, 400, customErr.GetHttpStatusCode())
	})

	t.Run("Invalid code", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "client1",
			Code:         "invalid_code",
			RedirectURI:  "https://example.com/callback",
			CodeVerifier: "code_verifier",
		}

		client := &models.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(nil, nil).Once()
		// Reuse-detection retry: validator now consults used codes too. Both miss = genuinely unknown.
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), true).Return(nil, nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.GetCode())
		assert.Equal(t, "Code is invalid.", customErr.GetDescription())
		assert.Equal(t, 400, customErr.GetHttpStatusCode())
	})

	t.Run("Mismatched redirect URI", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "client1",
			Code:         "valid_code",
			RedirectURI:  "https://example.com/wrong_callback",
			CodeVerifier: "code_verifier",
		}

		client := &models.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		codeEntity := &models.Code{
			CodeHash:    "hash_of_valid_code",
			RedirectURI: "https://example.com/callback",
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.GetCode())
		assert.Equal(t, "Invalid redirect_uri.", customErr.GetDescription())
		assert.Equal(t, 400, customErr.GetHttpStatusCode())
	})

	t.Run("Mismatched client_id", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "client1",
			Code:         "valid_code",
			RedirectURI:  "https://example.com/callback",
			CodeVerifier: "code_verifier",
		}

		client := &models.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		codeEntity := &models.Code{
			CodeHash:    "hash_of_valid_code",
			RedirectURI: "https://example.com/callback",
			Client: models.Client{
				ClientIdentifier: "client2",
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, codeEntity).Return(nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.GetCode())
		assert.Equal(t, "The client_id provided does not match the client_id from code.", customErr.GetDescription())
		assert.Equal(t, 400, customErr.GetHttpStatusCode())
	})

	t.Run("Disabled user", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "client1",
			Code:         "valid_code",
			RedirectURI:  "https://example.com/callback",
			CodeVerifier: "code_verifier",
		}

		client := &models.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		codeEntity := &models.Code{
			CodeHash:    "hash_of_valid_code",
			RedirectURI: "https://example.com/callback",
			Client: models.Client{
				ClientIdentifier: "client1",
			},
			User: models.User{
				Enabled: false,
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, codeEntity).Return(nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.GetCode())
		assert.Equal(t, "The user account is disabled.", customErr.GetDescription())
		assert.Equal(t, 400, customErr.GetHttpStatusCode())
	})

	t.Run("Expired code", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "client1",
			Code:         "valid_code",
			RedirectURI:  "https://example.com/callback",
			CodeVerifier: "code_verifier",
		}

		client := &models.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		codeEntity := &models.Code{
			CodeHash:    "hash_of_valid_code",
			RedirectURI: "https://example.com/callback",
			Client: models.Client{
				ClientIdentifier: "client1",
			},
			User: models.User{
				Enabled: true,
			},
			CreatedAt: sql.NullTime{
				Time:  time.Now().UTC().Add(-2 * time.Minute),
				Valid: true,
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, codeEntity).Return(nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.GetCode())
		assert.Equal(t, "Code has expired.", customErr.GetDescription())
		assert.Equal(t, 400, customErr.GetHttpStatusCode())
	})

	t.Run("Invalid PKCE code verifier", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "client1",
			Code:         "valid_code",
			RedirectURI:  "https://example.com/callback",
			CodeVerifier: "invalid_code_verifier",
		}

		client := &models.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		codeEntity := &models.Code{
			CodeHash:    "hash_of_valid_code",
			RedirectURI: "https://example.com/callback",
			Client: models.Client{
				ClientIdentifier: "client1",
			},
			User: models.User{
				Enabled: true,
			},
			CreatedAt: sql.NullTime{
				Time:  time.Now().UTC(),
				Valid: true,
			},
			CodeChallenge: sql.NullString{String: "valid_code_challenge", Valid: true},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, codeEntity).Return(nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.GetCode())
		assert.Equal(t, "Invalid code_verifier (PKCE).", customErr.GetDescription())
		assert.Equal(t, 400, customErr.GetHttpStatusCode())
	})

	t.Run("Missing client secret for non-public client", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "non_public_client",
			Code:         "valid_code",
			RedirectURI:  "https://example.com/callback",
			CodeVerifier: "code_verifier",
			// ClientSecret is intentionally left empty
		}

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "non_public_client",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 false,
		}

		codeEntity := &models.Code{
			CodeHash:    "hash_of_valid_code",
			RedirectURI: "https://example.com/callback",
			ClientId:    1,
			Client:      *client,
			UserId:      1,
			User: models.User{
				Id:      1,
				Enabled: true,
			},
			CreatedAt: sql.NullTime{
				Time:  time.Now().UTC().Add(-10 * time.Second),
				Valid: true,
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "non_public_client").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, codeEntity).Return(nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		// RFC 6749 Section 5.2: invalid_client for missing client credentials
		assert.Equal(t, "invalid_client", customErr.GetCode())
		assert.Equal(t, "This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed.", customErr.GetDescription())
		assert.Equal(t, http.StatusUnauthorized, customErr.GetHttpStatusCode())
	})

	t.Run("Client authentication failed for non-public client", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "confidential_client",
			Code:         "valid_code",
			RedirectURI:  "https://example.com/callback",
			CodeVerifier: "code_verifier",
			ClientSecret: "incorrect_secret",
		}

		clientSecret := "client_secret"
		clientSecretEncrypted, err := encryption.EncryptData(clientSecret)
		assert.Nil(t, err)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "confidential_client",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    []byte(clientSecretEncrypted),
		}

		codeEntity := &models.Code{
			CodeHash:    "hash_of_valid_code",
			RedirectURI: "https://example.com/callback",
			ClientId:    1,
			Client:      *client,
			UserId:      1,
			User: models.User{
				Id:      1,
				Enabled: true,
			},
			CreatedAt: sql.NullTime{
				Time:  time.Now().UTC().Add(-10 * time.Second),
				Valid: true,
			},
			CodeChallenge: sql.NullString{String: "valid_code_challenge", Valid: true},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "confidential_client").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, codeEntity).Return(nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		// RFC 6749 Section 5.2: invalid_client for failed client authentication
		assert.Equal(t, "invalid_client", customErr.GetCode())
		assert.Equal(t, "Client authentication failed. Please review your client_secret.", customErr.GetDescription())
		assert.Equal(t, http.StatusUnauthorized, customErr.GetHttpStatusCode())
	})

	t.Run("Public client with unnecessary client secret", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "public_client",
			Code:         "valid_code",
			RedirectURI:  "https://example.com/callback",
			CodeVerifier: "code_verifier",
			ClientSecret: "unnecessary_secret", // Public client shouldn't provide this
		}

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "public_client",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		codeEntity := &models.Code{
			CodeHash:    "hash_of_valid_code",
			RedirectURI: "https://example.com/callback",
			ClientId:    1,
			Client:      *client,
			UserId:      1,
			User: models.User{
				Id:      1,
				Enabled: true,
			},
			CreatedAt: sql.NullTime{
				Time:  time.Now().UTC().Add(-10 * time.Second),
				Valid: true,
			},
			CodeChallenge: sql.NullString{String: "valid_code_challenge", Valid: true},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "public_client").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, codeEntity).Return(nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_request", customErr.GetCode())
		assert.Equal(t, "This client is configured as public, which means a client_secret is not required. To proceed, please remove the client_secret from your request.", customErr.GetDescription())
		assert.Equal(t, http.StatusBadRequest, customErr.GetHttpStatusCode())
	})

	t.Run("Valid non-expired code", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "valid_client",
			Code:         "valid_code",
			RedirectURI:  "https://example.com/callback",
			CodeVerifier: "valid_code_verifier",
		}

		client := &models.Client{
			ClientIdentifier:         "valid_client",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		codeEntity := &models.Code{
			CodeHash:    "hash_of_valid_code",
			RedirectURI: "https://example.com/callback",
			Client: models.Client{
				ClientIdentifier: "valid_client",
			},
			User: models.User{
				Enabled: true,
			},
			CreatedAt: sql.NullTime{
				Time:  time.Now().UTC().Add(-30 * time.Second), // Code created 30 seconds ago
				Valid: true,
			},
			CodeChallenge: sql.NullString{String: oauth.GeneratePKCECodeChallenge("valid_code_verifier"), Valid: true},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "valid_client").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, codeEntity).Return(nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, codeEntity, result.CodeEntity)
	})

	t.Run("Public client with valid code verifier", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		codeVerifier := "valid_code_verifier_for_public_client"
		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "public_client",
			Code:         "valid_code_for_public_client",
			RedirectURI:  "https://example.com/public-client/callback",
			CodeVerifier: codeVerifier,
		}

		client := &models.Client{
			ClientIdentifier:         "public_client",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		codeEntity := &models.Code{
			CodeHash:    "hash_of_valid_code_for_public_client",
			RedirectURI: "https://example.com/public-client/callback",
			Client: models.Client{
				ClientIdentifier: "public_client",
			},
			User: models.User{
				Enabled: true,
			},
			CreatedAt: sql.NullTime{
				Time:  time.Now().UTC().Add(-30 * time.Second),
				Valid: true,
			},
			CodeChallenge:       sql.NullString{String: oauth.GeneratePKCECodeChallenge(codeVerifier), Valid: true},
			CodeChallengeMethod: sql.NullString{String: "S256", Valid: true},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "public_client").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, codeEntity).Return(nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, codeEntity, result.CodeEntity)
		assert.True(t, client.IsPublic)
		assert.Empty(t, input.ClientSecret, "Public client should not provide a client secret")
	})
}

// TestValidateTokenRequest_AuthCodeReuse exercises the auth-code reuse detection
// path. Reuse must only surface as AuthCodeReusedError after the request fully
// authenticates against the previously-used code (correct redirect_uri,
// client_id, client_secret/PKCE). Auth-gate failures must NOT produce the
// sentinel: an attacker observing a code on the wire could otherwise force
// session revocation by replaying it with wrong credentials.
func TestValidateTokenRequest_AuthCodeReuse(t *testing.T) {

	// reusedCodeFixture builds a Code entity that simulates a previously-used
	// code: the validator's first GetCodeByCodeHash(used=false) call returns
	// nil, the retry GetCodeByCodeHash(used=true) returns this entity, and
	// the auth gate runs against it.
	reusedCodeFixture := func(client *models.Client, withPKCE bool) *models.Code {
		c := &models.Code{
			Id:          42,
			CodeHash:    "hash_of_reused_code",
			RedirectURI: "https://example.com/callback",
			ClientId:    client.Id,
			Client:      *client,
			UserId:      1,
			User: models.User{
				Id:      1,
				Enabled: true,
			},
			// Intentionally older than the 60s expiration window so we can
			// verify the expiration check is GATED on !wasReused.
			CreatedAt: sql.NullTime{
				Time:  time.Now().UTC().Add(-10 * time.Minute),
				Valid: true,
			},
			SessionIdentifier: "session-abc",
		}
		if withPKCE {
			// SHA256 of "code_verifier" base64url-encoded.
			c.CodeChallenge = sql.NullString{
				String: oauth.GeneratePKCECodeChallenge("code_verifier"),
				Valid:  true,
			}
		}
		return c
	}

	t.Run("Reuse with correct credentials returns AuthCodeReusedError sentinel (public client + PKCE)", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "client1",
			Code:         "reused_code",
			RedirectURI:  "https://example.com/callback",
			CodeVerifier: "code_verifier",
		}

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		codeEntity := reusedCodeFixture(client, true)

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(nil, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), true).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, codeEntity).Return(nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		reused, ok := err.(*customerrors.AuthCodeReusedError)
		assert.True(t, ok, "expected *AuthCodeReusedError sentinel, got %T", err)
		assert.NotNil(t, reused.Code)
		assert.Equal(t, codeEntity.Id, reused.Code.Id)
		assert.Equal(t, "session-abc", reused.Code.SessionIdentifier)
		assert.NotNil(t, reused.Detail)
		assert.Equal(t, "invalid_grant", reused.Detail.GetCode())
		assert.Equal(t, "Code is invalid.", reused.Detail.GetDescription())
		assert.Equal(t, http.StatusBadRequest, reused.Detail.GetHttpStatusCode())
	})

	t.Run("Reuse with correct credentials returns sentinel (confidential client + correct secret)", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		clientSecret := "the_secret"
		clientSecretEncrypted, err := encryption.EncryptData(clientSecret)
		assert.Nil(t, err)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "confidential_client",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    []byte(clientSecretEncrypted),
		}

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "confidential_client",
			Code:         "reused_code",
			RedirectURI:  "https://example.com/callback",
			ClientSecret: clientSecret, // correct
		}

		codeEntity := reusedCodeFixture(client, false)

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "confidential_client").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(nil, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), true).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, codeEntity).Return(nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		reused, ok := err.(*customerrors.AuthCodeReusedError)
		assert.True(t, ok, "expected *AuthCodeReusedError sentinel, got %T", err)
		assert.Equal(t, codeEntity.Id, reused.Code.Id)
	})

	t.Run("Reuse with disabled user still returns sentinel (User.Enabled gated on !wasReused)", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "client1",
			Code:         "reused_code",
			RedirectURI:  "https://example.com/callback",
			CodeVerifier: "code_verifier",
		}

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		codeEntity := reusedCodeFixture(client, true)
		codeEntity.User.Enabled = false // would normally trigger ErrUserDisabled

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(nil, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), true).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, codeEntity).Return(nil).Once()

		_, err := validator.ValidateTokenRequest(ctx, input)

		_, ok := err.(*customerrors.AuthCodeReusedError)
		assert.True(t, ok, "expected sentinel even with disabled user; user-state checks must be skipped on reuse path. got %T", err)
	})

	t.Run("Reuse with wrong client_id does NOT produce sentinel", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		// Attacker's client_id matches what they're submitting, but the code
		// was issued to a different client.
		attackerClient := &models.Client{
			Id:                       2,
			ClientIdentifier:         "attacker_client",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}
		victimClient := &models.Client{
			Id:                       1,
			ClientIdentifier:         "victim_client",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "attacker_client",
			Code:         "reused_code",
			RedirectURI:  "https://example.com/callback",
			CodeVerifier: "code_verifier",
		}

		codeEntity := reusedCodeFixture(victimClient, true)

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "attacker_client").Return(attackerClient, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(nil, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), true).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, codeEntity).Return(nil).Once()

		_, err := validator.ValidateTokenRequest(ctx, input)

		_, isSentinel := err.(*customerrors.AuthCodeReusedError)
		assert.False(t, isSentinel, "wrong client_id must not yield revocation sentinel")
		detail, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", detail.GetCode())
		assert.Contains(t, detail.GetDescription(), "client_id")
	})

	t.Run("Reuse with wrong redirect_uri does NOT produce sentinel", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "client1",
			Code:         "reused_code",
			RedirectURI:  "https://attacker.example.com/callback",
			CodeVerifier: "code_verifier",
		}

		codeEntity := reusedCodeFixture(client, true)

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(nil, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), true).Return(codeEntity, nil).Once()

		_, err := validator.ValidateTokenRequest(ctx, input)

		_, isSentinel := err.(*customerrors.AuthCodeReusedError)
		assert.False(t, isSentinel, "wrong redirect_uri must not yield revocation sentinel")
		detail, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", detail.GetCode())
		assert.Equal(t, "Invalid redirect_uri.", detail.GetDescription())
	})

	t.Run("Reuse with confidential client and missing client_secret does NOT produce sentinel", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		clientSecret := "the_secret"
		clientSecretEncrypted, err := encryption.EncryptData(clientSecret)
		assert.Nil(t, err)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "confidential_client",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    []byte(clientSecretEncrypted),
		}

		input := &ValidateTokenRequestInput{
			GrantType:   "authorization_code",
			ClientId:    "confidential_client",
			Code:        "reused_code",
			RedirectURI: "https://example.com/callback",
			// ClientSecret intentionally missing
		}

		codeEntity := reusedCodeFixture(client, false)

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "confidential_client").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(nil, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), true).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, codeEntity).Return(nil).Once()

		_, err = validator.ValidateTokenRequest(ctx, input)

		_, isSentinel := err.(*customerrors.AuthCodeReusedError)
		assert.False(t, isSentinel, "missing client_secret must not yield revocation sentinel")
		detail, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_client", detail.GetCode())
	})

	t.Run("Reuse with confidential client and wrong client_secret does NOT produce sentinel", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		clientSecret := "the_secret"
		clientSecretEncrypted, err := encryption.EncryptData(clientSecret)
		assert.Nil(t, err)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "confidential_client",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    []byte(clientSecretEncrypted),
		}

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "confidential_client",
			Code:         "reused_code",
			RedirectURI:  "https://example.com/callback",
			ClientSecret: "wrong_secret",
		}

		codeEntity := reusedCodeFixture(client, false)

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "confidential_client").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(nil, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), true).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, codeEntity).Return(nil).Once()

		_, err = validator.ValidateTokenRequest(ctx, input)

		_, isSentinel := err.(*customerrors.AuthCodeReusedError)
		assert.False(t, isSentinel, "wrong client_secret must not yield revocation sentinel")
		detail, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_client", detail.GetCode())
	})

	t.Run("Reuse with wrong PKCE code_verifier does NOT produce sentinel", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "client1",
			Code:         "reused_code",
			RedirectURI:  "https://example.com/callback",
			CodeVerifier: "wrong_verifier",
		}

		codeEntity := reusedCodeFixture(client, true)

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(nil, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), true).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, codeEntity).Return(nil).Once()

		_, err := validator.ValidateTokenRequest(ctx, input)

		_, isSentinel := err.(*customerrors.AuthCodeReusedError)
		assert.False(t, isSentinel, "wrong code_verifier must not yield revocation sentinel")
		detail, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", detail.GetCode())
		assert.Equal(t, "Invalid code_verifier (PKCE).", detail.GetDescription())
	})

	t.Run("Code-not-found (truly unknown) returns plain invalid_grant, not sentinel", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "client1",
			Code:         "totally_unknown_code",
			RedirectURI:  "https://example.com/callback",
			CodeVerifier: "code_verifier",
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(nil, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), true).Return(nil, nil).Once()

		_, err := validator.ValidateTokenRequest(ctx, input)

		_, isSentinel := err.(*customerrors.AuthCodeReusedError)
		assert.False(t, isSentinel, "unknown code must not yield revocation sentinel")
		detail, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", detail.GetCode())
		assert.Equal(t, "Code is invalid.", detail.GetDescription())
	})
}

func TestValidateTokenRequest_ClientCredentials(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

	settings := &models.Settings{}
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	t.Run("Client credentials flow not enabled", func(t *testing.T) {
		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "client1",
			ClientSecret: "secret",
		}

		client := &models.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			ClientCredentialsEnabled: false,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "unauthorized_client", customErr.GetCode())
		assert.Equal(t, "The client associated with the provided client_id does not support client credentials flow.", customErr.GetDescription())
		assert.Equal(t, 400, customErr.GetHttpStatusCode())
	})

	t.Run("Public client not eligible for client credentials", func(t *testing.T) {
		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "client1",
			ClientSecret: "secret",
		}

		client := &models.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			IsPublic:                 true,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "unauthorized_client", customErr.GetCode())
		assert.Equal(t, "A public client is not eligible for the client credentials flow. Please review the client configuration.", customErr.GetDescription())
		assert.Equal(t, 400, customErr.GetHttpStatusCode())
	})

	t.Run("Missing client secret", func(t *testing.T) {
		input := &ValidateTokenRequestInput{
			GrantType: "client_credentials",
			ClientId:  "client1",
			// ClientSecret is intentionally left empty
		}

		client := &models.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			IsPublic:                 false,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		// RFC 6749 Section 5.2: invalid_client for missing client credentials
		assert.Equal(t, "invalid_client", customErr.GetCode())
		assert.Equal(t, "This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed.", customErr.GetDescription())
		assert.Equal(t, http.StatusUnauthorized, customErr.GetHttpStatusCode())
	})

	t.Run("Valid client credentials request", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "valid_client",
			ClientSecret: "valid_secret",
			Scope:        "resource:permission",
		}

		clientSecret := "valid_secret"
		clientSecretEncrypted, _ := encryption.EncryptData(clientSecret)

		client := &models.Client{
			ClientIdentifier:         "valid_client",
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
			// Ids are load-bearing: ownership is decided by resource-scoped permission id,
			// so a fixture leaving them zero matches every other zero and passes whether the
			// check is right, wrong, or absent. Do not tidy these back to bare identifiers.
			Permissions: []models.Permission{{Id: 10, PermissionIdentifier: "permission", ResourceId: 1}},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "valid_client").Return(client, nil)
		mockDB.On("ClientLoadPermissions", mock.Anything, client).Return(nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, mock.AnythingOfType("[]models.Permission")).Return(nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "resource").Return(&models.Resource{Id: 1, ResourceIdentifier: "resource"}, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return([]models.Permission{{Id: 10, PermissionIdentifier: "permission", ResourceId: 1}}, nil)

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, client, result.Client)
		assert.Equal(t, "resource:permission", result.Scope)
	})

	t.Run("Invalid client secret", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "valid_client",
			ClientSecret: "invalid_secret",
		}

		clientSecret := "valid_secret"
		clientSecretEncrypted, _ := encryption.EncryptData(clientSecret)

		client := &models.Client{
			ClientIdentifier:         "valid_client",
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "valid_client").Return(client, nil)

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_client", customErr.GetCode())
		assert.Equal(t, "Client authentication failed.", customErr.GetDescription())
	})

	t.Run("Valid scope", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "valid_client",
			ClientSecret: "valid_secret",
			Scope:        "resource1:read resource2:write",
		}

		clientSecret := "valid_secret"
		clientSecretEncrypted, _ := encryption.EncryptData(clientSecret)

		client := &models.Client{
			ClientIdentifier:         "valid_client",
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
			// Ids are load-bearing, see "Valid client credentials request" above.
			Permissions: []models.Permission{
				{Id: 10, PermissionIdentifier: "read", ResourceId: 1},
				{Id: 20, PermissionIdentifier: "write", ResourceId: 2},
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "valid_client").Return(client, nil)
		mockDB.On("ClientLoadPermissions", mock.Anything, client).Return(nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, mock.AnythingOfType("[]models.Permission")).Return(nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "resource1").Return(&models.Resource{Id: 1, ResourceIdentifier: "resource1"}, nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "resource2").Return(&models.Resource{Id: 2, ResourceIdentifier: "resource2"}, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return([]models.Permission{{Id: 10, PermissionIdentifier: "read", ResourceId: 1}}, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(2)).Return([]models.Permission{{Id: 20, PermissionIdentifier: "write", ResourceId: 2}}, nil)

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "resource1:read resource2:write", result.Scope)
	})

	t.Run("Invalid scope format", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "valid_client",
			ClientSecret: "valid_secret",
			Scope:        "invalid_scope",
		}

		clientSecret := "valid_secret"
		clientSecretEncrypted, _ := encryption.EncryptData(clientSecret)

		client := &models.Client{
			ClientIdentifier:         "valid_client",
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "valid_client").Return(client, nil)
		mockDB.On("ClientLoadPermissions", mock.Anything, client).Return(nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, mock.AnythingOfType("[]models.Permission")).Return(nil)

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_scope", customErr.GetCode())
		assert.Contains(t, customErr.GetDescription(), "Invalid scope format")
	})

	t.Run("Scope not granted to client", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "valid_client",
			ClientSecret: "valid_secret",
			Scope:        "resource:read",
		}

		clientSecret := "valid_secret"
		clientSecretEncrypted, _ := encryption.EncryptData(clientSecret)

		client := &models.Client{
			ClientIdentifier:         "valid_client",
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
			Permissions:              []models.Permission{}, // Empty permissions
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "valid_client").Return(client, nil)
		mockDB.On("ClientLoadPermissions", mock.Anything, client).Return(nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, mock.AnythingOfType("[]models.Permission")).Return(nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "resource").Return(&models.Resource{Id: 1, ResourceIdentifier: "resource"}, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return([]models.Permission{{PermissionIdentifier: "read"}}, nil)

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_scope", customErr.GetCode())
		assert.Contains(t, customErr.GetDescription(), "Permission to access scope 'resource:read' is not granted to the client")
	})

	t.Run("ID token scope in client credentials", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "valid_client",
			ClientSecret: "valid_secret",
			Scope:        "openid profile",
		}

		clientSecret := "valid_secret"
		clientSecretEncrypted, _ := encryption.EncryptData(clientSecret)

		client := &models.Client{
			ClientIdentifier:         "valid_client",
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "valid_client").Return(client, nil)
		mockDB.On("ClientLoadPermissions", mock.Anything, client).Return(nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, mock.AnythingOfType("[]models.Permission")).Return(nil)

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_request", customErr.GetCode())
		assert.Contains(t, customErr.GetDescription(), "Id token scopes (such as 'openid') are not supported in the client credentials flow")
	})

	t.Run("Non-existent resource in scope", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "valid_client",
			ClientSecret: "valid_secret",
			Scope:        "non_existent_resource:read",
		}

		clientSecret := "valid_secret"
		clientSecretEncrypted, _ := encryption.EncryptData(clientSecret)

		client := &models.Client{
			ClientIdentifier:         "valid_client",
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "valid_client").Return(client, nil)
		mockDB.On("ClientLoadPermissions", mock.Anything, client).Return(nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, mock.AnythingOfType("[]models.Permission")).Return(nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "non_existent_resource").Return(nil, nil)

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_scope", customErr.GetCode())
		assert.Contains(t, customErr.GetDescription(), "Could not find a resource with identifier 'non_existent_resource'")
	})

	t.Run("Non-existent permission in scope", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "valid_client",
			ClientSecret: "valid_secret",
			Scope:        "resource:non_existent_permission",
		}

		clientSecret := "valid_secret"
		clientSecretEncrypted, _ := encryption.EncryptData(clientSecret)

		client := &models.Client{
			ClientIdentifier:         "valid_client",
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "valid_client").Return(client, nil)
		mockDB.On("ClientLoadPermissions", mock.Anything, client).Return(nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, mock.AnythingOfType("[]models.Permission")).Return(nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "resource").Return(&models.Resource{Id: 1, ResourceIdentifier: "resource"}, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return([]models.Permission{}, nil)

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_scope", customErr.GetCode())
		assert.Contains(t, customErr.GetDescription(), "The resource identified by 'resource' doesn't grant the 'non_existent_permission' permission")
	})

	t.Run("Multiple valid scopes", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "valid_client",
			ClientSecret: "valid_secret",
			Scope:        "resource1:read resource2:write resource3:delete",
		}

		clientSecret := "valid_secret"
		clientSecretEncrypted, _ := encryption.EncryptData(clientSecret)

		client := &models.Client{
			ClientIdentifier:         "valid_client",
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
			// Ids are load-bearing, see "Valid client credentials request" above.
			Permissions: []models.Permission{
				{Id: 10, PermissionIdentifier: "read", ResourceId: 1},
				{Id: 20, PermissionIdentifier: "write", ResourceId: 2},
				{Id: 30, PermissionIdentifier: "delete", ResourceId: 3},
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "valid_client").Return(client, nil)
		mockDB.On("ClientLoadPermissions", mock.Anything, client).Return(nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, mock.AnythingOfType("[]models.Permission")).Return(nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "resource1").Return(&models.Resource{Id: 1, ResourceIdentifier: "resource1"}, nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "resource2").Return(&models.Resource{Id: 2, ResourceIdentifier: "resource2"}, nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "resource3").Return(&models.Resource{Id: 3, ResourceIdentifier: "resource3"}, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return([]models.Permission{{Id: 10, PermissionIdentifier: "read", ResourceId: 1}}, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(2)).Return([]models.Permission{{Id: 20, PermissionIdentifier: "write", ResourceId: 2}}, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(3)).Return([]models.Permission{{Id: 30, PermissionIdentifier: "delete", ResourceId: 3}}, nil)

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "resource1:read resource2:write resource3:delete", result.Scope)
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
		billingRead      = models.Permission{Id: 10, PermissionIdentifier: "read", ResourceId: 1}
		billingManage    = models.Permission{Id: 12, PermissionIdentifier: "manage", ResourceId: 1}
		reportsRead      = models.Permission{Id: 20, PermissionIdentifier: "read", ResourceId: 2}
		archiveRead      = models.Permission{Id: 30, PermissionIdentifier: "read", ResourceId: 3}
		authserverManage = models.Permission{Id: 40, PermissionIdentifier: "manage", ResourceId: 4}
	)

	ccSecretEncrypted, _ := encryption.EncryptData("valid_secret")

	// Registered with .Maybe() because each case reaches only the lookups its own
	// scope string requires, and the assertion that matters is the outcome rather
	// than the call set. The two error-propagation subtests below register their own.
	registerCatalog := func(mockDB *mocks_data.Database) {
		for _, r := range []struct {
			identifier string
			id         int64
			perms      []models.Permission
		}{
			{"billing-api", 1, []models.Permission{billingRead, billingManage}},
			{"reports-api", 2, []models.Permission{reportsRead}},
			{"archive-api", 3, []models.Permission{archiveRead}},
			{"authserver", 4, []models.Permission{authserverManage}},
		} {
			mockDB.On("GetResourceByResourceIdentifier", mock.Anything, r.identifier).
				Return(&models.Resource{Id: r.id, ResourceIdentifier: r.identifier}, nil).Maybe()
			mockDB.On("GetPermissionsByResourceId", mock.Anything, r.id).Return(r.perms, nil).Maybe()
		}
		// Anything not in the catalog resolves to nil, exercising the not-found branch.
		for _, unknown := range []string{"nope-api", ""} {
			mockDB.On("GetResourceByResourceIdentifier", mock.Anything, unknown).Return(nil, nil).Maybe()
		}
	}

	// runCC drives one client credentials request against the catalog above.
	// wantCode == "" means the request must be accepted with scope wantScope.
	runCC := func(t *testing.T, clientPerms []models.Permission, scope, wantCode, wantDesc, wantScope string) {
		t.Helper()

		mockDB := mocks_data.NewDatabase(t)
		validator := NewTokenValidator(mockDB, mocks_oauth.NewTokenParser(t), mocks_user.NewPermissionChecker(t))

		client := &models.Client{
			ClientIdentifier:         "cc_client",
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    ccSecretEncrypted,
			Permissions:              clientPerms,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "cc_client").Return(client, nil)
		mockDB.On("ClientLoadPermissions", mock.Anything, client).Return(nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, mock.AnythingOfType("[]models.Permission")).Return(nil)
		registerCatalog(mockDB)

		result, err := validator.ValidateTokenRequest(ctx, &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "cc_client",
			ClientSecret: "valid_secret",
			Scope:        scope,
		})

		if wantCode == "" {
			assert.NoError(t, err)
			if assert.NotNil(t, result) {
				assert.Equal(t, wantScope, result.Scope)
			}
			return
		}

		assert.Nil(t, result)
		customErr, ok := err.(*customerrors.ErrorDetail)
		if !assert.True(t, ok, "expected *customerrors.ErrorDetail, got %T: %v", err, err) {
			return
		}
		assert.Equal(t, wantCode, customErr.GetCode())
		assert.Contains(t, customErr.GetDescription(), wantDesc)
	}

	ownershipCases := []struct {
		name        string
		clientPerms []models.Permission
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
			clientPerms: []models.Permission{billingRead},
			scope:       "reports-api:read",
			wantCode:    "invalid_scope",
			wantDesc:    "Permission to access scope 'reports-api:read' is not granted to the client.",
		},
		{
			name:        "same-resource read is allowed",
			clientPerms: []models.Permission{billingRead},
			scope:       "billing-api:read",
			wantScope:   "billing-api:read",
		},
		{
			name:        "cross-resource read is denied in the other direction",
			clientPerms: []models.Permission{reportsRead},
			scope:       "billing-api:read",
			wantCode:    "invalid_scope",
			wantDesc:    "Permission to access scope 'billing-api:read' is not granted to the client.",
		},
		{
			name:        "holding the identifier on two other resources does not help",
			clientPerms: []models.Permission{billingRead, archiveRead},
			scope:       "reports-api:read",
			wantCode:    "invalid_scope",
			wantDesc:    "Permission to access scope 'reports-api:read' is not granted to the client.",
		},
		// These two differ only in ordering. A short-circuit that accepted the whole
		// request on the first granted scope would pass one and fail the other.
		{
			name:        "a denied scope after a granted one is still denied",
			clientPerms: []models.Permission{billingRead},
			scope:       "billing-api:read reports-api:read",
			wantCode:    "invalid_scope",
			wantDesc:    "Permission to access scope 'reports-api:read' is not granted to the client.",
		},
		{
			name:        "a denied scope before a granted one is still denied",
			clientPerms: []models.Permission{billingRead},
			scope:       "reports-api:read billing-api:read",
			wantCode:    "invalid_scope",
			wantDesc:    "Permission to access scope 'reports-api:read' is not granted to the client.",
		},
		// The escalation the issue is really about: "manage" on a custom resource must
		// not reach the built-in "manage" on the system authserver resource, which is
		// full Admin API access.
		{
			name:        "custom manage does not reach authserver manage",
			clientPerms: []models.Permission{billingManage},
			scope:       "authserver:manage",
			wantCode:    "invalid_scope",
			wantDesc:    "Permission to access scope 'authserver:manage' is not granted to the client.",
		},
		{
			// Not redundant with "same-resource read is allowed": this is the grant
			// administrative tooling depends on, and it stops the case above passing
			// for the wrong reason.
			name:        "a genuine authserver manage grant still works",
			clientPerms: []models.Permission{authserverManage},
			scope:       "authserver:manage",
			wantScope:   "authserver:manage",
		},
		// Deduping (added in a later stage) must not be able to launder a denied
		// scope. Diverges from the old behaviour for two independent reasons at once,
		// so keep it even if deduping is ever reverted.
		{
			name:        "a repeated cross-resource scope is denied",
			clientPerms: []models.Permission{billingRead},
			scope:       "reports-api:read reports-api:read",
			wantCode:    "invalid_scope",
			wantDesc:    "Permission to access scope 'reports-api:read' is not granted to the client.",
		},
		// Paths that return before ownership is decided. These do not change
		// behaviour; they pin every early exit now that ownership depends on ids
		// resolved from the requested resource.
		{
			name:        "unknown resource",
			clientPerms: []models.Permission{billingRead},
			scope:       "nope-api:read",
			wantCode:    "invalid_scope",
			wantDesc:    "Could not find a resource with identifier 'nope-api'",
		},
		{
			name:        "permission does not exist on the requested resource",
			clientPerms: []models.Permission{billingRead},
			scope:       "billing-api:delete",
			wantCode:    "invalid_scope",
			wantDesc:    "doesn't grant the 'delete' permission",
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
			clientPerms: []models.Permission{billingRead},
			scope:       "billing-api:read:extra",
			wantCode:    "invalid_scope",
			wantDesc:    "Invalid scope format",
		},
		{
			name:        "empty permission part",
			clientPerms: []models.Permission{billingRead},
			scope:       "billing-api:",
			wantCode:    "invalid_scope",
			wantDesc:    "doesn't grant the '' permission",
		},
		{
			name:        "empty resource part",
			clientPerms: []models.Permission{billingRead},
			scope:       ":read",
			wantCode:    "invalid_scope",
			wantDesc:    "Could not find a resource with identifier ''",
		},
		{
			name:        "only colons",
			clientPerms: []models.Permission{billingRead},
			scope:       "::",
			wantCode:    "invalid_scope",
			wantDesc:    "Invalid scope format",
		},
		{
			name:        "no colon at all",
			clientPerms: []models.Permission{billingRead},
			scope:       "billing-api",
			wantCode:    "invalid_scope",
			wantDesc:    "Invalid scope format",
		},
		{
			name:        "openid is rejected for this grant",
			clientPerms: []models.Permission{billingRead},
			scope:       "openid",
			wantCode:    "invalid_request",
			wantDesc:    "are not supported in the client credentials flow",
		},
		{
			name:        "offline_access is rejected for this grant",
			clientPerms: []models.Permission{billingRead},
			scope:       "offline_access",
			wantCode:    "invalid_request",
			wantDesc:    "are not supported in the client credentials flow",
		},
		{
			name:        "an OIDC scope alongside a granted one is still rejected",
			clientPerms: []models.Permission{billingRead},
			scope:       "openid billing-api:read",
			wantCode:    "invalid_request",
			wantDesc:    "are not supported in the client credentials flow",
		},
		// The next two look inconsistent and are correct. IsIdTokenScope is an exact
		// slices.Contains, so "OPENID" is not recognized as an OIDC scope and falls
		// through to the format check; IsOfflineAccessScope uses strings.EqualFold, so
		// "OFFLINE_ACCESS" is recognized. Keep both: they document a real asymmetry
		// between two adjacent helpers that otherwise reads as a typo.
		{
			name:        "uppercase OPENID falls through to the format check",
			clientPerms: []models.Permission{billingRead},
			scope:       "OPENID",
			wantCode:    "invalid_scope",
			wantDesc:    "Invalid scope format",
		},
		{
			name:        "uppercase OFFLINE_ACCESS is recognized and rejected",
			clientPerms: []models.Permission{billingRead},
			scope:       "OFFLINE_ACCESS",
			wantCode:    "invalid_request",
			wantDesc:    "are not supported in the client credentials flow",
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
		setup func(*mocks_data.Database)
	}{
		{
			name: "GetResourceByResourceIdentifier error propagates",
			setup: func(mockDB *mocks_data.Database) {
				mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "billing-api").
					Return(nil, errors.New("database is down"))
			},
		},
		{
			name: "GetPermissionsByResourceId error propagates",
			setup: func(mockDB *mocks_data.Database) {
				mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "billing-api").
					Return(&models.Resource{Id: 1, ResourceIdentifier: "billing-api"}, nil)
				mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).
					Return(nil, errors.New("database is down"))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := mocks_data.NewDatabase(t)
			validator := NewTokenValidator(mockDB, mocks_oauth.NewTokenParser(t), mocks_user.NewPermissionChecker(t))

			client := &models.Client{
				ClientIdentifier:         "cc_client",
				Enabled:                  true,
				ClientCredentialsEnabled: true,
				IsPublic:                 false,
				ClientSecretEncrypted:    ccSecretEncrypted,
				Permissions:              []models.Permission{billingRead},
			}

			mockDB.On("GetClientByClientIdentifier", mock.Anything, "cc_client").Return(client, nil)
			mockDB.On("ClientLoadPermissions", mock.Anything, client).Return(nil)
			mockDB.On("PermissionsLoadResources", mock.Anything, mock.AnythingOfType("[]models.Permission")).Return(nil)
			tc.setup(mockDB)

			result, err := validator.ValidateTokenRequest(ctx, &ValidateTokenRequestInput{
				GrantType:    "client_credentials",
				ClientId:     "cc_client",
				ClientSecret: "valid_secret",
				Scope:        "billing-api:read",
			})

			assert.Nil(t, result)
			assert.EqualError(t, err, "database is down")
			_, isErrorDetail := err.(*customerrors.ErrorDetail)
			assert.False(t, isErrorDetail, "a database failure must not be reported as an OAuth error")
		})
	}
}

func TestValidateTokenRequest_RefreshToken_AuthCodeDisabled(t *testing.T) {
	t.Run("Client with authorization code flow disabled", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			RefreshToken: "some_refresh_token",
		}

		client := &models.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: false,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "unauthorized_client", customErr.GetCode())
		assert.Equal(t, "The client associated with the provided client_id does not support authorization code flow.", customErr.GetDescription())
		assert.Equal(t, http.StatusBadRequest, customErr.GetHttpStatusCode())
	})

	t.Run("Missing client secret for confidential client", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "confidential_client",
			RefreshToken: "some_refresh_token",
			// ClientSecret is intentionally left empty
		}

		client := &models.Client{
			ClientIdentifier:         "confidential_client",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 false,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "confidential_client").Return(client, nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		// RFC 6749 Section 5.2: invalid_client for missing client credentials
		assert.Equal(t, "invalid_client", customErr.GetCode())
		assert.Equal(t, "This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed.", customErr.GetDescription())
		assert.Equal(t, http.StatusUnauthorized, customErr.GetHttpStatusCode())
	})

	t.Run("Incorrect client secret for confidential client", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "confidential_client",
			RefreshToken: "some_refresh_token",
			ClientSecret: "incorrect_secret",
		}

		correctSecret := "correct_secret"
		encryptedSecret, _ := encryption.EncryptData(correctSecret)

		client := &models.Client{
			ClientIdentifier:         "confidential_client",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    encryptedSecret,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "confidential_client").Return(client, nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		// RFC 6749 Section 5.2: invalid_client for failed client authentication
		assert.Equal(t, "invalid_client", customErr.GetCode())
		assert.Equal(t, "Client authentication failed. Please review your client_secret.", customErr.GetDescription())
		assert.Equal(t, http.StatusUnauthorized, customErr.GetHttpStatusCode())
	})

	t.Run("Missing refresh token", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType: "refresh_token",
			ClientId:  "client1",
			// RefreshToken is intentionally left empty
		}

		client := &models.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true, // Using a public client to bypass client secret check
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_request", customErr.GetCode())
		assert.Equal(t, "Missing required refresh_token parameter.", customErr.GetDescription())
		assert.Equal(t, http.StatusBadRequest, customErr.GetHttpStatusCode())
	})

	t.Run("Invalid refresh token", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			RefreshToken: "invalid_refresh_token",
		}

		client := &models.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()
		mockTokenParser.On("DecodeAndValidateTokenString", "invalid_refresh_token", (*rsa.PublicKey)(nil), true).
			Return(nil, errors.New("token is expired")).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.GetCode())
		assert.Equal(t, "The refresh token is invalid (token is expired).", customErr.GetDescription())
		assert.Equal(t, http.StatusBadRequest, customErr.GetHttpStatusCode())
	})

	t.Run("Refresh token without JTI claim", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			RefreshToken: "refresh_token_without_jti",
		}

		client := &models.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()

		// Mock a JwtToken without a JTI claim
		mockJwtToken := &oauth.JwtToken{}
		mockTokenParser.On("DecodeAndValidateTokenString", "refresh_token_without_jti", (*rsa.PublicKey)(nil), true).
			Return(mockJwtToken, nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "the refresh token is invalid because it does not contain a jti claim")
	})

	t.Run("Refresh token not found in database", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			RefreshToken: "non_existent_refresh_token",
		}

		client := &models.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()

		mockJwtToken := &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"jti": "non_existent_jti",
			},
		}
		mockTokenParser.On("DecodeAndValidateTokenString", "non_existent_refresh_token", (*rsa.PublicKey)(nil), true).
			Return(mockJwtToken, nil).Once()
		mockDB.On("GetRefreshTokenByJti", (*sql.Tx)(nil), "non_existent_jti").Return(nil, nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)

		// UPDATED DELIBERATELY, not a stale assertion: this used to be a plain error,
		// which JsonError maps to a 500. A validly signed refresh token with no row is
		// an invalid grant, not a server fault (RFC 6749 Section 5.2, #128).
		detail, ok := err.(*customerrors.ErrorDetail)
		require.Truef(t, ok, "a missing refresh token row must be an ErrorDetail, got %T", err)
		assert.Equal(t, "invalid_grant", detail.GetCode())
		assert.Equal(t, http.StatusBadRequest, detail.GetHttpStatusCode())

		// The message must NOT reveal that the row was missing, since that would
		// distinguish a never-issued JTI from a revoked one.
		assert.Equal(t, "The refresh token is invalid.", detail.GetDescription())
		assert.NotContains(t, detail.GetDescription(), "database")
	})

	t.Run("Refresh token with mismatched client", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{
			UserSessionIdleTimeoutInSeconds: 3600,
			UserSessionMaxLifetimeInSeconds: 86400,
		}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			RefreshToken: "mismatched_refresh_token",
		}

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		refreshTokenJwt := &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"jti": "mismatched_jti",
				"typ": "Refresh",
			},
		}

		refreshToken := &models.RefreshToken{
			RefreshTokenJti: "mismatched_jti",
			CodeId:          sql.NullInt64{Int64: 1, Valid: true}, // Auth code flow token
			Code: models.Code{
				ClientId: 2, // Different client ID
				User: models.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", "mismatched_refresh_token", (*rsa.PublicKey)(nil), true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, "mismatched_jti").Return(refreshToken, nil)
		mockDB.On("RefreshTokenLoadCode", mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, &refreshToken.Code).Return(nil)

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_request", customErr.GetCode())
		assert.Contains(t, customErr.GetDescription(), "The refresh token is invalid because it does not belong to the client")
	})

	t.Run("Refresh token for disabled user", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{
			UserSessionIdleTimeoutInSeconds: 3600,
			UserSessionMaxLifetimeInSeconds: 86400,
		}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			RefreshToken: "disabled_user_refresh_token",
		}

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		refreshTokenJwt := &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"jti": "disabled_user_jti",
				"typ": "Refresh",
			},
		}

		refreshToken := &models.RefreshToken{
			RefreshTokenJti: "disabled_user_jti",
			CodeId:          sql.NullInt64{Int64: 1, Valid: true}, // Auth code flow token
			Code: models.Code{
				ClientId: 1,
				User: models.User{
					Id:      1,
					Enabled: false, // User is disabled
				},
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", "disabled_user_refresh_token", (*rsa.PublicKey)(nil), true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, "disabled_user_jti").Return(refreshToken, nil)
		mockDB.On("RefreshTokenLoadCode", mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, &refreshToken.Code).Return(nil)

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.GetCode())
		assert.Equal(t, "The user account is disabled.", customErr.GetDescription())
		assert.Equal(t, http.StatusBadRequest, customErr.GetHttpStatusCode())
	})

	t.Run("Refresh token with nil session", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{
			UserSessionIdleTimeoutInSeconds: 3600,
			UserSessionMaxLifetimeInSeconds: 86400,
		}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			RefreshToken: "nil_session_refresh_token",
		}

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		refreshTokenJwt := &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"jti": "nil_session_jti",
				"typ": "Refresh",
			},
		}

		refreshToken := &models.RefreshToken{
			RefreshTokenJti:   "nil_session_jti",
			SessionIdentifier: "non_existent_session",
			CodeId:            sql.NullInt64{Int64: 1, Valid: true}, // Auth code flow token
			Code: models.Code{
				ClientId: 1,
				User: models.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", "nil_session_refresh_token", (*rsa.PublicKey)(nil), true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, "nil_session_jti").Return(refreshToken, nil)
		mockDB.On("RefreshTokenLoadCode", mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, &refreshToken.Code).Return(nil)
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "non_existent_session").Return(nil, nil)

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.GetCode())
		assert.Equal(t, "The refresh token is invalid because the associated session has expired or been terminated.", customErr.GetDescription())
		assert.Equal(t, http.StatusBadRequest, customErr.GetHttpStatusCode())
	})

	t.Run("Refresh token with invalid session", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{
			UserSessionIdleTimeoutInSeconds: 3600,
			UserSessionMaxLifetimeInSeconds: 86400,
		}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			RefreshToken: "invalid_session_refresh_token",
		}

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		refreshTokenJwt := &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"jti": "invalid_session_jti",
				"typ": "Refresh",
			},
		}

		refreshToken := &models.RefreshToken{
			RefreshTokenJti:   "invalid_session_jti",
			SessionIdentifier: "expired_session",
			CodeId:            sql.NullInt64{Int64: 1, Valid: true}, // Auth code flow token
			Code: models.Code{
				ClientId: 1,
				User: models.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		expiredSession := &models.UserSession{
			SessionIdentifier: "expired_session",
			Started:           time.Now().UTC().Add(-48 * time.Hour), // Started 2 days ago
			LastAccessed:      time.Now().UTC().Add(-25 * time.Hour), // Last accessed 25 hours ago
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", "invalid_session_refresh_token", (*rsa.PublicKey)(nil), true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, "invalid_session_jti").Return(refreshToken, nil)
		mockDB.On("RefreshTokenLoadCode", mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, &refreshToken.Code).Return(nil)
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "expired_session").Return(expiredSession, nil)

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.GetCode())
		assert.Equal(t, "The refresh token is invalid because the associated session has expired or been terminated.", customErr.GetDescription())
		assert.Equal(t, http.StatusBadRequest, customErr.GetHttpStatusCode())
	})

	t.Run("Expired offline refresh token", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			RefreshToken: "expired_offline_refresh_token",
		}

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		pastTime := time.Now().UTC().Add(-24 * time.Hour)
		refreshTokenJwt := &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"jti":                         "expired_offline_jti",
				"typ":                         "Offline",
				"offline_access_max_lifetime": float64(pastTime.Unix()),
			},
		}

		refreshToken := &models.RefreshToken{
			RefreshTokenJti: "expired_offline_jti",
			CodeId:          sql.NullInt64{Int64: 1, Valid: true}, // Auth code flow token
			Code: models.Code{
				ClientId: 1,
				User: models.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", "expired_offline_refresh_token", (*rsa.PublicKey)(nil), true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, "expired_offline_jti").Return(refreshToken, nil)
		mockDB.On("RefreshTokenLoadCode", mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, &refreshToken.Code).Return(nil)

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.GetCode())
		assert.Equal(t, "The refresh token is invalid because it has expired (offline_access_max_lifetime).", customErr.GetDescription())
		assert.Equal(t, http.StatusBadRequest, customErr.GetHttpStatusCode())
	})

	t.Run("Offline refresh token without max lifetime claim", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			RefreshToken: "invalid_offline_refresh_token",
		}

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		refreshTokenJwt := &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"jti": "invalid_offline_jti",
				"typ": "Offline",
				// offline_access_max_lifetime claim is missing
			},
		}

		refreshToken := &models.RefreshToken{
			RefreshTokenJti: "invalid_offline_jti",
			CodeId:          sql.NullInt64{Int64: 1, Valid: true}, // Auth code flow token
			Code: models.Code{
				ClientId: 1,
				User: models.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", "invalid_offline_refresh_token", (*rsa.PublicKey)(nil), true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, "invalid_offline_jti").Return(refreshToken, nil)
		mockDB.On("RefreshTokenLoadCode", mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, &refreshToken.Code).Return(nil)

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "the refresh token is invalid because it does not contain an offline_access_max_lifetime claim")
	})

	t.Run("Refresh token with invalid typ claim", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			RefreshToken: "invalid_typ_refresh_token",
		}

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		refreshTokenJwt := &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"jti": "invalid_typ_jti",
				"typ": "InvalidType", // Invalid typ claim
			},
		}

		refreshToken := &models.RefreshToken{
			RefreshTokenJti: "invalid_typ_jti",
			CodeId:          sql.NullInt64{Int64: 1, Valid: true}, // Auth code flow token
			Code: models.Code{
				ClientId: 1,
				User: models.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", "invalid_typ_refresh_token", (*rsa.PublicKey)(nil), true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, "invalid_typ_jti").Return(refreshToken, nil)
		mockDB.On("RefreshTokenLoadCode", mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, &refreshToken.Code).Return(nil)

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "the refresh token is invalid because it does not contain a valid typ claim")
	})

	t.Run("Refresh token with scope not in original grant", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{
			UserSessionIdleTimeoutInSeconds: 3600,
			UserSessionMaxLifetimeInSeconds: 86400,
		}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			RefreshToken: "invalid_scope_refresh_token",
			Scope:        "openid profile email address", // 'address' is not in original scopes
		}

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		refreshTokenJwt := &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"jti": "invalid_scope_jti",
				"typ": "Refresh",
			},
		}

		refreshToken := &models.RefreshToken{
			RefreshTokenJti:   "invalid_scope_jti",
			SessionIdentifier: "test_session",
			CodeId:            sql.NullInt64{Int64: 1, Valid: true}, // Auth code flow token
			Code: models.Code{
				ClientId: 1,
				Scope:    "openid profile email", // Original scopes
				User: models.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		userSession := &models.UserSession{
			SessionIdentifier: "test_session",
			Started:           time.Now().UTC().Add(-30 * time.Minute),
			LastAccessed:      time.Now().UTC().Add(-5 * time.Minute),
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", "invalid_scope_refresh_token", (*rsa.PublicKey)(nil), true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, "invalid_scope_jti").Return(refreshToken, nil)
		mockDB.On("RefreshTokenLoadCode", mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, &refreshToken.Code).Return(nil)
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "test_session").Return(userSession, nil)

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.GetCode())
		assert.Contains(t, customErr.GetDescription(), "Scope 'address' is not recognized")
		assert.Equal(t, http.StatusBadRequest, customErr.GetHttpStatusCode())
	})

	t.Run("Valid offline refresh token", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			RefreshToken: "valid_offline_refresh_token",
		}

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
			ConsentRequired:          true,
		}

		futureTime := time.Now().UTC().Add(24 * time.Hour)
		refreshTokenJwt := &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"jti":                         "valid_offline_jti",
				"typ":                         "Offline",
				"offline_access_max_lifetime": float64(futureTime.Unix()),
				"sub":                         "user123",
			},
		}

		refreshToken := &models.RefreshToken{
			RefreshTokenJti: "valid_offline_jti",
			CodeId:          sql.NullInt64{Int64: 1, Valid: true}, // Auth code flow token
			Code: models.Code{
				ClientId: 1,
				UserId:   1,
				Scope:    "openid profile email offline_access",
				User: models.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		userConsent := &models.UserConsent{
			UserId:   1,
			ClientId: 1,
			Scope:    "openid profile email offline_access",
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", "valid_offline_refresh_token", (*rsa.PublicKey)(nil), true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, "valid_offline_jti").Return(refreshToken, nil)
		mockDB.On("RefreshTokenLoadCode", mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, &refreshToken.Code).Return(nil)
		mockDB.On("GetUserBySubject", mock.Anything, "user123").Return(&models.User{Id: 1, Enabled: true}, nil)
		mockDB.On("GetConsentByUserIdAndClientId", mock.Anything, int64(1), int64(1)).Return(userConsent, nil)

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, refreshToken, result.RefreshToken)
		assert.Equal(t, refreshTokenJwt, result.RefreshTokenInfo)
	})

	t.Run("Consent is looked up once for a multi-scope refresh", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			RefreshToken: "valid_offline_refresh_token",
		}

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
			ConsentRequired:          true,
		}

		futureTime := time.Now().UTC().Add(24 * time.Hour)
		refreshTokenJwt := &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"jti":                         "valid_offline_jti",
				"typ":                         "Offline",
				"offline_access_max_lifetime": float64(futureTime.Unix()),
				"sub":                         "user123",
			},
		}

		refreshToken := &models.RefreshToken{
			RefreshTokenJti: "valid_offline_jti",
			CodeId:          sql.NullInt64{Int64: 1, Valid: true},
			Code: models.Code{
				ClientId: 1,
				UserId:   1,
				Scope:    "openid profile email offline_access",
				User: models.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		userConsent := &models.UserConsent{
			UserId:   1,
			ClientId: 1,
			Scope:    "openid profile email offline_access",
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", "valid_offline_refresh_token", (*rsa.PublicKey)(nil), true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, "valid_offline_jti").Return(refreshToken, nil)
		mockDB.On("RefreshTokenLoadCode", mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, &refreshToken.Code).Return(nil)
		mockDB.On("GetUserBySubject", mock.Anything, "user123").Return(&models.User{Id: 1, Enabled: true}, nil)
		// The refresh carries four scopes; the consent lookup must run once, not once per scope.
		mockDB.On("GetConsentByUserIdAndClientId", mock.Anything, int64(1), int64(1)).Return(userConsent, nil).Times(1)

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		mockDB.AssertNumberOfCalls(t, "GetConsentByUserIdAndClientId", 1)
	})

	t.Run("Valid refresh token with reduced scope", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{
			UserSessionIdleTimeoutInSeconds: 3600,
			UserSessionMaxLifetimeInSeconds: 86400,
		}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			RefreshToken: "valid_refresh_token",
			Scope:        "openid srv1:read", // Reduced scope (should be allowed)
		}

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		refreshTokenJwt := &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"jti": "valid_refresh_jti",
				"typ": "Refresh",
				"sub": "user123",
			},
		}

		refreshToken := &models.RefreshToken{
			RefreshTokenJti:   "valid_refresh_jti",
			SessionIdentifier: "test_session",
			CodeId:            sql.NullInt64{Int64: 1, Valid: true}, // Auth code flow token
			Code: models.Code{
				ClientId: 1,
				UserId:   1,
				Scope:    "openid srv1:read srv1:write", // Original scope
				User: models.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		userSession := &models.UserSession{
			SessionIdentifier: "test_session",
			Started:           time.Now().UTC().Add(-30 * time.Minute),
			LastAccessed:      time.Now().UTC().Add(-5 * time.Minute),
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", "valid_refresh_token", (*rsa.PublicKey)(nil), true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, "valid_refresh_jti").Return(refreshToken, nil)
		mockDB.On("RefreshTokenLoadCode", mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, &refreshToken.Code).Return(nil)
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "test_session").Return(userSession, nil)
		mockDB.On("GetUserBySubject", mock.Anything, "user123").Return(&models.User{Id: 1, Enabled: true}, nil)
		mockPermissionChecker.On("UserHasScopePermission", int64(1), "srv1:read").Return(true, nil)

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, refreshToken, result.RefreshToken)
		assert.Equal(t, refreshTokenJwt, result.RefreshTokenInfo)
		assert.Equal(t, "openid srv1:read srv1:write", result.CodeEntity.Scope)
	})

	t.Run("Refresh token with revoked consent", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{
			UserSessionIdleTimeoutInSeconds: 3600,
			UserSessionMaxLifetimeInSeconds: 86400,
		}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			RefreshToken: "revoked_consent_refresh_token",
		}

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
			ConsentRequired:          true,
		}

		refreshTokenJwt := &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"jti": "revoked_consent_jti",
				"typ": "Refresh",
				"sub": "user123",
			},
		}

		refreshToken := &models.RefreshToken{
			RefreshTokenJti:   "revoked_consent_jti",
			SessionIdentifier: "test_session",
			CodeId:            sql.NullInt64{Int64: 1, Valid: true}, // Auth code flow token
			Code: models.Code{
				ClientId: 1,
				UserId:   1,
				Scope:    "openid profile email",
				User: models.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		userSession := &models.UserSession{
			SessionIdentifier: "test_session",
			Started:           time.Now().UTC().Add(-30 * time.Minute),
			LastAccessed:      time.Now().UTC().Add(-5 * time.Minute),
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", "revoked_consent_refresh_token", (*rsa.PublicKey)(nil), true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, "revoked_consent_jti").Return(refreshToken, nil)
		mockDB.On("RefreshTokenLoadCode", mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, &refreshToken.Code).Return(nil)
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "test_session").Return(userSession, nil)
		mockDB.On("GetUserBySubject", mock.Anything, "user123").Return(&models.User{Id: 1, Enabled: true}, nil)
		mockDB.On("GetConsentByUserIdAndClientId", mock.Anything, int64(1), int64(1)).Return(nil, nil) // Consent not found

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.GetCode())
		assert.Contains(t, customErr.GetDescription(), "The user has either not given consent to this client or the previously granted consent has been revoked")
		assert.Equal(t, http.StatusBadRequest, customErr.GetHttpStatusCode())
	})

	t.Run("Refresh token with a scope missing from the consent", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{
			UserSessionIdleTimeoutInSeconds: 3600,
			UserSessionMaxLifetimeInSeconds: 86400,
		}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			RefreshToken: "partial_consent_refresh_token",
		}

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
			ConsentRequired:          true,
		}

		refreshTokenJwt := &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"jti": "partial_consent_jti",
				"typ": "Refresh",
				"sub": "user123",
			},
		}

		refreshToken := &models.RefreshToken{
			RefreshTokenJti:   "partial_consent_jti",
			SessionIdentifier: "test_session",
			CodeId:            sql.NullInt64{Int64: 1, Valid: true},
			Code: models.Code{
				ClientId: 1,
				UserId:   1,
				Scope:    "openid profile email",
				User: models.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		userSession := &models.UserSession{
			SessionIdentifier: "test_session",
			Started:           time.Now().UTC().Add(-30 * time.Minute),
			LastAccessed:      time.Now().UTC().Add(-5 * time.Minute),
		}

		// The user consented to openid and profile, but no longer to email.
		userConsent := &models.UserConsent{
			UserId:   1,
			ClientId: 1,
			Scope:    "openid profile",
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", "partial_consent_refresh_token", (*rsa.PublicKey)(nil), true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, "partial_consent_jti").Return(refreshToken, nil)
		mockDB.On("RefreshTokenLoadCode", mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, &refreshToken.Code).Return(nil)
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "test_session").Return(userSession, nil)
		mockDB.On("GetUserBySubject", mock.Anything, "user123").Return(&models.User{Id: 1, Enabled: true}, nil)
		mockDB.On("GetConsentByUserIdAndClientId", mock.Anything, int64(1), int64(1)).Return(userConsent, nil)

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.GetCode())
		assert.Contains(t, customErr.GetDescription(), "The user has not consented to the 'email' permission")
		assert.Equal(t, http.StatusBadRequest, customErr.GetHttpStatusCode())
	})

	t.Run("Refresh token with revoked user permission", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

		settings := &models.Settings{
			UserSessionIdleTimeoutInSeconds: 3600,
			UserSessionMaxLifetimeInSeconds: 86400,
		}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			RefreshToken: "revoked_permission_refresh_token",
		}

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		refreshTokenJwt := &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"jti": "revoked_permission_jti",
				"typ": "Refresh",
				"sub": "user123",
			},
		}

		refreshToken := &models.RefreshToken{
			RefreshTokenJti:   "revoked_permission_jti",
			SessionIdentifier: "test_session",
			CodeId:            sql.NullInt64{Int64: 1, Valid: true}, // Auth code flow token
			Code: models.Code{
				ClientId: 1,
				UserId:   1,
				Scope:    "openid profile email resource:read",
				User: models.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		userSession := &models.UserSession{
			SessionIdentifier: "test_session",
			Started:           time.Now().UTC().Add(-30 * time.Minute),
			LastAccessed:      time.Now().UTC().Add(-5 * time.Minute),
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", "revoked_permission_refresh_token", (*rsa.PublicKey)(nil), true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, "revoked_permission_jti").Return(refreshToken, nil)
		mockDB.On("RefreshTokenLoadCode", mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, &refreshToken.Code).Return(nil)
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "test_session").Return(userSession, nil)
		mockDB.On("GetUserBySubject", mock.Anything, "user123").Return(&models.User{Id: 1, Enabled: true}, nil)
		mockPermissionChecker.On("UserHasScopePermission", int64(1), "resource:read").Return(false, nil) // Permission revoked

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.GetCode())
		assert.Contains(t, customErr.GetDescription(), "The user does not have the 'resource:read' permission")
		assert.Equal(t, http.StatusBadRequest, customErr.GetHttpStatusCode())
	})
}

// ============================================================================
// PKCE Optional Tests - Testing the optional PKCE behavior at token endpoint
// ============================================================================

func TestValidateTokenRequest_PKCE_NoPKCEUsed_NoVerifierProvided_Success(t *testing.T) {
	// When PKCE was NOT used during authorization and no code_verifier is provided,
	// the token request should succeed
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

	settings := &models.Settings{}
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	input := &ValidateTokenRequestInput{
		GrantType:    "authorization_code",
		ClientId:     "client1",
		Code:         "valid_code",
		RedirectURI:  "https://example.com/callback",
		CodeVerifier: "", // No code_verifier provided
	}

	client := &models.Client{
		ClientIdentifier:         "client1",
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 true,
	}

	// Code entity has NO code_challenge stored (PKCE was not used)
	codeEntity := &models.Code{
		CodeHash:      "hash_of_valid_code",
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: sql.NullString{Valid: false}, // PKCE was not used
		Client: models.Client{
			ClientIdentifier: "client1",
		},
		User: models.User{
			Enabled: true,
		},
		CreatedAt: sql.NullTime{
			Time:  time.Now().UTC(),
			Valid: true,
		},
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()
	mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
	mockDB.On("CodeLoadClient", mock.Anything, codeEntity).Return(nil).Once()
	mockDB.On("CodeLoadUser", mock.Anything, codeEntity).Return(nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, input)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, codeEntity, result.CodeEntity)
}

func TestValidateTokenRequest_PKCE_NoPKCEUsed_VerifierProvided_Fails(t *testing.T) {
	// When PKCE was NOT used during authorization but code_verifier IS provided,
	// this should fail (strict mode)
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

	settings := &models.Settings{}
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	input := &ValidateTokenRequestInput{
		GrantType:    "authorization_code",
		ClientId:     "client1",
		Code:         "valid_code",
		RedirectURI:  "https://example.com/callback",
		CodeVerifier: "some_code_verifier", // code_verifier provided but PKCE was not used
	}

	client := &models.Client{
		ClientIdentifier:         "client1",
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 true,
	}

	// Code entity has NO code_challenge stored (PKCE was not used)
	codeEntity := &models.Code{
		CodeHash:      "hash_of_valid_code",
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: sql.NullString{Valid: false}, // PKCE was not used
		Client: models.Client{
			ClientIdentifier: "client1",
		},
		User: models.User{
			Enabled: true,
		},
		CreatedAt: sql.NullTime{
			Time:  time.Now().UTC(),
			Valid: true,
		},
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()
	mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
	mockDB.On("CodeLoadClient", mock.Anything, codeEntity).Return(nil).Once()
	mockDB.On("CodeLoadUser", mock.Anything, codeEntity).Return(nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, input)

	assert.Nil(t, result)
	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "invalid_request", customErr.GetCode())
	assert.Equal(t, "The code_verifier parameter was provided, but PKCE was not used during authorization.", customErr.GetDescription())
	assert.Equal(t, http.StatusBadRequest, customErr.GetHttpStatusCode())
}

func TestValidateTokenRequest_PKCE_PKCEUsed_ValidVerifier_Success(t *testing.T) {
	// When PKCE was used during authorization and a valid code_verifier is provided,
	// the token request should succeed
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

	settings := &models.Settings{}
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	codeVerifier := "valid_code_verifier_string_that_is_long_enough"
	expectedCodeChallenge := oauth.GeneratePKCECodeChallenge(codeVerifier)

	input := &ValidateTokenRequestInput{
		GrantType:    "authorization_code",
		ClientId:     "client1",
		Code:         "valid_code",
		RedirectURI:  "https://example.com/callback",
		CodeVerifier: codeVerifier,
	}

	client := &models.Client{
		ClientIdentifier:         "client1",
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 true,
	}

	// Code entity has the code_challenge stored (PKCE was used)
	codeEntity := &models.Code{
		CodeHash:      "hash_of_valid_code",
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: sql.NullString{String: expectedCodeChallenge, Valid: true},
		Client: models.Client{
			ClientIdentifier: "client1",
		},
		User: models.User{
			Enabled: true,
		},
		CreatedAt: sql.NullTime{
			Time:  time.Now().UTC(),
			Valid: true,
		},
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()
	mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
	mockDB.On("CodeLoadClient", mock.Anything, codeEntity).Return(nil).Once()
	mockDB.On("CodeLoadUser", mock.Anything, codeEntity).Return(nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, input)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, codeEntity, result.CodeEntity)
}

func TestValidateTokenRequest_PKCE_PKCEUsed_NoVerifier_Fails(t *testing.T) {
	// When PKCE was used during authorization but no code_verifier is provided,
	// this should fail
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

	settings := &models.Settings{}
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	input := &ValidateTokenRequestInput{
		GrantType:    "authorization_code",
		ClientId:     "client1",
		Code:         "valid_code",
		RedirectURI:  "https://example.com/callback",
		CodeVerifier: "", // No code_verifier provided but PKCE was used
	}

	client := &models.Client{
		ClientIdentifier:         "client1",
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 true,
	}

	// Code entity has the code_challenge stored (PKCE was used)
	codeEntity := &models.Code{
		CodeHash:      "hash_of_valid_code",
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: sql.NullString{String: "stored_code_challenge", Valid: true},
		Client: models.Client{
			ClientIdentifier: "client1",
		},
		User: models.User{
			Enabled: true,
		},
		CreatedAt: sql.NullTime{
			Time:  time.Now().UTC(),
			Valid: true,
		},
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()
	mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
	mockDB.On("CodeLoadClient", mock.Anything, codeEntity).Return(nil).Once()
	mockDB.On("CodeLoadUser", mock.Anything, codeEntity).Return(nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, input)

	assert.Nil(t, result)
	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "invalid_request", customErr.GetCode())
	assert.Equal(t, "Missing required code_verifier parameter.", customErr.GetDescription())
	assert.Equal(t, http.StatusBadRequest, customErr.GetHttpStatusCode())
}

func TestValidateTokenRequest_PKCE_PKCEUsed_WrongVerifier_Fails(t *testing.T) {
	// When PKCE was used during authorization but wrong code_verifier is provided,
	// this should fail
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

	settings := &models.Settings{}
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	// The stored code_challenge was generated from "correct_verifier"
	correctVerifier := "correct_code_verifier_string_that_is_long_enough"
	storedCodeChallenge := oauth.GeneratePKCECodeChallenge(correctVerifier)

	input := &ValidateTokenRequestInput{
		GrantType:    "authorization_code",
		ClientId:     "client1",
		Code:         "valid_code",
		RedirectURI:  "https://example.com/callback",
		CodeVerifier: "wrong_code_verifier_string_that_is_long_enough", // Wrong verifier
	}

	client := &models.Client{
		ClientIdentifier:         "client1",
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 true,
	}

	// Code entity has the code_challenge stored (PKCE was used)
	codeEntity := &models.Code{
		CodeHash:      "hash_of_valid_code",
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: sql.NullString{String: storedCodeChallenge, Valid: true},
		Client: models.Client{
			ClientIdentifier: "client1",
		},
		User: models.User{
			Enabled: true,
		},
		CreatedAt: sql.NullTime{
			Time:  time.Now().UTC(),
			Valid: true,
		},
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()
	mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
	mockDB.On("CodeLoadClient", mock.Anything, codeEntity).Return(nil).Once()
	mockDB.On("CodeLoadUser", mock.Anything, codeEntity).Return(nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, input)

	assert.Nil(t, result)
	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "invalid_grant", customErr.GetCode())
	assert.Equal(t, "Invalid code_verifier (PKCE).", customErr.GetDescription())
	assert.Equal(t, http.StatusBadRequest, customErr.GetHttpStatusCode())
}

func TestValidateTokenRequest_PKCE_EmptyStringCodeChallenge_TreatedAsNoPKCE(t *testing.T) {
	// When code_challenge is an empty string with Valid=true, it should be treated as no PKCE
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

	settings := &models.Settings{}
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	input := &ValidateTokenRequestInput{
		GrantType:    "authorization_code",
		ClientId:     "client1",
		Code:         "valid_code",
		RedirectURI:  "https://example.com/callback",
		CodeVerifier: "", // No code_verifier
	}

	client := &models.Client{
		ClientIdentifier:         "client1",
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 true,
	}

	// Code entity has empty string code_challenge (edge case)
	codeEntity := &models.Code{
		CodeHash:      "hash_of_valid_code",
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: sql.NullString{String: "", Valid: true}, // Empty string, Valid=true
		Client: models.Client{
			ClientIdentifier: "client1",
		},
		User: models.User{
			Enabled: true,
		},
		CreatedAt: sql.NullTime{
			Time:  time.Now().UTC(),
			Valid: true,
		},
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()
	mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
	mockDB.On("CodeLoadClient", mock.Anything, codeEntity).Return(nil).Once()
	mockDB.On("CodeLoadUser", mock.Anything, codeEntity).Return(nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, input)

	// Empty string code_challenge should be treated as no PKCE, so this should succeed
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, codeEntity, result.CodeEntity)
}

// =============================================================================
// ROPC (Resource Owner Password Credentials) Tests - RFC 6749 Section 4.3
// =============================================================================

func TestValidateTokenRequest_ROPC_Success(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	passwordHash, _ := hashutil.HashPassword("correctpassword")
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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "ropc-client").Return(client, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, "user@example.com").Return(user, nil).Once()
	mockDB.On("UserLoadPermissions", mock.Anything, user).Return(nil).Once()
	mockDB.On("UserLoadGroups", mock.Anything, user).Return(nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, input)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, client, result.Client)
	assert.Equal(t, user, result.User)
	assert.Equal(t, "openid", result.Scope)
}

func TestValidateTokenRequest_ROPC_GlobalDisabled(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: false, // Globally disabled
	}
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "ropc-client").Return(client, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, input)

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
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: false, // Globally disabled
	}
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	passwordHash, _ := hashutil.HashPassword("correctpassword")
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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "ropc-client").Return(client, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, "user@example.com").Return(user, nil).Once()
	mockDB.On("UserLoadPermissions", mock.Anything, user).Return(nil).Once()
	mockDB.On("UserLoadGroups", mock.Anything, user).Return(nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, input)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, client, result.Client)
	assert.Equal(t, user, result.User)
}

func TestValidateTokenRequest_ROPC_ClientOverrideDisabled(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true, // Globally enabled
	}
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "ropc-client").Return(client, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, input)

	assert.Nil(t, result)
	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "unauthorized_client", customErr.GetCode())
}

func TestValidateTokenRequest_ROPC_MissingUsername(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "ropc-client").Return(client, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, input)

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
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "ropc-client").Return(client, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, input)

	assert.Nil(t, result)
	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "invalid_request", customErr.GetCode())
	assert.Equal(t, "Missing required password parameter.", customErr.GetDescription())
	assert.Equal(t, 400, customErr.GetHttpStatusCode())
}

func TestValidateTokenRequest_ROPC_UserNotFound(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "ropc-client").Return(client, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, "nonexistent@example.com").Return(nil, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, input)

	assert.Nil(t, result)
	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "invalid_grant", customErr.GetCode())
	assert.Equal(t, "Invalid resource owner credentials.", customErr.GetDescription())
	assert.Equal(t, 400, customErr.GetHttpStatusCode())
}

func TestValidateTokenRequest_ROPC_InvalidPassword(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	passwordHash, _ := hashutil.HashPassword("correctpassword")
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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "ropc-client").Return(client, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, "user@example.com").Return(user, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, input)

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
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	passwordHash, _ := hashutil.HashPassword("correctpassword")
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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "ropc-client").Return(client, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, "user@example.com").Return(user, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, input)

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
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	passwordHash, _ := hashutil.HashPassword("correctpassword")
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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "ropc-client").Return(client, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, "user@example.com").Return(user, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, input)

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
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "ropc-client").Return(client, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, input)

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
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

	encryptedSecret, _ := encryption.EncryptData("correct-secret")

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "ropc-client").Return(client, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, input)

	assert.Nil(t, result)
	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "invalid_client", customErr.GetCode())
	assert.Equal(t, "Client authentication failed.", customErr.GetDescription())
	assert.Equal(t, 401, customErr.GetHttpStatusCode())
}

func TestValidateTokenRequest_ROPC_ConfidentialClient_Success(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

	encryptedSecret, _ := encryption.EncryptData("correct-secret")

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	passwordHash, _ := hashutil.HashPassword("userpassword")
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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "ropc-client").Return(client, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, "user@example.com").Return(user, nil).Once()
	mockDB.On("UserLoadPermissions", mock.Anything, user).Return(nil).Once()
	mockDB.On("UserLoadGroups", mock.Anything, user).Return(nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, input)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, client, result.Client)
	assert.Equal(t, user, result.User)
	assert.Equal(t, "openid profile", result.Scope)
}

func TestValidateTokenRequest_ROPC_EmptyScope_DefaultsToOpenId(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	passwordHash, _ := hashutil.HashPassword("correctpassword")
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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "ropc-client").Return(client, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, "user@example.com").Return(user, nil).Once()
	mockDB.On("UserLoadPermissions", mock.Anything, user).Return(nil).Once()
	mockDB.On("UserLoadGroups", mock.Anything, user).Return(nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, input)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "openid", result.Scope) // Should default to openid
}

func TestValidateTokenRequest_ROPC_WithOfflineAccess(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	passwordHash, _ := hashutil.HashPassword("correctpassword")
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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "ropc-client").Return(client, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, "user@example.com").Return(user, nil).Once()
	mockDB.On("UserLoadPermissions", mock.Anything, user).Return(nil).Once()
	mockDB.On("UserLoadGroups", mock.Anything, user).Return(nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, input)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Contains(t, result.Scope, "offline_access")
}

func TestValidateTokenRequest_ROPC_InvalidScopeFormat(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	passwordHash, _ := hashutil.HashPassword("correctpassword")
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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "ropc-client").Return(client, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, "user@example.com").Return(user, nil).Once()
	mockDB.On("UserLoadPermissions", mock.Anything, user).Return(nil).Once()
	mockDB.On("UserLoadGroups", mock.Anything, user).Return(nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, input)

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
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	passwordHash, _ := hashutil.HashPassword("correctpassword")
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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "ropc-client").Return(client, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, "user@example.com").Return(user, nil).Once()
	mockDB.On("UserLoadPermissions", mock.Anything, user).Return(nil).Once()
	mockDB.On("UserLoadGroups", mock.Anything, user).Return(nil).Once()
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "api").Return(resource, nil).Once()
	mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return(permissions, nil).Once()
	mockPermissionChecker.On("UserHasScopePermission", int64(1), "api:read").Return(true, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, input)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Contains(t, result.Scope, "api:read")
}

func TestValidateTokenRequest_ROPC_ResourcePermission_UserLacksPermission(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

	settings := &models.Settings{
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	passwordHash, _ := hashutil.HashPassword("correctpassword")
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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "ropc-client").Return(client, nil).Once()
	mockDB.On("GetUserByEmail", mock.Anything, "user@example.com").Return(user, nil).Once()
	mockDB.On("UserLoadPermissions", mock.Anything, user).Return(nil).Once()
	mockDB.On("UserLoadGroups", mock.Anything, user).Return(nil).Once()
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "api").Return(resource, nil).Once()
	mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return(permissions, nil).Once()
	mockPermissionChecker.On("UserHasScopePermission", int64(1), "api:read").Return(false, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, input)

	assert.Nil(t, result)
	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "invalid_scope", customErr.GetCode())
	assert.Contains(t, customErr.GetDescription(), "does not have permission")
	assert.Equal(t, 400, customErr.GetHttpStatusCode())
}

// TestValidateTokenRequest_RefreshToken_ROPC_InjectedUserInfoScope covers the ROPC refresh defect
// fixed alongside #104: generateAccessTokenCore appends authserver:userinfo to any token carrying
// an OIDC scope, and the refresh path used to re-check that appended scope against the user's
// permissions, so the server rejected a scope it had injected itself.
//
// These cases hand-build the stored refresh token, which is the only way to express them. After
// the issuer fix no newly issued ROPC refresh token records the injected scope, so the first case
// below is reachable in production only for tokens issued BEFORE the fix, and an integration test
// cannot construct it without writing a refresh token row directly.
func TestValidateTokenRequest_RefreshToken_ROPC_InjectedUserInfoScope(t *testing.T) {
	userInfoScope := constants.AuthServerResourceIdentifier + ":" + constants.UserinfoPermissionIdentifier

	testCases := []struct {
		name string
		// storedScope is RefreshToken.Scope, which for ROPC is what the validator re-checks.
		storedScope string
		// requestedScope is the refresh request's `scope` parameter. Empty means omitted, in which
		// case the validator falls back to storedScope and the two sources it could derive the
		// OIDC-scope condition from are identical. Only a down-scoping request tells them apart.
		requestedScope string
		wantAccepted   bool
	}{
		{
			// A legacy token: the user asked for openid, the server appended the userinfo scope
			// and recorded it. The user holds no permissions, which before the fix was enough to
			// make this fail. Must now succeed, and that is what makes the fix retroactive.
			name:         "injected alongside an OIDC scope is not re-checked",
			storedScope:  "openid " + userInfoScope,
			wantAccepted: true,
		},
		{
			// THE NEGATIVE CONTROL, and the reason the exception is conditional rather than
			// blanket. validateROPCScopes has no guard against requesting authserver:userinfo
			// explicitly, so this scope can be a genuine user grant. With no OIDC scope present
			// nothing was injected, so the permission must still be checked, otherwise revoking it
			// would never take effect on refresh. Do not "simplify" the exception to an
			// unconditional skip: this case is the only thing standing in the way.
			name:         "explicitly granted without an OIDC scope is still re-checked",
			storedScope:  userInfoScope,
			wantAccepted: false,
		},
		{
			// THE ONLY CASE THAT PINS THE CHOICE OF SOURCE for the OIDC-scope condition, which is
			// tokenScope (the original grant) rather than the request's scope. Here they disagree:
			// the grant carries openid, the request does not.
			//
			// Expected to SUCCEED. The grant was OIDC-scoped, so its userinfo scope is injected and
			// unpoliced; refreshing the full scope would inject it into the new access token
			// whatever the user holds, so denying this narrower request would refuse a subset of
			// what the same token can have for the asking.
			//
			// Deriving the condition from the request instead would see no OIDC scope, apply the
			// permission check and reject. The other two rows cannot detect that, because in both
			// the request is omitted and the two sources coincide.
			name:           "legacy grant down-scoped to bare userinfo is not re-checked",
			storedScope:    "openid " + userInfoScope,
			requestedScope: userInfoScope,
			wantAccepted:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := mocks_data.NewDatabase(t)
			mockTokenParser := mocks_oauth.NewTokenParser(t)
			mockPermissionChecker := mocks_user.NewPermissionChecker(t)

			validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)
			ctx := context.WithValue(context.Background(), constants.ContextKeySettings, &models.Settings{})

			input := &ValidateTokenRequestInput{
				GrantType:    "refresh_token",
				ClientId:     "ropc_client",
				RefreshToken: "ropc_refresh_token",
				Scope:        tc.requestedScope,
			}

			client := &models.Client{
				Id:                       1,
				ClientIdentifier:         "ropc_client",
				Enabled:                  true,
				AuthorizationCodeEnabled: true,
				IsPublic:                 true,
			}

			// ROPC refresh tokens are always "Offline": there is no browser session.
			refreshTokenJwt := &oauth.JwtToken{
				Claims: jwt.MapClaims{
					"jti":                         "ropc_jti",
					"typ":                         "Offline",
					"sub":                         "ropc_user_subject",
					"offline_access_max_lifetime": float64(time.Now().UTC().Add(24 * time.Hour).Unix()),
				},
			}

			user := models.User{Id: 7, Enabled: true}

			// CodeId invalid is what marks this a ROPC token (isROPCToken := !refreshToken.CodeId.Valid),
			// which is why the validator reads RefreshToken.Scope rather than Code.Scope.
			refreshToken := &models.RefreshToken{
				RefreshTokenJti: "ropc_jti",
				CodeId:          sql.NullInt64{Valid: false},
				UserId:          sql.NullInt64{Int64: 7, Valid: true},
				ClientId:        sql.NullInt64{Int64: 1, Valid: true},
				Scope:           tc.storedScope,
				User:            user,
				Client:          *client,
			}

			mockDB.On("GetClientByClientIdentifier", mock.Anything, "ropc_client").Return(client, nil)
			mockTokenParser.On("DecodeAndValidateTokenString", "ropc_refresh_token", (*rsa.PublicKey)(nil), true).
				Return(refreshTokenJwt, nil)
			mockDB.On("GetRefreshTokenByJti", mock.Anything, "ropc_jti").Return(refreshToken, nil)
			mockDB.On("RefreshTokenLoadUser", mock.Anything, refreshToken).Return(nil)
			mockDB.On("RefreshTokenLoadClient", mock.Anything, refreshToken).Return(nil)
			mockDB.On("GetUserBySubject", mock.Anything, "ropc_user_subject").Return(&user, nil)

			// The user holds nothing. In the accepted case the scope must never be looked up at
			// all, so no UserHasScopePermission expectation is registered: mocks_user.NewPermissionChecker(t)
			// fails the test if an unexpected call is made, which is what proves the skip happened.
			if !tc.wantAccepted {
				mockPermissionChecker.On("UserHasScopePermission", int64(7), userInfoScope).Return(false, nil)
			}

			result, err := validator.ValidateTokenRequest(ctx, input)

			if tc.wantAccepted {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				return
			}

			assert.Nil(t, result)
			customErr, ok := err.(*customerrors.ErrorDetail)
			if !assert.True(t, ok, "expected *customerrors.ErrorDetail, got %T: %v", err, err) {
				return
			}
			assert.Equal(t, "invalid_grant", customErr.GetCode())
			assert.Contains(t, customErr.GetDescription(),
				fmt.Sprintf("The user does not have the '%v' permission", userInfoScope))
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
	billingResource := models.Resource{Id: 1, ResourceIdentifier: "billing-api"}
	reportsResource := models.Resource{Id: 2, ResourceIdentifier: "reports-api"}

	billingRead := models.Permission{Id: 10, PermissionIdentifier: "read", ResourceId: 1, Resource: billingResource}
	reportsRead := models.Permission{Id: 20, PermissionIdentifier: "read", ResourceId: 2, Resource: reportsResource}

	testCases := []struct {
		name string
		// clientPerms carry a populated Resource, as PermissionsLoadResources would leave them.
		clientPerms []models.Permission
		wantScope   string
		// resourcesLookedUp is what the VALIDATION step then resolves, each expected exactly once.
		resourcesLookedUp []models.Resource
	}{
		{
			// Also confirms the expansion is resource-qualified: a client holding "read" on two
			// resources gets both "billing-api:read" and "reports-api:read", not one of them twice.
			// That distinction started mattering when the ownership check became resource-scoped.
			name:              "the same permission identifier on two resources yields both scopes",
			clientPerms:       []models.Permission{billingRead, reportsRead},
			wantScope:         "billing-api:read reports-api:read",
			resourcesLookedUp: []models.Resource{billingResource, reportsResource},
		},
		{
			// Empty scope short-circuits validateClientCredentialsScopes, so nothing is looked up.
			name:              "a client holding nothing yields an empty scope",
			clientPerms:       nil,
			wantScope:         "",
			resourcesLookedUp: nil,
		},
		{
			name:              "a single grant yields a single scope",
			clientPerms:       []models.Permission{billingRead},
			wantScope:         "billing-api:read",
			resourcesLookedUp: []models.Resource{billingResource},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := mocks_data.NewDatabase(t)
			validator := NewTokenValidator(mockDB, mocks_oauth.NewTokenParser(t), mocks_user.NewPermissionChecker(t))
			ctx := context.WithValue(context.Background(), constants.ContextKeySettings, &models.Settings{})

			clientSecretEncrypted, _ := encryption.EncryptData("valid_secret")
			client := &models.Client{
				ClientIdentifier:         "cc_client",
				Enabled:                  true,
				ClientCredentialsEnabled: true,
				IsPublic:                 false,
				ClientSecretEncrypted:    clientSecretEncrypted,
				Permissions:              tc.clientPerms,
			}

			mockDB.On("GetClientByClientIdentifier", mock.Anything, "cc_client").Return(client, nil)
			mockDB.On("ClientLoadPermissions", mock.Anything, client).Return(nil)
			mockDB.On("PermissionsLoadResources", mock.Anything, mock.AnythingOfType("[]models.Permission")).Return(nil)

			// .Once() is the assertion. Two calls per resource means the expansion is looking
			// resources up again instead of using the association already loaded above.
			for i := range tc.resourcesLookedUp {
				res := tc.resourcesLookedUp[i]
				mockDB.On("GetResourceByResourceIdentifier", mock.Anything, res.ResourceIdentifier).
					Return(&res, nil).Once()
				var perms []models.Permission
				for _, p := range tc.clientPerms {
					if p.ResourceId == res.Id {
						perms = append(perms, p)
					}
				}
				mockDB.On("GetPermissionsByResourceId", mock.Anything, res.Id).Return(perms, nil).Once()
			}

			// Scope deliberately omitted, which is what selects the expansion branch.
			result, err := validator.ValidateTokenRequest(ctx, &ValidateTokenRequestInput{
				GrantType:    "client_credentials",
				ClientId:     "cc_client",
				ClientSecret: "valid_secret",
			})

			assert.NoError(t, err)
			if assert.NotNil(t, result) {
				assert.Equal(t, tc.wantScope, result.Scope)
			}
		})
	}
}

// TestValidateTokenRequest_AuthStateGeneration covers the three places the generation
// boundary is enforced during validation (#106 stage 3). Each is an independent branch, and
// each negative pairs with a matching-generation case so it varies exactly one field.
//
// The auth-code refresh case is the important one. It gives the refresh token and its
// joined code DIFFERENT generations, which is the only assertion that can distinguish
// decision 11(a) from its opposite: reading the code there would reject exactly the tokens
// a self-service password change promoted, which is what decision 4 exists to preserve.
func TestValidateTokenRequest_AuthStateGeneration(t *testing.T) {
	t.Run("authorization code redemption", func(t *testing.T) {
		for _, tc := range []struct {
			name           string
			codeGeneration int64
			userGeneration int64
			wantAccepted   bool
		}{
			{"matching generation is redeemable", 3, 3, true},
			// Varies only the code's generation. A code issued before a credential change
			// cannot be redeemed after it, which is what covers an outstanding code and a
			// ceremony that straddled the change. Neither is reachable by the revocation
			// sweep, since the sweep only sees rows that exist when it runs.
			{"superseded code is rejected", 3, 4, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				mockDB := mocks_data.NewDatabase(t)
				mockTokenParser := mocks_oauth.NewTokenParser(t)
				mockPermissionChecker := mocks_user.NewPermissionChecker(t)
				validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)
				ctx := context.WithValue(context.Background(), constants.ContextKeySettings, &models.Settings{})

				client := &models.Client{
					Id: 1, ClientIdentifier: "test_client", Enabled: true,
					AuthorizationCodeEnabled: true, IsPublic: true,
				}
				code := &models.Code{
					Id: 5, ClientId: 1, UserId: 7,
					RedirectURI:         "https://example.com/cb",
					Scope:               "openid",
					CreatedAt:           sql.NullTime{Time: time.Now().UTC(), Valid: true},
					AuthStateGeneration: tc.codeGeneration,
					Client:              *client,
					User:                models.User{Id: 7, Enabled: true, AuthStateGeneration: tc.userGeneration},
				}

				mockDB.On("GetClientByClientIdentifier", mock.Anything, "test_client").Return(client, nil)
				mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, false).Return(code, nil)
				// No-ops: Client and User are already populated on the fixture above, and the
				// loaders are what the validator calls before reaching the generation check.
				mockDB.On("CodeLoadClient", mock.Anything, code).Return(nil)
				mockDB.On("CodeLoadUser", mock.Anything, code).Return(nil)

				result, err := validator.ValidateTokenRequest(ctx, &ValidateTokenRequestInput{
					GrantType:   "authorization_code",
					ClientId:    "test_client",
					Code:        "the-code",
					RedirectURI: "https://example.com/cb",
				})

				if tc.wantAccepted {
					assert.NoError(t, err)
					assert.NotNil(t, result)
					return
				}
				assert.Nil(t, result)
				customErr, ok := err.(*customerrors.ErrorDetail)
				if assert.True(t, ok, "expected *customerrors.ErrorDetail, got %T: %v", err, err) {
					assert.Equal(t, "invalid_grant", customErr.GetCode())
				}
			})
		}
	})

	t.Run("auth code refresh reads the token row, not the joined code", func(t *testing.T) {
		for _, tc := range []struct {
			name            string
			tokenGeneration int64
			codeGeneration  int64
			userGeneration  int64
			wantAccepted    bool
		}{
			{
				// THE ROW THAT PINS decision 11(a). The token was promoted to 4 while its
				// code stayed at 3, which is exactly the state a self-service password
				// change leaves the preserved session in. Reading the code would reject it.
				name:            "promoted token whose code lags is accepted",
				tokenGeneration: 4, codeGeneration: 3, userGeneration: 4, wantAccepted: true,
			},
			{
				// Varies only the token's generation from the row above.
				name:            "superseded token is rejected even though its code matches",
				tokenGeneration: 3, codeGeneration: 4, userGeneration: 4, wantAccepted: false,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				mockDB := mocks_data.NewDatabase(t)
				mockTokenParser := mocks_oauth.NewTokenParser(t)
				mockPermissionChecker := mocks_user.NewPermissionChecker(t)
				validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)
				ctx := context.WithValue(context.Background(), constants.ContextKeySettings, &models.Settings{
					UserSessionIdleTimeoutInSeconds: 3600,
					UserSessionMaxLifetimeInSeconds: 86400,
				})

				client := &models.Client{
					Id: 1, ClientIdentifier: "test_client", Enabled: true,
					AuthorizationCodeEnabled: true, IsPublic: true,
				}
				user := models.User{Id: 7, Enabled: true, AuthStateGeneration: tc.userGeneration}
				refreshToken := &models.RefreshToken{
					RefreshTokenJti:     "the-jti",
					CodeId:              sql.NullInt64{Int64: 5, Valid: true},
					SessionIdentifier:   "sid-1",
					AuthStateGeneration: tc.tokenGeneration,
					Code: models.Code{
						Id: 5, ClientId: 1, UserId: 7, Scope: "openid",
						SessionIdentifier:   "sid-1",
						AuthStateGeneration: tc.codeGeneration,
						User:                user,
					},
				}

				mockDB.On("GetClientByClientIdentifier", mock.Anything, "test_client").Return(client, nil)
				mockTokenParser.On("DecodeAndValidateTokenString", "the-refresh-token", (*rsa.PublicKey)(nil), true).
					Return(&oauth.JwtToken{Claims: jwt.MapClaims{
						"jti": "the-jti", "typ": "Refresh", "sub": "user_subject",
					}}, nil)
				mockDB.On("GetRefreshTokenByJti", mock.Anything, "the-jti").Return(refreshToken, nil)
				mockDB.On("RefreshTokenLoadCode", mock.Anything, refreshToken).Return(nil)
				mockDB.On("CodeLoadUser", mock.Anything, &refreshToken.Code).Return(nil)

				if tc.wantAccepted {
					now := time.Now().UTC()
					mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "sid-1").
						Return(&models.UserSession{
							Id: 9, SessionIdentifier: "sid-1",
							Started: now.Add(-10 * time.Minute), LastAccessed: now,
						}, nil)
					mockDB.On("GetUserBySubject", mock.Anything, "user_subject").Return(&user, nil)
				}

				result, err := validator.ValidateTokenRequest(ctx, &ValidateTokenRequestInput{
					GrantType:    "refresh_token",
					ClientId:     "test_client",
					RefreshToken: "the-refresh-token",
				})

				if tc.wantAccepted {
					assert.NoError(t, err)
					assert.NotNil(t, result)
					return
				}
				assert.Nil(t, result)
				customErr, ok := err.(*customerrors.ErrorDetail)
				if assert.True(t, ok, "expected *customerrors.ErrorDetail, got %T: %v", err, err) {
					assert.Equal(t, "invalid_grant", customErr.GetCode())
				}
			})
		}
	})

	t.Run("ROPC refresh", func(t *testing.T) {
		// An independent branch: isROPCToken splits on CodeId being invalid, so a single
		// "one refresh case" would have left this uncovered entirely.
		for _, tc := range []struct {
			name            string
			tokenGeneration int64
			userGeneration  int64
			wantAccepted    bool
		}{
			{"matching generation is refreshable", 3, 3, true},
			{"superseded token is rejected", 3, 4, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				mockDB := mocks_data.NewDatabase(t)
				mockTokenParser := mocks_oauth.NewTokenParser(t)
				mockPermissionChecker := mocks_user.NewPermissionChecker(t)
				validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)
				ctx := context.WithValue(context.Background(), constants.ContextKeySettings, &models.Settings{})

				client := &models.Client{
					Id: 1, ClientIdentifier: "ropc_client", Enabled: true,
					AuthorizationCodeEnabled: true, IsPublic: true,
				}
				user := models.User{Id: 7, Enabled: true, AuthStateGeneration: tc.userGeneration}
				refreshToken := &models.RefreshToken{
					RefreshTokenJti:     "ropc_jti",
					CodeId:              sql.NullInt64{Valid: false},
					UserId:              sql.NullInt64{Int64: 7, Valid: true},
					ClientId:            sql.NullInt64{Int64: 1, Valid: true},
					Scope:               "openid",
					AuthStateGeneration: tc.tokenGeneration,
					User:                user,
					Client:              *client,
				}

				mockDB.On("GetClientByClientIdentifier", mock.Anything, "ropc_client").Return(client, nil)
				mockTokenParser.On("DecodeAndValidateTokenString", "ropc_refresh_token", (*rsa.PublicKey)(nil), true).
					Return(&oauth.JwtToken{Claims: jwt.MapClaims{
						"jti": "ropc_jti", "typ": "Offline", "sub": "ropc_user_subject",
						"offline_access_max_lifetime": float64(time.Now().UTC().Add(24 * time.Hour).Unix()),
					}}, nil)
				mockDB.On("GetRefreshTokenByJti", mock.Anything, "ropc_jti").Return(refreshToken, nil)
				mockDB.On("RefreshTokenLoadUser", mock.Anything, refreshToken).Return(nil)
				mockDB.On("RefreshTokenLoadClient", mock.Anything, refreshToken).Return(nil)
				if tc.wantAccepted {
					mockDB.On("GetUserBySubject", mock.Anything, "ropc_user_subject").Return(&user, nil)
				}

				result, err := validator.ValidateTokenRequest(ctx, &ValidateTokenRequestInput{
					GrantType:    "refresh_token",
					ClientId:     "ropc_client",
					RefreshToken: "ropc_refresh_token",
				})

				if tc.wantAccepted {
					assert.NoError(t, err)
					assert.NotNil(t, result)
					return
				}
				assert.Nil(t, result)
				customErr, ok := err.(*customerrors.ErrorDetail)
				if assert.True(t, ok, "expected *customerrors.ErrorDetail, got %T: %v", err, err) {
					assert.Equal(t, "invalid_grant", customErr.GetCode())
				}
			})
		}
	})
}

// TestValidateTokenRequest_RefreshToken_ExpiryPrecedesTheLookup pins the ordering that
// bounds replay containment's horizon: an expired refresh token is refused by the JWT
// expiration check BEFORE its row is ever read (#128).
//
// This lives at the unit tier deliberately, and cannot be moved to integration. An
// integration test observes only the HTTP response, which is an identical 400
// invalid_grant whether or not the lookup ran, so it would pass with the ordering
// reversed. Only a mocked database can assert that GetRefreshTokenByJti was never
// called.
//
// The LOAD-BEARING assertion is the literal `true` in the DecodeAndValidateTokenString
// expectation, which is the expiration check itself. Confirmed by mutation: changing that
// argument to false fails this test on the unmatched expectation. Without it the server
// would accept expired refresh tokens outright.
//
// The AssertNotCalled is weaker than it looks, and worth being honest about. The ordering
// is already forced structurally, since the lookup key is the jti claim read out of the
// parsed token, so the lookup cannot precede the parse. It is kept as a guard against a
// future rewrite that finds the row some other way, not as the thing that proves the
// current ordering.
//
// Why the ordering matters: containment fires on the persisted revoked flag, so if an
// expired token could reach the lookup it could still trigger a family cascade long after
// the protocol stopped accepting it. The horizon is bounded and protocol-defined instead.
func TestValidateTokenRequest_RefreshToken_ExpiryPrecedesTheLookup(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)
	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker)

	settings := &models.Settings{}
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

	input := &ValidateTokenRequestInput{
		GrantType:    "refresh_token",
		ClientId:     "client1",
		RefreshToken: "expired_refresh_token",
	}

	client := &models.Client{
		ClientIdentifier:         "client1",
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 true,
	}
	mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()

	// withExpirationCheck = true is what makes the parser reject an expired token.
	mockTokenParser.On("DecodeAndValidateTokenString", "expired_refresh_token", (*rsa.PublicKey)(nil), true).
		Return(nil, errors.New("token has invalid claims: token is expired")).Once()

	result, err := validator.ValidateTokenRequest(ctx, input)

	assert.Nil(t, result)
	require.Error(t, err)

	detail, ok := err.(*customerrors.ErrorDetail)
	require.Truef(t, ok, "an expired refresh token must be an ErrorDetail, got %T", err)
	assert.Equal(t, "invalid_grant", detail.GetCode())
	assert.Equal(t, http.StatusBadRequest, detail.GetHttpStatusCode())

	// Structurally redundant today, kept as a guard. See the doc comment.
	mockDB.AssertNotCalled(t, "GetRefreshTokenByJti", mock.Anything, mock.Anything)

	mockDB.AssertExpectations(t)
	mockTokenParser.AssertExpectations(t)
}
