package validators

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_oauth "github.com/leodip/goiabada/core/oauth/mocks"
	mocks_user "github.com/leodip/goiabada/core/user/mocks"
)

func TestValidateTokenRequest(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

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

	t.Run("Missing code_verifier parameter", func(t *testing.T) {

		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

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
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil).Once()

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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

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
		mockAuditLogger.On("Log", constants.AuditUserDisabled, mock.Anything).Return().Once()

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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

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
			CodeChallenge: "valid_code_challenge",
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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey: []byte("0123456789abcdef0123456789abcdef"), // 32-byte key for AES-256
		}
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
		assert.Equal(t, "invalid_request", customErr.GetCode())
		assert.Equal(t, "This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed.", customErr.GetDescription())
		assert.Equal(t, http.StatusBadRequest, customErr.GetHttpStatusCode())
	})

	t.Run("Client authentication failed for non-public client", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		aesEncryptionKey := "0123456789abcdef0123456789abcdef"
		settings := &models.Settings{
			AESEncryptionKey: []byte(aesEncryptionKey), // 32-byte key for AES-256
		}
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
		clientSecretEncrypted, err := encryption.EncryptText(clientSecret, []byte(aesEncryptionKey))
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
			CodeChallenge: "valid_code_challenge",
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
		assert.Equal(t, "invalid_grant", customErr.GetCode())
		assert.Equal(t, "Client authentication failed. Please review your client_secret.", customErr.GetDescription())
		assert.Equal(t, http.StatusBadRequest, customErr.GetHttpStatusCode())
	})

	t.Run("Public client with unnecessary client secret", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey: []byte("0123456789abcdef0123456789abcdef"), // 32-byte key for AES-256
		}
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
			CodeChallenge: "valid_code_challenge",
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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

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
			CodeChallenge: oauth.GeneratePKCECodeChallenge("valid_code_verifier"),
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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

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
			CodeChallenge:       oauth.GeneratePKCECodeChallenge(codeVerifier),
			CodeChallengeMethod: "S256",
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

func TestValidateTokenRequest_ClientCredentials(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_oauth.NewTokenParser(t)
	mockPermissionChecker := mocks_user.NewPermissionChecker(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

	settings := &models.Settings{
		AESEncryptionKey: []byte("0123456789abcdef0123456789abcdef"), // 32-byte key for AES-256
	}
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
		assert.Equal(t, "invalid_request", customErr.GetCode())
		assert.Equal(t, "This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed.", customErr.GetDescription())
		assert.Equal(t, 400, customErr.GetHttpStatusCode())
	})

	t.Run("Valid client credentials request", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey: []byte("0123456789abcdef0123456789abcdef"), // 32-byte key for AES-256
		}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "valid_client",
			ClientSecret: "valid_secret",
			Scope:        "resource:permission",
		}

		clientSecret := "valid_secret"
		clientSecretEncrypted, _ := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)

		client := &models.Client{
			ClientIdentifier:         "valid_client",
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
			Permissions:              []models.Permission{{PermissionIdentifier: "permission"}},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "valid_client").Return(client, nil)
		mockDB.On("ClientLoadPermissions", mock.Anything, client).Return(nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, mock.AnythingOfType("[]models.Permission")).Return(nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "resource").Return(&models.Resource{Id: 1, ResourceIdentifier: "resource"}, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return([]models.Permission{{PermissionIdentifier: "permission"}}, nil)

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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
		}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "valid_client",
			ClientSecret: "invalid_secret",
		}

		clientSecret := "valid_secret"
		clientSecretEncrypted, _ := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)

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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
		}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "valid_client",
			ClientSecret: "valid_secret",
			Scope:        "resource1:read resource2:write",
		}

		clientSecret := "valid_secret"
		clientSecretEncrypted, _ := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)

		client := &models.Client{
			ClientIdentifier:         "valid_client",
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
			Permissions:              []models.Permission{{PermissionIdentifier: "read"}, {PermissionIdentifier: "write"}},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "valid_client").Return(client, nil)
		mockDB.On("ClientLoadPermissions", mock.Anything, client).Return(nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, mock.AnythingOfType("[]models.Permission")).Return(nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "resource1").Return(&models.Resource{Id: 1, ResourceIdentifier: "resource1"}, nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "resource2").Return(&models.Resource{Id: 2, ResourceIdentifier: "resource2"}, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return([]models.Permission{{PermissionIdentifier: "read"}}, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(2)).Return([]models.Permission{{PermissionIdentifier: "write"}}, nil)

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "resource1:read resource2:write", result.Scope)
	})

	t.Run("Invalid scope format", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
		}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "valid_client",
			ClientSecret: "valid_secret",
			Scope:        "invalid_scope",
		}

		clientSecret := "valid_secret"
		clientSecretEncrypted, _ := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)

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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
		}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "valid_client",
			ClientSecret: "valid_secret",
			Scope:        "resource:read",
		}

		clientSecret := "valid_secret"
		clientSecretEncrypted, _ := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)

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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
		}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "valid_client",
			ClientSecret: "valid_secret",
			Scope:        "openid profile",
		}

		clientSecret := "valid_secret"
		clientSecretEncrypted, _ := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)

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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
		}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "valid_client",
			ClientSecret: "valid_secret",
			Scope:        "non_existent_resource:read",
		}

		clientSecret := "valid_secret"
		clientSecretEncrypted, _ := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)

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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
		}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "valid_client",
			ClientSecret: "valid_secret",
			Scope:        "resource:non_existent_permission",
		}

		clientSecret := "valid_secret"
		clientSecretEncrypted, _ := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)

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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
		}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "client_credentials",
			ClientId:     "valid_client",
			ClientSecret: "valid_secret",
			Scope:        "resource1:read resource2:write resource3:delete",
		}

		clientSecret := "valid_secret"
		clientSecretEncrypted, _ := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)

		client := &models.Client{
			ClientIdentifier:         "valid_client",
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
			Permissions:              []models.Permission{{PermissionIdentifier: "read"}, {PermissionIdentifier: "write"}, {PermissionIdentifier: "delete"}},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "valid_client").Return(client, nil)
		mockDB.On("ClientLoadPermissions", mock.Anything, client).Return(nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, mock.AnythingOfType("[]models.Permission")).Return(nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "resource1").Return(&models.Resource{Id: 1, ResourceIdentifier: "resource1"}, nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "resource2").Return(&models.Resource{Id: 2, ResourceIdentifier: "resource2"}, nil)
		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "resource3").Return(&models.Resource{Id: 3, ResourceIdentifier: "resource3"}, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return([]models.Permission{{PermissionIdentifier: "read"}}, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(2)).Return([]models.Permission{{PermissionIdentifier: "write"}}, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(3)).Return([]models.Permission{{PermissionIdentifier: "delete"}}, nil)

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "resource1:read resource2:write resource3:delete", result.Scope)
	})
}

func TestValidateTokenRequest_RefreshToken_AuthCodeDisabled(t *testing.T) {
	t.Run("Client with authorization code flow disabled", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
		}
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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
		}
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
		assert.Equal(t, "invalid_request", customErr.GetCode())
		assert.Equal(t, "This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed.", customErr.GetDescription())
		assert.Equal(t, http.StatusBadRequest, customErr.GetHttpStatusCode())
	})

	t.Run("Incorrect client secret for confidential client", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		aesKey := []byte("0123456789abcdef0123456789abcdef")
		settings := &models.Settings{
			AESEncryptionKey: aesKey,
		}
		ctx := context.WithValue(context.Background(), constants.ContextKeySettings, settings)

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "confidential_client",
			RefreshToken: "some_refresh_token",
			ClientSecret: "incorrect_secret",
		}

		correctSecret := "correct_secret"
		encryptedSecret, _ := encryption.EncryptText(correctSecret, aesKey)

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
		assert.Equal(t, "invalid_grant", customErr.GetCode())
		assert.Equal(t, "Client authentication failed. Please review your client_secret.", customErr.GetDescription())
		assert.Equal(t, http.StatusBadRequest, customErr.GetHttpStatusCode())
	})

	t.Run("Missing refresh token", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
		}
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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
		}
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
		mockTokenParser.On("DecodeAndValidateTokenString", ctx, "invalid_refresh_token", (*rsa.PublicKey)(nil)).
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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
		}
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
		mockTokenParser.On("DecodeAndValidateTokenString", ctx, "refresh_token_without_jti", (*rsa.PublicKey)(nil)).
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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
		}
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
		mockTokenParser.On("DecodeAndValidateTokenString", ctx, "non_existent_refresh_token", (*rsa.PublicKey)(nil)).
			Return(mockJwtToken, nil).Once()
		mockDB.On("GetRefreshTokenByJti", (*sql.Tx)(nil), "non_existent_jti").Return(nil, nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "the refresh token is invalid because it does not exist in the database")
	})

	t.Run("Refresh token with mismatched client", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey:                []byte("0123456789abcdef0123456789abcdef"),
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
			Code: models.Code{
				ClientId: 2, // Different client ID
				User: models.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", ctx, "mismatched_refresh_token", (*rsa.PublicKey)(nil)).Return(refreshTokenJwt, nil)
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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey:                []byte("0123456789abcdef0123456789abcdef"),
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
			Code: models.Code{
				ClientId: 1,
				User: models.User{
					Id:      1,
					Enabled: false, // User is disabled
				},
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", ctx, "disabled_user_refresh_token", (*rsa.PublicKey)(nil)).Return(refreshTokenJwt, nil)
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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey:                []byte("0123456789abcdef0123456789abcdef"),
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
			Code: models.Code{
				ClientId: 1,
				User: models.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", ctx, "nil_session_refresh_token", (*rsa.PublicKey)(nil)).Return(refreshTokenJwt, nil)
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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey:                []byte("0123456789abcdef0123456789abcdef"),
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
		mockTokenParser.On("DecodeAndValidateTokenString", ctx, "invalid_session_refresh_token", (*rsa.PublicKey)(nil)).Return(refreshTokenJwt, nil)
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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
		}
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
				"jti": "expired_offline_jti",
				"typ": "Offline",
				//"offline_access_max_lifetime":  pastTime.Unix(),
				"offline_access_max_lifetime": float64(pastTime.Unix()),
			},
		}

		refreshToken := &models.RefreshToken{
			RefreshTokenJti: "expired_offline_jti",
			Code: models.Code{
				ClientId: 1,
				User: models.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", ctx, "expired_offline_refresh_token", (*rsa.PublicKey)(nil)).Return(refreshTokenJwt, nil)
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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
		}
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
			Code: models.Code{
				ClientId: 1,
				User: models.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", ctx, "invalid_offline_refresh_token", (*rsa.PublicKey)(nil)).Return(refreshTokenJwt, nil)
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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
		}
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
			Code: models.Code{
				ClientId: 1,
				User: models.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", ctx, "invalid_typ_refresh_token", (*rsa.PublicKey)(nil)).Return(refreshTokenJwt, nil)
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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey:                []byte("0123456789abcdef0123456789abcdef"),
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
		mockTokenParser.On("DecodeAndValidateTokenString", ctx, "invalid_scope_refresh_token", (*rsa.PublicKey)(nil)).Return(refreshTokenJwt, nil)
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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
		}
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
		mockTokenParser.On("DecodeAndValidateTokenString", ctx, "valid_offline_refresh_token", (*rsa.PublicKey)(nil)).Return(refreshTokenJwt, nil)
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

	t.Run("Valid refresh token with reduced scope", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey:                []byte("0123456789abcdef0123456789abcdef"),
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
		mockTokenParser.On("DecodeAndValidateTokenString", ctx, "valid_refresh_token", (*rsa.PublicKey)(nil)).Return(refreshTokenJwt, nil)
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
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey:                []byte("0123456789abcdef0123456789abcdef"),
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
		mockTokenParser.On("DecodeAndValidateTokenString", ctx, "revoked_consent_refresh_token", (*rsa.PublicKey)(nil)).Return(refreshTokenJwt, nil)
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

	t.Run("Refresh token with revoked user permission", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockPermissionChecker := mocks_user.NewPermissionChecker(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, mockAuditLogger)

		settings := &models.Settings{
			AESEncryptionKey:                []byte("0123456789abcdef0123456789abcdef"),
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
		mockTokenParser.On("DecodeAndValidateTokenString", ctx, "revoked_permission_refresh_token", (*rsa.PublicKey)(nil)).Return(refreshTokenJwt, nil)
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
