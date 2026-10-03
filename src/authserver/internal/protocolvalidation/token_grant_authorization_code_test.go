package protocolvalidation

import (
	"context"
	"database/sql"
	"net/http"
	"testing"
	"time"

	"errors"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_protocolvalidation "github.com/leodip/goiabada/authserver/internal/protocolvalidation/mocks"
)

func TestValidateTokenRequest_AuthorizationCode(t *testing.T) {

	t.Run("Authorization code flow not enabled", func(t *testing.T) {

		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &models.Settings{}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType: "authorization_code",
			ClientId:  "client1",
		}

		client := &models.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: false,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "unauthorized_client", customErr.Code())
		assert.Equal(t, "The client associated with the provided client_id does not support authorization code flow.", customErr.Description())
		assert.Equal(t, 400, customErr.HTTPStatus())
	})

	t.Run("Missing code parameter", func(t *testing.T) {

		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &models.Settings{}
		ctx := context.Background()

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

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_request", customErr.Code())
		assert.Equal(t, "Missing required code parameter.", customErr.Description())
		assert.Equal(t, 400, customErr.HTTPStatus())
	})

	t.Run("Missing redirect_uri parameter", func(t *testing.T) {

		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &models.Settings{}
		ctx := context.Background()

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

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_request", customErr.Code())
		assert.Equal(t, "Missing required redirect_uri parameter.", customErr.Description())
		assert.Equal(t, 400, customErr.HTTPStatus())
	})

	t.Run("Missing code_verifier parameter when PKCE was used", func(t *testing.T) {
		// Now that PKCE is optional, code_verifier is only required if code_challenge was stored
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &models.Settings{}
		ctx := context.Background()

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

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_request", customErr.Code())
		assert.Equal(t, "Missing required code_verifier parameter.", customErr.Description())
		assert.Equal(t, 400, customErr.HTTPStatus())
	})

	t.Run("Invalid code", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &models.Settings{}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "client1",
			Code:         "invalid_code",
			RedirectURI:  "https://example.com/callback",
			CodeVerifier: testCodeVerifier,
		}

		client := &models.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(nil, nil).Once()
		// Reuse-detection retry: validator now consults used codes too. Both miss = genuinely unknown.
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), true).Return(nil, nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.Code())
		assert.Equal(t, "Code is invalid.", customErr.Description())
		assert.Equal(t, 400, customErr.HTTPStatus())
	})

	t.Run("Mismatched redirect URI", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &models.Settings{}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "client1",
			Code:         "valid_code",
			RedirectURI:  "https://example.com/wrong_callback",
			CodeVerifier: testCodeVerifier,
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

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.Code())
		assert.Equal(t, "Invalid redirect_uri.", customErr.Description())
		assert.Equal(t, 400, customErr.HTTPStatus())
	})

	t.Run("Mismatched client_id", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &models.Settings{}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "client1",
			Code:         "valid_code",
			RedirectURI:  "https://example.com/callback",
			CodeVerifier: testCodeVerifier,
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

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.Code())
		assert.Equal(t, "The client_id provided does not match the client_id from code.", customErr.Description())
		assert.Equal(t, 400, customErr.HTTPStatus())
	})

	t.Run("Disabled user", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &models.Settings{}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "client1",
			Code:         "valid_code",
			RedirectURI:  "https://example.com/callback",
			CodeVerifier: testCodeVerifier,
		}

		client := &models.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		// The right verifier, so the request proves it may redeem the code and reaches the
		// user's state, which is read only below PKCE (#137).
		codeEntity := &models.Code{
			CodeHash:      "hash_of_valid_code",
			RedirectURI:   "https://example.com/callback",
			CodeChallenge: sql.NullString{String: oauth.GeneratePKCECodeChallenge(testCodeVerifier), Valid: true},
			Client: models.Client{
				ClientIdentifier: "client1",
			},
			User: models.User{
				Enabled: false,
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		// The flat wording, never one naming the account (#137); the type is what the handler
		// writes AuditUserDisabled from.
		var disabled *UserDisabledError
		require.ErrorAs(t, err, &disabled)
		var customErr *oauth.ErrorDetail
		require.ErrorAs(t, err, &customErr)
		assert.Equal(t, "invalid_grant", customErr.Code())
		assert.Equal(t, "Code is invalid.", customErr.Description())
		assert.Equal(t, 400, customErr.HTTPStatus())
	})

	t.Run("Expired code", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &models.Settings{}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "client1",
			Code:         "valid_code",
			RedirectURI:  "https://example.com/callback",
			CodeVerifier: testCodeVerifier,
		}

		client := &models.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		// The right verifier, as in the disabled-user case above: the age is read only below
		// PKCE (#137).
		codeEntity := &models.Code{
			CodeHash:      "hash_of_valid_code",
			RedirectURI:   "https://example.com/callback",
			CodeChallenge: sql.NullString{String: oauth.GeneratePKCECodeChallenge(testCodeVerifier), Valid: true},
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

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.Code())
		assert.Equal(t, "Code has expired.", customErr.Description())
		assert.Equal(t, 400, customErr.HTTPStatus())
	})

	t.Run("Invalid PKCE code verifier", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &models.Settings{}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "client1",
			Code:         "valid_code",
			RedirectURI:  "https://example.com/callback",
			CodeVerifier: wrongCodeVerifier,
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

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.Code())
		assert.Equal(t, "Invalid code_verifier (PKCE).", customErr.Description())
		assert.Equal(t, 400, customErr.HTTPStatus())
	})

	t.Run("Missing client secret for non-public client", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &models.Settings{}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "non_public_client",
			Code:         "valid_code",
			RedirectURI:  "https://example.com/callback",
			CodeVerifier: testCodeVerifier,
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

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "non_public_client").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()

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

	t.Run("Client authentication failed for non-public client", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &models.Settings{}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "confidential_client",
			Code:         "valid_code",
			RedirectURI:  "https://example.com/callback",
			CodeVerifier: testCodeVerifier,
			ClientSecret: "incorrect_secret",
		}

		clientSecret := "client_secret"
		clientSecretEncrypted, err := testDataCipher.Encrypt(clientSecret)
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

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "confidential_client").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		// RFC 6749 Section 5.2: invalid_client for failed client authentication
		assert.Equal(t, "invalid_client", customErr.Code())
		assert.Equal(t, "Client authentication failed. Please review your client_secret.", customErr.Description())
		assert.Equal(t, http.StatusUnauthorized, customErr.HTTPStatus())
	})

	t.Run("Public client with unnecessary client secret", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &models.Settings{}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "public_client",
			Code:         "valid_code",
			RedirectURI:  "https://example.com/callback",
			CodeVerifier: testCodeVerifier,
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

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "public_client").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_request", customErr.Code())
		assert.Equal(t, "This client is configured as public, which means a client_secret is not required. To proceed, please remove the client_secret from your request.", customErr.Description())
		assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
	})

	t.Run("Valid non-expired code", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &models.Settings{}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "valid_client",
			Code:         "valid_code",
			RedirectURI:  "https://example.com/callback",
			CodeVerifier: testCodeVerifier,
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
			CodeChallenge: sql.NullString{String: oauth.GeneratePKCECodeChallenge(testCodeVerifier), Valid: true},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "valid_client").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
		expectRedirectURIStillRegistered(mockDB, "https://example.com/callback")

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, codeEntity, grantAs[*AuthorizationCodeGrant](t, result).Code)
	})

	t.Run("Public client with valid code verifier", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &models.Settings{}
		ctx := context.Background()

		codeVerifier := testCodeVerifier
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

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "public_client").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
		expectRedirectURIStillRegistered(mockDB, "https://example.com/public-client/callback")

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, codeEntity, grantAs[*AuthorizationCodeGrant](t, result).Code)
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
			// verify the expiration check is read below the wasReused return.
			CreatedAt: sql.NullTime{
				Time:  time.Now().UTC().Add(-10 * time.Minute),
				Valid: true,
			},
			SessionIdentifier: "session-abc",
		}
		if withPKCE {
			// SHA256 of testCodeVerifier base64url-encoded.
			c.CodeChallenge = sql.NullString{
				String: oauth.GeneratePKCECodeChallenge(testCodeVerifier),
				Valid:  true,
			}
		}
		return c
	}

	t.Run("Reuse with correct credentials returns AuthCodeReusedError sentinel (public client + PKCE)", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &models.Settings{}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "client1",
			Code:         "reused_code",
			RedirectURI:  "https://example.com/callback",
			CodeVerifier: testCodeVerifier,
		}

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		codeEntity := reusedCodeFixture(client, true)

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(nil, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), true).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		reused, ok := err.(*AuthCodeReusedError)
		assert.True(t, ok, "expected *AuthCodeReusedError sentinel, got %T", err)
		assert.NotNil(t, reused.Code)
		assert.Equal(t, codeEntity.Id, reused.Code.Id)
		assert.Equal(t, "session-abc", reused.Code.SessionIdentifier)
		assert.NotNil(t, reused.Detail)
		assert.Equal(t, "invalid_grant", reused.Detail.Code())
		assert.Equal(t, "Code is invalid.", reused.Detail.Description())
		assert.Equal(t, http.StatusBadRequest, reused.Detail.HTTPStatus())
	})

	t.Run("Reuse with correct credentials returns sentinel (confidential client + correct secret)", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &models.Settings{}
		ctx := context.Background()

		clientSecret := "the_secret"
		clientSecretEncrypted, err := testDataCipher.Encrypt(clientSecret)
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

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "confidential_client").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(nil, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), true).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		reused, ok := err.(*AuthCodeReusedError)
		assert.True(t, ok, "expected *AuthCodeReusedError sentinel, got %T", err)
		assert.Equal(t, codeEntity.Id, reused.Code.Id)
	})

	t.Run("Reuse with a disabled, superseded user still returns sentinel (account state read below the reuse return)", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &models.Settings{}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "client1",
			Code:         "reused_code",
			RedirectURI:  "https://example.com/callback",
			CodeVerifier: testCodeVerifier,
		}

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		codeEntity := reusedCodeFixture(client, true)
		// Every account-state refusal applies to this code at once: the user is disabled, the
		// generation moved, and the fixture is already past the 60 second life. #77's cascade
		// still runs, because all three are read below the wasReused return (#137).
		codeEntity.User.Enabled = false
		codeEntity.AuthStateGeneration = 1
		codeEntity.User.AuthStateGeneration = 2

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(nil, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), true).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()

		_, err := validator.ValidateTokenRequest(ctx, settings, input)

		_, ok := err.(*AuthCodeReusedError)
		assert.True(t, ok, "expected sentinel even with disabled user; user-state checks must be skipped on reuse path. got %T", err)
	})

	t.Run("Reuse with wrong client_id does NOT produce sentinel", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &models.Settings{}
		ctx := context.Background()

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
			CodeVerifier: testCodeVerifier,
		}

		codeEntity := reusedCodeFixture(victimClient, true)

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "attacker_client").Return(attackerClient, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(nil, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), true).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()

		_, err := validator.ValidateTokenRequest(ctx, settings, input)

		_, isSentinel := err.(*AuthCodeReusedError)
		assert.False(t, isSentinel, "wrong client_id must not yield revocation sentinel")
		detail, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", detail.Code())
		assert.Contains(t, detail.Description(), "client_id")
	})

	t.Run("Reuse with wrong redirect_uri does NOT produce sentinel", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &models.Settings{}
		ctx := context.Background()

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
			CodeVerifier: testCodeVerifier,
		}

		codeEntity := reusedCodeFixture(client, true)

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(nil, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), true).Return(codeEntity, nil).Once()

		_, err := validator.ValidateTokenRequest(ctx, settings, input)

		_, isSentinel := err.(*AuthCodeReusedError)
		assert.False(t, isSentinel, "wrong redirect_uri must not yield revocation sentinel")
		detail, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", detail.Code())
		assert.Equal(t, "Invalid redirect_uri.", detail.Description())
	})

	t.Run("Reuse with confidential client and missing client_secret does NOT produce sentinel", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &models.Settings{}
		ctx := context.Background()

		clientSecret := "the_secret"
		clientSecretEncrypted, err := testDataCipher.Encrypt(clientSecret)
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

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "confidential_client").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(nil, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), true).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()

		_, err = validator.ValidateTokenRequest(ctx, settings, input)

		_, isSentinel := err.(*AuthCodeReusedError)
		assert.False(t, isSentinel, "missing client_secret must not yield revocation sentinel")
		detail, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_client", detail.Code())
	})

	t.Run("Reuse with confidential client and wrong client_secret does NOT produce sentinel", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &models.Settings{}
		ctx := context.Background()

		clientSecret := "the_secret"
		clientSecretEncrypted, err := testDataCipher.Encrypt(clientSecret)
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

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "confidential_client").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(nil, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), true).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()

		_, err = validator.ValidateTokenRequest(ctx, settings, input)

		_, isSentinel := err.(*AuthCodeReusedError)
		assert.False(t, isSentinel, "wrong client_secret must not yield revocation sentinel")
		detail, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_client", detail.Code())
	})

	t.Run("Reuse with wrong PKCE code_verifier does NOT produce sentinel", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &models.Settings{}
		ctx := context.Background()

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
			CodeVerifier: wrongCodeVerifier,
		}

		codeEntity := reusedCodeFixture(client, true)

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(nil, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), true).Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()

		_, err := validator.ValidateTokenRequest(ctx, settings, input)

		_, isSentinel := err.(*AuthCodeReusedError)
		assert.False(t, isSentinel, "wrong code_verifier must not yield revocation sentinel")
		detail, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", detail.Code())
		assert.Equal(t, "Invalid code_verifier (PKCE).", detail.Description())
	})

	t.Run("Code-not-found (truly unknown) returns plain invalid_grant, not sentinel", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &models.Settings{}
		ctx := context.Background()

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
			CodeVerifier: testCodeVerifier,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(nil, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), true).Return(nil, nil).Once()

		_, err := validator.ValidateTokenRequest(ctx, settings, input)

		_, isSentinel := err.(*AuthCodeReusedError)
		assert.False(t, isSentinel, "unknown code must not yield revocation sentinel")
		detail, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", detail.Code())
		assert.Equal(t, "Code is invalid.", detail.Description())
	})
}

// ============================================================================
// PKCE Optional Tests - Testing the optional PKCE behavior at token endpoint
// ============================================================================

func TestValidateTokenRequest_PKCE_NoPKCEUsed_NoVerifierProvided_Success(t *testing.T) {
	// When PKCE was NOT used during authorization and no code_verifier is provided,
	// the token request should succeed.
	//
	// The fixture is CONFIDENTIAL, and it used to be public (#245). The no-PKCE success
	// case remains valid, but only for a client that authenticates: a public client is
	// now refused a challenge-less code, which is what the _PublicClient_Fails
	// counterpart below asserts.
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &models.Settings{}
	ctx := context.Background()

	input := &ValidateTokenRequestInput{
		GrantType:    "authorization_code",
		ClientId:     "client1",
		ClientSecret: "client_secret",
		Code:         "valid_code",
		RedirectURI:  "https://example.com/callback",
		CodeVerifier: "", // No code_verifier provided
	}

	clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
	require.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "client1",
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 false,
		ClientSecretEncrypted:    clientSecretEncrypted,
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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()
	mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
	mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
	mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
	expectRedirectURIStillRegistered(mockDB, "https://example.com/callback")

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, codeEntity, grantAs[*AuthorizationCodeGrant](t, result).Code)
}

func TestValidateTokenRequest_PKCE_NoPKCEUsed_VerifierProvided_Fails(t *testing.T) {
	// When PKCE was NOT used during authorization but code_verifier IS provided,
	// this should fail (strict mode). This is the PKCE downgrade guard RFC 9700 section
	// 2.1.1 requires.
	//
	// The fixture is CONFIDENTIAL, and it used to be public (#245). It has to be: a public
	// client presenting a challenge-less code is now refused above this guard, so a public
	// fixture would pass on the wrong refusal and stop covering the downgrade guard at all.
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &models.Settings{}
	ctx := context.Background()

	input := &ValidateTokenRequestInput{
		GrantType:    "authorization_code",
		ClientId:     "client1",
		ClientSecret: "client_secret",
		Code:         "valid_code",
		RedirectURI:  "https://example.com/callback",
		CodeVerifier: "some_code_verifier", // code_verifier provided but PKCE was not used
	}

	clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
	require.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "client1",
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 false,
		ClientSecretEncrypted:    clientSecretEncrypted,
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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()
	mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
	mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
	mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	assert.Nil(t, result)
	assert.Error(t, err)
	customErr, ok := err.(*oauth.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "invalid_request", customErr.Code())
	assert.Equal(t, "The code_verifier parameter was provided, but PKCE was not used during authorization.", customErr.Description())
	assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
}

func TestValidateTokenRequest_PKCE_PKCEUsed_ValidVerifier_Success(t *testing.T) {
	// When PKCE was used during authorization and a valid code_verifier is provided,
	// the token request should succeed
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &models.Settings{}
	ctx := context.Background()

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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()
	mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
	mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
	mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
	expectRedirectURIStillRegistered(mockDB, "https://example.com/callback")

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, codeEntity, grantAs[*AuthorizationCodeGrant](t, result).Code)
}

func TestValidateTokenRequest_PKCE_PKCEUsed_NoVerifier_Fails(t *testing.T) {
	// When PKCE was used during authorization but no code_verifier is provided,
	// this should fail
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &models.Settings{}
	ctx := context.Background()

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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()
	mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
	mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
	mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	assert.Nil(t, result)
	assert.Error(t, err)
	customErr, ok := err.(*oauth.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "invalid_request", customErr.Code())
	assert.Equal(t, "Missing required code_verifier parameter.", customErr.Description())
	assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
}

func TestValidateTokenRequest_PKCE_PKCEUsed_WrongVerifier_Fails(t *testing.T) {
	// When PKCE was used during authorization but wrong code_verifier is provided,
	// this should fail
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &models.Settings{}
	ctx := context.Background()

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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()
	mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
	mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
	mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	assert.Nil(t, result)
	assert.Error(t, err)
	customErr, ok := err.(*oauth.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "invalid_grant", customErr.Code())
	assert.Equal(t, "Invalid code_verifier (PKCE).", customErr.Description())
	assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
}

func TestValidateTokenRequest_PKCE_EmptyStringCodeChallenge_TreatedAsNoPKCE(t *testing.T) {
	// When code_challenge is an empty string with Valid=true, it should be treated as no PKCE.
	//
	// Confidential for the same reason as the test above (#245): treating empty as no PKCE
	// still means success for a client that authenticates, and refusal for one that does not.
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &models.Settings{}
	ctx := context.Background()

	input := &ValidateTokenRequestInput{
		GrantType:    "authorization_code",
		ClientId:     "client1",
		ClientSecret: "client_secret",
		Code:         "valid_code",
		RedirectURI:  "https://example.com/callback",
		CodeVerifier: "", // No code_verifier
	}

	clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
	require.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "client1",
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 false,
		ClientSecretEncrypted:    clientSecretEncrypted,
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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()
	mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(codeEntity, nil).Once()
	mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
	mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
	expectRedirectURIStillRegistered(mockDB, "https://example.com/callback")

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	// Empty string code_challenge should be treated as no PKCE, so this should succeed
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, codeEntity, grantAs[*AuthorizationCodeGrant](t, result).Code)
}

// =============================================================================
// Public clients always use PKCE (#245) - the redemption half of the mandate
// =============================================================================

// publicClientChallengelessCode builds the fixture the four tests below share: a public
// client, and a code whose stored challenge is whatever the caller passes. Everything
// else is an ordinary, valid authorization code redemption, so the only thing any row
// here can be refused for is the rule under test.
func publicClientChallengelessCode(t *testing.T, storedChallenge sql.NullString, isPublic bool) (
	*TokenValidator, *ValidateTokenRequestInput, *models.Settings) {
	t.Helper()

	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)
	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &models.Settings{}

	client := &models.Client{
		Id:                       1,
		ClientIdentifier:         "client1",
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 isPublic,
	}

	codeEntity := &models.Code{
		CodeHash:      "hash_of_valid_code",
		RedirectURI:   "https://example.com/callback",
		ClientId:      1,
		CodeChallenge: storedChallenge,
		Client:        models.Client{ClientIdentifier: "client1"},
		User:          models.User{Id: 7, Enabled: true},
		CreatedAt:     sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()
	mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).
		Return(codeEntity, nil).Once()
	mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
	mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()

	input := &ValidateTokenRequestInput{
		GrantType:   "authorization_code",
		ClientId:    "client1",
		Code:        "valid_code",
		RedirectURI: "https://example.com/callback",
	}

	return validator, input, settings
}

func TestValidateTokenRequest_PKCE_NoPKCEUsed_PublicClient_Fails(t *testing.T) {
	// The defect #245 is about. A public client presents nothing at this endpoint, so a
	// code carrying no challenge is bound to nothing and whoever holds it gets the tokens.
	validator, input, settings := publicClientChallengelessCode(t, sql.NullString{Valid: false}, true)

	result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

	assert.Nil(t, result)
	customErr, ok := err.(*oauth.ErrorDetail)
	if assert.True(t, ok, "expected *oauth.ErrorDetail, got %T: %v", err, err) {
		assert.Equal(t, "invalid_grant", customErr.Code())
		assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
		assert.Contains(t, customErr.Description(), "public clients are required to use PKCE")
	}
}

func TestValidateTokenRequest_PKCE_EmptyStringCodeChallenge_PublicClient_Fails(t *testing.T) {
	// Varies exactly one field from the row above: Valid is true and the string is empty.
	// Without this row a predicate written as !CodeChallenge.Valid, with no != "" beside
	// it, passes every other new case while still accepting a challenge-less grant.
	validator, input, settings := publicClientChallengelessCode(t,
		sql.NullString{String: "", Valid: true}, true)

	result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

	assert.Nil(t, result)
	customErr, ok := err.(*oauth.ErrorDetail)
	if assert.True(t, ok, "expected *oauth.ErrorDetail, got %T: %v", err, err) {
		assert.Equal(t, "invalid_grant", customErr.Code())
		assert.Contains(t, customErr.Description(), "public clients are required to use PKCE")
	}
}

// TestValidateTokenRequest_AuthorizationCode_SessionOwnership covers the redemption half of
// #133's post-issuance backstop (decision 8, option B). A code carries the session identifier
// its ceremony was bound to, and until this check the authorization_code branch never loaded
// that session at all, so a code minted for user 1 carrying user 2's session identifier
// redeemed like any other.
//
// Issuance can no longer produce one, so what this reaches is the population minted in the
// window between an account switch and the upgrade. It is a small window by construction:
// authCodeExpirationInSeconds is 60.
//
// Three rows, and the middle one is the deliberate limit rather than an oversight. Sessions
// are swept once they idle out or reach their maximum lifetime, so a code whose session row
// has gone is the ordinary state of an older grant and MUST still redeem. That is exactly why
// this cannot be complete, and the residual is documented in concepts/user-sessions.mdx.
//
// A fourth case is covered without a row here: a code with no session identifier performs no
// lookup at all. Every other authorization_code test in this file leaves SessionIdentifier
// empty and mocks no lookup, and the database mock is strict, so a lookup on the empty path
// would fail all of them.
func TestValidateTokenRequest_AuthorizationCode_SessionOwnership(t *testing.T) {
	const grantUserId = int64(1)
	const sid = "sid-of-the-browser"

	// setup returns a validator whose code names `sid`. sessionOwner nil means the row is
	// gone, which is the swept case; otherwise it is the user the row belongs to. A non-nil
	// lookupErr makes the lookup itself fail, which is a third outcome and not a fourth
	// flavour of absence.
	setup := func(t *testing.T, sessionOwner *int64, lookupErr error) (*TokenValidator, *ValidateTokenRequestInput, *models.Settings) {
		t.Helper()

		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)
		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &models.Settings{}

		// Confidential, and it used to be public (#245). The subject is the code's session
		// ownership, and the code carries no challenge, so a public client would now be
		// refused by the PKCE boundary before the session is ever looked up.
		clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
		require.NoError(t, err)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
		}

		codeEntity := &models.Code{
			CodeHash:          "hash_of_valid_code",
			RedirectURI:       "https://example.com/callback",
			SessionIdentifier: sid,
			// Both sides of the comparison are non-zero, so the accept row is a real match
			// rather than the zero-to-zero one an incomplete fixture would give.
			UserId: grantUserId,
			Client: models.Client{ClientIdentifier: "client1"},
			User:   models.User{Id: grantUserId, Enabled: true},
			CreatedAt: sql.NullTime{
				Time:  time.Now().UTC(),
				Valid: true,
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).
			Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
		expectRedirectURIStillRegistered(mockDB, "https://example.com/callback")

		switch {
		case lookupErr != nil:
			mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sid).Return(nil, lookupErr).Once()
		case sessionOwner == nil:
			mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sid).Return(nil, nil).Once()
		default:
			mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sid).
				Return(&models.UserSession{SessionIdentifier: sid, UserId: *sessionOwner}, nil).Once()
		}

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "client1",
			ClientSecret: "client_secret",
			Code:         "valid_code",
			RedirectURI:  "https://example.com/callback",
		}

		return validator, input, settings
	}

	owner := func(id int64) *int64 { return &id }

	t.Run("a session belonging to the code's user is accepted", func(t *testing.T) {
		validator, input, settings := setup(t, owner(grantUserId), nil)

		result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("a session that has already been swept is accepted", func(t *testing.T) {
		// The deliberate hole, asserted so nobody closes it by accident. Refusing on a
		// missing row would refuse every grant whose session has simply timed out, which is
		// most of them.
		validator, input, settings := setup(t, nil, nil)

		result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("a failed lookup is propagated, not read as a swept session", func(t *testing.T) {
		// The row above is accepted when it is genuinely absent. A lookup that FAILED says
		// nothing about whether the session exists, so treating the two alike would let an
		// unreachable database wave every cross-bound code through. This is the case that
		// pins the difference: the same error comes back, unwrapped into an OAuth refusal.
		lookupErr := errors.New("database is down")
		validator, input, settings := setup(t, nil, lookupErr)

		result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

		assert.Nil(t, result)
		assert.ErrorIs(t, err, lookupErr)
		_, isErrorDetail := err.(*oauth.ErrorDetail)
		assert.False(t, isErrorDetail, "a database failure must not be reported as an OAuth error")
	})

	t.Run("a session belonging to another user is refused", func(t *testing.T) {
		validator, input, settings := setup(t, owner(grantUserId+1), nil)

		result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.Code())
		assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
		// The wording a revoked code and a superseded generation already share. A message
		// naming the mismatch would tell the presenter that the session exists and belongs
		// to somebody else.
		assert.Equal(t, "Code is invalid.", customErr.Description())
	})
}

// TestValidateTokenRequest_AuthorizationCode_RedirectURIStillRegistered covers #241 decision 5's
// registration boundary at redemption. The comparison near the top of the arm weighs the submitted
// redirect_uri against the one stored on the code, and that stored value is a copy taken at
// minting which nothing rematches against the client, so without this check a code delivered one
// second before an administrator removes a callback stays redeemable for the rest of its 60 second
// life.
//
// The fixture is TestValidateTokenRequest_AuthorizationCode_SessionOwnership's, with the
// registration outcome as the variable: registered is what ClientLoadRedirectURIs writes onto the
// client, and a non-nil loadErr makes the load itself fail, which is a distinct outcome and not a
// third flavour of "not registered".
func TestValidateTokenRequest_AuthorizationCode_RedirectURIStillRegistered(t *testing.T) {
	const grantUserId = int64(1)

	// codeChallenge empty means the code was minted without PKCE, which is every case but the
	// last; the last needs a stored challenge so that a wrong verifier is a genuine PKCE
	// failure rather than the strict-mode rejection of an unexpected one.
	setup := func(t *testing.T, codeRedirectURI string, registered []string, loadErr error, codeChallenge string) (*TokenValidator, *ValidateTokenRequestInput, *models.Settings) {
		t.Helper()

		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)
		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &models.Settings{}

		// Confidential, and the code carries no challenge, so the PKCE boundary (#245) does not
		// pre-empt the subject. The secret also gives the ordering cases below something real to
		// get wrong.
		clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
		require.NoError(t, err)

		client := &models.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
		}

		codeEntity := &models.Code{
			CodeHash:          "hash_of_valid_code",
			RedirectURI:       codeRedirectURI,
			SessionIdentifier: "",
			UserId:            grantUserId,
			Client:            models.Client{ClientIdentifier: "client1"},
			User:              models.User{Id: grantUserId, Enabled: true},
			CodeChallenge:     sql.NullString{String: codeChallenge, Valid: codeChallenge != ""},
			CreatedAt: sql.NullTime{
				Time:  time.Now().UTC(),
				Valid: true,
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).
			Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()

		// registered nil means the caller does not expect the load to happen at all, which is
		// what the two ordering cases assert: a strict mockery double fails the test if the
		// validator calls it anyway. loadErr is the third outcome.
		switch {
		case loadErr != nil:
			mockDB.On("ClientLoadRedirectURIs", mock.Anything, mock.Anything, client).Return(loadErr).Once()
		case registered != nil:
			mockDB.On("ClientLoadRedirectURIs", mock.Anything, mock.Anything, client).Run(func(args mock.Arguments) {
				c := args.Get(2).(*models.Client)
				c.RedirectURIs = nil
				for _, uri := range registered {
					c.RedirectURIs = append(c.RedirectURIs, models.RedirectURI{URI: uri})
				}
			}).Return(nil).Once()
		}

		input := &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "client1",
			ClientSecret: "client_secret",
			Code:         "valid_code",
			RedirectURI:  codeRedirectURI,
		}

		return validator, input, settings
	}

	t.Run("a code whose redirect URI is still registered is redeemable", func(t *testing.T) {
		validator, input, settings := setup(t, "https://example.com/callback",
			[]string{"https://other.example.com/cb", "https://example.com/callback"}, nil, "")

		result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("a code whose redirect URI was deregistered is refused", func(t *testing.T) {
		validator, input, settings := setup(t, "https://example.com/callback",
			[]string{"https://other.example.com/cb"}, nil, "")

		result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

		assert.Nil(t, result)
		customErr, ok := err.(*oauth.ErrorDetail)
		require.True(t, ok)
		// Matched the way HandleTokenPost matches it, by value against the sentinel, because
		// that equality is what ties the audit row to the wire message (#241 decision 10).
		assert.True(t, errors.Is(err, ErrCodeRedirectURIDeregistered))
		assert.Equal(t, "invalid_grant", customErr.Code())
		assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
		// Legible rather than the flat "Code is invalid." the refusals above it give. The
		// presenter has already authenticated, and an administrator who rotated a callback
		// needs to be able to tell this apart from a submitted value that differs from the
		// code's, which returns "Invalid redirect_uri."
		assert.Contains(t, customErr.Description(), "no longer registered on the client")
	})

	t.Run("a client with no registrations left refuses every outstanding code", func(t *testing.T) {
		validator, input, settings := setup(t, "https://example.com/callback",
			[]string{}, nil, "")

		result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

		assert.Nil(t, result)
		// errors.Is alone: matching the sentinel already establishes the value is an
		// *ErrorDetail carrying exactly its details, which is what ErrorDetail.Is compares.
		assert.True(t, errors.Is(err, ErrCodeRedirectURIDeregistered))
	})

	t.Run("a loopback code still matches its registered portless URI", func(t *testing.T) {
		// The flag's whole reason, and the case that would break if somebody made it
		// conditional to match the emitter's false. A native app registers
		// http://127.0.0.1/callback and requests an ephemeral port at authorization time, so
		// the code stores the ported form and nothing exact-matches it (RFC 8252, decision 5).
		validator, input, settings := setup(t, "http://127.0.0.1:54321/callback",
			[]string{"http://127.0.0.1/callback"}, nil, "")

		result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("a failed load is propagated, not read as a deregistration", func(t *testing.T) {
		// The same distinction the session ownership check draws. An unreachable database says
		// nothing about whether the URI is registered, so turning the failure into a refusal
		// would report an outage as an administrative action.
		loadErr := errors.New("database is down")
		validator, input, settings := setup(t, "https://example.com/callback",
			nil, loadErr, "")

		result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

		assert.Nil(t, result)
		assert.ErrorIs(t, err, loadErr)
		_, isErrorDetail := err.(*oauth.ErrorDetail)
		assert.False(t, isErrorDetail, "a database failure must not be reported as an OAuth error")
	})

	t.Run("a wrong client secret is answered before the registration is read", func(t *testing.T) {
		// THE ORDERING CASE, and it is asserted by ABSENCE: setup is given a nil registered
		// list, so no ClientLoadRedirectURIs expectation exists and the strict mockery double
		// fails the test if the validator reads the registrations anyway. That is what pins the
		// check below client authentication (#137): an unauthenticated presenter of a stolen
		// code must not learn from the answer whether the grant's destination still exists.
		// Do not "simplify" this by adding the expectation.
		validator, input, settings := setup(t, "https://example.com/callback",
			nil, nil, "")
		input.ClientSecret = "wrong_secret"

		result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

		assert.Nil(t, result)
		customErr, ok := err.(*oauth.ErrorDetail)
		require.True(t, ok)
		assert.Equal(t, "invalid_client", customErr.Code())
	})

	t.Run("a wrong PKCE verifier is answered before the registration is read", func(t *testing.T) {
		// The other half of the ordering case, asserted the same way and for the same reason.
		// The code carries a challenge here, so a wrong verifier is a real PKCE failure rather
		// than the strict-mode rejection of an unexpected one, and it must not reach the
		// registration read. Again: no ClientLoadRedirectURIs expectation, deliberately.
		validator, input, settings := setup(t, "https://example.com/callback",
			nil, nil, oauth.GeneratePKCECodeChallenge(testCodeVerifier))
		input.CodeVerifier = wrongCodeVerifier

		result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

		assert.Nil(t, result)
		customErr, ok := err.(*oauth.ErrorDetail)
		require.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.Code())
		assert.Equal(t, "Invalid code_verifier (PKCE).", customErr.Description())
	})
}
