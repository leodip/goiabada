package protocolvalidation

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"testing"
	"time"

	"errors"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation/mocks"
)

func TestValidateTokenRequest_RefreshToken_AuthCodeDisabled(t *testing.T) {
	t.Run("Client with authorization code flow disabled", func(t *testing.T) {
		// The negative control for a rule that MOVED rather than vanished. This subtest used
		// to assert the validator refuses here; it now asserts it accepts, because the flow
		// gate lives in HandleTokenPost's refresh arm below replay containment. Re-adding a
		// gate to this arm fails this case, which is the only thing stopping a later reader
		// from quietly suppressing containment for a stolen token again (#250).
		//
		// The refusal itself is owned by TestHandleTokenPost_Refresh_FlowGate in
		// authserver/internal/handlers/handler_token_test.go, which holds the whole truth
		// table. Kept under this name because it is the case a git log -S on the deleted
		// gate's sentence lands on.
		const grantUserId = int64(7)

		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &record.Settings{
			UserSessionIdleTimeoutInSeconds: 3600,
			UserSessionMaxLifetimeInSeconds: 86400,
		}
		ctx := context.Background()

		clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
		require.NoError(t, err)

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			RefreshToken: "some_refresh_token",
			ClientSecret: "client_secret",
		}

		client := &record.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: false,
			ClientSecretEncrypted:    clientSecretEncrypted,
		}

		// An authorization code flow token: CodeId valid, so the handler's gate would be the
		// one to refuse it. Reaching the end of the arm is the assertion.
		user := record.User{Id: grantUserId, Enabled: true}
		refreshToken := &record.RefreshToken{
			RefreshTokenJti:   "some_jti",
			SessionIdentifier: "sid-1",
			CodeId:            sql.NullInt64{Int64: 5, Valid: true},
			Code: record.Code{
				Id:                5,
				ClientId:          client.Id,
				UserId:            grantUserId,
				Scope:             "openid",
				SessionIdentifier: "sid-1",
				User:              user,
			},
		}

		now := time.Now().UTC()
		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()
		mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "some_refresh_token", true).
			Return(&oauth.JwtToken{Claims: jwt.MapClaims{
				"jti": "some_jti", "typ": "Refresh", "sub": "user_subject",
			}}, nil).Once()
		mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "some_jti").Return(refreshToken, nil).Once()
		mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
		mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil).Once()
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "sid-1").
			Return(&record.UserSession{
				Id: 9, SessionIdentifier: "sid-1", UserId: grantUserId,
				Started: now.Add(-10 * time.Minute), LastAccessed: now,
			}, nil).Once()
		mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, "user_subject").Return(&user, nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		require.NoError(t, err, "the validator must hold no flow rule on the refresh arm")
		require.NotNil(t, result)
		assert.False(t, grantAs[*RefreshTokenGrant](t, result).Client.AuthorizationCodeEnabled,
			"the fixture is only meaningful while the flow is off")
	})

	t.Run("Missing client secret for confidential client", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &record.Settings{}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "confidential_client",
			RefreshToken: "some_refresh_token",
			// ClientSecret is intentionally left empty
		}

		client := &record.Client{
			ClientIdentifier:         "confidential_client",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 false,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "confidential_client").Return(client, nil).Once()

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

	t.Run("Incorrect client secret for confidential client", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &record.Settings{}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "confidential_client",
			RefreshToken: "some_refresh_token",
			ClientSecret: "incorrect_secret",
		}

		correctSecret := "correct_secret"
		encryptedSecret, _ := testDataCipher.Encrypt(correctSecret)

		client := &record.Client{
			ClientIdentifier:         "confidential_client",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    encryptedSecret,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "confidential_client").Return(client, nil).Once()

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

	t.Run("Missing refresh token", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &record.Settings{}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType: "refresh_token",
			ClientId:  "client1",
			// RefreshToken is intentionally left empty
		}

		client := &record.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true, // Using a public client to bypass client secret check
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_request", customErr.Code())
		assert.Equal(t, "Missing required refresh_token parameter.", customErr.Description())
		assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
	})

	t.Run("Invalid refresh token", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &record.Settings{}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			RefreshToken: "invalid_refresh_token",
		}

		client := &record.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()
		mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "invalid_refresh_token", true).
			Return(nil, errors.New("token is expired")).Once()

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.Code())
		assert.Equal(t, "The refresh token is invalid (token is expired).", customErr.Description())
		assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
	})

	t.Run("Refresh token without JTI claim", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &record.Settings{}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			RefreshToken: "refresh_token_without_jti",
		}

		client := &record.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()

		// Mock a JwtToken without a JTI claim
		mockJwtToken := &oauth.JwtToken{}
		mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "refresh_token_without_jti", true).
			Return(mockJwtToken, nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "the refresh token is invalid because it does not contain a jti claim")
	})

	t.Run("Refresh token not found in database", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &record.Settings{}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			RefreshToken: "non_existent_refresh_token",
		}

		client := &record.Client{
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 true,
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()

		mockJwtToken := &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"jti": "non_existent_jti",
			},
		}
		mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "non_existent_refresh_token", true).
			Return(mockJwtToken, nil).Once()
		mockDB.On("GetRefreshTokenByJti", mock.Anything, (*sql.Tx)(nil), "non_existent_jti").Return(nil, nil).Once()

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)

		// UPDATED DELIBERATELY, not a stale assertion: this used to be a plain error,
		// which JSONError maps to a 500. A validly signed refresh token with no row is
		// an invalid grant, not a server fault (RFC 6749 Section 5.2, #128).
		detail, ok := err.(*oauth.ErrorDetail)
		require.Truef(t, ok, "a missing refresh token row must be an ErrorDetail, got %T", err)
		assert.Equal(t, "invalid_grant", detail.Code())
		assert.Equal(t, http.StatusBadRequest, detail.HTTPStatus())

		// The message must NOT reveal that the row was missing, since that would
		// distinguish a never-issued JTI from a revoked one.
		assert.Equal(t, "The refresh token is invalid.", detail.Description())
		assert.NotContains(t, detail.Description(), "database")
	})

	t.Run("Refresh token with mismatched client", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &record.Settings{
			UserSessionIdleTimeoutInSeconds: 3600,
			UserSessionMaxLifetimeInSeconds: 86400,
		}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			RefreshToken: "mismatched_refresh_token",
		}

		client := &record.Client{
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

		refreshToken := &record.RefreshToken{
			RefreshTokenJti: "mismatched_jti",
			CodeId:          sql.NullInt64{Int64: 1, Valid: true}, // Auth code flow token
			Code: record.Code{
				ClientId: 2, // Different client ID
				User: record.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "mismatched_refresh_token", true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "mismatched_jti").Return(refreshToken, nil)
		mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
		mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil)

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_request", customErr.Code())
		assert.Contains(t, customErr.Description(), "The refresh token is invalid because it does not belong to the client")
	})

	t.Run("Refresh token for disabled user", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &record.Settings{
			UserSessionIdleTimeoutInSeconds: 3600,
			UserSessionMaxLifetimeInSeconds: 86400,
		}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			RefreshToken: "disabled_user_refresh_token",
		}

		client := &record.Client{
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

		refreshToken := &record.RefreshToken{
			RefreshTokenJti: "disabled_user_jti",
			CodeId:          sql.NullInt64{Int64: 1, Valid: true}, // Auth code flow token
			Code: record.Code{
				ClientId: 1,
				User: record.User{
					Id:      1,
					Enabled: false, // User is disabled
				},
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "disabled_user_refresh_token", true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "disabled_user_jti").Return(refreshToken, nil)
		mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
		mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil)

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		// The wording that says nothing about why, never one naming the account (#137); the
		// type is what the handler writes EventUserDisabled from.
		var disabled *UserDisabledError
		require.ErrorAs(t, err, &disabled)
		var customErr *oauth.ErrorDetail
		require.ErrorAs(t, err, &customErr)
		assert.Equal(t, "invalid_grant", customErr.Code())
		assert.Equal(t, invalidRefreshTokenMessage, customErr.Description())
		assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
	})

	t.Run("Refresh token with nil session", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &record.Settings{
			UserSessionIdleTimeoutInSeconds: 3600,
			UserSessionMaxLifetimeInSeconds: 86400,
		}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			ClientSecret: "client_secret",
			RefreshToken: "nil_session_refresh_token",
		}

		clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
		require.NoError(t, err)

		client := &record.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
		}

		refreshTokenJwt := &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"jti": "nil_session_jti",
				"typ": "Refresh",
			},
		}

		refreshToken := &record.RefreshToken{
			RefreshTokenJti:   "nil_session_jti",
			SessionIdentifier: "non_existent_session",
			CodeId:            sql.NullInt64{Int64: 1, Valid: true}, // Auth code flow token
			Code: record.Code{
				ClientId: 1,
				User: record.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "nil_session_refresh_token", true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "nil_session_jti").Return(refreshToken, nil)
		mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
		mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil)
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "non_existent_session").Return(nil, nil)

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.Code())
		assert.Equal(t, "The refresh token is invalid because the associated session has expired or been terminated.", customErr.Description())
		assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
	})

	t.Run("Refresh token with invalid session", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &record.Settings{
			UserSessionIdleTimeoutInSeconds: 3600,
			UserSessionMaxLifetimeInSeconds: 86400,
		}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			ClientSecret: "client_secret",
			RefreshToken: "invalid_session_refresh_token",
		}

		clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
		require.NoError(t, err)

		client := &record.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
		}

		refreshTokenJwt := &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"jti": "invalid_session_jti",
				"typ": "Refresh",
			},
		}

		refreshToken := &record.RefreshToken{
			RefreshTokenJti:   "invalid_session_jti",
			SessionIdentifier: "expired_session",
			CodeId:            sql.NullInt64{Int64: 1, Valid: true}, // Auth code flow token
			Code: record.Code{
				ClientId: 1,
				User: record.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		expiredSession := &record.UserSession{
			SessionIdentifier: "expired_session",
			UserId:            1,                                     // owned by the code's user, so expiry is what refuses it
			Started:           time.Now().UTC().Add(-48 * time.Hour), // Started 2 days ago
			LastAccessed:      time.Now().UTC().Add(-25 * time.Hour), // Last accessed 25 hours ago
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "invalid_session_refresh_token", true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "invalid_session_jti").Return(refreshToken, nil)
		mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
		mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil)
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "expired_session").Return(expiredSession, nil)

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.Code())
		assert.Equal(t, "The refresh token is invalid because the associated session has expired or been terminated.", customErr.Description())
		assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
	})

	t.Run("Expired offline refresh token", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &record.Settings{}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			ClientSecret: "client_secret",
			RefreshToken: "expired_offline_refresh_token",
		}

		clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
		require.NoError(t, err)

		client := &record.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
		}

		pastTime := time.Now().UTC().Add(-24 * time.Hour)
		refreshTokenJwt := &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"jti":                         "expired_offline_jti",
				"typ":                         "Offline",
				"offline_access_max_lifetime": float64(pastTime.Unix()),
			},
		}

		refreshToken := &record.RefreshToken{
			RefreshTokenJti: "expired_offline_jti",
			CodeId:          sql.NullInt64{Int64: 1, Valid: true}, // Auth code flow token
			Code: record.Code{
				ClientId: 1,
				User: record.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "expired_offline_refresh_token", true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "expired_offline_jti").Return(refreshToken, nil)
		mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
		mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil)

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.Code())
		assert.Equal(t, "The refresh token is invalid because it has expired (offline_access_max_lifetime).", customErr.Description())
		assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
	})

	t.Run("Offline refresh token without max lifetime claim", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &record.Settings{}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			ClientSecret: "client_secret",
			RefreshToken: "invalid_offline_refresh_token",
		}

		clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
		require.NoError(t, err)

		client := &record.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
		}

		refreshTokenJwt := &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"jti": "invalid_offline_jti",
				"typ": "Offline",
				// offline_access_max_lifetime claim is missing
			},
		}

		refreshToken := &record.RefreshToken{
			RefreshTokenJti: "invalid_offline_jti",
			CodeId:          sql.NullInt64{Int64: 1, Valid: true}, // Auth code flow token
			Code: record.Code{
				ClientId: 1,
				User: record.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "invalid_offline_refresh_token", true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "invalid_offline_jti").Return(refreshToken, nil)
		mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
		mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil)

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "the refresh token is invalid because it does not contain an offline_access_max_lifetime claim")
	})

	t.Run("Refresh token with invalid typ claim", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &record.Settings{}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			ClientSecret: "client_secret",
			RefreshToken: "invalid_typ_refresh_token",
		}

		clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
		require.NoError(t, err)

		client := &record.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
		}

		refreshTokenJwt := &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"jti": "invalid_typ_jti",
				"typ": "InvalidType", // Invalid typ claim
			},
		}

		refreshToken := &record.RefreshToken{
			RefreshTokenJti: "invalid_typ_jti",
			CodeId:          sql.NullInt64{Int64: 1, Valid: true}, // Auth code flow token
			Code: record.Code{
				ClientId: 1,
				User: record.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "invalid_typ_refresh_token", true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "invalid_typ_jti").Return(refreshToken, nil)
		mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
		mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil)

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "the refresh token is invalid because it does not contain a valid typ claim")
	})

	t.Run("Refresh token with scope not in original grant", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &record.Settings{
			UserSessionIdleTimeoutInSeconds: 3600,
			UserSessionMaxLifetimeInSeconds: 86400,
		}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			ClientSecret: "client_secret",
			RefreshToken: "invalid_scope_refresh_token",
			Scope:        "openid profile email address", // 'address' is not in original scopes
		}

		clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
		require.NoError(t, err)

		client := &record.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
		}

		refreshTokenJwt := &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"jti": "invalid_scope_jti",
				"typ": "Refresh",
			},
		}

		refreshToken := &record.RefreshToken{
			RefreshTokenJti:   "invalid_scope_jti",
			SessionIdentifier: "test_session",
			CodeId:            sql.NullInt64{Int64: 1, Valid: true}, // Auth code flow token
			Code: record.Code{
				ClientId: 1,
				UserId:   1,
				Scope:    "openid profile email", // Original scopes
				User: record.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		userSession := &record.UserSession{
			SessionIdentifier: "test_session",
			UserId:            1, // the code's user; a session belonging to anyone else is refused
			Started:           time.Now().UTC().Add(-30 * time.Minute),
			LastAccessed:      time.Now().UTC().Add(-5 * time.Minute),
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "invalid_scope_refresh_token", true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "invalid_scope_jti").Return(refreshToken, nil)
		mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
		mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil)
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "test_session").Return(userSession, nil)

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		// invalid_scope since #425: the grant is intact and the request exceeds it, which RFC 6749
		// section 5.2 names invalid_scope for. It answered invalid_grant before.
		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_scope", customErr.Code())
		assert.Equal(t, "Scope 'address' is not recognized. The original access token does not grant the 'address' permission.",
			customErr.Description())
		assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
	})

	t.Run("Valid offline refresh token", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &record.Settings{}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			ClientSecret: "client_secret",
			RefreshToken: "valid_offline_refresh_token",
		}

		clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
		require.NoError(t, err)

		client := &record.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
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

		refreshToken := &record.RefreshToken{
			RefreshTokenJti: "valid_offline_jti",
			CodeId:          sql.NullInt64{Int64: 1, Valid: true}, // Auth code flow token
			Code: record.Code{
				ClientId: 1,
				UserId:   1,
				Scope:    "openid profile email offline_access",
				User: record.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		userConsent := &record.UserConsent{
			UserId:   1,
			ClientId: 1,
			Scope:    "openid profile email offline_access",
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "valid_offline_refresh_token", true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "valid_offline_jti").Return(refreshToken, nil)
		mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
		mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil)
		mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, "user123").Return(&record.User{Id: 1, Enabled: true}, nil)
		mockDB.On("GetConsentByUserIdAndClientId", mock.Anything, mock.Anything, int64(1), int64(1)).Return(userConsent, nil)

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.NoError(t, err)
		grant := grantAs[*RefreshTokenGrant](t, result)
		assert.Equal(t, refreshToken, grant.RefreshToken)
		assert.False(t, grant.IsROPC, "a token with a code was minted by the authorization code flow")
	})

	t.Run("Consent is looked up once for a multi-scope refresh", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &record.Settings{}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			ClientSecret: "client_secret",
			RefreshToken: "valid_offline_refresh_token",
		}

		clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
		require.NoError(t, err)

		client := &record.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
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

		refreshToken := &record.RefreshToken{
			RefreshTokenJti: "valid_offline_jti",
			CodeId:          sql.NullInt64{Int64: 1, Valid: true},
			Code: record.Code{
				ClientId: 1,
				UserId:   1,
				Scope:    "openid profile email offline_access",
				User: record.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		userConsent := &record.UserConsent{
			UserId:   1,
			ClientId: 1,
			Scope:    "openid profile email offline_access",
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "valid_offline_refresh_token", true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "valid_offline_jti").Return(refreshToken, nil)
		mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
		mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil)
		mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, "user123").Return(&record.User{Id: 1, Enabled: true}, nil)
		// The refresh carries four scopes; the consent lookup must run once, not once per scope.
		mockDB.On("GetConsentByUserIdAndClientId", mock.Anything, mock.Anything, int64(1), int64(1)).Return(userConsent, nil).Times(1)

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		mockDB.AssertNumberOfCalls(t, "GetConsentByUserIdAndClientId", 1)
	})

	t.Run("Valid refresh token with reduced scope", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &record.Settings{
			UserSessionIdleTimeoutInSeconds: 3600,
			UserSessionMaxLifetimeInSeconds: 86400,
		}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			ClientSecret: "client_secret",
			RefreshToken: "valid_refresh_token",
			Scope:        "openid srv1:read", // Reduced scope (should be allowed)
		}

		clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
		require.NoError(t, err)

		client := &record.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
		}

		refreshTokenJwt := &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"jti": "valid_refresh_jti",
				"typ": "Refresh",
				"sub": "user123",
			},
		}

		refreshToken := &record.RefreshToken{
			RefreshTokenJti:   "valid_refresh_jti",
			SessionIdentifier: "test_session",
			CodeId:            sql.NullInt64{Int64: 1, Valid: true}, // Auth code flow token
			Code: record.Code{
				ClientId: 1,
				UserId:   1,
				Scope:    "openid srv1:read srv1:write", // Original scope
				User: record.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		userSession := &record.UserSession{
			SessionIdentifier: "test_session",
			UserId:            1, // the code's user; a session belonging to anyone else is refused
			Started:           time.Now().UTC().Add(-30 * time.Minute),
			LastAccessed:      time.Now().UTC().Add(-5 * time.Minute),
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "valid_refresh_token", true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "valid_refresh_jti").Return(refreshToken, nil)
		mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
		mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil)
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "test_session").Return(userSession, nil)
		mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, "user123").Return(&record.User{Id: 1, Enabled: true}, nil)
		mockPermissionChecker.On("UserHasScopePermission", mock.Anything, int64(1), "srv1:read").Return(true, nil)

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.NoError(t, err)
		grant := grantAs[*RefreshTokenGrant](t, result)
		assert.Equal(t, refreshToken, grant.RefreshToken)
		assert.False(t, grant.IsROPC, "a token with a code was minted by the authorization code flow")
		assert.Equal(t, "openid srv1:read srv1:write", grant.RefreshToken.Code.Scope)
		assert.Equal(t, "openid srv1:read", grant.ScopeRequested, "the narrower scope the request asked for travels on the grant")
	})

	t.Run("Refresh token with revoked consent", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &record.Settings{
			UserSessionIdleTimeoutInSeconds: 3600,
			UserSessionMaxLifetimeInSeconds: 86400,
		}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			ClientSecret: "client_secret",
			RefreshToken: "revoked_consent_refresh_token",
		}

		clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
		require.NoError(t, err)

		client := &record.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
			ConsentRequired:          true,
		}

		refreshTokenJwt := &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"jti": "revoked_consent_jti",
				"typ": "Refresh",
				"sub": "user123",
			},
		}

		refreshToken := &record.RefreshToken{
			RefreshTokenJti:   "revoked_consent_jti",
			SessionIdentifier: "test_session",
			CodeId:            sql.NullInt64{Int64: 1, Valid: true}, // Auth code flow token
			Code: record.Code{
				ClientId: 1,
				UserId:   1,
				Scope:    "openid profile email",
				User: record.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		userSession := &record.UserSession{
			SessionIdentifier: "test_session",
			UserId:            1, // the code's user; a session belonging to anyone else is refused
			Started:           time.Now().UTC().Add(-30 * time.Minute),
			LastAccessed:      time.Now().UTC().Add(-5 * time.Minute),
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "revoked_consent_refresh_token", true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "revoked_consent_jti").Return(refreshToken, nil)
		mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
		mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil)
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "test_session").Return(userSession, nil)
		mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, "user123").Return(&record.User{Id: 1, Enabled: true}, nil)
		mockDB.On("GetConsentByUserIdAndClientId", mock.Anything, mock.Anything, int64(1), int64(1)).Return(nil, nil) // Consent not found

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.Code())
		assert.Contains(t, customErr.Description(), "The user has either not given consent to this client or the previously granted consent has been revoked")
		assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
	})

	t.Run("Refresh token with a scope missing from the consent", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &record.Settings{
			UserSessionIdleTimeoutInSeconds: 3600,
			UserSessionMaxLifetimeInSeconds: 86400,
		}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			ClientSecret: "client_secret",
			RefreshToken: "partial_consent_refresh_token",
		}

		clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
		require.NoError(t, err)

		client := &record.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
			ConsentRequired:          true,
		}

		refreshTokenJwt := &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"jti": "partial_consent_jti",
				"typ": "Refresh",
				"sub": "user123",
			},
		}

		refreshToken := &record.RefreshToken{
			RefreshTokenJti:   "partial_consent_jti",
			SessionIdentifier: "test_session",
			CodeId:            sql.NullInt64{Int64: 1, Valid: true},
			Code: record.Code{
				ClientId: 1,
				UserId:   1,
				Scope:    "openid profile email",
				User: record.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		userSession := &record.UserSession{
			SessionIdentifier: "test_session",
			UserId:            1, // the code's user; a session belonging to anyone else is refused
			Started:           time.Now().UTC().Add(-30 * time.Minute),
			LastAccessed:      time.Now().UTC().Add(-5 * time.Minute),
		}

		// The user consented to openid and profile, but no longer to email.
		userConsent := &record.UserConsent{
			UserId:   1,
			ClientId: 1,
			Scope:    "openid profile",
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "partial_consent_refresh_token", true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "partial_consent_jti").Return(refreshToken, nil)
		mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
		mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil)
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "test_session").Return(userSession, nil)
		mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, "user123").Return(&record.User{Id: 1, Enabled: true}, nil)
		mockDB.On("GetConsentByUserIdAndClientId", mock.Anything, mock.Anything, int64(1), int64(1)).Return(userConsent, nil)

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.Code())
		assert.Contains(t, customErr.Description(), "The user has not consented to the 'email' permission")
		assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
	})

	t.Run("Refresh token with revoked user permission", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &record.Settings{
			UserSessionIdleTimeoutInSeconds: 3600,
			UserSessionMaxLifetimeInSeconds: 86400,
		}
		ctx := context.Background()

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			ClientSecret: "client_secret",
			RefreshToken: "revoked_permission_refresh_token",
		}

		clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
		require.NoError(t, err)

		client := &record.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
		}

		refreshTokenJwt := &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"jti": "revoked_permission_jti",
				"typ": "Refresh",
				"sub": "user123",
			},
		}

		refreshToken := &record.RefreshToken{
			RefreshTokenJti:   "revoked_permission_jti",
			SessionIdentifier: "test_session",
			CodeId:            sql.NullInt64{Int64: 1, Valid: true}, // Auth code flow token
			Code: record.Code{
				ClientId: 1,
				UserId:   1,
				Scope:    "openid profile email resource:read",
				User: record.User{
					Id:      1,
					Enabled: true,
				},
			},
		}

		userSession := &record.UserSession{
			SessionIdentifier: "test_session",
			UserId:            1, // the code's user; a session belonging to anyone else is refused
			Started:           time.Now().UTC().Add(-30 * time.Minute),
			LastAccessed:      time.Now().UTC().Add(-5 * time.Minute),
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "revoked_permission_refresh_token", true).Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "revoked_permission_jti").Return(refreshToken, nil)
		mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
		mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil)
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "test_session").Return(userSession, nil)
		mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, "user123").Return(&record.User{Id: 1, Enabled: true}, nil)
		mockPermissionChecker.On("UserHasScopePermission", mock.Anything, int64(1), "resource:read").Return(false, nil) // Permission revoked

		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.Code())
		assert.Contains(t, customErr.Description(), "The user does not have the 'resource:read' permission")
		assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
	})
}

// publicClientChallengelessRefresh is the refresh-arm counterpart of the helper above: an
// auth code flow refresh token whose code carries the challenge the caller passes. The
// grant is otherwise entirely valid, so the accepted row proves the fixture reaches the
// end of the arm rather than stopping somewhere harmless on the way.
func publicClientChallengelessRefresh(t *testing.T, storedChallenge sql.NullString, isPublic bool) (
	*TokenValidator, *ValidateTokenRequestInput, *record.Settings) {
	t.Helper()

	const grantUserId = int64(7)

	mockDB := datamocks.NewDatabase(t)
	mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
	mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)
	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &record.Settings{
		UserSessionIdleTimeoutInSeconds: 3600,
		UserSessionMaxLifetimeInSeconds: 86400,
	}

	client := &record.Client{
		Id:                       1,
		ClientIdentifier:         "client1",
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 isPublic,
	}

	input := &ValidateTokenRequestInput{
		GrantType:    "refresh_token",
		ClientId:     "client1",
		RefreshToken: "the-refresh-token",
	}

	if !isPublic {
		clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
		require.NoError(t, err)
		client.ClientSecretEncrypted = clientSecretEncrypted
		input.ClientSecret = "client_secret"
	}

	user := record.User{Id: grantUserId, Enabled: true}
	refreshToken := &record.RefreshToken{
		RefreshTokenJti:   "the-jti",
		SessionIdentifier: "sid-1",
		CodeId:            sql.NullInt64{Int64: 5, Valid: true}, // auth code flow token
		Code: record.Code{
			Id:                5,
			ClientId:          1,
			UserId:            grantUserId,
			Scope:             "openid",
			SessionIdentifier: "sid-1",
			CodeChallenge:     storedChallenge,
			User:              user,
		},
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil)
	mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "the-refresh-token", true).
		Return(&oauth.JwtToken{Claims: jwt.MapClaims{
			"jti": "the-jti", "typ": "Refresh", "sub": "user_subject",
		}}, nil)
	mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "the-jti").Return(refreshToken, nil)
	mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil)
	mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil)
	// Only the accepted row reaches these two.
	now := time.Now().UTC()
	mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "sid-1").
		Return(&record.UserSession{
			Id: 9, SessionIdentifier: "sid-1", UserId: grantUserId,
			Started: now.Add(-10 * time.Minute), LastAccessed: now,
		}, nil).Maybe()
	mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, "user_subject").Return(&user, nil).Maybe()

	return validator, input, settings
}

func TestValidateTokenRequest_RefreshToken_NoPKCEUsed_PublicClient_Fails(t *testing.T) {
	// The durable half of the exposure. A code lives 60 seconds; a refresh token descended
	// from a challenge-less code keeps minting access tokens for the life of the grant.
	validator, input, settings := publicClientChallengelessRefresh(t, sql.NullString{Valid: false}, true)

	result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

	assert.Nil(t, result)
	customErr, ok := err.(*oauth.ErrorDetail)
	if assert.True(t, ok, "expected *oauth.ErrorDetail, got %T: %v", err, err) {
		assert.Equal(t, "invalid_grant", customErr.Code())
		assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
		assert.Contains(t, customErr.Description(), "public clients are required to use PKCE")
	}
}

func TestValidateTokenRequest_RefreshToken_EmptyStringCodeChallenge_PublicClient_Fails(t *testing.T) {
	// The refresh arm's empty-string row, for the reason the redemption arm has one: the
	// rule is "absent OR empty", and a .Valid-only predicate would pass every other case.
	validator, input, settings := publicClientChallengelessRefresh(t,
		sql.NullString{String: "", Valid: true}, true)

	result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

	assert.Nil(t, result)
	customErr, ok := err.(*oauth.ErrorDetail)
	if assert.True(t, ok, "expected *oauth.ErrorDetail, got %T: %v", err, err) {
		assert.Equal(t, "invalid_grant", customErr.Code())
		assert.Contains(t, customErr.Description(), "public clients are required to use PKCE")
	}
}

func TestValidateTokenRequest_RefreshToken_NoPKCEUsed_ConfidentialClient_Succeeds(t *testing.T) {
	// The positive control, and the row that pins the rule on IsPublic rather than on the
	// PKCE requirement: the same challenge-less grant still refreshes for a client that
	// authenticates, because the secret is what binds the redemption.
	validator, input, settings := publicClientChallengelessRefresh(t, sql.NullString{Valid: false}, false)

	result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestValidateTokenRequest_RefreshToken_PublicClientWithSecret_Fails(t *testing.T) {
	// Decision 11's symmetry, the refresh_token arm. The authorization_code arm has always
	// refused a superfluous secret from a public client; this arm used to ignore it.
	mockDB := datamocks.NewDatabase(t)
	mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
	mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)
	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &record.Settings{}
	ctx := context.Background()

	client := &record.Client{
		Id:                       1,
		ClientIdentifier:         "client1",
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 true,
	}
	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()

	result, err := validator.ValidateTokenRequest(ctx, settings, &ValidateTokenRequestInput{
		GrantType:    "refresh_token",
		ClientId:     "client1",
		ClientSecret: "a_secret_this_client_does_not_have",
		RefreshToken: "the-refresh-token",
	})

	assert.Nil(t, result)
	customErr, ok := err.(*oauth.ErrorDetail)
	if assert.True(t, ok, "expected *oauth.ErrorDetail, got %T: %v", err, err) {
		assert.Equal(t, "invalid_request", customErr.Code())
		assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
		assert.Contains(t, customErr.Description(), "remove the client_secret from your request")
	}
	// The strict mock is the second assertion: the refusal answers before the refresh token
	// is ever parsed or looked up.
}

// storedGrant describes a hand-built refresh token for the stored-scope cases below.
type storedGrant struct {
	// ropc makes it an ROPC token, which has no code and carries its scope on the token row,
	// rather than an authorization code one, whose scope the arm reads from the code.
	ropc  bool
	scope string
	// consentScope, when set, makes the client require consent and is the consent row's scope.
	// Authorization code grants only: the arm skips consent for ROPC.
	consentScope string
}

// newStoredGrantRefresh wires a validator over strict mocks for one refresh of g, and hands back the
// permission checker so a case registers only the checks it expects to reach. Every read the arm
// makes before it compares the requested scope with the grant is stubbed. The subject lookup and
// the consent row come after that comparison, so they are stubbed only when reachesUser is set, and
// a case that stops at the comparison fails if it reads either.
func newStoredGrantRefresh(t *testing.T, g storedGrant, requestedScope string, reachesUser bool) (
	*TokenValidator, *protocolvalidationmocks.PermissionChecker, *record.Settings, *ValidateTokenRequestInput) {
	t.Helper()

	mockDB := datamocks.NewDatabase(t)
	mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
	mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)
	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &record.Settings{
		UserSessionIdleTimeoutInSeconds: 3600,
		UserSessionMaxLifetimeInSeconds: 86400,
	}

	input := &ValidateTokenRequestInput{
		GrantType:    "refresh_token",
		ClientId:     "client1",
		RefreshToken: "stored_grant_refresh_token",
		Scope:        requestedScope,
	}
	user := record.User{Id: 1, Subject: "user123", Enabled: true}

	var client *record.Client
	var refreshTokenJwt *oauth.JwtToken
	var refreshToken *record.RefreshToken
	if g.ropc {
		// Always Offline, because ROPC creates no browser session, and presented by a public
		// client, so no secret.
		client = &record.Client{Id: 1, ClientIdentifier: "client1", Enabled: true, IsPublic: true}
		refreshTokenJwt = &oauth.JwtToken{Claims: jwt.MapClaims{
			"jti":                         "stored_grant_jti",
			"typ":                         "Offline",
			"sub":                         "user123",
			"offline_access_max_lifetime": float64(time.Now().UTC().Add(24 * time.Hour).Unix()),
		}}
		refreshToken = &record.RefreshToken{
			RefreshTokenJti: "stored_grant_jti",
			CodeId:          sql.NullInt64{Valid: false},
			UserId:          sql.NullInt64{Int64: 1, Valid: true},
			ClientId:        sql.NullInt64{Int64: 1, Valid: true},
			AuthenticatedAt: sql.NullTime{Time: time.Now().UTC().Add(-time.Hour), Valid: true},
			Scope:           g.scope,
			User:            user,
			Client:          *client,
		}
		mockDB.On("RefreshTokenLoadUser", mock.Anything, mock.Anything, refreshToken).Return(nil).Once()
		mockDB.On("RefreshTokenLoadClient", mock.Anything, mock.Anything, refreshToken).Return(nil).Once()
	} else {
		// Session-bound, which is what a release before #425 issued for OFFLINE_ACCESS: issuance
		// matched offline_access exactly, so the uppercase spelling never made a grant offline.
		clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
		require.NoError(t, err)
		client = &record.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			ClientSecretEncrypted:    clientSecretEncrypted,
			ConsentRequired:          g.consentScope != "",
		}
		input.ClientSecret = "client_secret"
		refreshTokenJwt = &oauth.JwtToken{Claims: jwt.MapClaims{
			"jti": "stored_grant_jti",
			"typ": "Refresh",
			"sub": "user123",
		}}
		refreshToken = &record.RefreshToken{
			RefreshTokenJti:   "stored_grant_jti",
			SessionIdentifier: "test_session",
			CodeId:            sql.NullInt64{Int64: 1, Valid: true},
			Code:              record.Code{ClientId: 1, UserId: 1, Scope: g.scope, User: user},
		}
		userSession := &record.UserSession{
			SessionIdentifier: "test_session",
			UserId:            1,
			Started:           time.Now().UTC().Add(-30 * time.Minute),
			LastAccessed:      time.Now().UTC().Add(-5 * time.Minute),
		}
		mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil).Once()
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "test_session").
			Return(userSession, nil).Once()
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()
	mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "stored_grant_refresh_token", true).
		Return(refreshTokenJwt, nil).Once()
	mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "stored_grant_jti").Return(refreshToken, nil).Once()
	mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()

	if reachesUser {
		mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, "user123").Return(&user, nil).Once()
		if g.consentScope != "" {
			mockDB.On("GetConsentByUserIdAndClientId", mock.Anything, mock.Anything, int64(1), int64(1)).
				Return(&record.UserConsent{UserId: 1, ClientId: 1, Scope: g.consentScope}, nil).Once()
		}
	}

	return validator, mockPermissionChecker, settings, input
}

// TestValidateTokenRequest_RefreshToken_StoredScopeThisServerDoesNotIssue pins the refresh arm's
// answer to a grant carrying a value that is none of the scopes this server issues: 400
// invalid_grant, with the permission checker never asked. The value that exists in production is
// OFFLINE_ACCESS, stored for a client that sent the uppercase spelling while the validators still
// case-folded offline_access, before #425 made the match exact. It used to fall through to
// UserHasScopePermission as if it were a resource scope, which refused it as a caller's bug and
// answered 500.
//
// The grant is hand-built because no current issuing path can store such a value. The integration
// tier builds the same state by rewriting a real grant's rows.
//
// No refused row registers a permission checker expectation: the strict mock fails the test if the
// value reaches the check at all, and AssertNotCalled says so explicitly.
func TestValidateTokenRequest_RefreshToken_StoredScopeThisServerDoesNotIssue(t *testing.T) {
	const notIssued = "Scope '%v' is not recognized. It is not a scope this server issues."

	testCases := []struct {
		name           string
		grant          storedGrant
		requestedScope string // empty means omitted, so the arm checks the whole stored grant
		// permissionScope, when set, is the one resource scope the checker is asked about, and
		// it answers held.
		permissionScope string
		wantDesc        string // empty means accepted
	}{
		{
			name:     "authorization code grant, scope omitted",
			grant:    storedGrant{scope: "openid profile email OFFLINE_ACCESS"},
			wantDesc: fmt.Sprintf(notIssued, "OFFLINE_ACCESS"),
		},
		{
			// The population that lasts: an ROPC refresh token is always offline, so it lives up
			// to the offline maximum lifetime.
			name:     "ROPC grant, scope omitted",
			grant:    storedGrant{ropc: true, scope: "openid OFFLINE_ACCESS"},
			wantDesc: fmt.Sprintf(notIssued, "OFFLINE_ACCESS"),
		},
		{
			// The comparison with the grant passes, since the value is in it, and the refusal
			// still comes: asking for it explicitly is no different from inheriting it.
			name:           "the value requested explicitly",
			grant:          storedGrant{scope: "openid profile email OFFLINE_ACCESS"},
			requestedScope: "openid OFFLINE_ACCESS",
			wantDesc:       fmt.Sprintf(notIssued, "OFFLINE_ACCESS"),
		},
		{
			// The way out a client already has, and the reason the refusal must not spend the
			// token: narrowing the request to leave the value out.
			name:           "authorization code grant, a request that leaves the value out",
			grant:          storedGrant{scope: "openid profile email OFFLINE_ACCESS"},
			requestedScope: "openid profile",
		},
		{
			name:           "ROPC grant, a request that leaves the value out",
			grant:          storedGrant{ropc: true, scope: "openid OFFLINE_ACCESS"},
			requestedScope: "openid",
		},
		{
			name:     "a mixed-case spelling",
			grant:    storedGrant{scope: "openid Offline_Access"},
			wantDesc: fmt.Sprintf(notIssued, "Offline_Access"),
		},
		{
			name:     "a value with two separators",
			grant:    storedGrant{scope: "openid backend-svc:read:extra"},
			wantDesc: fmt.Sprintf(notIssued, "backend-svc:read:extra"),
		},
		{
			// Refused before the consent comparison, so the answer does not depend on the client's
			// consent setting. Checked the other way round, this consent row, which lacks the
			// value, would refuse it as unconsented instead.
			name:     "a client requiring consent gets the same answer",
			grant:    storedGrant{scope: "openid profile OFFLINE_ACCESS", consentScope: "openid profile"},
			wantDesc: fmt.Sprintf(notIssued, "OFFLINE_ACCESS"),
		},
		{
			// The negative control: a resource-shaped value still goes to the permission check, so
			// the refusal does not swallow resource scopes.
			name:            "a resource scope still reaches the permission check",
			grant:           storedGrant{scope: "openid backend-svc:read"},
			permissionScope: "backend-svc:read",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator, mockPermissionChecker, settings, input := newStoredGrantRefresh(t, tc.grant, tc.requestedScope, true)
			if tc.permissionScope != "" {
				mockPermissionChecker.On("UserHasScopePermission", mock.Anything, int64(1), tc.permissionScope).
					Return(true, nil).Once()
			}

			result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

			if tc.wantDesc == "" {
				require.NoError(t, err)
				assert.NotNil(t, result)
				return
			}

			assert.Nil(t, result)
			var customErr *oauth.ErrorDetail
			require.ErrorAs(t, err, &customErr)
			assert.Equal(t, "invalid_grant", customErr.Code())
			assert.Equal(t, tc.wantDesc, customErr.Description())
			assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
			mockPermissionChecker.AssertNotCalled(t, "UserHasScopePermission", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// TestValidateTokenRequest_RefreshToken_RequestedScopeBeyondTheGrant pins invalid_scope for a
// refresh that asks for a value its grant does not hold, on both kinds of grant: RFC 6749 section
// 5.2 names invalid_scope for a requested scope that "exceeds the scope granted by the resource
// owner". It answered invalid_grant until #425. The comparison comes before the subject lookup,
// so newStoredGrantRefresh stubs neither the user nor the consent row, and the permission checker
// is never asked.
func TestValidateTokenRequest_RefreshToken_RequestedScopeBeyondTheGrant(t *testing.T) {
	testCases := []struct {
		name           string
		grant          storedGrant
		requestedScope string
		beyond         string // the value the request asks for beyond the grant
	}{
		{
			name:           "authorization code grant asked for a resource scope it does not hold",
			grant:          storedGrant{scope: "openid profile"},
			requestedScope: "openid backend-svc:read",
			beyond:         "backend-svc:read",
		},
		{
			name:           "ROPC grant asked for a resource scope it does not hold",
			grant:          storedGrant{ropc: true, scope: "openid"},
			requestedScope: "openid backend-svc:read",
			beyond:         "backend-svc:read",
		},
		{
			// Scope values are case-sensitive, RFC 6749 section 3.3: a grant that stored the
			// uppercase spelling does not hold offline_access, so asking for it asks beyond the grant.
			name:           "offline_access against a grant that stored the uppercase spelling",
			grant:          storedGrant{scope: "openid OFFLINE_ACCESS"},
			requestedScope: "openid offline_access",
			beyond:         "offline_access",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator, mockPermissionChecker, settings, input := newStoredGrantRefresh(t, tc.grant, tc.requestedScope, false)

			result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

			assert.Nil(t, result)
			var customErr *oauth.ErrorDetail
			require.ErrorAs(t, err, &customErr)
			assert.Equal(t, "invalid_scope", customErr.Code())
			assert.Equal(t,
				fmt.Sprintf("Scope '%v' is not recognized. The original access token does not grant the '%v' permission.",
					tc.beyond, tc.beyond),
				customErr.Description())
			assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
			mockPermissionChecker.AssertNotCalled(t, "UserHasScopePermission", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// TestValidateTokenRequest_RefreshToken_RequestedScopeWithinTheGrant pins that a refresh asking for
// the whole grant, or a part of it, is accepted on both kinds of grant, which RFC 6749 section 6
// permits for any scope "originally granted by the resource owner". The whole grant is the first
// row because it is what a client echoing the reported scope sends: the reported scope is the grant
// since #449, where it used to carry an appended authserver:userinfo the grant did not hold, so the
// echo was refused as asking beyond it. A resource scope in the request is re-checked against the
// user's permissions; a claim scope is not a permission and is not.
func TestValidateTokenRequest_RefreshToken_RequestedScopeWithinTheGrant(t *testing.T) {
	const grant = "openid profile backend-svc:read"

	testCases := []struct {
		name           string
		grant          storedGrant
		requestedScope string
		// permissionScope, when set, is the one resource scope the checker is asked about, and it
		// answers held. Empty means the checker must not be asked at all.
		permissionScope string
	}{
		{
			name:            "authorization code grant, the whole grant echoed",
			grant:           storedGrant{scope: grant},
			requestedScope:  grant,
			permissionScope: "backend-svc:read",
		},
		{
			name:            "ROPC grant, the whole grant echoed",
			grant:           storedGrant{ropc: true, scope: grant},
			requestedScope:  grant,
			permissionScope: "backend-svc:read",
		},
		{
			name:           "authorization code grant, narrowed to openid",
			grant:          storedGrant{scope: grant},
			requestedScope: "openid",
		},
		{
			name:           "ROPC grant, narrowed to openid",
			grant:          storedGrant{ropc: true, scope: grant},
			requestedScope: "openid",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator, mockPermissionChecker, settings, input := newStoredGrantRefresh(t, tc.grant, tc.requestedScope, true)
			if tc.permissionScope != "" {
				mockPermissionChecker.On("UserHasScopePermission", mock.Anything, int64(1), tc.permissionScope).
					Return(true, nil).Once()
			}

			result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

			require.NoError(t, err)
			assert.NotNil(t, result)
			if tc.permissionScope == "" {
				mockPermissionChecker.AssertNotCalled(t, "UserHasScopePermission", mock.Anything, mock.Anything, mock.Anything)
			}
		})
	}
}

// TestValidateTokenRequest_RefreshToken_StoredGrantNamingUserinfo pins what a refresh token whose
// stored grant names authserver:userinfo gets once the permission it named is gone: 400
// invalid_grant from the ordinary permission re-check, which asks the checker and is answered false,
// as UserHasScopePermission answers for a permission that no longer exists. Such a grant is an ROPC
// token issued before its refresh token recorded the undecorated grant, or one that requested the
// scope explicitly. Until #449 the re-check exempted the scope when the grant also held a claim scope,
// because issuance appended it to every such token; nothing appends it now, and /userinfo gates on
// openid, so the exemption went with the append.
//
// The refusal comes before the token is spent, so narrowing the request to leave the scope out
// still refreshes, the last row. Nothing earlier refuses these grants: the scope is in the grant, so
// the subset comparison passes, and it is resource-shaped, so the not-issued check passes.
func TestValidateTokenRequest_RefreshToken_StoredGrantNamingUserinfo(t *testing.T) {
	const userinfoScope = "authserver:userinfo"

	testCases := []struct {
		name           string
		storedScope    string
		requestedScope string // empty means omitted, so the arm checks the whole stored grant
		wantAccepted   bool
	}{
		{
			// Keep this: accepted until #449, through the exemption.
			name:        "beside openid, scope omitted",
			storedScope: "openid " + userinfoScope,
		},
		{
			// Keep this: accepted until #449, through the exemption, which read the stored grant
			// rather than the request.
			name:           "beside openid, requested explicitly",
			storedScope:    "openid " + userinfoScope,
			requestedScope: userinfoScope,
		},
		{
			// Refused before #449 too: with no claim scope the exemption never applied.
			name:        "alone",
			storedScope: userinfoScope,
		},
		{
			name:           "beside openid, a request that leaves it out",
			storedScope:    "openid " + userinfoScope,
			requestedScope: "openid",
			wantAccepted:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator, mockPermissionChecker, settings, input := newStoredGrantRefresh(t,
				storedGrant{ropc: true, scope: tc.storedScope}, tc.requestedScope, true)
			if !tc.wantAccepted {
				mockPermissionChecker.On("UserHasScopePermission", mock.Anything, int64(1), userinfoScope).
					Return(false, nil).Once()
			}

			result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

			if tc.wantAccepted {
				require.NoError(t, err)
				assert.NotNil(t, result)
				mockPermissionChecker.AssertNotCalled(t, "UserHasScopePermission", mock.Anything, mock.Anything, mock.Anything)
				return
			}

			assert.Nil(t, result)
			var customErr *oauth.ErrorDetail
			require.ErrorAs(t, err, &customErr)
			assert.Equal(t, "invalid_grant", customErr.Code())
			assert.Equal(t,
				"Scope 'authserver:userinfo' is not recognized. The user does not have the 'authserver:userinfo' permission.",
				customErr.Description())
			assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
		})
	}
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
	mockDB := datamocks.NewDatabase(t)
	mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
	mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)
	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	settings := &record.Settings{}
	ctx := context.Background()

	input := &ValidateTokenRequestInput{
		GrantType:    "refresh_token",
		ClientId:     "client1",
		RefreshToken: "expired_refresh_token",
	}

	client := &record.Client{
		ClientIdentifier:         "client1",
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 true,
	}
	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()

	// withExpirationCheck = true is what makes the parser reject an expired token.
	mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "expired_refresh_token", true).
		Return(nil, errors.New("token has invalid claims: token is expired")).Once()

	result, err := validator.ValidateTokenRequest(ctx, settings, input)

	assert.Nil(t, result)
	require.Error(t, err)

	detail, ok := err.(*oauth.ErrorDetail)
	require.Truef(t, ok, "an expired refresh token must be an ErrorDetail, got %T", err)
	assert.Equal(t, "invalid_grant", detail.Code())
	assert.Equal(t, http.StatusBadRequest, detail.HTTPStatus())

	// Structurally redundant today, kept as a guard. See the doc comment.
	mockDB.AssertNotCalled(t, "GetRefreshTokenByJti", mock.Anything, mock.Anything, mock.Anything)

	mockDB.AssertExpectations(t)
	mockTokenParser.AssertExpectations(t)
}

// TestValidateTokenRequest_RefreshToken_SessionOwnership covers the refresh half of #133's
// post-issuance backstop: a normal refresh token names a session in its `sid`, and until this
// check nothing on the path compared that session's owner with the grant's user.
//
// The two subtests differ in exactly one field, the session's UserId, so neither can pass with
// the comparison removed. Everything else is the ordinary auth code flow refresh: the grant
// belongs to user 1, the client matches, the session is well inside both its idle timeout and
// its max lifetime.
//
// A cross-bound grant is no longer reachable through issuance, so what this protects is the
// tokens minted before that fix. Left unchecked they refresh indefinitely against a stranger's
// session and bump it on the way, which both keeps that session alive on someone else's
// activity and ends the grant when its owner signs out.
func TestValidateTokenRequest_RefreshToken_SessionOwnership(t *testing.T) {
	const grantUserId = int64(1)

	setup := func(t *testing.T, sessionUserId int64) (*TokenValidator, *ValidateTokenRequestInput, *record.Settings) {
		t.Helper()

		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)
		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &record.Settings{
			UserSessionIdleTimeoutInSeconds: 3600,
			UserSessionMaxLifetimeInSeconds: 86400,
		}

		// Confidential, and it used to be public (#245). The subject is session ownership,
		// and the grant's code carries no challenge, so a public client would now be refused
		// by the PKCE boundary before the session is ever looked up.
		clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
		require.NoError(t, err)

		client := &record.Client{
			Id:                       1,
			ClientIdentifier:         "client1",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
		}

		refreshTokenJwt := &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"jti": "ownership_jti",
				"typ": "Refresh",
				"sub": "user123",
			},
		}

		refreshToken := &record.RefreshToken{
			RefreshTokenJti:   "ownership_jti",
			SessionIdentifier: "session_of_interest",
			CodeId:            sql.NullInt64{Int64: 1, Valid: true}, // auth code flow token
			Code: record.Code{
				ClientId: 1,
				UserId:   grantUserId,
				Scope:    "openid",
				User: record.User{
					Id:      grantUserId,
					Enabled: true,
				},
			},
		}

		userSession := &record.UserSession{
			SessionIdentifier: "session_of_interest",
			UserId:            sessionUserId,
			Started:           time.Now().UTC().Add(-30 * time.Minute),
			LastAccessed:      time.Now().UTC().Add(-5 * time.Minute),
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "ownership_refresh_token", true).
			Return(refreshTokenJwt, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "ownership_jti").Return(refreshToken, nil)
		mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
		mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil)
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "session_of_interest").
			Return(userSession, nil)
		// Only reached once the session is accepted, so the refusing subtest never calls it.
		mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, "user123").
			Return(&record.User{Id: grantUserId, Enabled: true}, nil).Maybe()

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "client1",
			ClientSecret: "client_secret",
			RefreshToken: "ownership_refresh_token",
		}

		return validator, input, settings
	}

	t.Run("a session belonging to the grant's user is accepted", func(t *testing.T) {
		validator, input, settings := setup(t, grantUserId)

		result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("a session belonging to another user is refused", func(t *testing.T) {
		validator, input, settings := setup(t, grantUserId+1)

		result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.Code())
		assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
		// The same wording an expired or terminated session gets. A distinct message here
		// would tell the presenter that the session exists and belongs to someone else.
		assert.Contains(t, customErr.Description(),
			"the associated session has expired or been terminated")
	})
}

// TestValidateTokenRequest_OfflineRefreshToken_SessionOwnership covers the last shape #133's
// decision 8 reaches: an offline refresh token descended from a cross-bound authorization
// code. The Offline arm deliberately never consults the session, because an offline grant is
// meant to outlive the browser session it came from, and that silence is what a pre-fix
// cross-bound grant rode for the whole offline maximum lifetime, seeded at a year, re-copying
// the code's inherited acr on every rotation. Only acr was inherited: amr and auth_time
// described the ceremony that actually happened.
//
// The three rows are the same three the code branch has, and the middle one carries the same
// weight for a stronger reason here: "the session is gone" is not an edge case for an offline
// grant, it is the steady state, so the swept row is what proves this check did not quietly
// tie offline tokens back to a session.
//
// The session identifier is read from the CODE, not from the token row. Only a Refresh token
// stores one of its own; for an Offline token the issuer puts the max lifetime in that column
// instead, which is why the fixture leaves RefreshToken.SessionIdentifier empty.
func TestValidateTokenRequest_OfflineRefreshToken_SessionOwnership(t *testing.T) {
	const grantUserId = int64(7)
	const sid = "sid-of-the-browser"

	// lookupErr makes the session lookup fail. expired puts the grant past its offline
	// maximum lifetime and registers NO lookup at all, so the strict mock is what asserts
	// the ordering: reaching the session before rejecting an expired token is a failure,
	// not a slower pass.
	setup := func(t *testing.T, sessionOwner *int64, lookupErr error, expired bool) (*TokenValidator, *ValidateTokenRequestInput, *record.Settings) {
		t.Helper()

		mockDB := datamocks.NewDatabase(t)
		mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
		mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)
		validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

		settings := &record.Settings{}

		// Confidential, and it used to be public (#245). The subject is the offline grant's
		// session ownership, and its code carries no challenge, so a public client would now
		// be refused by the PKCE boundary before any of these rows could measure anything.
		clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
		require.NoError(t, err)

		client := &record.Client{
			Id:                       1,
			ClientIdentifier:         "test_client",
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			IsPublic:                 false,
			ClientSecretEncrypted:    clientSecretEncrypted,
		}
		user := record.User{Id: grantUserId, Enabled: true}

		refreshToken := &record.RefreshToken{
			RefreshTokenJti: "the-jti",
			CodeId:          sql.NullInt64{Int64: 5, Valid: true},
			// Empty, and that is production's shape for an Offline token rather than a
			// shortcut: the issuer stores the max lifetime in this column instead.
			SessionIdentifier: "",
			Code: record.Code{
				Id: 5, ClientId: 1, UserId: grantUserId, Scope: "openid offline_access",
				SessionIdentifier: sid,
				User:              user,
			},
		}

		maxLifetime := time.Now().UTC().Add(24 * time.Hour)
		if expired {
			maxLifetime = time.Now().UTC().Add(-1 * time.Hour)
		}
		offlineClaims := &oauth.JwtToken{Claims: jwt.MapClaims{
			"jti": "the-jti", "typ": "Offline", "sub": "user_subject",
			"offline_access_max_lifetime": float64(maxLifetime.Unix()),
		}}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test_client").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "the-refresh-token", true).
			Return(offlineClaims, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "the-jti").Return(refreshToken, nil)
		mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
		mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil)

		switch {
		case expired:
			// Deliberately no expectation. datamocks.Database is strict, so a lookup here
			// fails the test, which is the whole assertion.
		case lookupErr != nil:
			mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sid).Return(nil, lookupErr).Once()
		case sessionOwner == nil:
			mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sid).Return(nil, nil).Once()
		default:
			mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sid).
				Return(&record.UserSession{SessionIdentifier: sid, UserId: *sessionOwner}, nil).Once()
		}

		// Only the accepted rows reach these two: an Offline refresh always re-checks
		// consent, whatever the client's ConsentRequired says.
		mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, "user_subject").Return(&user, nil).Maybe()
		mockDB.On("GetConsentByUserIdAndClientId", mock.Anything, mock.Anything, grantUserId, int64(1)).
			Return(&record.UserConsent{UserId: grantUserId, ClientId: 1, Scope: "openid offline_access"}, nil).Maybe()

		input := &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "test_client",
			ClientSecret: "client_secret",
			RefreshToken: "the-refresh-token",
		}

		return validator, input, settings
	}

	owner := func(id int64) *int64 { return &id }

	t.Run("a session belonging to the grant's user is accepted", func(t *testing.T) {
		validator, input, settings := setup(t, owner(grantUserId), nil, false)

		result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("a session that has already been swept is accepted", func(t *testing.T) {
		// An offline grant outliving its session is the whole point of the type. This row
		// is what pins that the new check did not change that.
		validator, input, settings := setup(t, nil, nil, false)

		result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("a failed lookup is propagated, not read as a swept session", func(t *testing.T) {
		// Absence accepts, and for an offline grant absence is the steady state, so the
		// temptation to treat a failed lookup as one more way of being absent is real here.
		// It must not be: a database that cannot answer has not said the session is gone.
		lookupErr := errors.New("database is down")
		validator, input, settings := setup(t, nil, lookupErr, false)

		result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

		assert.Nil(t, result)
		assert.ErrorIs(t, err, lookupErr)
		_, isErrorDetail := err.(*oauth.ErrorDetail)
		assert.False(t, isErrorDetail, "a database failure must not be reported as an OAuth error")
	})

	t.Run("an expired grant is refused before the session is ever looked up", func(t *testing.T) {
		// The ordering #133 requires, expiry checked before the session lookup, and the one shape
		// that can observe it: an affected grant, so its code carries a session identifier, that
		// is already past its offline maximum lifetime. Every other expired-offline fixture in
		// this file has an empty code sid and so performs no lookup whatever the order. The strict
		// mock carries the assertion; the error only confirms which gate did the refusing.
		validator, input, settings := setup(t, owner(grantUserId+1), nil, true)

		result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

		assert.Nil(t, result)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.Code())
		assert.Contains(t, customErr.Description(), "offline_access_max_lifetime")
	})

	t.Run("a session belonging to another user is refused", func(t *testing.T) {
		validator, input, settings := setup(t, owner(grantUserId+1), nil, false)

		result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_grant", customErr.Code())
		assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
		// The shared session message, the same one a revoked code gets on this arm.
		assert.Contains(t, customErr.Description(),
			"the associated session has expired or been terminated")
	})
}

// TestValidateTokenRequest_RefreshToken_SubjectResolvesToNoUser covers #123: GetUserBySubject
// answers (nil, nil) for a subject that names no row, and the permission re-check dereferences
// user.Id, so the process panicked.
//
// The two rows pin the PLACEMENT of the refusal, not merely its existence. The dereference sits
// inside a branch skipped for OIDC scopes and offline_access, so a
// check written at the dereference passes the resource-scope row and fails the OIDC-only one: that
// refresh would be accepted, minting a fresh access token for a subject that resolves to nothing.
// Only a check above the loop satisfies both.
//
// Both rows assert a plain error rather than a *oauth.ErrorDetail, which is the 500 of
// decision 8a. No supported operation can produce such a token (DeleteUser removes the user's
// refresh tokens in the same transaction, and the authorization-code ones go by CASCADE), so this
// is an internal inconsistency rather than anything the client did, and this arm already answers
// its other signed-but-impossible states the same way.
func TestValidateTokenRequest_RefreshToken_SubjectResolvesToNoUser(t *testing.T) {
	testCases := []struct {
		name string
		// storedScope is RefreshToken.Scope, which for a ROPC token is what the validator re-checks.
		storedScope string
	}{
		{
			// Never reaches the dereference: IsClaimScope skips the permission re-check
			// entirely. Today this arm would succeed, so it is the row that fails if the refusal
			// is written at the panic site instead of above the loop.
			name:        "an OIDC-only scope never reaches the dereference and is still refused",
			storedScope: "openid",
		},
		{
			// The panic path #123 reports: a resource scope takes the branch that reads user.Id.
			// No UserHasScopePermission expectation is registered, and protocolvalidationmocks.NewPermissionChecker(t)
			// fails on an unexpected call, so this also proves the refusal happens before the loop.
			name:        "a resource scope is refused before the permission re-check",
			storedScope: "billing-api:read",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := datamocks.NewDatabase(t)
			mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
			mockPermissionChecker := protocolvalidationmocks.NewPermissionChecker(t)

			validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)
			settings := &record.Settings{}
			ctx := context.Background()

			input := &ValidateTokenRequestInput{
				GrantType:    "refresh_token",
				ClientId:     "ropc_client",
				RefreshToken: "ropc_refresh_token",
			}

			client := &record.Client{
				Id:                       1,
				ClientIdentifier:         "ropc_client",
				Enabled:                  true,
				AuthorizationCodeEnabled: true,
				IsPublic:                 true,
			}

			refreshTokenJwt := &oauth.JwtToken{
				Claims: jwt.MapClaims{
					"jti":                         "ropc_jti",
					"typ":                         "Offline",
					"sub":                         "orphaned_subject",
					"offline_access_max_lifetime": float64(time.Now().UTC().Add(24 * time.Hour).Unix()),
				},
			}

			// CodeId invalid marks this a ROPC token, which is what makes the validator read
			// RefreshToken.Scope and skip the consent check.
			refreshToken := &record.RefreshToken{
				RefreshTokenJti: "ropc_jti",
				CodeId:          sql.NullInt64{Valid: false},
				UserId:          sql.NullInt64{Int64: 7, Valid: true},
				ClientId:        sql.NullInt64{Int64: 1, Valid: true},
				AuthenticatedAt: sql.NullTime{Time: time.Now().UTC().Add(-time.Hour), Valid: true},
				Scope:           tc.storedScope,
				User:            record.User{Id: 7, Enabled: true},
				Client:          *client,
			}

			mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc_client").Return(client, nil)
			mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "ropc_refresh_token", true).
				Return(refreshTokenJwt, nil)
			mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "ropc_jti").Return(refreshToken, nil)
			mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
			mockDB.On("RefreshTokenLoadUser", mock.Anything, mock.Anything, refreshToken).Return(nil)
			mockDB.On("RefreshTokenLoadClient", mock.Anything, mock.Anything, refreshToken).Return(nil)

			// The row the whole test is about: a signed, live refresh token whose sub names nothing.
			mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, "orphaned_subject").Return(nil, nil)

			result, err := validator.ValidateTokenRequest(ctx, settings, input)

			assert.Nil(t, result)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "subject not found: orphaned_subject")

			// A 500, not a 400: an ErrorDetail here would mean the server told the client its
			// request was bad when the tokens and the users table disagree.
			var detail *oauth.ErrorDetail
			assert.False(t, errors.As(err, &detail),
				"expected a plain error carrying a 500, got a client-facing ErrorDetail: %v", err)
		})
	}
}
