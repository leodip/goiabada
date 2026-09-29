package protocolvalidation

import (
	"context"
	"database/sql"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	mocks_protocolvalidation "github.com/leodip/goiabada/authserver/internal/protocolvalidation/mocks"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestValidateTokenRequest_RefreshToken_TheAuthenticationInstant pins #125's refusal at the token
// endpoint. An ROPC refresh token carries its grant's authentication instant on its own row, since
// the grant has no code; one issued before migration 000051 carries none, and no refresh of it can
// issue the auth_time OpenID Connect Core 1.0 section 12.2 requires, so it is refused as
// invalid_grant, per RFC 6749 section 5.2. An authorization-code token's instant is on its code, so
// the column is NULL on every one of them and that is no reason to refuse it.
//
// Strict mocks throughout: a refused row registers nothing past the refusal, so a refusal that
// came later than it should, reading the user by subject, fails the test.
func TestValidateTokenRequest_RefreshToken_TheAuthenticationInstant(t *testing.T) {
	recorded := sql.NullTime{Time: time.Now().UTC().Add(-72 * time.Hour), Valid: true}

	t.Run("ROPC", func(t *testing.T) {
		for _, tc := range []struct {
			name          string
			instant       sql.NullTime
			tokenClientId int64
			wantCode      string
			wantDesc      string // empty means accepted
		}{
			{"a token recording its instant is refreshable", recorded, 1, "", ""},
			{"a token recording none is refused", sql.NullTime{}, 1,
				"invalid_grant", "The refresh token is invalid."},
			// Ownership comes first, so another client presenting a pre-000051 token learns only
			// that it is not theirs.
			{"another client's token recording none is refused as not its own", sql.NullTime{}, 2,
				"invalid_request", "The refresh token is invalid because it does not belong to the client."},
		} {
			t.Run(tc.name, func(t *testing.T) {
				mockDB := mocks_data.NewDatabase(t)
				mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
				validator := NewTokenValidator(mockDB, mockTokenParser, mocks_protocolvalidation.NewPermissionChecker(t), testDataCipher)

				client := &models.Client{
					Id: 1, ClientIdentifier: "ropc_client", Enabled: true,
					AuthorizationCodeEnabled: true, IsPublic: true,
				}
				user := models.User{Id: 7, Enabled: true}
				refreshToken := &models.RefreshToken{
					RefreshTokenJti: "ropc_jti",
					CodeId:          sql.NullInt64{Valid: false},
					UserId:          sql.NullInt64{Int64: 7, Valid: true},
					ClientId:        sql.NullInt64{Int64: tc.tokenClientId, Valid: true},
					AuthenticatedAt: tc.instant,
					Scope:           "openid",
					User:            user,
					Client:          *client,
				}

				mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc_client").Return(client, nil)
				mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "ropc_refresh_token", true).
					Return(&oauth.JwtToken{Claims: jwt.MapClaims{
						"jti": "ropc_jti", "typ": "Offline", "sub": "ropc_user_subject",
						"offline_access_max_lifetime": float64(time.Now().UTC().Add(24 * time.Hour).Unix()),
					}}, nil)
				mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "ropc_jti").Return(refreshToken, nil)
				mockDB.On("RefreshTokenLoadUser", mock.Anything, mock.Anything, refreshToken).Return(nil)
				mockDB.On("RefreshTokenLoadClient", mock.Anything, mock.Anything, refreshToken).Return(nil)
				if tc.wantDesc == "" {
					mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, "ropc_user_subject").Return(&user, nil)
				}

				result, err := validator.ValidateTokenRequest(context.Background(), &models.Settings{}, &ValidateTokenRequestInput{
					GrantType:    "refresh_token",
					ClientId:     "ropc_client",
					RefreshToken: "ropc_refresh_token",
				})

				if tc.wantDesc == "" {
					require.NoError(t, err)
					grant := grantAs[*RefreshTokenGrant](t, result)
					assert.Same(t, refreshToken, grant.RefreshToken)
					assert.True(t, grant.IsROPC, "a token with no code was minted by the password grant")
					return
				}
				assert.Nil(t, result)
				var detail *customerrors.ErrorDetail
				require.ErrorAs(t, err, &detail)
				assert.Equal(t, tc.wantCode, detail.GetCode())
				assert.Equal(t, tc.wantDesc, detail.GetDescription())
				assert.Equal(t, http.StatusBadRequest, detail.GetHttpStatusCode())
			})
		}
	})

	t.Run("an authorization-code token needs none, its instant being on its code", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		validator := NewTokenValidator(mockDB, mockTokenParser, mocks_protocolvalidation.NewPermissionChecker(t), testDataCipher)

		clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
		require.NoError(t, err)
		client := &models.Client{
			Id: 1, ClientIdentifier: "test_client", Enabled: true,
			AuthorizationCodeEnabled: true, ClientSecretEncrypted: clientSecretEncrypted,
		}
		user := models.User{Id: 7, Enabled: true}
		refreshToken := &models.RefreshToken{
			RefreshTokenJti:   "the-jti",
			CodeId:            sql.NullInt64{Int64: 5, Valid: true},
			SessionIdentifier: "sid-1",
			// NULL, as on every authorization-code token.
			AuthenticatedAt: sql.NullTime{},
			Code: models.Code{
				Id: 5, ClientId: 1, UserId: 7, Scope: "openid", SessionIdentifier: "sid-1",
				AuthenticatedAt: recorded.Time, User: user,
			},
		}

		now := time.Now().UTC()
		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test_client").Return(client, nil)
		mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "the-refresh-token", true).
			Return(&oauth.JwtToken{Claims: jwt.MapClaims{"jti": "the-jti", "typ": "Refresh", "sub": "user_subject"}}, nil)
		mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "the-jti").Return(refreshToken, nil)
		mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil)
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil)
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "sid-1").
			Return(&models.UserSession{
				Id: 9, SessionIdentifier: "sid-1", UserId: 7,
				Started: now.Add(-10 * time.Minute), LastAccessed: now,
			}, nil)
		mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, "user_subject").Return(&user, nil)

		result, err := validator.ValidateTokenRequest(context.Background(), &models.Settings{
			UserSessionIdleTimeoutInSeconds: 3600,
			UserSessionMaxLifetimeInSeconds: 86400,
		}, &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "test_client",
			ClientSecret: "client_secret",
			RefreshToken: "the-refresh-token",
		})

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Same(t, refreshToken, grantAs[*RefreshTokenGrant](t, result).RefreshToken)
	})
}
