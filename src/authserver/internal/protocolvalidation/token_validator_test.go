package protocolvalidation

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_protocolvalidation "github.com/leodip/goiabada/authserver/internal/protocolvalidation/mocks"
)

// expectRedirectURIStillRegistered arms the registration read #241 added at the very end of the
// authorization_code arm, for the fixtures either side of it whose subject is something else. The
// URI it registers is the one the fixture's code carries, so these tests keep asserting what they
// always asserted and the new check simply passes.
//
// .Maybe() rather than .Once(), because several of these fixtures are shared by subtests that
// refuse higher up the arm and never reach the read. Nothing is weakened by that: the check is
// owned by TestValidateTokenRequest_AuthorizationCode_RedirectURIStillRegistered, which asserts
// both that it fires and, through the ABSENCE of this expectation, that it does not fire above
// client authentication and PKCE.
func expectRedirectURIStillRegistered(mockDB *mocks_data.Database, uri string) {
	mockDB.On("ClientLoadRedirectURIs", mock.Anything, mock.Anything, mock.AnythingOfType("*models.Client")).
		Run(func(args mock.Arguments) {
			c := args.Get(2).(*models.Client)
			c.RedirectURIs = []models.RedirectURI{{URI: uri}}
		}).Return(nil).Maybe()
}

// grantAs asserts that a validated request is the grant a case expects and returns it typed, so a
// case that reads a field reads it off the one grant that carries it (#437).
func grantAs[G TokenGrant](t *testing.T, grant TokenGrant) G {
	t.Helper()
	typed, ok := grant.(G)
	require.True(t, ok, "the validator returned %T", grant)
	return typed
}

func TestValidateTokenRequest(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
	mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)

	validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)

	t.Run("Missing required client_id", func(t *testing.T) {
		input := &ValidateTokenRequestInput{
			GrantType: "authorization_code",
			// ClientId is intentionally left empty
		}

		settings := &models.Settings{}
		ctx := context.Background()
		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_request", customErr.Code())
		assert.Equal(t, "Missing required client_id parameter.", customErr.Description())
		assert.Equal(t, 400, customErr.HTTPStatus())
	})

	t.Run("Client does not exist", func(t *testing.T) {
		input := &ValidateTokenRequestInput{
			GrantType: "authorization_code",
			ClientId:  "non_existent_client",
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "non_existent_client").Return(nil, nil)

		settings := &models.Settings{}
		ctx := context.Background()
		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_client", customErr.Code())
		assert.Equal(t, "Client does not exist.", customErr.Description())
		assert.Equal(t, 401, customErr.HTTPStatus())
		assert.Equal(t, `Basic realm="goiabada"`, customErr.WWWAuthenticate())
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

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "disabled_client").Return(disabledClient, nil)

		settings := &models.Settings{}
		ctx := context.Background()
		result, err := validator.ValidateTokenRequest(ctx, settings, input)

		assert.Nil(t, result)
		assert.Error(t, err)
		customErr, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_client", customErr.Code())
		assert.Equal(t, "Client is disabled.", customErr.Description())
		assert.Equal(t, 401, customErr.HTTPStatus())
		assert.Equal(t, `Basic realm="goiabada"`, customErr.WWWAuthenticate())
	})

	// The rows below consult oidc's grant table through the exported method; the table's own rows
	// are pinned in oidc/grant_type_test.go (#437). Before the table, unsupported_grant_type was
	// asserted only by the integration tier.
	enabledClient := &models.Client{Id: 42, ClientIdentifier: "grant_table_client", Enabled: true}
	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "grant_table_client").Return(enabledClient, nil)

	for _, grantType := range []string{"implicit", "PASSWORD", "urn:ietf:params:oauth:grant-type:device_code"} {
		t.Run("grant the table does not accept: "+grantType, func(t *testing.T) {
			input := &ValidateTokenRequestInput{GrantType: oidc.GrantType(grantType), ClientId: "grant_table_client"}

			result, err := validator.ValidateTokenRequest(context.Background(), &models.Settings{}, input)

			assert.Nil(t, result)
			var customErr *oauth.ErrorDetail
			require.ErrorAs(t, err, &customErr)
			assert.Equal(t, "unsupported_grant_type", customErr.Code())
			assert.Equal(t, "Unsupported grant_type.", customErr.Description())
			assert.Equal(t, 400, customErr.HTTPStatus())
		})
	}

	// The table and the validator's arms agree: every grant the table accepts reaches an arm,
	// which refuses this otherwise empty request on its own terms (a flow switched off, or no
	// client secret), never as an unsupported grant and never as the no-arm internal error.
	for _, grantType := range []oidc.GrantType{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken,
		oidc.GrantTypeClientCredentials, oidc.GrantTypePassword} {
		t.Run("grant the table accepts reaches its arm: "+grantType.String(), func(t *testing.T) {
			input := &ValidateTokenRequestInput{GrantType: grantType, ClientId: "grant_table_client"}

			result, err := validator.ValidateTokenRequest(context.Background(), &models.Settings{}, input)

			assert.Nil(t, result)
			var customErr *oauth.ErrorDetail
			require.ErrorAs(t, err, &customErr)
			assert.NotEqual(t, "unsupported_grant_type", customErr.Code())
		})
	}

	// The client checks run before the grant check, as they did when the switch's default arm
	// answered it: an unknown grant with no client_id is still the missing client_id.
	t.Run("unknown grant with a missing client_id answers the client_id first", func(t *testing.T) {
		input := &ValidateTokenRequestInput{GrantType: "urn:ietf:params:oauth:grant-type:device_code"}

		result, err := validator.ValidateTokenRequest(context.Background(), &models.Settings{}, input)

		assert.Nil(t, result)
		var customErr *oauth.ErrorDetail
		require.ErrorAs(t, err, &customErr)
		assert.Equal(t, "invalid_request", customErr.Code())
		assert.Equal(t, "Missing required client_id parameter.", customErr.Description())
	})
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
				mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
				mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)
				validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)
				settings := &models.Settings{}
				ctx := context.Background()

				// Confidential, with a secret, because the subject here is the generation
				// boundary and nothing else. It was public only to sidestep the secret
				// check, and a public client with a challenge-less code is now refused
				// before the generation check is ever reached (#245).
				clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
				require.NoError(t, err)

				client := &models.Client{
					Id: 1, ClientIdentifier: "test_client", Enabled: true,
					AuthorizationCodeEnabled: true, IsPublic: false,
					ClientSecretEncrypted: clientSecretEncrypted,
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

				mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test_client").Return(client, nil)
				mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.Anything, false).Return(code, nil)
				// No-ops: Client and User are already populated on the fixture above, and the
				// loaders are what the validator calls before reaching the generation check.
				mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, code).Return(nil)
				mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, code).Return(nil)
				expectRedirectURIStillRegistered(mockDB, "https://example.com/cb")

				result, err := validator.ValidateTokenRequest(ctx, settings, &ValidateTokenRequestInput{
					GrantType:    "authorization_code",
					ClientId:     "test_client",
					ClientSecret: "client_secret",
					Code:         "the-code",
					RedirectURI:  "https://example.com/cb",
				})

				if tc.wantAccepted {
					assert.NoError(t, err)
					assert.NotNil(t, result)
					return
				}
				assert.Nil(t, result)
				customErr, ok := err.(*oauth.ErrorDetail)
				if assert.True(t, ok, "expected *oauth.ErrorDetail, got %T: %v", err, err) {
					assert.Equal(t, "invalid_grant", customErr.Code())
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
				mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
				mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)
				validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)
				settings := &models.Settings{
					UserSessionIdleTimeoutInSeconds: 3600,
					UserSessionMaxLifetimeInSeconds: 86400,
				}
				ctx := context.Background()

				// Confidential for the same reason as the redemption case above: the
				// subject is the generation boundary, and a public client whose grant
				// descends from a challenge-less code is now refused before it (#245).
				clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
				require.NoError(t, err)

				client := &models.Client{
					Id: 1, ClientIdentifier: "test_client", Enabled: true,
					AuthorizationCodeEnabled: true, IsPublic: false,
					ClientSecretEncrypted: clientSecretEncrypted,
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

				mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test_client").Return(client, nil)
				mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "the-refresh-token", true).
					Return(&oauth.JwtToken{Claims: jwt.MapClaims{
						"jti": "the-jti", "typ": "Refresh", "sub": "user_subject",
					}}, nil)
				mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "the-jti").Return(refreshToken, nil)
				mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
				mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil)
				mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil)

				if tc.wantAccepted {
					now := time.Now().UTC()
					mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "sid-1").
						Return(&models.UserSession{
							Id: 9, SessionIdentifier: "sid-1", UserId: 7,
							Started: now.Add(-10 * time.Minute), LastAccessed: now,
						}, nil)
					mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, "user_subject").Return(&user, nil)
				}

				result, err := validator.ValidateTokenRequest(ctx, settings, &ValidateTokenRequestInput{
					GrantType:    "refresh_token",
					ClientId:     "test_client",
					ClientSecret: "client_secret",
					RefreshToken: "the-refresh-token",
				})

				if tc.wantAccepted {
					assert.NoError(t, err)
					assert.NotNil(t, result)
					return
				}
				assert.Nil(t, result)
				customErr, ok := err.(*oauth.ErrorDetail)
				if assert.True(t, ok, "expected *oauth.ErrorDetail, got %T: %v", err, err) {
					assert.Equal(t, "invalid_grant", customErr.Code())
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
				mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
				mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)
				validator := NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher)
				settings := &models.Settings{}
				ctx := context.Background()

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
					AuthenticatedAt:     sql.NullTime{Time: time.Now().UTC().Add(-time.Hour), Valid: true},
					Scope:               "openid",
					AuthStateGeneration: tc.tokenGeneration,
					User:                user,
					Client:              *client,
				}

				mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "ropc_client").Return(client, nil)
				mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "ropc_refresh_token", true).
					Return(&oauth.JwtToken{Claims: jwt.MapClaims{
						"jti": "ropc_jti", "typ": "Offline", "sub": "ropc_user_subject",
						"offline_access_max_lifetime": float64(time.Now().UTC().Add(24 * time.Hour).Unix()),
					}}, nil)
				mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "ropc_jti").Return(refreshToken, nil)
				mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
				mockDB.On("RefreshTokenLoadUser", mock.Anything, mock.Anything, refreshToken).Return(nil)
				mockDB.On("RefreshTokenLoadClient", mock.Anything, mock.Anything, refreshToken).Return(nil)
				if tc.wantAccepted {
					mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, "ropc_user_subject").Return(&user, nil)
				}

				result, err := validator.ValidateTokenRequest(ctx, settings, &ValidateTokenRequestInput{
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
				customErr, ok := err.(*oauth.ErrorDetail)
				if assert.True(t, ok, "expected *oauth.ErrorDetail, got %T: %v", err, err) {
					assert.Equal(t, "invalid_grant", customErr.Code())
				}
			})
		}
	})
}

// TestValidateTokenRequest_RevokedCode covers the termination boundary at both redemption
// sites (#129 decisions 4 and 7): a code marked revoked cannot be redeemed, and neither can
// a refresh token descended from one.
//
// Half of these subtests are about ORDERING rather than rejection, and they are the only
// testable content of decision 7. The revoked check deliberately sits apart from the
// user-enabled, generation and expiry checks in the same function, behind client
// authentication and PKCE, because that earlier block discloses account state to an
// unauthenticated presenter of a stolen code and #137 exists to close it. Nothing else would
// notice the check drifting up into that block: every rejection row would still pass, since
// the request is still refused, just earlier and to a caller who has proved nothing. Each
// ordering row therefore varies exactly ONE thing from an otherwise-valid revoked request and
// names the gate that must answer instead.
//
// Two positive controls, one per grant type, because a check that rejected everything would
// satisfy every negative row here.
func TestValidateTokenRequest_RevokedCode(t *testing.T) {
	newValidator := func(t *testing.T) (*TokenValidator, *mocks_data.Database, *mocks_protocolvalidation.TokenParser) {
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
		mockPermissionChecker := mocks_protocolvalidation.NewPermissionChecker(t)
		return NewTokenValidator(mockDB, mockTokenParser, mockPermissionChecker, testDataCipher), mockDB, mockTokenParser
	}

	t.Run("authorization code redemption", func(t *testing.T) {
		t.Run("a revoked code is refused", func(t *testing.T) {
			validator, mockDB, _ := newValidator(t)
			settings := &models.Settings{}
			ctx := context.Background()

			clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
			require.NoError(t, err)

			client := &models.Client{
				Id: 1, ClientIdentifier: "test_client", Enabled: true,
				AuthorizationCodeEnabled: true, IsPublic: false,
				ClientSecretEncrypted: clientSecretEncrypted,
			}
			code := &models.Code{
				Id: 5, ClientId: 1, UserId: 7,
				RedirectURI: "https://example.com/cb",
				Scope:       "openid",
				CreatedAt:   sql.NullTime{Time: time.Now().UTC(), Valid: true},
				Revoked:     true,
				Client:      *client,
				User:        models.User{Id: 7, Enabled: true},
			}

			mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test_client").Return(client, nil)
			mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.Anything, false).Return(code, nil)
			mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, code).Return(nil)
			mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, code).Return(nil)

			result, err := validator.ValidateTokenRequest(ctx, settings, &ValidateTokenRequestInput{
				GrantType:    "authorization_code",
				ClientId:     "test_client",
				ClientSecret: "client_secret",
				Code:         "the-code",
				RedirectURI:  "https://example.com/cb",
			})

			assert.Nil(t, result)
			customErr, ok := err.(*oauth.ErrorDetail)
			if assert.True(t, ok, "expected *oauth.ErrorDetail, got %T: %v", err, err) {
				assert.Equal(t, "invalid_grant", customErr.Code())
				// Generic on purpose: the message must not tell a caller that the session was
				// terminated, which is the disclosure position the neighbouring checks take.
				assert.Equal(t, "Code is invalid.", customErr.Description())
			}
		})

		t.Run("the same code unrevoked is redeemable", func(t *testing.T) {
			// The positive control. Varies exactly one field from the row above.
			validator, mockDB, _ := newValidator(t)
			settings := &models.Settings{}
			ctx := context.Background()

			clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
			require.NoError(t, err)

			client := &models.Client{
				Id: 1, ClientIdentifier: "test_client", Enabled: true,
				AuthorizationCodeEnabled: true, IsPublic: false,
				ClientSecretEncrypted: clientSecretEncrypted,
			}
			code := &models.Code{
				Id: 5, ClientId: 1, UserId: 7,
				RedirectURI: "https://example.com/cb",
				Scope:       "openid",
				CreatedAt:   sql.NullTime{Time: time.Now().UTC(), Valid: true},
				Revoked:     false,
				Client:      *client,
				User:        models.User{Id: 7, Enabled: true},
			}

			mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test_client").Return(client, nil)
			mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.Anything, false).Return(code, nil)
			mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, code).Return(nil)
			mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, code).Return(nil)
			expectRedirectURIStillRegistered(mockDB, "https://example.com/cb")

			result, err := validator.ValidateTokenRequest(ctx, settings, &ValidateTokenRequestInput{
				GrantType:    "authorization_code",
				ClientId:     "test_client",
				ClientSecret: "client_secret",
				Code:         "the-code",
				RedirectURI:  "https://example.com/cb",
			})

			assert.NoError(t, err)
			assert.NotNil(t, result)
		})

		t.Run("ordering: a wrong PKCE verifier answers before the revoked check", func(t *testing.T) {
			validator, mockDB, _ := newValidator(t)
			settings := &models.Settings{}
			ctx := context.Background()

			client := &models.Client{
				Id: 1, ClientIdentifier: "test_client", Enabled: true,
				AuthorizationCodeEnabled: true, IsPublic: true,
			}
			code := &models.Code{
				Id: 5, ClientId: 1, UserId: 7,
				RedirectURI:   "https://example.com/cb",
				Scope:         "openid",
				CreatedAt:     sql.NullTime{Time: time.Now().UTC(), Valid: true},
				Revoked:       true,
				CodeChallenge: sql.NullString{String: oauth.GeneratePKCECodeChallenge(testCodeVerifier), Valid: true},
				Client:        *client,
				User:          models.User{Id: 7, Enabled: true},
			}

			mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test_client").Return(client, nil)
			mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.Anything, false).Return(code, nil)
			mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, code).Return(nil)
			mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, code).Return(nil)

			result, err := validator.ValidateTokenRequest(ctx, settings, &ValidateTokenRequestInput{
				GrantType:    "authorization_code",
				ClientId:     "test_client",
				Code:         "the-code",
				RedirectURI:  "https://example.com/cb",
				CodeVerifier: wrongCodeVerifier,
			})

			assert.Nil(t, result)
			customErr, ok := err.(*oauth.ErrorDetail)
			if assert.True(t, ok, "expected *oauth.ErrorDetail, got %T: %v", err, err) {
				// PKCE, not the revoked check. If this reads "Code is invalid." the revoked
				// check has moved ahead of PKCE, which is what decision 7 forbids.
				assert.Equal(t, "Invalid code_verifier (PKCE).", customErr.Description())
			}
		})

		t.Run("ordering: a missing client secret answers before the revoked check", func(t *testing.T) {
			validator, mockDB, _ := newValidator(t)
			settings := &models.Settings{}
			ctx := context.Background()

			clientSecretEncrypted, err := testDataCipher.Encrypt("the_client_secret")
			require.NoError(t, err)

			client := &models.Client{
				Id: 1, ClientIdentifier: "test_client", Enabled: true,
				AuthorizationCodeEnabled: true, IsPublic: false,
				ClientSecretEncrypted: []byte(clientSecretEncrypted),
			}
			code := &models.Code{
				Id: 5, ClientId: 1, UserId: 7,
				RedirectURI: "https://example.com/cb",
				Scope:       "openid",
				CreatedAt:   sql.NullTime{Time: time.Now().UTC(), Valid: true},
				Revoked:     true,
				Client:      *client,
				User:        models.User{Id: 7, Enabled: true},
			}

			mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test_client").Return(client, nil)
			mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.Anything, false).Return(code, nil)
			mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, code).Return(nil)
			mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, code).Return(nil)

			result, err := validator.ValidateTokenRequest(ctx, settings, &ValidateTokenRequestInput{
				GrantType:   "authorization_code",
				ClientId:    "test_client",
				Code:        "the-code",
				RedirectURI: "https://example.com/cb",
				// No ClientSecret, on a confidential client.
			})

			assert.Nil(t, result)
			customErr, ok := err.(*oauth.ErrorDetail)
			if assert.True(t, ok, "expected *oauth.ErrorDetail, got %T: %v", err, err) {
				// Client authentication, not the revoked check. An unauthenticated presenter
				// of a stolen code must not learn that its session was terminated.
				assert.Equal(t, "invalid_client", customErr.Code())
			}
		})

		t.Run("ordering: a wrong client secret answers before the revoked check", func(t *testing.T) {
			// KEEP THIS ROW. It is the one that actually pins decision 7 on the confidential
			// path, and the row above is the benign member of its class: a MISSING secret is
			// refused by a length check that runs before decryption, so that row stays green
			// if the revoked check is moved to just after it and before the constant-time
			// comparison. That placement would hand a termination-state oracle to anyone
			// holding a stolen code and any nonempty string, which is exactly what decision 7
			// exists to prevent. A PRESENT but wrong secret is the only input that fails if
			// the check moves anywhere ahead of authentication completing.
			validator, mockDB, _ := newValidator(t)
			settings := &models.Settings{}
			ctx := context.Background()

			clientSecretEncrypted, err := testDataCipher.Encrypt("the_real_client_secret")
			require.NoError(t, err)

			client := &models.Client{
				Id: 1, ClientIdentifier: "test_client", Enabled: true,
				AuthorizationCodeEnabled: true, IsPublic: false,
				ClientSecretEncrypted: []byte(clientSecretEncrypted),
			}
			code := &models.Code{
				Id: 5, ClientId: 1, UserId: 7,
				RedirectURI: "https://example.com/cb",
				Scope:       "openid",
				CreatedAt:   sql.NullTime{Time: time.Now().UTC(), Valid: true},
				Revoked:     true,
				Client:      *client,
				User:        models.User{Id: 7, Enabled: true},
			}

			mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test_client").Return(client, nil)
			mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.Anything, false).Return(code, nil)
			mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, code).Return(nil)
			mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, code).Return(nil)

			result, err := validator.ValidateTokenRequest(ctx, settings, &ValidateTokenRequestInput{
				GrantType:    "authorization_code",
				ClientId:     "test_client",
				Code:         "the-code",
				RedirectURI:  "https://example.com/cb",
				ClientSecret: "not_the_real_client_secret",
			})

			assert.Nil(t, result)
			customErr, ok := err.(*oauth.ErrorDetail)
			if assert.True(t, ok, "expected *oauth.ErrorDetail, got %T: %v", err, err) {
				assert.Equal(t, "invalid_client", customErr.Code())
				assert.Equal(t, "Client authentication failed. Please review your client_secret.",
					customErr.Description())
			}
		})

		t.Run("ordering: reuse answers before the revoked check", func(t *testing.T) {
			// A revoked code that was ALSO already used. Reuse must win, because its error
			// carries the code entity that drives #77's containment cascade, and a
			// revoked-code rejection landing first would suppress it.
			validator, mockDB, _ := newValidator(t)
			settings := &models.Settings{}
			ctx := context.Background()

			clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
			require.NoError(t, err)

			client := &models.Client{
				Id: 1, ClientIdentifier: "test_client", Enabled: true,
				AuthorizationCodeEnabled: true, IsPublic: false,
				ClientSecretEncrypted: clientSecretEncrypted,
			}
			code := &models.Code{
				Id: 5, ClientId: 1, UserId: 7,
				RedirectURI: "https://example.com/cb",
				Scope:       "openid",
				CreatedAt:   sql.NullTime{Time: time.Now().UTC(), Valid: true},
				Used:        true,
				Revoked:     true,
				Client:      *client,
				User:        models.User{Id: 7, Enabled: true},
			}

			mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test_client").Return(client, nil)
			// Not among unused codes, then found among used ones: that is the reuse path.
			mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.Anything, false).Return(nil, nil)
			mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.Anything, true).Return(code, nil)
			mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, code).Return(nil)
			mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, code).Return(nil)

			result, err := validator.ValidateTokenRequest(ctx, settings, &ValidateTokenRequestInput{
				GrantType:    "authorization_code",
				ClientId:     "test_client",
				ClientSecret: "client_secret",
				Code:         "the-code",
				RedirectURI:  "https://example.com/cb",
			})

			assert.Nil(t, result)
			reuseErr, ok := err.(*AuthCodeReusedError)
			if assert.True(t, ok, "expected *AuthCodeReusedError, got %T: %v", err, err) {
				assert.Equal(t, code, reuseErr.Code,
					"the reuse error must carry the code entity, or the containment cascade has nothing to act on")
			}
		})
	})

	t.Run("auth code refresh", func(t *testing.T) {
		// Fixtures shared by the three rows below. An OFFLINE token deliberately: the typ
		// switch's Offline branch never consults the session, so this is the case the
		// pre-existing checks cannot reach and the marker exists for.
		//
		// CONFIDENTIAL, and it used to be public (#245). The subject of these rows is the
		// code marker, and the code they build carries no challenge, so a public client
		// would now be refused by the PKCE boundary immediately below the marker check and
		// every row here would pass for the wrong reason.
		clientSecretEncrypted, err := testDataCipher.Encrypt("client_secret")
		require.NoError(t, err)

		build := func(revoked bool, clientIdOnCode int64) (*models.Client, *models.RefreshToken, models.User) {
			client := &models.Client{
				Id: 1, ClientIdentifier: "test_client", Enabled: true,
				AuthorizationCodeEnabled: true, IsPublic: false,
				ClientSecretEncrypted: clientSecretEncrypted,
			}
			user := models.User{Id: 7, Enabled: true}
			refreshToken := &models.RefreshToken{
				RefreshTokenJti:   "the-jti",
				CodeId:            sql.NullInt64{Int64: 5, Valid: true},
				SessionIdentifier: "",
				Code: models.Code{
					Id: 5, ClientId: clientIdOnCode, UserId: 7, Scope: "openid offline_access",
					SessionIdentifier: "sid-1",
					Revoked:           revoked,
					User:              user,
				},
			}
			return client, refreshToken, user
		}

		offlineClaims := func() *oauth.JwtToken {
			return &oauth.JwtToken{Claims: jwt.MapClaims{
				"jti": "the-jti", "typ": "Offline", "sub": "user_subject",
				"offline_access_max_lifetime": float64(time.Now().UTC().Add(24 * time.Hour).Unix()),
			}}
		}

		t.Run("an offline token whose code was revoked is refused", func(t *testing.T) {
			validator, mockDB, mockTokenParser := newValidator(t)
			settings := &models.Settings{}
			ctx := context.Background()
			client, refreshToken, _ := build(true, 1)

			mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test_client").Return(client, nil)
			mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "the-refresh-token", true).
				Return(offlineClaims(), nil)
			mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "the-jti").Return(refreshToken, nil)
			mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
			mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil)
			mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil)

			result, err := validator.ValidateTokenRequest(ctx, settings, &ValidateTokenRequestInput{
				GrantType:    "refresh_token",
				ClientId:     "test_client",
				ClientSecret: "client_secret",
				RefreshToken: "the-refresh-token",
			})

			assert.Nil(t, result)
			customErr, ok := err.(*oauth.ErrorDetail)
			if assert.True(t, ok, "expected *oauth.ErrorDetail, got %T: %v", err, err) {
				assert.Equal(t, "invalid_grant", customErr.Code())
			}
		})

		t.Run("the same token with an unrevoked code still refreshes", func(t *testing.T) {
			// The positive control, and the row that proves the marker rather than the
			// Offline branch is what refused above: an offline grant is designed to outlive
			// its browser session, so this must keep working (decision 2).
			validator, mockDB, mockTokenParser := newValidator(t)
			settings := &models.Settings{}
			ctx := context.Background()
			client, refreshToken, user := build(false, 1)

			mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test_client").Return(client, nil)
			mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "the-refresh-token", true).
				Return(offlineClaims(), nil)
			mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "the-jti").Return(refreshToken, nil)
			mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
			mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil)
			mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil)
			// #133's ownership check on the Offline arm looks the code's session up. It
			// belongs to user 7, the grant's own user, so it accepts and the row still
			// measures what it was written to measure.
			mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "sid-1").
				Return(&models.UserSession{SessionIdentifier: "sid-1", UserId: 7}, nil)
			mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, "user_subject").Return(&user, nil)
			// An Offline refresh always re-checks consent, whatever the client's
			// ConsentRequired says, so the accepted path needs a live consent row covering
			// the scopes. None of the rejection rows reach this far.
			mockDB.On("GetConsentByUserIdAndClientId", mock.Anything, mock.Anything, int64(7), int64(1)).
				Return(&models.UserConsent{UserId: 7, ClientId: 1, Scope: "openid offline_access"}, nil)

			result, err := validator.ValidateTokenRequest(ctx, settings, &ValidateTokenRequestInput{
				GrantType:    "refresh_token",
				ClientId:     "test_client",
				ClientSecret: "client_secret",
				RefreshToken: "the-refresh-token",
			})

			assert.NoError(t, err)
			assert.NotNil(t, result)
		})

		t.Run("ordering: the wrong client answers before the revoked check", func(t *testing.T) {
			// The code belongs to client 2 while client 1 presents the token. Ownership must
			// answer, so a client that does not hold the grant cannot learn from this
			// endpoint that somebody's session was terminated.
			validator, mockDB, mockTokenParser := newValidator(t)
			settings := &models.Settings{}
			ctx := context.Background()
			client, refreshToken, _ := build(true, 2)

			mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test_client").Return(client, nil)
			mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "the-refresh-token", true).
				Return(offlineClaims(), nil)
			mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "the-jti").Return(refreshToken, nil)
			mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
			mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil)
			mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil)

			result, err := validator.ValidateTokenRequest(ctx, settings, &ValidateTokenRequestInput{
				GrantType:    "refresh_token",
				ClientId:     "test_client",
				ClientSecret: "client_secret",
				RefreshToken: "the-refresh-token",
			})

			assert.Nil(t, result)
			customErr, ok := err.(*oauth.ErrorDetail)
			if assert.True(t, ok, "expected *oauth.ErrorDetail, got %T: %v", err, err) {
				assert.Equal(t, "invalid_request", customErr.Code())
				assert.Equal(t, "The refresh token is invalid because it does not belong to the client.",
					customErr.Description())
			}
		})
	})

	t.Run("ROPC refresh is unaffected", func(t *testing.T) {
		// A ROPC token has code_id NULL and no session, so there is no grant origin to
		// terminate and refreshToken.Code is the zero value. Reading Revoked off it would be
		// meaningless, and the !isROPCToken guard is what keeps this path out of the check.
		// Its own zero value is false, so this row would pass with the guard deleted; it is
		// here to pin the branch as deliberate and to fail if the guard is ever inverted.
		validator, mockDB, mockTokenParser := newValidator(t)
		settings := &models.Settings{}
		ctx := context.Background()

		client := &models.Client{
			Id: 1, ClientIdentifier: "ropc_client", Enabled: true,
			AuthorizationCodeEnabled: true, IsPublic: true,
		}
		user := models.User{Id: 7, Enabled: true}
		refreshToken := &models.RefreshToken{
			RefreshTokenJti: "ropc_jti",
			CodeId:          sql.NullInt64{Valid: false},
			UserId:          sql.NullInt64{Int64: 7, Valid: true},
			ClientId:        sql.NullInt64{Int64: 1, Valid: true},
			AuthenticatedAt: sql.NullTime{Time: time.Now().UTC().Add(-time.Hour), Valid: true},
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
		mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
		mockDB.On("RefreshTokenLoadUser", mock.Anything, mock.Anything, refreshToken).Return(nil)
		mockDB.On("RefreshTokenLoadClient", mock.Anything, mock.Anything, refreshToken).Return(nil)
		mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, "ropc_user_subject").Return(&user, nil)

		result, err := validator.ValidateTokenRequest(ctx, settings, &ValidateTokenRequestInput{
			GrantType:    "refresh_token",
			ClientId:     "ropc_client",
			RefreshToken: "ropc_refresh_token",
		})

		assert.NoError(t, err)
		assert.True(t, grantAs[*RefreshTokenGrant](t, result).IsROPC)
	})
}

// TestTokenGrant_EachGrantNamesItsGrantType holds each validated grant to the grant table entry
// the handler dispatches it as. A grant type naming another grant would send its request down the
// wrong arm everywhere GrantType() is read.
func TestTokenGrant_EachGrantNamesItsGrantType(t *testing.T) {
	for _, tc := range []struct {
		grant TokenGrant
		want  oidc.GrantType
	}{
		{&AuthorizationCodeGrant{}, oidc.GrantTypeAuthorizationCode},
		{&ClientCredentialsGrant{}, oidc.GrantTypeClientCredentials},
		{&RefreshTokenGrant{}, oidc.GrantTypeRefreshToken},
		{&PasswordGrant{}, oidc.GrantTypePassword},
	} {
		assert.Equal(t, tc.want, tc.grant.GrantType(), "%T", tc.grant)
		assert.True(t, tc.want.AcceptedAtTokenEndpoint(), "%T names a grant the token endpoint refuses", tc.grant)
	}
}

// TestAsTokenGrant_ARefusalIsANilInterface pins the one thing asTokenGrant exists for. A grant
// method refuses with a nil pointer beside its error, and returned straight through the
// TokenGrant result that pointer becomes an interface which is not nil, so a caller checking the
// grant would take a refusal for a grant. The comparison is ==, not assert.Nil, because assert.Nil
// reads through the interface and calls a nil pointer inside one nil as well.
func TestAsTokenGrant_ARefusalIsANilInterface(t *testing.T) {
	refused := errs.New("refused")

	grant, err := asTokenGrant((*AuthorizationCodeGrant)(nil), refused)

	assert.Same(t, refused, err)
	assert.True(t, grant == nil, "a refusal came back as a non-nil %T", grant)

	accepted := &AuthorizationCodeGrant{Code: &models.Code{Id: 7}}
	grant, err = asTokenGrant(accepted, nil)

	require.NoError(t, err)
	assert.Same(t, accepted, grant)
}
