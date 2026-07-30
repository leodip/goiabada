package oauth

import (
	"database/sql"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// This file owns two exhaustive tables for #106: which access tokens carry a sid claim
// (decision 9), and where each access token's auth_state_generation comes from
// (decision 13). Both are asserted against the generator functions directly rather than
// through GenerateTokenResponseFor*, because generateAccessTokenCore touches no database
// and the tables are about claim assembly, not about wiring.
//
// What these cannot prove: that a real JWT round-trips the claim through a real HTTP
// exchange and that the middleware then enforces it. Stage 5's integration tests do that.

func generationTestSettings() *models.Settings {
	return &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		UserSessionIdleTimeoutInSeconds:         1200,
		UserSessionMaxLifetimeInSeconds:         2400,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
	}
}

// generationTestCode builds a redeemable code with its Client and User already attached,
// so no database is needed.
func generationTestCode(scope string, sessionIdentifier string, codeGeneration int64, userGeneration int64) *models.Code {
	return &models.Code{
		Id:                  1,
		ClientId:            1,
		UserId:              1,
		Scope:               scope,
		AuthenticatedAt:     time.Now().UTC().Add(-5 * time.Minute),
		SessionIdentifier:   sessionIdentifier,
		AcrLevel:            "urn:goiabada:level1",
		AuthMethods:         "pwd",
		AuthStateGeneration: codeGeneration,
		Client: models.Client{
			Id:                       1,
			ClientIdentifier:         "test-client",
			TokenExpirationInSeconds: 900,
		},
		User: models.User{
			Id:                  1,
			Subject:             uuid.New(),
			Username:            "testuser",
			Email:               "test@example.com",
			AuthStateGeneration: userGeneration,
		},
	}
}

// parseAccessTokenClaims parses a signed token WITHOUT validating it: these tests assert
// what was emitted, and expiry or signature policy is not what is under test here.
func parseAccessTokenClaims(t *testing.T, tokenStr string) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	parser := jwt.NewParser()
	_, _, err := parser.ParseUnverified(tokenStr, claims)
	require.NoError(t, err, "parse access token")
	return claims
}

// TestAccessToken_SidEmission is the exhaustive owner of the sid-emission table
// (#106 decision 9).
//
// An access token on an offline grant must NOT carry sid. It outlives the browser session
// by design, so a sid the middleware will later fail to resolve turns a working offline
// client into a rejected one, which is the defect this decision fixes.
func TestAccessToken_SidEmission(t *testing.T) {
	settings := generationTestSettings()
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(getTestPrivateKey(t))
	require.NoError(t, err, "parse test private key")

	// generateAccessTokenCore consults the database for a profile picture when the
	// profile scope is present, so a mock is needed even though nothing here is about
	// pictures. Maybe(), because the rows using bare "openid" never reach it.
	mockDB := mocks_data.NewDatabase(t)
	mockDB.On("UserHasProfilePicture", mock.Anything, mock.Anything).Return(false, nil).Maybe()
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081")
	now := time.Now().UTC()
	const sid = "test-session-123"

	tests := []struct {
		name    string
		code    *models.Code
		scope   string
		parent  *models.RefreshToken
		wantSid bool
	}{
		{
			name:    "initial exchange, session-bound grant, emits sid",
			code:    generationTestCode("openid profile", sid, 0, 0),
			scope:   "openid profile",
			wantSid: true,
		},
		{
			name:    "initial exchange, offline_access granted, no sid",
			code:    generationTestCode("openid offline_access", sid, 0, 0),
			scope:   "openid offline_access",
			wantSid: false,
		},
		{
			name:    "initial exchange, no session identifier at all, no sid",
			code:    generationTestCode("openid", "", 0, 0),
			scope:   "openid",
			wantSid: false,
		},
		{
			name:    "refresh of a session-bound token, emits sid",
			code:    generationTestCode("openid profile", sid, 0, 0),
			scope:   "openid profile",
			parent:  &models.RefreshToken{RefreshTokenType: sessionRefreshTokenType},
			wantSid: true,
		},
		{
			name:    "refresh of an offline token, no sid",
			code:    generationTestCode("openid offline_access", sid, 0, 0),
			scope:   "openid offline_access",
			parent:  &models.RefreshToken{RefreshTokenType: offlineRefreshTokenType},
			wantSid: false,
		},
		{
			// KEEP THIS ROW. It looks redundant next to the one above, and it is the
			// regression guard for the trap in decision 9: a caller may legitimately
			// down-scope on refresh and drop offline_access from the REQUEST while the
			// grant remains offline. A predicate reading the request's effective scope
			// emits sid here and resurrects the bug intermittently, which is worse than
			// failing consistently. The predicate must read the grant.
			name:    "refresh of an offline grant, request down-scoped away offline_access, no sid",
			code:    generationTestCode("openid offline_access", sid, 0, 0),
			scope:   "openid",
			parent:  &models.RefreshToken{RefreshTokenType: offlineRefreshTokenType},
			wantSid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tokenStr, _, err := issuer.generateAccessToken(settings, tc.code, tc.scope, now, privKey, "test-kid", tc.parent)
			require.NoError(t, err, "generateAccessToken")

			claims := parseAccessTokenClaims(t, tokenStr)
			_, present := claims["sid"]
			assert.Equal(t, tc.wantSid, present, "sid claim presence")
			if tc.wantSid {
				assert.Equal(t, sid, claims["sid"], "sid value")
			}
		})
	}
}

// TestAccessToken_GenerationProvenance is the exhaustive owner of the provenance table
// (#106 decision 13): every access token inherits its generation from the credential that
// authorized THAT issuance, never from a freshly loaded user and never from a refresh
// token's joined code.
//
// The values are deliberately conflicting and nonzero. If the correct and incorrect
// sources shared a value, a read of the wrong one would be indistinguishable, and a table
// written with 0 would pass with the assignment missing entirely.
func TestAccessToken_GenerationProvenance(t *testing.T) {
	settings := generationTestSettings()
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(getTestPrivateKey(t))
	require.NoError(t, err, "parse test private key")

	// generateAccessTokenCore consults the database for a profile picture when the
	// profile scope is present, so a mock is needed even though nothing here is about
	// pictures. Maybe(), because the rows using bare "openid" never reach it.
	mockDB := mocks_data.NewDatabase(t)
	mockDB.On("UserHasProfilePicture", mock.Anything, mock.Anything).Return(false, nil).Maybe()
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081")
	now := time.Now().UTC()
	const sid = "test-session-123"

	t.Run("initial code exchange takes the code's generation", func(t *testing.T) {
		// code 7 against a user already at 9: reading the user would emit 9.
		code := generationTestCode("openid", sid, 7, 9)
		tokenStr, _, err := issuer.generateAccessToken(settings, code, code.Scope, now, privKey, "test-kid", nil)
		require.NoError(t, err)
		assert.EqualValues(t, 7, parseAccessTokenClaims(t, tokenStr)["auth_state_generation"])
	})

	t.Run("auth-code refresh takes the parent token's generation, not the code's", func(t *testing.T) {
		// This row FAILED under the design before decision 13. Three-way conflict so a
		// read of either wrong source is visible: the preserved session's token was
		// promoted to 7 while its code stayed at 3, and the user has since reached 9.
		code := generationTestCode("openid", sid, 3, 9)
		parent := &models.RefreshToken{RefreshTokenType: sessionRefreshTokenType, AuthStateGeneration: 7}
		tokenStr, _, err := issuer.generateAccessToken(settings, code, code.Scope, now, privKey, "test-kid", parent)
		require.NoError(t, err)
		assert.EqualValues(t, 7, parseAccessTokenClaims(t, tokenStr)["auth_state_generation"])
	})

	t.Run("initial ROPC takes the validated user snapshot, not a reload", func(t *testing.T) {
		// One row, not two. There used to be a second "racing credential change" case here
		// that built an identical fixture and therefore asserted nothing extra.
		//
		// The conflict that makes this meaningful lives at the handler boundary, not here:
		// generateROPCAccessToken only ever sees the snapshot it is given. So the snapshot
		// is 7 while the persisted user is at 9, and the assertion is that the token
		// carries 7. If a credential change lands mid-request, emitting 7 is the correct,
		// fail-closed outcome: the middleware rejects it against the user's newer
		// generation rather than the request laundering itself forward. The
		// handler-to-issuer seam is pinned separately in handler_token's ROPC test.
		input := &ROPCGrantInput{
			Client: &models.Client{Id: 1, ClientIdentifier: "test-client", TokenExpirationInSeconds: 900},
			User:   &models.User{Id: 1, Subject: uuid.New(), Username: "testuser", AuthStateGeneration: 7},
			Scope:  "openid",
		}
		tokenStr, _, err := issuer.generateROPCAccessToken(settings, input, input.Scope, now, privKey, "test-kid", nil)
		require.NoError(t, err)

		claims := parseAccessTokenClaims(t, tokenStr)
		assert.EqualValues(t, 7, claims["auth_state_generation"])
		// ROPC is sessionless: no sid regardless of what accompanied the request.
		assert.NotContains(t, claims, "sid")
	})

	t.Run("ROPC refresh takes the parent token's generation, not the reloaded user's", func(t *testing.T) {
		// This row FAILED under the design before decision 13: the ROPC refresh path
		// reloads the user, so reading input.User here stamps a grant authenticated at 7
		// with the current 9 and launders it forward.
		input := &ROPCGrantInput{
			Client: &models.Client{Id: 1, ClientIdentifier: "test-client", TokenExpirationInSeconds: 900},
			User:   &models.User{Id: 1, Subject: uuid.New(), Username: "testuser", AuthStateGeneration: 9},
			Scope:  "openid",
		}
		parent := &models.RefreshToken{RefreshTokenType: offlineRefreshTokenType, AuthStateGeneration: 7}
		tokenStr, _, err := issuer.generateROPCAccessToken(settings, input, input.Scope, now, privKey, "test-kid", parent)
		require.NoError(t, err)
		assert.EqualValues(t, 7, parseAccessTokenClaims(t, tokenStr)["auth_state_generation"])
	})

	t.Run("implicit takes the AuthContext's generation", func(t *testing.T) {
		input := &ImplicitGrantInput{
			Client:              &models.Client{Id: 1, ClientIdentifier: "test-client", TokenExpirationInSeconds: 900},
			User:                &models.User{Id: 1, Subject: uuid.New(), Username: "testuser", AuthStateGeneration: 9},
			Scope:               "openid",
			AcrLevel:            "urn:goiabada:level1",
			AuthMethods:         "pwd",
			SessionIdentifier:   sid,
			AuthenticatedAt:     now,
			AuthStateGeneration: 7,
		}
		tokenInput := issuer.createTokenInputFromImplicit(input)
		tokenStr, _, err := issuer.generateAccessTokenCore(settings, tokenInput, now, privKey, "test-kid")
		require.NoError(t, err)

		claims := parseAccessTokenClaims(t, tokenStr)
		assert.EqualValues(t, 7, claims["auth_state_generation"])
		// Implicit issues no refresh token, so nothing outlives the session and sid stays.
		assert.Equal(t, sid, claims["sid"], "implicit access tokens keep sid")
	})
}

// TestPersistedGeneration_Stamping is the exhaustive owner of the persisted-state stamping
// table (#106 finding 28). It asserts the generation actually written onto new codes and
// refresh tokens, by capturing the model handed to CreateCode and CreateRefreshToken.
//
// Nothing else in the plan would notice a missing stamp: stage 3's validator tests build
// models.Code{AuthStateGeneration: N} fixtures directly and never traverse issuance, and
// stage 1b's data tests exercise the narrow write methods rather than the issuers.
//
// The failure a missing stamp produces is severe and quiet. The row lands at the column
// default of 0, which behaves correctly while the user is still at generation 0, and then
// the FIRST credential change locks that user out of every subsequent login, because each
// new code compares 0 against their advanced generation. A feature meant to evict attackers
// would instead evict the account owner, and only after appearing to work.
//
// Two properties of the fixtures are load-bearing and must survive any tidy-up:
//   - The generations are NONZERO. A table written with 0 coincides with the column default
//     and passes with the assignment missing entirely.
//   - The correct and incorrect sources are given DIFFERENT values, so a read of the wrong
//     one is distinguishable rather than accidentally right.
func TestPersistedGeneration_Stamping(t *testing.T) {
	settings := generationTestSettings()
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(getTestPrivateKey(t))
	require.NoError(t, err, "parse test private key")
	now := time.Now().UTC()
	const sid = "test-session-123"

	t.Run("codes inherit the AuthContext's generation, not the current user's", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		issuer := NewCodeIssuer(mockDB)

		mockDB.On("GetClientByClientIdentifier", mock.Anything, "test-client").
			Return(&models.Client{Id: 1, ClientIdentifier: "test-client"}, nil)

		var captured *models.Code
		mockDB.On("CreateCode", mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) { captured = args.Get(1).(*models.Code) }).
			Return(nil)

		input := &CreateCodeInput{SessionIdentifier: sid}
		input.ClientId = "test-client"
		input.UserId = 1
		input.RedirectURI = "https://example.com/cb"
		input.Scope = "openid"
		input.ResponseMode = "query"
		input.AuthStateGeneration = 7 // the user is at 9; reading the user would emit 9

		_, err := issuer.CreateAuthCode(input)
		require.NoError(t, err, "CreateAuthCode")
		require.NotNil(t, captured, "CreateCode was never called")
		assert.EqualValues(t, 7, captured.AuthStateGeneration,
			"the code must carry the generation this ceremony authenticated under")
	})

	t.Run("initial auth-code refresh token inherits its code's generation", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		issuer := NewTokenIssuer(mockDB, "http://localhost:8081")

		// code 7 against a user already at 9.
		code := generationTestCode("openid offline_access", sid, 7, 9)

		var captured *models.RefreshToken
		mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) { captured = args.Get(1).(*models.RefreshToken) }).
			Return(nil)

		_, _, err := issuer.generateRefreshToken(settings, code, code.Scope, now, privKey, "test-kid", nil)
		require.NoError(t, err, "generateRefreshToken")
		require.NotNil(t, captured, "CreateRefreshToken was never called")
		assert.EqualValues(t, 7, captured.AuthStateGeneration)
	})

	t.Run("auth-code rotation inherits the parent token, not the code or the user", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		issuer := NewTokenIssuer(mockDB, "http://localhost:8081")

		// Three-way conflict on purpose: parent 7, code 3, user 9. A read of either wrong
		// source is therefore visible rather than only one of them.
		code := generationTestCode("openid offline_access", sid, 3, 9)
		parent := &models.RefreshToken{
			RefreshTokenJti:      "parent-jti",
			FirstRefreshTokenJti: "first-jti",
			RefreshTokenType:     offlineRefreshTokenType,
			AuthStateGeneration:  7,
			MaxLifetime:          sqlNullTime(now.Add(24 * time.Hour)),
		}

		var captured *models.RefreshToken
		mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) { captured = args.Get(1).(*models.RefreshToken) }).
			Return(nil)

		_, _, err := issuer.generateRefreshToken(settings, code, code.Scope, now, privKey, "test-kid", parent)
		require.NoError(t, err, "generateRefreshToken")
		require.NotNil(t, captured, "CreateRefreshToken was never called")
		assert.EqualValues(t, 7, captured.AuthStateGeneration)
	})

	t.Run("initial ROPC refresh token inherits the validated user snapshot", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		issuer := NewTokenIssuer(mockDB, "http://localhost:8081")

		input := &ROPCGrantInput{
			Client: &models.Client{Id: 1, ClientIdentifier: "test-client"},
			User:   &models.User{Id: 1, Subject: uuid.New(), AuthStateGeneration: 7},
			Scope:  "openid",
		}

		var captured *models.RefreshToken
		mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) { captured = args.Get(1).(*models.RefreshToken) }).
			Return(nil)

		_, _, err := issuer.generateRefreshTokenForROPC(settings, input, input.Scope, now, privKey, "test-kid", nil)
		require.NoError(t, err, "generateRefreshTokenForROPC")
		require.NotNil(t, captured, "CreateRefreshToken was never called")
		assert.EqualValues(t, 7, captured.AuthStateGeneration)
	})

	t.Run("ROPC rotation inherits the parent token, not the reloaded user", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		issuer := NewTokenIssuer(mockDB, "http://localhost:8081")

		// The refresh path reloads the user, so this fixture puts the reloaded user at 9
		// while the grant was authenticated at 7.
		input := &ROPCGrantInput{
			Client: &models.Client{Id: 1, ClientIdentifier: "test-client"},
			User:   &models.User{Id: 1, Subject: uuid.New(), AuthStateGeneration: 9},
			Scope:  "openid",
		}
		parent := &models.RefreshToken{
			RefreshTokenJti:      "parent-jti",
			FirstRefreshTokenJti: "first-jti",
			RefreshTokenType:     offlineRefreshTokenType,
			AuthStateGeneration:  7,
			MaxLifetime:          sqlNullTime(now.Add(24 * time.Hour)),
		}

		var captured *models.RefreshToken
		mockDB.On("CreateRefreshToken", mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) { captured = args.Get(1).(*models.RefreshToken) }).
			Return(nil)

		_, _, err := issuer.generateRefreshTokenForROPC(settings, input, input.Scope, now, privKey, "test-kid", parent)
		require.NoError(t, err, "generateRefreshTokenForROPC")
		require.NotNil(t, captured, "CreateRefreshToken was never called")
		assert.EqualValues(t, 7, captured.AuthStateGeneration)
	})
}

func sqlNullTime(t time.Time) sql.NullTime {
	return sql.NullTime{Time: t, Valid: true}
}
