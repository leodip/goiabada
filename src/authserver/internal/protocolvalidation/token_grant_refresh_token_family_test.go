package protocolvalidation

import (
	"context"
	"database/sql"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	mocks_protocolvalidation "github.com/leodip/goiabada/authserver/internal/protocolvalidation/mocks"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

// Seam 2 for the revoked-family record (#132, #259, #437). A live refresh token whose rotation
// family is recorded as revoked is refused at presentation. The record is written by replay
// containment and by a client made public in the same transaction as the revocation, and it is what
// refuses a child that committed live into a family whose sweep had already run.
//
// The check sits below the ownership check, for the reason #137 states for the user's state (a
// public client_id is no secret, so a check above ownership would let anyone holding a stolen token
// tell which families were contained), and below every refusal that already answers a token: the
// user's state, the generation, the revoked code. A token one of those refuses keeps its wording.
// It is skipped for a token whose own row is revoked, which is a replay and is the redemption's to
// contain and audit.
//
// Each refusal is compared with the control's, so a check moved above the ownership check or above
// client authentication changes that row's answer and fails it, and the rows that reach the check
// show it is what refuses, not something the row happens to trip first.

func TestValidateTokenRequest_RefreshGrant_ARevokedFamilyIsRefusedBelowTheOtherGates(t *testing.T) {
	const (
		clientSecret = "client_secret"
		familyJti    = "family-jti"
	)

	type attempt struct {
		name             string
		clientIdentifier string
		clientSecret     string
		userEnabled      bool
		tokenRevoked     bool
		familyRevoked    bool
		familyLookup     error
		// want is the refusal; nil means the lookup failed and that failure is the answer.
		want *wantRefusal
		// reachesFamily says whether the record is read at all, which is the assertion for the rows
		// that show what the check sits below.
		reachesFamily bool
	}

	familyRefusal := &wantRefusal{code: "invalid_grant", description: "The refresh token is invalid.", status: http.StatusBadRequest}

	attempts := []attempt{
		{
			name: "the token's own client, family recorded", clientIdentifier: "client1", clientSecret: clientSecret,
			userEnabled: true, familyRevoked: true, want: familyRefusal, reachesFamily: true,
		},
		{
			// The user's state is read above the record, so a disabled user's token is answered by the
			// disabled-user wrapper that writes EventUserDisabled, and the record is never read.
			name: "the token's own client, family recorded, user disabled", clientIdentifier: "client1", clientSecret: clientSecret,
			userEnabled: false, familyRevoked: true,
			want: &wantRefusal{code: "invalid_grant", description: "The refresh token is invalid.", status: http.StatusBadRequest, userDisabled: true},
		},
		{
			// A token whose own row is revoked is a replay: the record is not consulted, and it goes on
			// to the checks below, which here refuse it for the session it is bound to, exactly as
			// they did before the record existed. The redemption contains the family and audits it.
			name: "a revoked token of a recorded family is left to the redemption", clientIdentifier: "client1", clientSecret: clientSecret,
			userEnabled: true, tokenRevoked: true, familyRevoked: true,
			want: &wantRefusal{code: "invalid_grant", description: "The refresh token is invalid because the associated session has expired or been terminated.", status: http.StatusBadRequest},
		},
		{
			// Another client's token: the same answer a live token gets, whether or not its family is
			// recorded, because the record is never read.
			name: "another client's token, family recorded", clientIdentifier: "client2",
			userEnabled: true, familyRevoked: true,
			want: &wantRefusal{code: "invalid_request", description: "The refresh token is invalid because it does not belong to the client.", status: http.StatusBadRequest},
		},
		{
			name: "wrong secret, family recorded", clientIdentifier: "client1", clientSecret: "not_the_secret",
			userEnabled: true, familyRevoked: true,
			want: &wantRefusal{code: "invalid_client", description: "Client authentication failed. Please review your client_secret.", status: http.StatusUnauthorized},
		},
		{
			// A lookup that cannot be performed is a fault and never a pass.
			name: "the record cannot be read", clientIdentifier: "client1", clientSecret: clientSecret,
			userEnabled: true, familyLookup: errs.New("connection refused"), reachesFamily: true,
		},
	}

	for _, ropc := range []bool{false, true} {
		shape := "code-descended token"
		if ropc {
			shape = "password grant token"
		}
		for _, a := range attempts {
			t.Run(shape+", "+a.name, func(t *testing.T) {
				mockDB := mocks_data.NewDatabase(t)
				mockTokenParser := mocks_protocolvalidation.NewTokenParser(t)
				validator := NewTokenValidator(mockDB, mockTokenParser,
					mocks_protocolvalidation.NewPermissionChecker(t), testDataCipher)

				clientSecretEncrypted, err := testDataCipher.Encrypt(clientSecret)
				require.NoError(t, err)
				clients := map[string]*models.Client{
					"client1": {Id: 1, ClientIdentifier: "client1", Enabled: true,
						AuthorizationCodeEnabled: true, ClientSecretEncrypted: clientSecretEncrypted},
					"client2": {Id: 2, ClientIdentifier: "client2", Enabled: true,
						AuthorizationCodeEnabled: true, IsPublic: true},
				}

				user := models.User{Id: 7, Enabled: a.userEnabled, AuthStateGeneration: 3}
				refreshToken := &models.RefreshToken{
					RefreshTokenJti: "the_jti", FirstRefreshTokenJti: familyJti, AuthStateGeneration: 3, Revoked: a.tokenRevoked,
				}
				if ropc {
					refreshToken.ClientId = sql.NullInt64{Int64: 1, Valid: true}
					refreshToken.UserId = sql.NullInt64{Int64: 7, Valid: true}
					refreshToken.User = user
					refreshToken.AuthenticatedAt = sql.NullTime{Time: time.Now().UTC().Add(-time.Hour), Valid: true}
				} else {
					refreshToken.CodeId = sql.NullInt64{Int64: 11, Valid: true}
					refreshToken.Code = models.Code{Id: 11, ClientId: 1, UserId: 7, User: user}
				}

				mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, a.clientIdentifier).
					Return(clients[a.clientIdentifier], nil).Once()
				mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "the_refresh_token", true).
					Return(&oauth.JwtToken{Claims: jwt.MapClaims{"jti": "the_jti", "typ": "Refresh"}}, nil).Maybe()
				mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "the_jti").Return(refreshToken, nil).Maybe()
				// The record is asked about by the family's first jti, never the presented token's.
				mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, familyJti).
					Return(a.familyRevoked, a.familyLookup).Maybe()
				// A token bound to no session, which is what a revoked token's row is refused for below.
				mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "").Return(nil, nil).Maybe()
				if ropc {
					mockDB.On("RefreshTokenLoadUser", mock.Anything, mock.Anything, refreshToken).Return(nil).Maybe()
					mockDB.On("RefreshTokenLoadClient", mock.Anything, mock.Anything, refreshToken).Return(nil).Maybe()
				} else {
					mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil).Maybe()
					mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil).Maybe()
				}

				grant, err := validator.ValidateTokenRequest(context.Background(), &models.Settings{},
					&ValidateTokenRequestInput{
						GrantType:    "refresh_token",
						ClientId:     a.clientIdentifier,
						ClientSecret: a.clientSecret,
						RefreshToken: "the_refresh_token",
					})

				assert.Nil(t, grant)
				if a.want != nil {
					assertRefusal(t, err, *a.want)
				} else {
					assert.ErrorIs(t, err, a.familyLookup)
				}
				if a.reachesFamily {
					mockDB.AssertCalled(t, "IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, familyJti)
				} else {
					mockDB.AssertNotCalled(t, "IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, mock.Anything)
				}
			})
		}
	}
}
