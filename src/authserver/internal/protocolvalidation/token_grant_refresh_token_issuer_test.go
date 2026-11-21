package protocolvalidation

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	protocolvalidationmocks "github.com/leodip/goiabada/authserver/internal/protocolvalidation/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/oauth"
)

// A refresh token is the current issuer's only while its iss and its aud are each exactly the
// configured issuer (#710 decision 1). A live one of an earlier issuer is refused with invalid_grant
// and the message that says nothing about why, before anything is rotated, and the refusal is a Warn
// record naming the token's issuer and the current one. It comes after client authentication, the
// match of the token to its client and the DPoP key match, so a presenter that has not passed those
// learns nothing of it, and first among the refusals of the token's state: ahead of a disabled
// user's and of PKCE. A token of an earlier issuer whose own row is revoked is a replay, and goes on
// to the redemption that contains its family (decision 3).
const (
	currentIssuer = "https://auth.example.com"
	earlierIssuer = "https://auth.example.org"
)

const issuerRefusalRecord = "refresh token refused for its issuer"

func TestValidateTokenRequest_RefreshGrant_ATokenOfAnEarlierIssuer(t *testing.T) {
	invalidToken := wantRefusal{code: "invalid_grant", description: "The refresh token is invalid.", status: http.StatusBadRequest}

	type attempt struct {
		name             string
		iss              string
		aud              interface{}
		clientIdentifier string
		binding          string
		want             wantRefusal
		// recorded says the issuer refusal writes its Warn record.
		recorded bool
	}
	attempts := []attempt{
		{name: "both claims of an earlier issuer", iss: earlierIssuer, aud: earlierIssuer, want: invalidToken, recorded: true},
		{name: "an aud of an earlier issuer", iss: currentIssuer, aud: earlierIssuer, want: invalidToken, recorded: true},
		{name: "an iss of an earlier issuer", iss: earlierIssuer, aud: currentIssuer, want: invalidToken, recorded: true},
		{name: "an aud that is an array holding the issuer", iss: currentIssuer, aud: []interface{}{currentIssuer},
			want: invalidToken, recorded: true},
		{
			name: "another client's token of an earlier issuer", iss: earlierIssuer, aud: earlierIssuer, clientIdentifier: "stranger",
			want: wantRefusal{code: "invalid_grant", description: "The refresh token is invalid because it does not belong to the client.",
				status: http.StatusBadRequest},
		},
		{
			name: "a bound token of an earlier issuer with no proof", iss: earlierIssuer, aud: earlierIssuer, binding: boundKey,
			want: wantRefusal{code: "invalid_grant", description: BoundRefreshTokenMessage, status: http.StatusBadRequest},
		},
		// The control: the same rows under the current issuer meet the disabled user, so the
		// answers above are the issuer's and not something the row trips anyway.
		{name: "a token of the current issuer", iss: currentIssuer, aud: currentIssuer,
			want: wantRefusal{code: "invalid_grant", description: "The refresh token is invalid.", status: http.StatusBadRequest,
				userDisabled: true}},
	}

	for _, ropc := range []bool{false, true} {
		shape := "code-descended token"
		if ropc {
			shape = "password grant token"
		}
		for _, a := range attempts {
			t.Run(shape+", "+a.name, func(t *testing.T) {
				mockDB := datamocks.NewDatabase(t)
				mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
				validator := NewTokenValidator(mockDB, mockTokenParser,
					protocolvalidationmocks.NewPermissionChecker(t), testDataCipher)

				// A public client and a code issued without PKCE, and a disabled user: each would
				// refuse the token if the issuer did not first.
				clients := map[string]*record.Client{
					"owner":    {ID: 1, ClientIdentifier: "owner", Enabled: true, AuthorizationCodeEnabled: true, IsPublic: true},
					"stranger": {ID: 2, ClientIdentifier: "stranger", Enabled: true, AuthorizationCodeEnabled: true, IsPublic: true},
				}
				clientIdentifier := "owner"
				if a.clientIdentifier != "" {
					clientIdentifier = a.clientIdentifier
				}
				user := record.User{ID: 7, Enabled: false, AuthStateGeneration: 3}
				refreshToken := &record.RefreshToken{ID: 21, RefreshTokenJTI: "the_jti", FirstRefreshTokenJTI: "family-jti",
					AuthStateGeneration: 3}
				if a.binding != "" {
					refreshToken.DPoPJkt = sql.NullString{String: a.binding, Valid: true}
				}
				typ := "Refresh"
				if ropc {
					typ = "Offline"
					refreshToken.ClientID = sql.NullInt64{Int64: 1, Valid: true}
					refreshToken.UserID = sql.NullInt64{Int64: 7, Valid: true}
					refreshToken.User = user
					refreshToken.AuthenticatedAt = sql.NullTime{Time: time.Now().UTC().Add(-time.Hour), Valid: true}
				} else {
					refreshToken.CodeID = sql.NullInt64{Int64: 11, Valid: true}
					refreshToken.Code = record.Code{ID: 11, ClientID: 1, UserID: 7, User: user}
				}

				mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, clientIdentifier).
					Return(clients[clientIdentifier], nil).Once()
				mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "the_refresh_token", true).
					Return(&oauth.JWTToken{Claims: jwt.MapClaims{"jti": "the_jti", "typ": typ, "iss": a.iss, "aud": a.aud,
						"offline_access_max_lifetime": float64(time.Now().Add(time.Hour).Unix())}}, nil).Once()
				mockDB.On("GetRefreshTokenByJTI", mock.Anything, mock.Anything, "the_jti").Return(refreshToken, nil).Once()
				if ropc {
					mockDB.On("RefreshTokenLoadUser", mock.Anything, mock.Anything, refreshToken).Return(nil).Once()
					mockDB.On("RefreshTokenLoadClient", mock.Anything, mock.Anything, refreshToken).Return(nil).Once()
				} else {
					mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil).Once()
					mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil).Once()
				}

				capture := logtest.CaptureSlog(t)
				grant, err := validator.ValidateTokenRequest(context.Background(), &record.Settings{Issuer: currentIssuer},
					&ValidateTokenRequestInput{
						GrantType:    "refresh_token",
						ClientID:     clientIdentifier,
						RefreshToken: "the_refresh_token",
					})

				assert.Nil(t, grant)
				assertRefusal(t, err, a.want)

				var records []logtest.CapturedRecord
				for _, r := range capture.Records() {
					if r.Message == issuerRefusalRecord {
						records = append(records, r)
					}
				}
				if !a.recorded {
					assert.Empty(t, records, "no issuer refusal is recorded")
					return
				}
				require.Len(t, records, 1, "one record of the issuer refusal")
				assert.Equal(t, slog.LevelWarn, records[0].Level)
				assert.Equal(t, a.iss, records[0].Attrs["token_issuer"])
				assert.Equal(t, currentIssuer, records[0].Attrs["issuer"])
				assert.Equal(t, "owner", records[0].Attrs["client_identifier"])
				assert.Equal(t, int64(21), records[0].Attrs["refresh_token_id"])
			})
		}
	}
}

// A rotated token of an earlier issuer is a replay: the validator hands it on with its revoked row,
// so the refresh redemption contains its family, as it does for any rotated token (#710 decision 3).
// Nothing records an issuer refusal.
func TestValidateTokenRequest_RefreshGrant_ARotatedTokenOfAnEarlierIssuerGoesOnToContainment(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
	validator := NewTokenValidator(mockDB, mockTokenParser, protocolvalidationmocks.NewPermissionChecker(t), testDataCipher)

	client := &record.Client{ID: 1, ClientIdentifier: "owner", Enabled: true, IsPublic: true}
	refreshToken := &record.RefreshToken{
		ID: 21, RefreshTokenJTI: "the_jti", FirstRefreshTokenJTI: "family-jti", AuthStateGeneration: 3, Revoked: true,
		ClientID:        sql.NullInt64{Int64: 1, Valid: true},
		UserID:          sql.NullInt64{Int64: 7, Valid: true},
		User:            record.User{ID: 7, Enabled: true, AuthStateGeneration: 3},
		AuthenticatedAt: sql.NullTime{Time: time.Now().UTC().Add(-time.Hour), Valid: true},
		Scope:           "openid",
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "owner").Return(client, nil).Once()
	mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "the_refresh_token", true).
		Return(&oauth.JWTToken{Claims: jwt.MapClaims{"jti": "the_jti", "typ": "Offline", "sub": "user-7",
			"iss": earlierIssuer, "aud": earlierIssuer,
			"offline_access_max_lifetime": float64(time.Now().Add(time.Hour).Unix())}}, nil).Once()
	mockDB.On("GetRefreshTokenByJTI", mock.Anything, mock.Anything, "the_jti").Return(refreshToken, nil).Once()
	mockDB.On("RefreshTokenLoadUser", mock.Anything, mock.Anything, refreshToken).Return(nil).Once()
	mockDB.On("RefreshTokenLoadClient", mock.Anything, mock.Anything, refreshToken).Return(nil).Once()
	mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, "user-7").Return(&record.User{ID: 7, Enabled: true}, nil).Once()

	capture := logtest.CaptureSlog(t)
	result, err := validator.ValidateTokenRequest(context.Background(), &record.Settings{Issuer: currentIssuer},
		&ValidateTokenRequestInput{GrantType: "refresh_token", ClientID: "owner", RefreshToken: "the_refresh_token"})

	require.NoError(t, err)
	grant := grantAs[*RefreshTokenGrant](t, result)
	assert.Same(t, refreshToken, grant.RefreshToken)
	assert.True(t, grant.RefreshToken.Revoked, "the redemption is handed the revoked row to contain")
	for _, r := range capture.Records() {
		assert.NotEqual(t, issuerRefusalRecord, r.Message, "a replay is not an issuer refusal")
	}
}
