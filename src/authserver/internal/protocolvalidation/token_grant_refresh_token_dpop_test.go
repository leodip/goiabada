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

// A refresh token bound to a DPoP key is refused invalid_grant unless the request's proof is by that
// key: a request with no proof, or with a valid proof by another key (#42 decision 11, RFC 9449
// section 5, answered as RFC 6749 section 5.2 answers a refresh token issued to another client). The
// refusal is a Warn record and nothing more: it is answered before the redemption, so a revoked
// token presented without the key never reaches the containment that would revoke its family, and a
// thief holding a leaked token cannot end the user's grant with it. It is enforced whatever the
// client's type is now.
//
// The check sits below client authentication and the ownership check, and above every check of the
// token's state, for the reason the ownership check gives (#137): a presenter that has not proved
// the key learns nothing about what became of the account or the family. Every row whose binding
// check passes meets a disabled user next, so its answer is the disabled user's, and the rows the
// binding refuses would otherwise have been answered that way too.
//
// The thumbprints are literals, RFC 7638 section 3.1's example and a second value of the same
// shape: the validator compares them, and never computes one.
const (
	boundKey   = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	anotherKey = "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U"
)

func TestValidateTokenRequest_RefreshGrant_ABoundTokenNeedsAProofByItsKey(t *testing.T) {
	const clientSecret = "client_secret"

	bindingRefusal := &wantRefusal{code: "invalid_grant",
		description: "The refresh token is bound to a DPoP key, and the request carries no proof by that key.",
		status:      http.StatusBadRequest}
	disabledUser := &wantRefusal{code: "invalid_grant", description: "The refresh token is invalid.",
		status: http.StatusBadRequest, userDisabled: true}

	type attempt struct {
		name             string
		binding          string
		thumbprint       string
		tokenRevoked     bool
		clientIdentifier string
		wrongSecret      bool
		want             *wantRefusal
		// warnReason is the Warn record's reason, empty when the binding check writes none.
		warnReason string
	}
	attempts := []attempt{
		{name: "a bound token with no proof", binding: boundKey, want: bindingRefusal, warnReason: "the request carries no dpop proof"},
		{name: "a bound token with a proof by another key", binding: boundKey, thumbprint: anotherKey, want: bindingRefusal,
			warnReason: "the request's dpop proof is by another key"},
		{name: "a bound token with a proof by its key", binding: boundKey, thumbprint: boundKey, want: disabledUser},
		{name: "an unbound token with no proof", want: disabledUser},
		{name: "an unbound token with a proof", thumbprint: anotherKey, want: disabledUser},
		{
			// A replay of a bound token without its key: refused here, so the redemption never contains
			// the family for it.
			name: "a revoked bound token with no proof", binding: boundKey, tokenRevoked: true, want: bindingRefusal,
			warnReason: "the request carries no dpop proof",
		},
		{
			name: "another client's bound token", binding: boundKey, clientIdentifier: "stranger",
			want: &wantRefusal{code: "invalid_grant", description: "The refresh token is invalid because it does not belong to the client.",
				status: http.StatusBadRequest},
		},
	}

	for _, ropc := range []bool{false, true} {
		shape := "code-descended token"
		if ropc {
			shape = "password grant token"
		}
		for _, public := range []bool{true, false} {
			clientType := "public client"
			if !public {
				clientType = "confidential client"
			}
			for _, a := range attempts {
				rows := []attempt{a}
				if !public && a.clientIdentifier == "" && a.binding != "" {
					rows = append(rows, attempt{name: a.name + ", with the wrong secret", binding: a.binding, thumbprint: a.thumbprint,
						tokenRevoked: a.tokenRevoked, wrongSecret: true,
						want: &wantRefusal{code: "invalid_client", description: "Client authentication failed. Please review your client_secret.",
							status: http.StatusUnauthorized}})
				}
				for _, a := range rows {
					t.Run(shape+", "+clientType+", "+a.name, func(t *testing.T) {
						mockDB := datamocks.NewDatabase(t)
						mockTokenParser := protocolvalidationmocks.NewTokenParser(t)
						validator := NewTokenValidator(mockDB, mockTokenParser,
							protocolvalidationmocks.NewPermissionChecker(t), testDataCipher)

						owner := &record.Client{Id: 1, ClientIdentifier: "owner", Enabled: true, AuthorizationCodeEnabled: true, IsPublic: public}
						secret := ""
						if !public {
							encrypted, err := testDataCipher.Encrypt(clientSecret)
							require.NoError(t, err)
							owner.ClientSecretEncrypted = encrypted
							secret = clientSecret
							if a.wrongSecret {
								secret = "not_the_secret"
							}
						}
						clients := map[string]*record.Client{
							"owner":    owner,
							"stranger": {Id: 2, ClientIdentifier: "stranger", Enabled: true, AuthorizationCodeEnabled: true, IsPublic: true},
						}
						clientIdentifier := "owner"
						if a.clientIdentifier != "" {
							clientIdentifier = a.clientIdentifier
							secret = ""
						}

						user := record.User{Id: 7, Enabled: false, AuthStateGeneration: 3}
						refreshToken := &record.RefreshToken{
							Id: 21, RefreshTokenJti: "the_jti", FirstRefreshTokenJti: "family-jti", AuthStateGeneration: 3,
							Revoked: a.tokenRevoked,
						}
						if a.binding != "" {
							refreshToken.DPoPJkt = sql.NullString{String: a.binding, Valid: true}
						}
						if ropc {
							refreshToken.ClientId = sql.NullInt64{Int64: 1, Valid: true}
							refreshToken.UserId = sql.NullInt64{Int64: 7, Valid: true}
							refreshToken.User = user
							refreshToken.AuthenticatedAt = sql.NullTime{Time: time.Now().UTC().Add(-time.Hour), Valid: true}
						} else {
							refreshToken.CodeId = sql.NullInt64{Int64: 11, Valid: true}
							refreshToken.Code = record.Code{Id: 11, ClientId: 1, UserId: 7, User: user,
								CodeChallenge: sql.NullString{String: "challenge", Valid: true}}
						}

						mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, clientIdentifier).
							Return(clients[clientIdentifier], nil).Once()
						mockTokenParser.On("DecodeAndValidateTokenString", mock.Anything, "the_refresh_token", true).
							Return(&oauth.JwtToken{Claims: jwt.MapClaims{"jti": "the_jti", "typ": "Refresh"}}, nil).Maybe()
						mockDB.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, "the_jti").Return(refreshToken, nil).Maybe()
						if ropc {
							mockDB.On("RefreshTokenLoadUser", mock.Anything, mock.Anything, refreshToken).Return(nil).Maybe()
							mockDB.On("RefreshTokenLoadClient", mock.Anything, mock.Anything, refreshToken).Return(nil).Maybe()
						} else {
							mockDB.On("RefreshTokenLoadCode", mock.Anything, mock.Anything, refreshToken).Return(nil).Maybe()
							mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, &refreshToken.Code).Return(nil).Maybe()
						}

						capture := logtest.CaptureSlog(t)
						grant, err := validator.ValidateTokenRequest(context.Background(), &record.Settings{},
							&ValidateTokenRequestInput{
								GrantType:      "refresh_token",
								ClientId:       clientIdentifier,
								ClientSecret:   secret,
								RefreshToken:   "the_refresh_token",
								DPoPThumbprint: a.thumbprint,
							})

						assert.Nil(t, grant)
						assertRefusal(t, err, *a.want)

						var bindingRecords []logtest.CapturedRecord
						for _, r := range capture.Records() {
							if r.Message == "refresh token refused for its dpop binding" {
								bindingRecords = append(bindingRecords, r)
							}
						}
						if a.warnReason == "" || a.wrongSecret {
							assert.Empty(t, bindingRecords, "no binding refusal is recorded")
							return
						}
						require.Len(t, bindingRecords, 1, "one record of the binding refusal")
						assert.Equal(t, slog.LevelWarn, bindingRecords[0].Level)
						assert.Equal(t, a.warnReason, bindingRecords[0].Attrs["reason"])
						assert.Equal(t, "owner", bindingRecords[0].Attrs["client_identifier"])
						assert.Equal(t, int64(21), bindingRecords[0].Attrs["refresh_token_id"])
						assert.NotContains(t, bindingRecords[0].Attrs, "dpop_jkt", "the record names no key")
					})
				}
			}
		}
	}
}
