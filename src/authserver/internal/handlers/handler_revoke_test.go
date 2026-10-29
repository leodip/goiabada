package handlers

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/render"
	"github.com/leodip/goiabada/authserver/internal/revocationmetrics"
	"github.com/leodip/goiabada/authserver/internal/signingkeys"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/leodip/goiabada/core/oauth"
)

// The revocation endpoint's handler (#676 decisions 1, 8, 10 and 12, RFC 7009): what a running server
// cannot be made to do on demand, a fault reading the keys or the database, which answers 503 and
// never the 200 of an invalid token, and what each outcome writes: the audit events with their
// payloads, the warning record of a refused client and the metric's label. The integration tier
// holds what the revocation does to the grant across endpoints.

const (
	revokeIssuer      = "https://auth.example.com"
	revokeCallerId    = int64(71)
	revokeOwnerId     = int64(72)
	revokeUserId      = int64(73)
	revokeGrantId     = "fam-of-the-grant"
	revokeRefreshJti  = "rt-presented"
	revokeAccessJti   = "at-presented"
	revokeTokenString = "the.presented.token"
	revokeCallerName  = "the-caller"
	revokeOwnerName   = "the-owner"
)

// revokeUnavailable is the answer to a fault: RFC 7009 section 2.2.1's 503, which tells the client
// the token still exists and it may retry.
const revokeUnavailableCode = "temporarily_unavailable"

// revokeEndpoint is the handler over a mocked database, token parser and audit logger, answering
// through the real JSON writer, so each test reads the status, headers and body a client would.
type revokeEndpoint struct {
	database    *datamocks.Database
	parser      *handlersmocks.TokenParser
	auditLogger *handlersmocks.AuditLogger
	registry    *metrics.Registry
	settings    *record.Settings
	handler     http.HandlerFunc
}

func newRevokeEndpoint(t *testing.T) *revokeEndpoint {
	t.Helper()
	e := &revokeEndpoint{
		database:    datamocks.NewDatabase(t),
		parser:      handlersmocks.NewTokenParser(t),
		auditLogger: handlersmocks.NewAuditLogger(t),
		registry:    metrics.NewRegistry(),
		settings:    &record.Settings{Id: 1, Issuer: revokeIssuer},
	}
	e.handler = HandleRevokePost(render.New(nil, nil), e.database, e.parser, testDataCipher, e.auditLogger,
		revocationmetrics.Register(e.registry))
	return e
}

// confidentialCaller is the calling client, a confidential one whose secret is "caller-secret".
func confidentialCaller(t *testing.T) *record.Client {
	t.Helper()
	encrypted, err := testDataCipher.Encrypt("caller-secret")
	require.NoError(t, err)
	return &record.Client{Id: revokeCallerId, ClientIdentifier: revokeCallerName, Enabled: true,
		ClientSecretEncrypted: encrypted}
}

// callerFound has the caller's lookup by its identifier answer client.
func (e *revokeEndpoint) callerFound(client *record.Client) {
	e.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, client.ClientIdentifier).
		Return(client, nil).Once()
}

// parses has the parser accept the presented token as token.
func (e *revokeEndpoint) parses(token *oauth.JwtToken) {
	e.parser.On("DecodeAndValidateTokenString", mock.Anything, revokeTokenString, true).Return(token, nil).Once()
}

// post submits form, with the caller's credentials in the body when secret is not empty.
func (e *revokeEndpoint) post(t *testing.T, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/auth/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withSettings(req, e.settings)
	rr := httptest.NewRecorder()
	e.handler.ServeHTTP(rr, req)
	return rr
}

// samples answers the revocation family's sample lines in the registry's exposition.
func (e *revokeEndpoint) samples(t *testing.T) []string {
	t.Helper()
	rec := httptest.NewRecorder()
	e.registry.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var samples []string
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if strings.HasPrefix(line, "goiabada_revocation_requests_total{") {
			samples = append(samples, line)
		}
	}
	return samples
}

func revokeOutcome(outcome string) []string {
	return []string{`goiabada_revocation_requests_total{outcome="` + outcome + `"} 1`}
}

// callerForm is a revocation of the presented token by the confidential caller, in the body.
func callerForm(extra ...string) url.Values {
	form := url.Values{"token": {revokeTokenString}, "client_id": {revokeCallerName}, "client_secret": {"caller-secret"}}
	for i := 0; i+1 < len(extra); i += 2 {
		form.Set(extra[i], extra[i+1])
	}
	return form
}

// grantAccessToken is a live access token of the password grant, naming its grant and no session,
// issued to clientIdentifier.
func grantAccessToken(clientIdentifier string) *oauth.JwtToken {
	return &oauth.JwtToken{
		TokenBase64: revokeTokenString,
		Header:      map[string]interface{}{"alg": "RS256", "typ": "at+jwt"},
		Claims: map[string]interface{}{
			"iss": revokeIssuer, "sub": "the-subject", "client_id": clientIdentifier, "grant_id": revokeGrantId,
			"jti": revokeAccessJti, "typ": "Bearer", "auth_time": float64(time.Now().Unix()),
			"auth_state_generation": float64(0),
		},
	}
}

// offlineRefreshToken is a live offline refresh token of the password grant.
func offlineRefreshToken() *oauth.JwtToken {
	return &oauth.JwtToken{
		TokenBase64: revokeTokenString,
		Header:      map[string]interface{}{"alg": "RS256", "typ": "JWT"},
		Claims: map[string]interface{}{
			"iss": revokeIssuer, "sub": "the-subject", "jti": revokeRefreshJti, "typ": "Offline",
			"offline_access_max_lifetime": float64(time.Now().Add(time.Hour).Unix()),
		},
	}
}

// accessTokenLive arms the reads the access-token check makes of a live token issued to owner, of
// an enabled user on generation 0, whose grant is live.
func (e *revokeEndpoint) accessTokenLive(owner *record.Client) {
	e.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, owner.ClientIdentifier).
		Return(owner, nil).Once()
	e.database.On("GetUserBySubject", mock.Anything, mock.Anything, "the-subject").
		Return(&record.User{Id: revokeUserId, Subject: "the-subject", Enabled: true}, nil).Once()
	e.database.On("IsRefreshTokenFamilyLive", mock.Anything, mock.Anything, revokeGrantId).Return(true, nil).Once()
}

// refreshTokenLive arms the reads the refresh-token check makes of a live password grant token of
// the client whose row id is ownerId.
func (e *revokeEndpoint) refreshTokenLive(ownerId int64) {
	row := &record.RefreshToken{
		Id: 9, RefreshTokenJti: revokeRefreshJti, FirstRefreshTokenJti: revokeGrantId, RefreshTokenType: "Offline",
		UserId:          sql.NullInt64{Int64: revokeUserId, Valid: true},
		ClientId:        sql.NullInt64{Int64: ownerId, Valid: true},
		AuthenticatedAt: sql.NullTime{Time: time.Now().Add(-time.Minute), Valid: true},
	}
	e.database.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, revokeRefreshJti).Return(row, nil).Once()
	e.database.On("RefreshTokenLoadUser", mock.Anything, mock.Anything, row).Run(func(args mock.Arguments) {
		args.Get(2).(*record.RefreshToken).User = record.User{Id: revokeUserId, Enabled: true}
	}).Return(nil).Once()
	e.database.On("RefreshTokenLoadClient", mock.Anything, mock.Anything, row).Return(nil).Once()
	e.database.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, revokeGrantId).Return(false, nil).Once()
}

// grantRevoked arms the sixth revocation operation over the grant, with one live member to sweep.
func (e *revokeEndpoint) grantRevoked() {
	datamocks.ExpectRunInTransaction(e.database, revokeTx)
	e.database.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, revokeGrantId, "client_revoked").
		Return(true, nil).Once()
	e.database.On("GetRefreshTokensByFirstRefreshTokenJti", mock.Anything, revokeTx, revokeGrantId).
		Return([]*record.RefreshToken{{Id: 9, RefreshTokenJti: revokeRefreshJti, FirstRefreshTokenJti: revokeGrantId}}, nil).Once()
	e.database.On("UpdateRefreshToken", mock.Anything, revokeTx, mock.Anything).Return(nil).Once()
}

// assertRevokedAnswer asserts the 200 with an empty body RFC 7009 section 2.2 answers.
func assertRevokedAnswer(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Empty(t, rr.Body.String())
}

// assertErrorAnswer asserts status and the error code and description of an RFC 6749 section 5.2
// error response; a description ending in "..." is matched as a prefix.
func assertErrorAnswer(t *testing.T, rr *httptest.ResponseRecorder, status int, code, description string) {
	t.Helper()
	require.Equal(t, status, rr.Code, rr.Body.String())
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	var body map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body), rr.Body.String())
	assert.Equal(t, code, body["error"])
	if prefix, ok := strings.CutSuffix(description, "..."); ok {
		assert.True(t, strings.HasPrefix(body["error_description"], prefix), body["error_description"])
	} else {
		assert.Equal(t, description, body["error_description"])
	}
}

// A refresh token's grant is revoked: 200 with nothing in the body, revoked_grant with the jtis the
// operation moved, and the revoked outcome.
func TestHandleRevokePost_RevokesTheGrantOfARefreshToken(t *testing.T) {
	e := newRevokeEndpoint(t)
	e.callerFound(confidentialCaller(t))
	e.parses(offlineRefreshToken())
	e.refreshTokenLive(revokeCallerId)
	e.grantRevoked()
	e.auditLogger.On("Log", mock.Anything, "revoked_grant", map[string]interface{}{
		"client_id":                  revokeCallerId,
		"user_id":                    revokeUserId,
		"grant_id":                   revokeGrantId,
		"token_type":                 "refresh_token",
		"revoked_refresh_token_jtis": []string{revokeRefreshJti},
	}).Return().Once()

	rr := e.post(t, callerForm())

	assertRevokedAnswer(t, rr)
	assert.Equal(t, revokeOutcome("revoked"), e.samples(t))
}

// An access token carrying grant_id revokes its whole grant, the refresh token included.
func TestHandleRevokePost_RevokesTheGrantOfAnAccessToken(t *testing.T) {
	e := newRevokeEndpoint(t)
	caller := confidentialCaller(t)
	e.callerFound(caller)
	e.parses(grantAccessToken(revokeCallerName))
	e.accessTokenLive(caller)
	e.grantRevoked()
	e.auditLogger.On("Log", mock.Anything, "revoked_grant", map[string]interface{}{
		"client_id":                  revokeCallerId,
		"user_id":                    revokeUserId,
		"grant_id":                   revokeGrantId,
		"token_type":                 "access_token",
		"revoked_refresh_token_jtis": []string{revokeRefreshJti},
	}).Return().Once()

	rr := e.post(t, callerForm())

	assertRevokedAnswer(t, rr)
	assert.Equal(t, revokeOutcome("revoked"), e.samples(t))
}

// token_type_hint is ignored (RFC 7009 section 2.1 MAY, section 5): a wrong hint and an unknown one
// change nothing, the token says what it is.
func TestHandleRevokePost_IgnoresTheHint(t *testing.T) {
	for _, hint := range []string{"access_token", "refresh_token", "not_a_hint"} {
		t.Run(hint, func(t *testing.T) {
			e := newRevokeEndpoint(t)
			e.callerFound(confidentialCaller(t))
			e.parses(offlineRefreshToken())
			e.refreshTokenLive(revokeCallerId)
			e.grantRevoked()
			e.auditLogger.On("Log", mock.Anything, "revoked_grant", mock.Anything).Return().Once()

			rr := e.post(t, callerForm("token_type_hint", hint))

			assertRevokedAnswer(t, rr)
		})
	}
}

// A public client revokes with its client_id alone (RFC 7009 section 5).
func TestHandleRevokePost_APublicClientRevokesWithItsIdentifierAlone(t *testing.T) {
	e := newRevokeEndpoint(t)
	caller := &record.Client{Id: revokeCallerId, ClientIdentifier: revokeCallerName, Enabled: true, IsPublic: true}
	e.callerFound(caller)
	e.parses(grantAccessToken(revokeCallerName))
	e.accessTokenLive(caller)
	e.grantRevoked()
	e.auditLogger.On("Log", mock.Anything, "revoked_grant", mock.Anything).Return().Once()

	rr := e.post(t, url.Values{"token": {revokeTokenString}, "client_id": {revokeCallerName}})

	assertRevokedAnswer(t, rr)
}

// Another client's live token is refused with 400 invalid_grant (decision 8): nothing is revoked,
// token_revocation_refused records the caller, the token's client and the type of token, and the
// outcome is refused.
func TestHandleRevokePost_RefusesAnotherClientsLiveToken(t *testing.T) {
	owner := &record.Client{Id: revokeOwnerId, ClientIdentifier: revokeOwnerName, Enabled: true}

	t.Run("an access token", func(t *testing.T) {
		e := newRevokeEndpoint(t)
		e.callerFound(confidentialCaller(t))
		e.parses(grantAccessToken(revokeOwnerName))
		e.accessTokenLive(owner)
		e.auditLogger.On("Log", mock.Anything, "token_revocation_refused", map[string]interface{}{
			"client_id":       revokeCallerId,
			"token_client_id": revokeOwnerId,
			"token_type":      "access_token",
		}).Return().Once()

		rr := e.post(t, callerForm())

		assertErrorAnswer(t, rr, http.StatusBadRequest, "invalid_grant", "The token was issued to another client.")
		assert.Equal(t, revokeOutcome("refused"), e.samples(t))
		assertNotAttempted(t, e.database, "RunInTransaction")
	})

	t.Run("a refresh token", func(t *testing.T) {
		e := newRevokeEndpoint(t)
		e.callerFound(confidentialCaller(t))
		e.parses(offlineRefreshToken())
		e.refreshTokenLive(revokeOwnerId)
		e.database.On("GetClientById", mock.Anything, mock.Anything, revokeOwnerId).Return(owner, nil).Once()
		e.auditLogger.On("Log", mock.Anything, "token_revocation_refused", map[string]interface{}{
			"client_id":       revokeCallerId,
			"token_client_id": revokeOwnerId,
			"token_type":      "refresh_token",
		}).Return().Once()

		rr := e.post(t, callerForm())

		assertErrorAnswer(t, rr, http.StatusBadRequest, "invalid_grant", "The token was issued to another client.")
		assert.Equal(t, revokeOutcome("refused"), e.samples(t))
		assertNotAttempted(t, e.database, "RunInTransaction")
	})
}

// A token that is not live is invalid, whatever client it names: 200, nothing revoked, nothing
// audited (RFC 7009 section 2.2), and the invalid_token outcome. No audit expectation is set, so any
// event fails the test.
func TestHandleRevokePost_AnInvalidTokenIsAnsweredOK(t *testing.T) {
	refusedByParser := errs.Wrap(signingkeys.ErrTokenRefused, "token is malformed")
	owner := &record.Client{Id: revokeOwnerId, ClientIdentifier: revokeOwnerName, Enabled: true}

	cases := []struct {
		name string
		arm  func(e *revokeEndpoint)
	}{
		{"a token the parser refuses: malformed, forged, expired or foreign", func(e *revokeEndpoint) {
			e.parser.On("DecodeAndValidateTokenString", mock.Anything, revokeTokenString, true).
				Return(nil, refusedByParser).Once()
		}},
		{"an access token issued before the upgrade", func(e *revokeEndpoint) {
			token := grantAccessToken(revokeCallerName)
			token.Header["typ"] = "JWT"
			delete(token.Claims, "client_id")
			delete(token.Claims, "grant_id")
			e.parses(token)
		}},
		{"an ID token", func(e *revokeEndpoint) {
			e.parses(&oauth.JwtToken{TokenBase64: revokeTokenString, Header: map[string]interface{}{"typ": "JWT"},
				Claims: map[string]interface{}{"iss": revokeIssuer, "sub": "the-subject", "typ": "ID", "jti": "id-1"}})
		}},
		{"an access token from another issuer", func(e *revokeEndpoint) {
			token := grantAccessToken(revokeCallerName)
			token.Claims["iss"] = "https://other.example.com"
			e.parses(token)
		}},
		{"an access token whose grant was revoked already", func(e *revokeEndpoint) {
			e.parses(grantAccessToken(revokeCallerName))
			e.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, revokeCallerName).
				Return(confidentialCaller(t), nil).Once()
			e.database.On("GetUserBySubject", mock.Anything, mock.Anything, "the-subject").
				Return(&record.User{Id: revokeUserId, Enabled: true}, nil).Once()
			e.database.On("IsRefreshTokenFamilyLive", mock.Anything, mock.Anything, revokeGrantId).Return(false, nil).Once()
		}},
		{"another client's access token whose grant was revoked already", func(e *revokeEndpoint) {
			e.parses(grantAccessToken(revokeOwnerName))
			e.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, revokeOwnerName).
				Return(owner, nil).Once()
			e.database.On("GetUserBySubject", mock.Anything, mock.Anything, "the-subject").
				Return(&record.User{Id: revokeUserId, Enabled: true}, nil).Once()
			e.database.On("IsRefreshTokenFamilyLive", mock.Anything, mock.Anything, revokeGrantId).Return(false, nil).Once()
		}},
		{"a refresh token with no row", func(e *revokeEndpoint) {
			e.parses(offlineRefreshToken())
			e.database.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, revokeRefreshJti).Return(nil, nil).Once()
		}},
		{"a refresh token already revoked", func(e *revokeEndpoint) {
			e.parses(offlineRefreshToken())
			row := &record.RefreshToken{Id: 9, RefreshTokenJti: revokeRefreshJti, FirstRefreshTokenJti: revokeGrantId,
				UserId: sql.NullInt64{Int64: revokeUserId, Valid: true}, ClientId: sql.NullInt64{Int64: revokeCallerId, Valid: true},
				AuthenticatedAt: sql.NullTime{Time: time.Now(), Valid: true}, Revoked: true}
			e.database.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, revokeRefreshJti).Return(row, nil).Once()
			e.database.On("RefreshTokenLoadUser", mock.Anything, mock.Anything, row).Run(func(args mock.Arguments) {
				args.Get(2).(*record.RefreshToken).User = record.User{Id: revokeUserId, Enabled: true}
			}).Return(nil).Once()
			e.database.On("RefreshTokenLoadClient", mock.Anything, mock.Anything, row).Return(nil).Once()
		}},
		{"another client's live refresh token, its client disabled", func(e *revokeEndpoint) {
			e.parses(offlineRefreshToken())
			e.refreshTokenLive(revokeOwnerId)
			e.database.On("GetClientById", mock.Anything, mock.Anything, revokeOwnerId).
				Return(&record.Client{Id: revokeOwnerId, ClientIdentifier: revokeOwnerName}, nil).Once()
		}},
		{"another client's live refresh token, its client deleted", func(e *revokeEndpoint) {
			e.parses(offlineRefreshToken())
			e.refreshTokenLive(revokeOwnerId)
			e.database.On("GetClientById", mock.Anything, mock.Anything, revokeOwnerId).Return(nil, nil).Once()
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newRevokeEndpoint(t)
			e.callerFound(confidentialCaller(t))
			tc.arm(e)

			rr := e.post(t, callerForm())

			assertRevokedAnswer(t, rr)
			assert.Equal(t, revokeOutcome("invalid_token"), e.samples(t))
			assertNotAttempted(t, e.database, "RunInTransaction")
		})
	}
}

// A fault reading the keys or the database answers 503, never the 200 of an invalid token, which
// would tell the client its token was revoked when it may still be live (RFC 7009 section 2.2.1).
// It is logged once at Error, nothing is audited, and the outcome is error.
func TestHandleRevokePost_AFaultAnswersServiceUnavailable(t *testing.T) {
	boom := errors.New("connection refused")

	cases := []struct {
		name string
		arm  func(e *revokeEndpoint)
	}{
		{"the caller cannot be looked up", func(e *revokeEndpoint) {
			e.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, revokeCallerName).
				Return(nil, boom).Once()
		}},
		{"the signing keys cannot be read", func(e *revokeEndpoint) {
			e.callerFound(confidentialCaller(t))
			e.parser.On("DecodeAndValidateTokenString", mock.Anything, revokeTokenString, true).Return(nil, boom).Once()
		}},
		{"the access token's state cannot be read", func(e *revokeEndpoint) {
			e.callerFound(confidentialCaller(t))
			e.parses(grantAccessToken(revokeCallerName))
			e.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, revokeCallerName).
				Return(confidentialCaller(t), nil).Once()
			e.database.On("GetUserBySubject", mock.Anything, mock.Anything, "the-subject").
				Return(&record.User{Id: revokeUserId, Enabled: true}, nil).Once()
			e.database.On("IsRefreshTokenFamilyLive", mock.Anything, mock.Anything, revokeGrantId).Return(false, boom).Once()
		}},
		{"the refresh token's row cannot be read", func(e *revokeEndpoint) {
			e.callerFound(confidentialCaller(t))
			e.parses(offlineRefreshToken())
			e.database.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, revokeRefreshJti).Return(nil, boom).Once()
		}},
		{"the refresh token's family cannot be read", func(e *revokeEndpoint) {
			e.callerFound(confidentialCaller(t))
			e.parses(offlineRefreshToken())
			row := &record.RefreshToken{Id: 9, RefreshTokenJti: revokeRefreshJti, FirstRefreshTokenJti: revokeGrantId,
				UserId: sql.NullInt64{Int64: revokeUserId, Valid: true}, ClientId: sql.NullInt64{Int64: revokeCallerId, Valid: true},
				AuthenticatedAt: sql.NullTime{Time: time.Now(), Valid: true}}
			e.database.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, revokeRefreshJti).Return(row, nil).Once()
			e.database.On("RefreshTokenLoadUser", mock.Anything, mock.Anything, row).Run(func(args mock.Arguments) {
				args.Get(2).(*record.RefreshToken).User = record.User{Id: revokeUserId, Enabled: true}
			}).Return(nil).Once()
			e.database.On("RefreshTokenLoadClient", mock.Anything, mock.Anything, row).Return(nil).Once()
			e.database.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, revokeGrantId).Return(false, boom).Once()
		}},
		{"another client's token's client cannot be read", func(e *revokeEndpoint) {
			e.callerFound(confidentialCaller(t))
			e.parses(offlineRefreshToken())
			e.refreshTokenLive(revokeOwnerId)
			e.database.On("GetClientById", mock.Anything, mock.Anything, revokeOwnerId).Return(nil, boom).Once()
		}},
		{"the revocation cannot commit", func(e *revokeEndpoint) {
			e.callerFound(confidentialCaller(t))
			e.parses(offlineRefreshToken())
			e.refreshTokenLive(revokeCallerId)
			datamocks.ExpectRunInTransactionRefused(e.database, boom)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newRevokeEndpoint(t)
			tc.arm(e)
			logged := logtest.CaptureSlog(t)

			rr := e.post(t, callerForm())

			assertErrorAnswer(t, rr, http.StatusServiceUnavailable, revokeUnavailableCode,
				"The token could not be revoked. Retry later...")
			assert.Equal(t, revokeOutcome("error"), e.samples(t))
			var errorRecords []logtest.CapturedRecord
			for _, record := range logged.Records() {
				if record.Level == slog.LevelError {
					errorRecords = append(errorRecords, record)
				}
			}
			require.Len(t, errorRecords, 1, logged.Text())
			assert.Equal(t, "unable to answer a token revocation request", errorRecords[0].Message)
			assert.Contains(t, fmt.Sprint(errorRecords[0].Attrs["error"]), "connection refused")
		})
	}
}

// A client that cannot be authenticated is refused as at the token endpoint, before the token is
// read: 401 invalid_client with the Basic challenge, one Warn record naming the revocation endpoint,
// no audit event, and the refused outcome.
func TestHandleRevokePost_ClientAuthenticationRefusal(t *testing.T) {
	cases := []struct {
		name   string
		arm    func(e *revokeEndpoint)
		form   url.Values
		basic  string
		reason string
		method string
	}{
		{"an unknown client, through the Authorization header", func(e *revokeEndpoint) {
			e.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "no-such-client").Return(nil, nil).Once()
		}, url.Values{"token": {revokeTokenString}}, "no-such-client:a-secret", "Client does not exist.", "client_secret_basic"},
		{"a wrong secret, in the body", func(e *revokeEndpoint) {
			e.callerFound(confidentialCaller(t))
		}, url.Values{"token": {revokeTokenString}, "client_id": {revokeCallerName}, "client_secret": {"wrong"}}, "",
			"Client authentication failed. Please review your client_secret.", "client_secret_post"},
		{"a confidential client with no secret", func(e *revokeEndpoint) {
			e.callerFound(confidentialCaller(t))
		}, url.Values{"token": {revokeTokenString}, "client_id": {revokeCallerName}}, "",
			"This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed.",
			"none"},
		{"a disabled client", func(e *revokeEndpoint) {
			caller := confidentialCaller(t)
			caller.Enabled = false
			e.callerFound(caller)
		}, callerForm(), "", "Client is disabled.", "client_secret_post"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newRevokeEndpoint(t)
			tc.arm(e)
			logged := logtest.CaptureSlog(t)

			req := httptest.NewRequest(http.MethodPost, "/auth/revoke", strings.NewReader(tc.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.basic != "" {
				req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(tc.basic)))
			}
			req = withSettings(req, e.settings)
			rr := httptest.NewRecorder()
			e.handler.ServeHTTP(rr, req)

			assertErrorAnswer(t, rr, http.StatusUnauthorized, "invalid_client", tc.reason)
			assert.Equal(t, `Basic realm="goiabada"`, rr.Header().Get("WWW-Authenticate"))
			assert.Equal(t, revokeOutcome("refused"), e.samples(t))

			records := logged.Records()
			require.Len(t, records, 1, logged.Text())
			assert.Equal(t, slog.LevelWarn, records[0].Level)
			assert.Equal(t, "client authentication refused at the revocation endpoint", records[0].Message)
			assert.Equal(t, tc.reason, records[0].Attrs["reason"])
			assert.Equal(t, tc.method, records[0].Attrs["client_auth_method"])
			assert.NotContains(t, records[0].Attrs, "grant_type")
		})
	}
}

// What can be refused before any token is read is answered 400 invalid_request, as RFC 7009 section
// 2.1 and RFC 6749 section 5.2 have it, and counted as refused: no token, a repeated parameter, two
// client authentication methods at once.
func TestHandleRevokePost_AMalformedRequestIsRefused(t *testing.T) {
	t.Run("no token", func(t *testing.T) {
		e := newRevokeEndpoint(t)
		e.callerFound(confidentialCaller(t))

		rr := e.post(t, url.Values{"client_id": {revokeCallerName}, "client_secret": {"caller-secret"}})

		assertErrorAnswer(t, rr, http.StatusBadRequest, "invalid_request", "Missing required token parameter.")
		assert.Equal(t, revokeOutcome("refused"), e.samples(t))
	})

	t.Run("a repeated token", func(t *testing.T) {
		e := newRevokeEndpoint(t)
		form := callerForm()
		form.Add("token", "another.token")

		rr := e.post(t, form)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), `"error":"invalid_request"`)
		assert.Equal(t, revokeOutcome("refused"), e.samples(t))
	})

	t.Run("a repeated hint is ignored with the hint", func(t *testing.T) {
		e := newRevokeEndpoint(t)
		e.callerFound(confidentialCaller(t))
		e.parser.On("DecodeAndValidateTokenString", mock.Anything, revokeTokenString, true).
			Return(nil, errs.Wrap(signingkeys.ErrTokenRefused, "malformed")).Once()
		form := callerForm("token_type_hint", "access_token")
		form.Add("token_type_hint", "refresh_token")

		rr := e.post(t, form)

		assertRevokedAnswer(t, rr)
	})
}

// An access token without grant_id, of the client credentials grant or the implicit flow, is not
// revoked yet (#676 slice 7 stores its jti): RFC 7009 section 2.2.1's unsupported_token_type, never
// the 200 that would claim it was.
func TestHandleRevokePost_AGrantlessAccessTokenIsNotRevokedYet(t *testing.T) {
	e := newRevokeEndpoint(t)
	caller := confidentialCaller(t)
	e.callerFound(caller)
	token := grantAccessToken(revokeCallerName)
	delete(token.Claims, "grant_id")
	delete(token.Claims, "auth_time")
	e.parses(token)
	e.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, revokeCallerName).Return(caller, nil).Once()

	rr := e.post(t, callerForm())

	assertErrorAnswer(t, rr, http.StatusBadRequest, "unsupported_token_type",
		"The authorization server does not support the revocation of the presented token type.")
	assert.Equal(t, revokeOutcome("refused"), e.samples(t))
	assertNotAttempted(t, e.database, "RunInTransaction")
}

// A fault met before the handler, on the revocation branch, is answered as the handler answers its
// own: 503, counted as error.
func TestRevocationFaults_AnswerServiceUnavailable(t *testing.T) {
	registry := metrics.NewRegistry()
	writer := RevocationFaults(render.New(nil, nil), revocationmetrics.Register(registry))
	logtest.CaptureSlog(t)

	rr := httptest.NewRecorder()
	writer.JSONError(rr, httptest.NewRequest(http.MethodPost, "/auth/revoke", nil), errors.New("no settings"))

	assertErrorAnswer(t, rr, http.StatusServiceUnavailable, revokeUnavailableCode, "The token could not be revoked. Retry later...")
	e := &revokeEndpoint{registry: registry}
	assert.Equal(t, revokeOutcome("error"), e.samples(t))
}
