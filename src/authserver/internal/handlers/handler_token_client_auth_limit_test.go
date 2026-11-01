package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/clientauth"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/render"
	"github.com/leodip/goiabada/authserver/internal/tokenmetrics"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/metrics"
)

// The client authentication limit at the token endpoint (#707 decisions 6, 7 and 10), over HTTP
// with the real validator and writer, the limiter port faked beneath them: a client over its budget
// is answered 429 at the point its grant checks the secret, in the shape the token endpoint's
// limiters answer, and is counted in no refusal metric of the endpoint's own.

// refusingSecretCheckLimiter answers every reservation with its refusal or its fault, recording the
// clients it was asked for. It implements clientauth.SecretCheckLimiter directly.
type refusingSecretCheckLimiter struct {
	fault error
	asked []string
}

func (l *refusingSecretCheckLimiter) ReserveSecretCheck(_ context.Context, clientIdentifier string) (clientauth.SecretCheckReservation, error) {
	l.asked = append(l.asked, clientIdentifier)
	if l.fault != nil {
		return nil, l.fault
	}
	return nil, &clientauth.LimitReachedError{RetryAfter: time.Hour}
}

// limitedTokenRequest is one grant's request for the_client, its client and the settings it is
// validated under. expect, when set, adds the reads the grant makes before it checks the secret.
type limitedTokenRequest struct {
	grant    string
	form     url.Values
	settings *record.Settings
	expect   func(database *datamocks.Database, client *record.Client)
}

func limitedTokenRequests() []limitedTokenRequest {
	return []limitedTokenRequest{
		{"authorization_code", url.Values{"grant_type": {"authorization_code"}, "code": {"the_code"},
			"redirect_uri": {"https://app.example.com/cb"}}, &record.Settings{}, expectRedeemableCode},
		{"client_credentials", url.Values{"grant_type": {"client_credentials"}}, &record.Settings{}, nil},
		{"refresh_token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"any"}}, &record.Settings{}, nil},
		{"password", url.Values{"grant_type": {"password"}, "username": {"user@example.com"}, "password": {"pw"}},
			&record.Settings{ResourceOwnerPasswordCredentialsEnabled: true}, nil},
	}
}

// expectRedeemableCode stores the_code, unused, for client and its redirect URI, so the redemption
// passes every check that comes before the secret's.
func expectRedeemableCode(database *datamocks.Database, client *record.Client) {
	code := &record.Code{Id: 11, CodeHash: hashutil.HashString("the_code"), ClientId: client.Id, Client: *client,
		RedirectURI: "https://app.example.com/cb", UserId: 5, User: record.User{Id: 5, Enabled: true},
		CreatedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true}}
	database.On("GetCodeByCodeHash", mock.Anything, mock.Anything, hashutil.HashString("the_code"), false).Return(code, nil).Once()
	database.On("CodeLoadClient", mock.Anything, mock.Anything, code).Return(nil).Once()
	database.On("CodeLoadUser", mock.Anything, mock.Anything, code).Return(nil).Once()
}

func overLimitClient(t *testing.T) *record.Client {
	t.Helper()
	encrypted, err := testDataCipher.Encrypt("the_client_secret")
	require.NoError(t, err)
	return &record.Client{Id: 7, ClientIdentifier: "the_client", Enabled: true, ClientCredentialsEnabled: true,
		AuthorizationCodeEnabled: true, ClientSecretEncrypted: encrypted}
}

func serveLimitedToken(t *testing.T, limiter clientauth.SecretCheckLimiter, client *record.Client,
	request limitedTokenRequest, secret string, registry *metrics.Registry) *httptest.ResponseRecorder {

	t.Helper()
	database := datamocks.NewDatabase(t)
	database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "the_client").Return(client, nil).Once()
	if request.expect != nil {
		request.expect(database, client)
	}
	handler := HandleTokenPost(render.New(nil, nil), datamocks.NewDatabase(t), handlersmocks.NewTokenIssuer(t),
		protocolvalidation.NewTokenValidator(database, nil, nil, testDataCipher, limiter),
		handlersmocks.NewAuditLogger(t), noCredentialFailures{}, tokenmetrics.Register(registry))

	form := url.Values{}
	for k, v := range request.form {
		form[k] = v
	}
	form.Set("client_id", "the_client")
	form.Set("client_secret", secret)
	req, err := http.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withSettings(req, request.settings)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// refusedTokenSamples answers the nonzero samples of the token endpoint's refusal metric.
func refusedTokenSamples(t *testing.T, registry *metrics.Registry) []string {
	t.Helper()
	var nonzero []string
	for _, sample := range tokenSamples(t, registry) {
		if strings.HasPrefix(sample, "goiabada_token_requests_refused_total{") && !strings.HasSuffix(sample, " 0") {
			nonzero = append(nonzero, sample)
		}
	}
	return nonzero
}

func TestHandleTokenPost_AClientOverItsLimitIsAnswered429AtEveryGrant(t *testing.T) {
	for _, request := range limitedTokenRequests() {
		for _, secret := range []string{"the_client_secret", "not_the_secret"} {
			t.Run(request.grant+" with "+secret, func(t *testing.T) {
				logs := logtest.CaptureSlog(t)
				registry := metrics.NewRegistry()
				limiter := &refusingSecretCheckLimiter{}

				rr := serveLimitedToken(t, limiter, overLimitClient(t), request, secret, registry)

				assert.Equal(t, http.StatusTooManyRequests, rr.Code)
				assert.Equal(t, "3600", rr.Header().Get("Retry-After"))
				assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
				assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
				assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
				assert.Empty(t, rr.Header().Get("WWW-Authenticate"), "the credentials were never judged")
				var body map[string]string
				require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body), "the body must be JSON: %q", rr.Body.String())
				assert.Equal(t, map[string]string{
					"error":             "invalid_request",
					"error_description": "Too many requests. Please wait and try again later.",
				}, body)
				assert.Equal(t, []string{"the_client"}, limiter.asked)

				assert.Empty(t, refusedTokenSamples(t, registry), "a 429 is the rate limiter's refusal, counted under its limiter")
				for _, record := range logs.Records() {
					assert.NotEqual(t, "client authentication refused at the token endpoint", record.Message,
						"the client was not refused authentication")
				}
			})
		}
	}
}

// The limit is consulted where the grant checks the secret, so a code grant that fails earlier,
// with an invalid code, keeps its earlier answer and spends nothing.
func TestHandleTokenPost_OverItsLimitAnInvalidCodeIsStillInvalidGrant(t *testing.T) {
	limiter := &refusingSecretCheckLimiter{}
	database := datamocks.NewDatabase(t)
	database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "the_client").Return(overLimitClient(t), nil).Once()
	database.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.Anything, false).Return(nil, nil).Once()
	database.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.Anything, true).Return(nil, nil).Once()
	handler := HandleTokenPost(render.New(nil, nil), datamocks.NewDatabase(t), handlersmocks.NewTokenIssuer(t),
		protocolvalidation.NewTokenValidator(database, nil, nil, testDataCipher, limiter),
		handlersmocks.NewAuditLogger(t), noCredentialFailures{}, testTokenMetrics())

	form := url.Values{"grant_type": {"authorization_code"}, "code": {"not-a-code"}, "redirect_uri": {"https://app.example.com/cb"},
		"client_id": {"the_client"}, "client_secret": {"the_client_secret"}}
	req, err := http.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, withSettings(req, &record.Settings{}))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "invalid_grant", body["error"])
	assert.Equal(t, "Code is invalid.", body["error_description"])
	assert.Empty(t, limiter.asked)
}

// A count the limiter cannot read is the token endpoint's own fault: 500 server_error, with none of
// a refusal's headers, counted as the endpoint counts its faults.
func TestHandleTokenPost_AClientAuthenticationCountThatCannotBeReadIsAServerError(t *testing.T) {
	for _, request := range limitedTokenRequests() {
		t.Run(request.grant, func(t *testing.T) {
			registry := metrics.NewRegistry()
			limiter := &refusingSecretCheckLimiter{fault: errors.New("connection refused")}

			rr := serveLimitedToken(t, limiter, overLimitClient(t), request, "the_client_secret", registry)

			assert.Equal(t, http.StatusInternalServerError, rr.Code)
			assert.Empty(t, rr.Header().Get("Retry-After"))
			var body map[string]string
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
			assert.Equal(t, "server_error", body["error"])
			assert.Equal(t, []string{
				`goiabada_token_requests_refused_total{grant_type="` + request.grant + `",error="server_error"} 1`,
			}, refusedTokenSamples(t, registry))
		})
	}
}
