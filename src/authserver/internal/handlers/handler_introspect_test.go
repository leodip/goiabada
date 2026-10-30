package handlers

import (
	"database/sql"
	"encoding/base64"
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
	"github.com/leodip/goiabada/authserver/internal/introspectionmetrics"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/render"
	"github.com/leodip/goiabada/authserver/internal/signingkeys"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/leodip/goiabada/core/oauth"
)

// The introspection endpoint's handler (#676 decisions 5, 7, 9 and 13, RFC 7662): the members of each
// answer, written out, which a running server cannot be made to produce on demand for every shape;
// a fault reading the keys or the database, which answers 500 and never {"active": false}; the
// Cache-Control of every answer; the warning record of a refused client; and the metric's label. The
// integration tier holds what each way a token dies does to the answer.

const (
	introspectIssuer      = "https://auth.example.com"
	introspectCallerId    = int64(81)
	introspectOwnerId     = int64(82)
	introspectUserId      = int64(83)
	introspectGrantId     = "fam-of-the-grant"
	introspectRefreshJti  = "rt-presented"
	introspectAccessJti   = "at-presented"
	introspectTokenString = "the.presented.token"
	introspectCallerName  = "the-api"
	introspectOwnerName   = "the-app"
	introspectResource    = "product-api"
	introspectResourceId  = int64(91)
)

// introspectEndpoint is the handler over a mocked database and token parser, answering through the
// real JSON writer, so each test reads the status, headers and body a caller would. It takes no
// audit logger: introspection changes nothing and writes no audit event (decision 11).
type introspectEndpoint struct {
	database *datamocks.Database
	parser   *handlersmocks.TokenParser
	registry *metrics.Registry
	settings *record.Settings
	handler  http.HandlerFunc
}

func newIntrospectEndpoint(t *testing.T) *introspectEndpoint {
	t.Helper()
	e := &introspectEndpoint{
		database: datamocks.NewDatabase(t),
		parser:   handlersmocks.NewTokenParser(t),
		registry: metrics.NewRegistry(),
		// The password grant is on, as it must be for refreshTokenRow's token to refresh.
		settings: &record.Settings{Id: 1, Issuer: introspectIssuer, ResourceOwnerPasswordCredentialsEnabled: true},
	}
	e.handler = HandleIntrospectPost(render.New(nil, nil), e.database, e.parser, testDataCipher,
		introspectionmetrics.Register(e.registry))
	return e
}

// introspectingCaller is the calling API's client, a confidential one whose secret is "api-secret".
func introspectingCaller(t *testing.T) *record.Client {
	t.Helper()
	encrypted, err := testDataCipher.Encrypt("api-secret")
	require.NoError(t, err)
	return &record.Client{Id: introspectCallerId, ClientIdentifier: introspectCallerName, Enabled: true,
		ClientSecretEncrypted: encrypted}
}

// tokenOwner is the client the presented access token was issued to.
func tokenOwner() *record.Client {
	return &record.Client{Id: introspectOwnerId, ClientIdentifier: introspectOwnerName, Enabled: true}
}

func (e *introspectEndpoint) callerFound(client *record.Client) {
	e.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, client.ClientIdentifier).
		Return(client, nil).Once()
}

func (e *introspectEndpoint) parses(token *oauth.JwtToken) {
	e.parser.On("DecodeAndValidateTokenString", mock.Anything, introspectTokenString, true).Return(token, nil).Once()
}

// lists arms the caller's introspection resources: the resources whose identifiers are given.
func (e *introspectEndpoint) lists(identifiers ...string) {
	links := []record.ClientIntrospectionResource{}
	resources := []record.Resource{}
	ids := []int64{}
	for i, identifier := range identifiers {
		id := introspectResourceId + int64(i)
		links = append(links, record.ClientIntrospectionResource{Id: 500 + int64(i), ClientId: introspectCallerId, ResourceId: id})
		resources = append(resources, record.Resource{Id: id, ResourceIdentifier: identifier})
		ids = append(ids, id)
	}
	e.database.On("GetClientIntrospectionResourcesByClientId", mock.Anything, mock.Anything, introspectCallerId).
		Return(links, nil).Once()
	e.database.On("GetResourcesByIds", mock.Anything, mock.Anything, ids).Return(resources, nil).Maybe()
}

func (e *introspectEndpoint) post(t *testing.T, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	return e.postBody(t, form.Encode(), nil)
}

// postBody posts body as it is, form-encoded or not, with the given Authorization header, if any.
func (e *introspectEndpoint) postBody(t *testing.T, body string, authorization *string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/auth/introspect", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if authorization != nil {
		req.Header.Set("Authorization", *authorization)
	}
	req = withSettings(req, e.settings)
	rr := httptest.NewRecorder()
	e.handler.ServeHTTP(rr, req)
	return rr
}

// samples answers the introspection family's sample lines in the registry's exposition.
func (e *introspectEndpoint) samples(t *testing.T) []string {
	t.Helper()
	rec := httptest.NewRecorder()
	e.registry.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var samples []string
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if strings.HasPrefix(line, "goiabada_introspection_requests_total{") {
			samples = append(samples, line)
		}
	}
	return samples
}

func introspectOutcome(outcome string) []string {
	return []string{`goiabada_introspection_requests_total{outcome="` + outcome + `"} 1`}
}

// apiForm is an introspection of the presented token by the API's client, in the body.
func apiForm(extra ...string) url.Values {
	form := url.Values{"token": {introspectTokenString}, "client_id": {introspectCallerName}, "client_secret": {"api-secret"}}
	for i := 0; i+1 < len(extra); i += 2 {
		form.Set(extra[i], extra[i+1])
	}
	return form
}

// apiAccessToken is a live access token of the password grant, naming its grant and no session,
// issued to the app for aud, with fixed times so the answer's members are literals.
func apiAccessToken(aud interface{}) *oauth.JwtToken {
	return &oauth.JwtToken{
		TokenBase64: introspectTokenString,
		Header:      map[string]interface{}{"alg": "RS256", "typ": "at+jwt", "kid": "key-1"},
		Claims: map[string]interface{}{
			"iss": introspectIssuer, "sub": "the-subject", "client_id": introspectOwnerName, "grant_id": introspectGrantId,
			"jti": introspectAccessJti, "typ": "Bearer", "aud": aud, "scope": "openid product-api:read",
			"iat": float64(1800000000), "nbf": float64(1800000000), "exp": float64(1800000300),
			"auth_time": float64(1799999990), "acr": "urn:goiabada:pwd", "auth_state_generation": float64(0),
			"email": "user@example.com",
		},
	}
}

// accessTokenLive arms the reads the access-token check makes of apiAccessToken: its client, an
// enabled user on generation 0, and a live grant.
func (e *introspectEndpoint) accessTokenLive() {
	e.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, introspectOwnerName).
		Return(tokenOwner(), nil).Once()
	e.database.On("GetUserBySubject", mock.Anything, mock.Anything, "the-subject").
		Return(&record.User{Id: introspectUserId, Subject: "the-subject", Enabled: true}, nil).Once()
	e.database.On("IsRefreshTokenFamilyLive", mock.Anything, mock.Anything, introspectGrantId).Return(true, nil).Once()
}

// callerRefreshToken is a live offline refresh token of the password grant, with fixed times.
func callerRefreshToken() *oauth.JwtToken {
	return &oauth.JwtToken{
		TokenBase64: introspectTokenString,
		Header:      map[string]interface{}{"alg": "RS256", "typ": "JWT", "kid": "key-1"},
		Claims: map[string]interface{}{
			"iss": introspectIssuer, "aud": introspectIssuer, "sub": "the-subject", "jti": introspectRefreshJti,
			"typ": "Offline", "scope": "openid offline_access", "iat": float64(1800000000), "nbf": float64(1800000000),
			"exp":                         float64(1800086400),
			"offline_access_max_lifetime": float64(time.Now().Add(time.Hour).Unix()),
		},
	}
}

// refreshTokenRow arms FindRefreshToken's reads of callerRefreshToken, a password grant token of the
// client whose row id is ownerId, and returns the row.
func (e *introspectEndpoint) refreshTokenRow(ownerId int64) *record.RefreshToken {
	row := &record.RefreshToken{
		Id: 9, RefreshTokenJti: introspectRefreshJti, FirstRefreshTokenJti: introspectGrantId, RefreshTokenType: "Offline",
		UserId:          sql.NullInt64{Int64: introspectUserId, Valid: true},
		ClientId:        sql.NullInt64{Int64: ownerId, Valid: true},
		AuthenticatedAt: sql.NullTime{Time: time.Now().Add(-time.Minute), Valid: true},
		Scope:           "openid offline_access",
	}
	e.database.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, introspectRefreshJti).Return(row, nil).Once()
	e.database.On("RefreshTokenLoadUser", mock.Anything, mock.Anything, row).Run(func(args mock.Arguments) {
		args.Get(2).(*record.RefreshToken).User = record.User{Id: introspectUserId, Enabled: true}
	}).Return(nil).Once()
	e.database.On("RefreshTokenLoadClient", mock.Anything, mock.Anything, row).Return(nil).Once()
	return row
}

// assertNotStored asserts the headers every introspection answer carries: no cache may keep it
// (RFC 7662 section 4), and the pair RFC 6749 section 5.1 writes.
func assertNotStored(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
}

// assertIntrospection asserts a 200 whose JSON body is exactly want.
func assertIntrospection(t *testing.T, rr *httptest.ResponseRecorder, want string) {
	t.Helper()
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	assert.JSONEq(t, want, rr.Body.String())
	assertNotStored(t, rr)
}

const inactiveAnswer = `{"active": false}`

// A live access token whose aud names a resource on the caller's list is active, answered with RFC
// 7662 section 2.2's members read from the token and nothing else: no auth_time, acr, email or the
// other claims it carries (decision 13). aud is answered as the token carries it.
func TestHandleIntrospectPost_ALiveAccessTokenForAListedResourceIsActive(t *testing.T) {
	cases := []struct {
		name   string
		aud    interface{}
		listed []string
		want   string
	}{
		{"one audience", introspectResource, []string{introspectResource}, `"product-api"`},
		{"several audiences, one of them listed", []interface{}{"authserver", introspectResource},
			[]string{"other-api", introspectResource}, `["authserver", "product-api"]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newIntrospectEndpoint(t)
			e.callerFound(introspectingCaller(t))
			e.parses(apiAccessToken(tc.aud))
			e.accessTokenLive()
			e.lists(tc.listed...)

			rr := e.post(t, apiForm())

			assertIntrospection(t, rr, `{
				"active": true,
				"scope": "openid product-api:read",
				"client_id": "the-app",
				"sub": "the-subject",
				"aud": `+tc.want+`,
				"iss": "https://auth.example.com",
				"exp": 1800000300,
				"iat": 1800000000,
				"nbf": 1800000000,
				"jti": "at-presented",
				"token_type": "Bearer"
			}`)
			assert.Equal(t, introspectOutcome("active"), e.samples(t))
		})
	}
}

// A live access token whose aud names no resource on the caller's list is answered exactly
// {"active": false}, which says nothing of why (RFC 7662 section 2.2): an empty list, another
// resource listed, and an audience that only differs in case.
func TestHandleIntrospectPost_AnAccessTokenForAResourceNotListedIsInactive(t *testing.T) {
	cases := []struct {
		name   string
		aud    interface{}
		listed []string
	}{
		{"nothing listed", introspectResource, nil},
		{"another resource listed", introspectResource, []string{"other-api"}},
		{"several audiences, none listed", []interface{}{"authserver", introspectResource}, []string{"other-api"}},
		{"the audience in another case", "Product-API", []string{introspectResource}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newIntrospectEndpoint(t)
			e.callerFound(introspectingCaller(t))
			e.parses(apiAccessToken(tc.aud))
			e.accessTokenLive()
			e.lists(tc.listed...)

			rr := e.post(t, apiForm())

			assertIntrospection(t, rr, inactiveAnswer)
			assert.Equal(t, introspectOutcome("inactive"), e.samples(t))
		})
	}
}

// A refresh token is answered to the client it was issued to, against the refresh grant's own
// check (decision 7): active, scope, client_id, sub, iss, exp, iat and jti, with no token_type and no
// aud. The caller's introspection resources are not read: they are for access tokens.
func TestHandleIntrospectPost_ARefreshTokenIsActiveToItsOwnClient(t *testing.T) {
	e := newIntrospectEndpoint(t)
	e.callerFound(introspectingCaller(t))
	e.parses(callerRefreshToken())
	e.refreshTokenRow(introspectCallerId)
	e.database.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, introspectGrantId).Return(false, nil).Once()

	rr := e.post(t, apiForm())

	assertIntrospection(t, rr, `{
		"active": true,
		"scope": "openid offline_access",
		"client_id": "the-api",
		"sub": "the-subject",
		"iss": "https://auth.example.com",
		"exp": 1800086400,
		"iat": 1800000000,
		"jti": "rt-presented"
	}`)
	assert.Equal(t, introspectOutcome("active"), e.samples(t))
	assertNotAttempted(t, e.database, "GetClientIntrospectionResourcesByClientId", "UpdateRefreshToken", "RunInTransaction")
}

// A live refresh token whose issuing flow is switched off for its client is inactive, as the refresh
// grant refuses it (#250): here the password grant, off for the deployment and inherited, or off for
// the client alone.
func TestHandleIntrospectPost_ARefreshTokenWhoseFlowIsSwitchedOffIsInactive(t *testing.T) {
	off := false
	cases := []struct {
		name   string
		global bool
		client *bool
	}{
		{"off for the deployment", false, nil},
		{"off for the client", true, &off},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newIntrospectEndpoint(t)
			e.settings.ResourceOwnerPasswordCredentialsEnabled = tc.global
			caller := introspectingCaller(t)
			caller.ResourceOwnerPasswordCredentialsEnabled = tc.client
			e.callerFound(caller)
			e.parses(callerRefreshToken())
			e.refreshTokenRow(introspectCallerId)
			e.database.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, introspectGrantId).Return(false, nil).Once()

			rr := e.post(t, apiForm())

			assertIntrospection(t, rr, inactiveAnswer)
			assert.Equal(t, introspectOutcome("inactive"), e.samples(t))
		})
	}
}

// Another client's refresh token is inactive, live or not, and nothing about its grant is read once
// its owner is known: the answer cannot tell a caller what became of a grant it does not own.
func TestHandleIntrospectPost_AnotherClientsRefreshTokenIsInactive(t *testing.T) {
	e := newIntrospectEndpoint(t)
	e.callerFound(introspectingCaller(t))
	e.parses(callerRefreshToken())
	e.refreshTokenRow(introspectOwnerId)

	rr := e.post(t, apiForm())

	assertIntrospection(t, rr, inactiveAnswer)
	assert.Equal(t, introspectOutcome("inactive"), e.samples(t))
	assertNotAttempted(t, e.database, "IsRefreshTokenFamilyRevoked", "GetUserSessionBySessionIdentifier")
}

// A token that is not live is inactive: one the parser refused, an access token the one check
// refuses, a refresh token the refresh check refuses or that has no row, an ID token and an access
// token issued before #676. The caller's list is not read for a token that is not live.
func TestHandleIntrospectPost_ATokenThatIsNotLiveIsInactive(t *testing.T) {
	cases := []struct {
		name string
		arm  func(e *introspectEndpoint)
	}{
		{"the parser refused it", func(e *introspectEndpoint) {
			e.parser.On("DecodeAndValidateTokenString", mock.Anything, introspectTokenString, true).
				Return(nil, errs.Wrap(signingkeys.ErrTokenRefused, "expired")).Once()
		}},
		{"an access token whose grant was revoked", func(e *introspectEndpoint) {
			e.parses(apiAccessToken(introspectResource))
			e.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, introspectOwnerName).
				Return(tokenOwner(), nil).Once()
			e.database.On("GetUserBySubject", mock.Anything, mock.Anything, "the-subject").
				Return(&record.User{Id: introspectUserId, Enabled: true}, nil).Once()
			e.database.On("IsRefreshTokenFamilyLive", mock.Anything, mock.Anything, introspectGrantId).Return(false, nil).Once()
		}},
		{"an access token of a disabled client", func(e *introspectEndpoint) {
			e.parses(apiAccessToken(introspectResource))
			owner := tokenOwner()
			owner.Enabled = false
			e.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, introspectOwnerName).
				Return(owner, nil).Once()
		}},
		{"an access token from another issuer", func(e *introspectEndpoint) {
			token := apiAccessToken(introspectResource)
			token.Claims["iss"] = "https://other.example.com"
			e.parses(token)
		}},
		{"an access token issued before #676", func(e *introspectEndpoint) {
			token := apiAccessToken(introspectResource)
			token.Header["typ"] = "JWT"
			e.parses(token)
		}},
		{"an ID token", func(e *introspectEndpoint) {
			e.parses(&oauth.JwtToken{TokenBase64: introspectTokenString, Header: map[string]interface{}{"typ": "JWT"},
				Claims: map[string]interface{}{"iss": introspectIssuer, "sub": "the-subject", "aud": introspectCallerName, "typ": "ID"}})
		}},
		{"a refresh token with no row", func(e *introspectEndpoint) {
			e.parses(callerRefreshToken())
			e.database.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, introspectRefreshJti).Return(nil, nil).Once()
		}},
		{"a refresh token of a revoked family", func(e *introspectEndpoint) {
			e.parses(callerRefreshToken())
			e.refreshTokenRow(introspectCallerId)
			e.database.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, introspectGrantId).Return(true, nil).Once()
		}},
		{"a refresh token rotated out", func(e *introspectEndpoint) {
			e.parses(callerRefreshToken())
			row := e.refreshTokenRow(introspectCallerId)
			row.Revoked = true
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newIntrospectEndpoint(t)
			e.callerFound(introspectingCaller(t))
			tc.arm(e)

			rr := e.post(t, apiForm())

			assertIntrospection(t, rr, inactiveAnswer)
			assert.Equal(t, introspectOutcome("inactive"), e.samples(t))
			assertNotAttempted(t, e.database, "GetClientIntrospectionResourcesByClientId", "UpdateRefreshToken",
				"RunInTransaction", "RecordRefreshTokenFamilyRevoked")
		})
	}
}

// token_type_hint is ignored (RFC 7662 section 2.1 MAY): a refresh token sent with the access-token
// hint is judged as the refresh token it is.
func TestHandleIntrospectPost_IgnoresTheHint(t *testing.T) {
	e := newIntrospectEndpoint(t)
	e.callerFound(introspectingCaller(t))
	e.parses(callerRefreshToken())
	e.refreshTokenRow(introspectCallerId)
	e.database.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, introspectGrantId).Return(false, nil).Once()

	rr := e.post(t, apiForm("token_type_hint", "access_token"))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), `"active":true`)
}

// A fault reading the keys or the database answers 500, never {"active": false}, which would report
// a fault as a dead token (decision 13). It is logged once at Error and counted as error.
func TestHandleIntrospectPost_AFaultAnswersInternalServerError(t *testing.T) {
	boom := errors.New("connection refused")

	cases := []struct {
		name string
		arm  func(e *introspectEndpoint)
	}{
		{"the caller cannot be looked up", func(e *introspectEndpoint) {
			e.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, introspectCallerName).
				Return(nil, boom).Once()
		}},
		{"the signing keys cannot be read", func(e *introspectEndpoint) {
			e.callerFound(introspectingCaller(t))
			e.parser.On("DecodeAndValidateTokenString", mock.Anything, introspectTokenString, true).Return(nil, boom).Once()
		}},
		{"the access token's grant cannot be read", func(e *introspectEndpoint) {
			e.callerFound(introspectingCaller(t))
			e.parses(apiAccessToken(introspectResource))
			e.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, introspectOwnerName).
				Return(tokenOwner(), nil).Once()
			e.database.On("GetUserBySubject", mock.Anything, mock.Anything, "the-subject").
				Return(&record.User{Id: introspectUserId, Enabled: true}, nil).Once()
			e.database.On("IsRefreshTokenFamilyLive", mock.Anything, mock.Anything, introspectGrantId).Return(false, boom).Once()
		}},
		{"the caller's list cannot be read", func(e *introspectEndpoint) {
			e.callerFound(introspectingCaller(t))
			e.parses(apiAccessToken(introspectResource))
			e.accessTokenLive()
			e.database.On("GetClientIntrospectionResourcesByClientId", mock.Anything, mock.Anything, introspectCallerId).
				Return(nil, boom).Once()
		}},
		{"the listed resources cannot be read", func(e *introspectEndpoint) {
			e.callerFound(introspectingCaller(t))
			e.parses(apiAccessToken(introspectResource))
			e.accessTokenLive()
			e.database.On("GetClientIntrospectionResourcesByClientId", mock.Anything, mock.Anything, introspectCallerId).
				Return([]record.ClientIntrospectionResource{{Id: 500, ClientId: introspectCallerId, ResourceId: introspectResourceId}}, nil).Once()
			e.database.On("GetResourcesByIds", mock.Anything, mock.Anything, []int64{introspectResourceId}).Return(nil, boom).Once()
		}},
		{"the refresh token's row cannot be read", func(e *introspectEndpoint) {
			e.callerFound(introspectingCaller(t))
			e.parses(callerRefreshToken())
			e.database.On("GetRefreshTokenByJti", mock.Anything, mock.Anything, introspectRefreshJti).Return(nil, boom).Once()
		}},
		{"the refresh token's family cannot be read", func(e *introspectEndpoint) {
			e.callerFound(introspectingCaller(t))
			e.parses(callerRefreshToken())
			e.refreshTokenRow(introspectCallerId)
			e.database.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, introspectGrantId).Return(false, boom).Once()
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newIntrospectEndpoint(t)
			tc.arm(e)
			logged := logtest.CaptureSlog(t)

			rr := e.post(t, apiForm())

			assertErrorAnswer(t, rr, http.StatusInternalServerError, "server_error",
				"An unexpected server error has occurred...")
			assertNotStored(t, rr)
			assert.NotContains(t, rr.Body.String(), "active")
			assert.Equal(t, introspectOutcome("error"), e.samples(t))
			var errorRecords []logtest.CapturedRecord
			for _, record := range logged.Records() {
				if record.Level == slog.LevelError {
					errorRecords = append(errorRecords, record)
				}
			}
			require.Len(t, errorRecords, 1, logged.Text())
			assert.Equal(t, "internal server error", errorRecords[0].Message)
			assert.Contains(t, fmt.Sprint(errorRecords[0].Attrs["error"]), "connection refused")
		})
	}
}

// A fault met before the handler, on the branch the endpoint alone is registered on, is answered as
// the handler answers its own: 500, not stored, and counted as error.
func TestIntrospectionFaults_AnswersAndCountsAFaultBeforeTheHandler(t *testing.T) {
	registry := metrics.NewRegistry()
	faults := IntrospectionFaults(render.New(nil, nil), introspectionmetrics.Register(registry))
	logtest.CaptureSlog(t)

	rr := httptest.NewRecorder()
	faults.JSONError(rr, httptest.NewRequest(http.MethodPost, "/auth/introspect", nil), errors.New("settings unreadable"))

	assertErrorAnswer(t, rr, http.StatusInternalServerError, "server_error", "An unexpected server error has occurred...")
	assertNotStored(t, rr)
	e := &introspectEndpoint{registry: registry}
	assert.Equal(t, introspectOutcome("error"), e.samples(t))
}

// A public client cannot authenticate, so it never introspects (RFC 7662 section 4, decision 9):
// 401 invalid_client with the Basic challenge, whether or not it sends a secret, before the token is
// read. One Warn record names the introspection endpoint, and the outcome is refused.
func TestHandleIntrospectPost_APublicClientIsRefused(t *testing.T) {
	for name, form := range map[string]url.Values{
		"with its client_id alone": {"token": {introspectTokenString}, "client_id": {"the-spa"}},
		"with a secret":            {"token": {introspectTokenString}, "client_id": {"the-spa"}, "client_secret": {"anything"}},
	} {
		t.Run(name, func(t *testing.T) {
			e := newIntrospectEndpoint(t)
			e.callerFound(&record.Client{Id: 84, ClientIdentifier: "the-spa", Enabled: true, IsPublic: true})
			logged := logtest.CaptureSlog(t)

			rr := e.post(t, form)

			assertErrorAnswer(t, rr, http.StatusUnauthorized, "invalid_client",
				"This client is configured as public, and a public client cannot introspect tokens. Introspect as a confidential client.")
			assert.Equal(t, `Basic realm="goiabada"`, rr.Header().Get("WWW-Authenticate"))
			assertNotStored(t, rr)
			assert.Equal(t, introspectOutcome("refused"), e.samples(t))
			records := logged.Records()
			require.Len(t, records, 1, logged.Text())
			assert.Equal(t, slog.LevelWarn, records[0].Level)
			assert.Equal(t, "client authentication refused at the introspection endpoint", records[0].Message)
		})
	}
}

// A client that cannot be authenticated is refused as at the token endpoint, before the token is
// read: 401 invalid_client with the Basic challenge, one Warn record naming the introspection
// endpoint, and the refused outcome.
func TestHandleIntrospectPost_ClientAuthenticationRefusal(t *testing.T) {
	cases := []struct {
		name   string
		arm    func(e *introspectEndpoint)
		form   url.Values
		basic  string
		reason string
		method string
	}{
		{"an unknown client, through the Authorization header", func(e *introspectEndpoint) {
			e.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "no-such-client").Return(nil, nil).Once()
		}, url.Values{"token": {introspectTokenString}}, "no-such-client:a-secret", "Client does not exist.", "client_secret_basic"},
		{"a wrong secret, in the body", func(e *introspectEndpoint) {
			e.callerFound(introspectingCaller(t))
		}, url.Values{"token": {introspectTokenString}, "client_id": {introspectCallerName}, "client_secret": {"wrong"}}, "",
			"Client authentication failed. Please review your client_secret.", "client_secret_post"},
		{"a disabled client", func(e *introspectEndpoint) {
			caller := introspectingCaller(t)
			caller.Enabled = false
			e.callerFound(caller)
		}, apiForm(), "", "Client is disabled.", "client_secret_post"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newIntrospectEndpoint(t)
			tc.arm(e)
			logged := logtest.CaptureSlog(t)

			req := httptest.NewRequest(http.MethodPost, "/auth/introspect", strings.NewReader(tc.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.basic != "" {
				req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(tc.basic)))
			}
			req = withSettings(req, e.settings)
			rr := httptest.NewRecorder()
			e.handler.ServeHTTP(rr, req)

			assertErrorAnswer(t, rr, http.StatusUnauthorized, "invalid_client", tc.reason)
			assert.Equal(t, `Basic realm="goiabada"`, rr.Header().Get("WWW-Authenticate"))
			assertNotStored(t, rr)
			assert.Equal(t, introspectOutcome("refused"), e.samples(t))

			records := logged.Records()
			require.Len(t, records, 1, logged.Text())
			assert.Equal(t, slog.LevelWarn, records[0].Level)
			assert.Equal(t, "client authentication refused at the introspection endpoint", records[0].Message)
			assert.Equal(t, tc.reason, records[0].Attrs["reason"])
			assert.Equal(t, tc.method, records[0].Attrs["client_auth_method"])
		})
	}
}

// What can be refused before any token is read is answered 400 invalid_request and counted as
// refused: no token, a repeated parameter.
func TestHandleIntrospectPost_AMalformedRequestIsRefused(t *testing.T) {
	t.Run("no token", func(t *testing.T) {
		e := newIntrospectEndpoint(t)
		e.callerFound(introspectingCaller(t))

		rr := e.post(t, url.Values{"client_id": {introspectCallerName}, "client_secret": {"api-secret"}})

		assertErrorAnswer(t, rr, http.StatusBadRequest, "invalid_request", "Missing required token parameter.")
		assertNotStored(t, rr)
		assert.Equal(t, introspectOutcome("refused"), e.samples(t))
	})

	t.Run("a repeated token", func(t *testing.T) {
		e := newIntrospectEndpoint(t)
		form := apiForm()
		form.Add("token", "another.token")

		rr := e.post(t, form)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), `"error":"invalid_request"`)
		assert.Equal(t, introspectOutcome("refused"), e.samples(t))
	})

	// Both refused before the client or the token is read: no lookup is armed, so one would fail.
	t.Run("a body that cannot be parsed", func(t *testing.T) {
		e := newIntrospectEndpoint(t)

		rr := e.postBody(t, "token=%zz", nil)

		assertErrorAnswer(t, rr, http.StatusBadRequest, "invalid_request", "The request body could not be parsed.")
		assertNotStored(t, rr)
		assert.Equal(t, introspectOutcome("refused"), e.samples(t))
	})

	t.Run("client credentials sent both as Basic and in the body", func(t *testing.T) {
		e := newIntrospectEndpoint(t)
		basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("a-client:a-secret"))

		rr := e.postBody(t, apiForm().Encode(), &basic)

		assertErrorAnswer(t, rr, http.StatusBadRequest, "invalid_request",
			"Client authentication failed: multiple authentication methods provided. "+
				"Use either HTTP Basic authentication OR client_secret in the request body, but not both.")
		assertNotStored(t, rr)
		assert.Equal(t, introspectOutcome("refused"), e.samples(t))
	})
}
