package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/dpop/dpoptest"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RequireRecentAuthentication is the step-up route guard (#782 decision 1): it admits a token whose
// sign-in is no older than the maximum age and at least the minimum level, and refuses any other
// with RFC 9470 section 3's challenge, 401 insufficient_user_authentication carrying the acr_values
// and max_age the caller signs in again with, and the API envelope's
// INSUFFICIENT_USER_AUTHENTICATION. As every 401, it carries the DPoP challenge after the Bearer
// one, the error in the challenge of the scheme used. The account download mounts it with 300
// seconds and urn:goiabada:level2_optional, which these tests use.

const (
	stepUpDescription  = "This endpoint requires a more recent sign-in, or a stronger one."
	stepUpRequirements = `error="insufficient_user_authentication", error_description="` + stepUpDescription +
		`", acr_values="urn:goiabada:level2_optional", max_age="300"`
	challengeStepUp = `Bearer realm="goiabada", ` + stepUpRequirements + `, ` + dpopChallengeBare
)

var apiInsufficientUserAuthentication = chainAnswer{http.StatusUnauthorized, challengeStepUp,
	`{"error_code":"INSUFFICIENT_USER_AUTHENTICATION","error_description":"` + stepUpDescription + `"}`}

// stepUpNow is the guard's fixed clock.
var stepUpNow = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

// stepUpToken is a console user's Account API token with the given claims added; a nil value
// leaves that claim out.
func stepUpToken(claims map[string]interface{}) oauth.JwtToken {
	token := oauth.JwtToken{Claims: map[string]interface{}{
		"sub": "u1", "client_id": builtin.AdminConsoleClientIdentifier, "scope": "openid authserver:manage-account",
	}}
	for name, value := range claims {
		if value != nil {
			token.Claims[name] = value
		}
	}
	return token
}

// signedInAgo is a token's auth_time claim, as JSON decoding hands it over, for a sign-in the given
// number of seconds before stepUpNow.
func signedInAgo(seconds int64) float64 {
	return float64(stepUpNow.Unix() - seconds)
}

// serveStepUpGuard runs the guard as the account download mounts it, and reports whether the next
// handler ran.
func serveStepUpGuard(t *testing.T, token *oauth.JwtToken) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/account/export", nil)
	if token != nil {
		req = req.WithContext(reqctx.WithBearerToken(req.Context(), *token))
	}
	rr := httptest.NewRecorder()
	reached := false
	guard := NewBearerTokenForAPI(nil, ResourceProofs{}).RequireRecentAuthentication(300*time.Second, record.AcrLevel2Optional,
		func() time.Time { return stepUpNow })
	guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		_, _ = w.Write([]byte("admitted"))
	})).ServeHTTP(rr, req)
	return rr, reached
}

func TestRequireRecentAuthentication_AdmitsARecentSignInAtTheLevelOrAbove(t *testing.T) {
	for _, tc := range []struct {
		name     string
		authTime float64
		acr      string
	}{
		{"signed in exactly 300 seconds ago at level2_optional", signedInAgo(300), "urn:goiabada:level2_optional"},
		{"signed in just now at level2_mandatory", signedInAgo(0), "urn:goiabada:level2_mandatory"},
		{"signed in 299 seconds ago at level2_mandatory", signedInAgo(299), "urn:goiabada:level2_mandatory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := stepUpToken(map[string]interface{}{"auth_time": tc.authTime, "acr": tc.acr})

			rr, reached := serveStepUpGuard(t, &token)

			assertChainAnswer(t, answerAdmitted, rr)
			assert.True(t, reached)
		})
	}
}

// Every refusal carries both parameters, whichever of the two was short, so a client signs in once
// and meets both.
func TestRequireRecentAuthentication_RefusesAnOldOrWeakOrUnreadableSignIn(t *testing.T) {
	for _, tc := range []struct {
		name   string
		claims map[string]interface{}
	}{
		{"signed in 301 seconds ago", map[string]interface{}{
			"auth_time": signedInAgo(301), "acr": "urn:goiabada:level2_optional"}},
		{"signed in an hour ago at level2_mandatory", map[string]interface{}{
			"auth_time": signedInAgo(3600), "acr": "urn:goiabada:level2_mandatory"}},
		{"signed in just now at level1", map[string]interface{}{
			"auth_time": signedInAgo(0), "acr": "urn:goiabada:level1"}},
		{"no acr", map[string]interface{}{
			"auth_time": signedInAgo(0), "acr": nil}},
		{"an acr this server does not know", map[string]interface{}{
			"auth_time": signedInAgo(0), "acr": "urn:goiabada:level3"}},
		{"an acr that is not a string", map[string]interface{}{
			"auth_time": signedInAgo(0), "acr": float64(2)}},
		{"no auth_time", map[string]interface{}{
			"auth_time": nil, "acr": "urn:goiabada:level2_optional"}},
		{"an auth_time that is not a number", map[string]interface{}{
			"auth_time": "1762516800", "acr": "urn:goiabada:level2_optional"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := logtest.CaptureSlog(t)
			token := stepUpToken(tc.claims)

			rr, reached := serveStepUpGuard(t, &token)

			assertChainAnswer(t, apiInsufficientUserAuthentication, rr)
			assert.False(t, reached, "a refusal calls no next handler")
			records := logs.Records()
			require.Len(t, records, 1, "one Warn record per refusal")
			assert.Equal(t, "rejecting bearer token: its sign-in is too old or too weak for the route", records[0].Message)
		})
	}
}

// No token in the context is a request that presented no bearer credential, answered as the other
// guards answer it.
func TestRequireRecentAuthentication_NoTokenIsTheMissingCredential(t *testing.T) {
	rr, reached := serveStepUpGuard(t, nil)

	assertChainAnswer(t, apiMissing, rr)
	assert.False(t, reached)
}

// The guard reads the clock on each request, not once when it is built.
func TestRequireRecentAuthentication_ReadsTheClockOnEachRequest(t *testing.T) {
	now := stepUpNow
	guard := NewBearerTokenForAPI(nil, ResourceProofs{}).RequireRecentAuthentication(300*time.Second, record.AcrLevel2Optional,
		func() time.Time { return now })(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("admitted"))
	}))
	token := stepUpToken(map[string]interface{}{"auth_time": signedInAgo(0), "acr": "urn:goiabada:level2_optional"})
	serve := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/account/export", nil)
		req = req.WithContext(reqctx.WithBearerToken(req.Context(), token))
		rr := httptest.NewRecorder()
		guard.ServeHTTP(rr, req)
		return rr
	}

	assertChainAnswer(t, answerAdmitted, serve())
	now = stepUpNow.Add(301 * time.Second)
	logtest.CaptureSlog(t)
	assertChainAnswer(t, apiInsufficientUserAuthentication, serve())
}

// Another maximum age and level are the challenge's parameters: the guard is reusable in front of a
// later operation with its own.
func TestRequireRecentAuthentication_TheChallengeNamesTheGuardsOwnFigures(t *testing.T) {
	logtest.CaptureSlog(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/account/anything", nil)
	token := stepUpToken(map[string]interface{}{"auth_time": signedInAgo(0), "acr": "urn:goiabada:level2_optional"})
	req = req.WithContext(reqctx.WithBearerToken(req.Context(), token))
	rr := httptest.NewRecorder()

	NewBearerTokenForAPI(nil, ResourceProofs{}).RequireRecentAuthentication(10*time.Minute, record.AcrLevel2Mandatory,
		func() time.Time { return stepUpNow })(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the next handler ran for a level the guard refuses")
	})).ServeHTTP(rr, req)

	require.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Equal(t, `Bearer realm="goiabada", error="insufficient_user_authentication", error_description="`+
		stepUpDescription+`", acr_values="urn:goiabada:level2_mandatory", max_age="600", `+dpopChallengeBare,
		rr.Header().Get("WWW-Authenticate"))
}

// A token presented with the DPoP scheme is refused in the DPoP challenge, after the bare Bearer
// one (RFC 9470 section 3, RFC 9449 section 7.2), on each surface, and its proof is not spent.
func TestRequireRecentAuthentication_ADPoPTokenIsRefusedInTheDPoPChallenge(t *testing.T) {
	key := dpoptest.RFC7517Key(t)
	api, userinfo := refusalAnswers(http.StatusUnauthorized,
		`Bearer realm="goiabada", `+dpopChallengeBare+`, `+stepUpRequirements,
		"INSUFFICIENT_USER_AUTHENTICATION", "insufficient_user_authentication", stepUpDescription)

	for surface, want := range map[string]chainAnswer{"api": api, "userinfo": userinfo} {
		t.Run(surface, func(t *testing.T) {
			logtest.CaptureSlog(t)
			store := newReplayStore()
			guards := dpopGuards(t, surface, dpopResourceBaseURL, store)
			chain := guards.JwtAuthorizationHeaderToContext()(guards.RequireRecentAuthentication(300*time.Second,
				record.AcrLevel2Optional, func() time.Time { return dpopNow })(guards.RecordDPoPProof()(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					t.Error("the next handler ran for a sign-in the guard refuses")
				}))))
			rr := httptest.NewRecorder()

			chain.ServeHTTP(rr, dpopRequest("DPoP "+tokenBound, key.ResourceProof(t, "GET", dpopUserinfoURL, dpopNow, tokenBound)))

			assertChainAnswer(t, want, rr)
			assert.Equal(t, 0, store.count(), "a refused request spends no proof")
		})
	}
}

// The guard in the chain the account download mounts: the client guard first, so another client's
// fresh or old token is CLIENT_NOT_ALLOWED and is never asked to sign the user in again, then the
// step-up guard.
func TestRequireRecentAuthentication_AfterTheClientGuard(t *testing.T) {
	guards := NewBearerTokenForAPI(nil, ResourceProofs{})
	chain := guards.RequireAdminConsoleClient()(guards.RequireRecentAuthentication(300*time.Second,
		record.AcrLevel2Optional, func() time.Time { return stepUpNow })(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("admitted")) })))

	for _, tc := range []struct {
		name     string
		clientId string
		authTime float64
		want     chainAnswer
	}{
		{"another client's old sign-in", "my-app", signedInAgo(3600), apiClientNotAllowed},
		{"another client's fresh sign-in", "my-app", signedInAgo(0), apiClientNotAllowed},
		{"the console's old sign-in", builtin.AdminConsoleClientIdentifier, signedInAgo(3600), apiInsufficientUserAuthentication},
		{"the console's fresh sign-in", builtin.AdminConsoleClientIdentifier, signedInAgo(0), answerAdmitted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logtest.CaptureSlog(t)
			token := stepUpToken(map[string]interface{}{"auth_time": tc.authTime, "acr": "urn:goiabada:level2_optional",
				"client_id": tc.clientId})
			req := httptest.NewRequest(http.MethodGet, "/api/v1/account/export", nil)
			req = req.WithContext(reqctx.WithBearerToken(req.Context(), token))
			rr := httptest.NewRecorder()
			chain.ServeHTTP(rr, req)
			assertChainAnswer(t, tc.want, rr)
		})
	}
}
