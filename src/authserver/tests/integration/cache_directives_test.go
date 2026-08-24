package integrationtests

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/stretchr/testify/assert"
)

// Ceremony pages carry an explicit refusal to store them (#247).
//
// A 200 with no cache directives is heuristically cacheable, so RFC 9111 section 4.2.2 tells an
// origin server that wants to prevent caching to say so, and RFC 6749 section 5.1 makes
// Cache-Control: no-store and Pragma: no-cache a MUST for any response carrying credentials. The
// login form carries a password field and the enrolment page renders the TOTP seed in plain text.
//
// This runs over real HTTP because the unit tier cannot make the claim that matters here: the
// template helper writing the pair says nothing about whether anything later in the chain, a
// middleware or the router, overwrites it before the response leaves the process. resp.Header on
// a client-side *http.Response is what a browser or a proxy actually receives.

// assertNotStorable requires both header fields on a response a user is looking at.
func assertNotStorable(t *testing.T, resp *http.Response, what string) {
	t.Helper()

	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"),
		"%s must tell caches not to store it", what)
	assert.Equal(t, "no-cache", resp.Header.Get("Pragma"),
		"%s must carry the Pragma field RFC 6749 5.1 also requires", what)
}

// TestCacheDirectives_ThePasswordFormIsNotStorable drives a fresh authorization request as far as
// the login form and stops there, which is as far as the claim goes: the page is rendered, and
// what it carries is a header the request that fetched it received.
func TestCacheDirectives_ThePasswordFormIsNotStorable(t *testing.T) {
	client, redirectUri, _, _ := createLevel2MandatoryUser(t, false)

	httpClient := createHttpClient(t)

	resp := loadPage(t, httpClient,
		authorizeUrlFor(client, redirectUri, "openid profile email", gofakeit.LetterN(8)))
	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	_ = resp.Body.Close()

	resp = loadPage(t, httpClient, redirectLocation)
	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	_ = resp.Body.Close()

	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	// The page really is the form, so the assertion below is about the page it claims to be.
	assert.NotEmpty(t, getCeremonyIdFromPage(t, resp),
		"the password form must have rendered, or the header assertion means nothing")

	assertNotStorable(t, resp, "the password form")
}

// TestCacheDirectives_TheOtpEnrolmentPageIsNotStorable is the same claim about the page that
// renders the TOTP seed in plain text, which is the surface #247 was opened about. The user has no
// authenticator yet, so /auth/otp answers with the enrolment arm.
func TestCacheDirectives_TheOtpEnrolmentPageIsNotStorable(t *testing.T) {
	client, redirectUri, user, password := createLevel2MandatoryUser(t, false)

	_, otpPage, _ := startOtpCeremony(t, client, redirectUri, user, password, "")
	defer func() { _ = otpPage.Body.Close() }()

	assert.Equal(t, http.StatusOK, otpPage.StatusCode)
	// Reading the seed off the page is what distinguishes the enrolment arm from the verification
	// one, and it is the credential the directives exist for.
	assert.NotEmpty(t, getOtpSecretFromEnrollmentPage(t, otpPage),
		"the enrolment page must render a secret, or the header assertion means nothing")

	assertNotStorable(t, otpPage, "the OTP enrolment page")
}

// TestCacheDirectives_TheEnrolmentJsonIsNotStorable is the same claim about the second surface that
// serves the TOTP seed, and the one response in this change that carries a credential without being
// rendered from a template: GET /api/v1/account/otp/enrollment answers JSON, hand-encoded, with a
// bearer token.
//
// A bearer token is not by itself protection. RFC 9111 section 3.5 stops a SHARED cache reusing a
// response to a request carrying an Authorization header, but section 3 still permits a private
// cache to store it, and an integrator's own client caching GETs is under no such rule at all.
//
// Over real HTTP because a router-level test cannot make this claim: the sweep in
// internal/server/routes_no_store_test.go builds initRoutes by hand, so it says nothing about
// whether the globally mounted chain in initMiddleware, or anything else the response passes on its
// way out of the process, overwrites the header first.
func TestCacheDirectives_TheEnrolmentJsonIsNotStorable(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)

	resp := makeAPIRequest(t, "GET",
		config.GetAuthServer().BaseURL+"/api/v1/account/otp/enrollment", accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	// The response really did carry the seed, so the header assertion is about the response the
	// directives exist for rather than about an error body that happens to be uncacheable.
	var enrollment api.AccountOTPEnrollmentResponse
	assert.NoError(t, json.NewDecoder(resp.Body).Decode(&enrollment))
	assert.NotEmpty(t, enrollment.SecretKey,
		"the enrolment response must carry a secret, or the header assertion means nothing")

	assertNotStorable(t, resp, "the OTP enrolment JSON")
}

// TestCacheDirectives_AnApiRefusalIsNotStorable is the mount position proven end to end. It is the
// property the sweep asserts on a hand-built router, checked here on the real one: the pair is
// written ahead of the guards, so a refusal carries it too.
//
// That the refusal is covered at all is not incidental. RFC 6749 section 5.1 scopes its MUST to any
// response containing sensitive information, and it is also what lets the sweep call all 105
// registered API routes without credentials and still assert something. Mounted behind the guards
// instead, this case fails and the sweep quietly stops testing anything.
func TestCacheDirectives_AnApiRefusalIsNotStorable(t *testing.T) {
	resp := makeAPIRequest(t, "GET",
		config.GetAuthServer().BaseURL+"/api/v1/account/otp/enrollment", "not-a-token", nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"the request must actually have been refused, or this is not testing a refusal")

	assertNotStorable(t, resp, "an unauthenticated refusal from the account API")
}
