package integrationtests

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The deferral, driven end to end. RFC 9700 section 4.11.2 requires that the authorization server
// "MUST always authenticate the user first and, with the exception of the silent authentication use
// case, prompt the user for credentials when needed, before redirecting the user", and before #213
// this server did the opposite: a logged-out browser loading one link with a bad scope was answered
// with a 302 to a host the client had chosen, with nothing rendered and nobody authenticated. That
// is attack 1 of that section verbatim, and probe/repro.md recorded it happening.
//
// The tests here drive the real ceremony rather than a recorder, which is what this tier is for:
// the routing decision belongs to the handler's own unit table, and what only integration can show
// is that an error parked in a cookie at /auth/authorize survives a login and comes back out of
// /auth/level1completed as the same protocol response the client would have received immediately.
//
// A redirect URI with no query of its own, so the emitted Location is a deterministic string and
// these tests can compare it as one. The query-preserving case is
// authorize_registered_query_state_test.go's, and it is not what is under test here.
const deferralRedirectURI = "https://deferred.example.com/callback"

// deferralState is the state the client sends, and it is deliberately awkward. Carrying an error
// through a second handler is the way a state echo gets lost or mangled, so the value that pinned
// #146 is the one used here: the space and the "+" because url.QueryEscape maps them onto each
// other, and "/" and "=" so a base64 CSRF token round-trips. RFC 6749 section 4.1.2 requires "the
// exact value received from the client", and on this path that value has been through the auth
// context cookie in between.
const deferralState = "csrf a+b/c="

// deferralStateEscaped is deferralState as it must appear on the wire. A literal, not a call to
// url.QueryEscape, so the encoding is pinned by this file rather than by the same function the
// emitter uses.
const deferralStateEscaped = "csrf+a%2Bb%2Fc%3D"

// invalidScopeDescription is what ValidateScopes says about the scope below, byte for byte. The
// deferred response must carry this and not a summary of it: decision 6 kept every existing
// assertion about error responses intact precisely because the description is part of the contract
// with the client, and it must not quietly change on the way through a second handler.
const invalidScopeDescription = "Invalid scope format: 'not_a_valid_scope'. Scopes must adhere to " +
	"the resource-identifier:permission-identifier format. For instance: backend-service:create-product."

// TestAuthorize_Deferred_CookielessRequestIsSentToLogin is probe/repro.md inverted: the exact
// request that used to be answered with a redirect to the client is now answered with the login
// page.
//
// Both halves are asserted, because they are two properties and only one of them is the issue. That
// the browser reaches /auth/level1 is the ceremony working; that the client's URI was NOT emitted is
// the security requirement, and an emitter that answered both would satisfy the first while
// breaking the second.
func TestAuthorize_Deferred_CookielessRequestIsSentToLogin(t *testing.T) {
	client, _, _ := newDeferralClient(t)

	// A fresh cookie jar. Nobody is authenticated, which is the whole point.
	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(deferralAuthorizeURL(client.ClientIdentifier, ""))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	location := assertRedirect(t, resp, "/auth/level1")

	assert.True(t, strings.HasPrefix(location, config.GetAuthServer().BaseURL),
		"the browser must be kept on this server, got %q", location)
	assert.NotContains(t, location, "deferred.example.com",
		"the client's redirect URI must not be emitted to an unauthenticated browser, got %q", location)

	redirected, err := url.Parse(location)
	require.NoError(t, err)
	assert.Empty(t, redirected.Query().Get("error"),
		"no error may reach the browser before it has authenticated, got %q", location)
}

// TestAuthorize_Deferred_QueryMode_DeliversAfterLogin is the property this change exists for: the
// error is not withheld, it is postponed. OIDC Core 3.1.2.2 with 3.1.2.6 requires that the error
// reach the client at its redirect URI, and RFC 9700 4.11.2 requires the login first, so the client
// receives exactly what it would have received, after the credentials it was owed.
//
// The Location is compared as a whole string rather than field by field, which is what makes the
// parameter order and the state encoding part of the assertion.
func TestAuthorize_Deferred_QueryMode_DeliversAfterLogin(t *testing.T) {
	client, user, password := newDeferralClient(t)
	httpClient := createHttpClient(t)

	resp := driveDeferral(t, httpClient,
		deferralAuthorizeURL(client.ClientIdentifier, "query"), user, password)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	location := resp.Header.Get("Location")

	assert.Equal(t,
		deferralRedirectURI+"?error=invalid_scope"+
			"&error_description="+url.QueryEscape(invalidScopeDescription)+
			"&state="+deferralStateEscaped,
		location)
}

// TestAuthorize_Deferred_FragmentMode_DeliversAfterLogin is the same delivery in the response mode
// that puts the parameters after a "#" rather than in the query.
//
// It is a separate case rather than a subtest sharing a ceremony because the response mode is
// carried across the deferral on the auth context, and this is one of the two tests that would
// notice if it were not.
func TestAuthorize_Deferred_FragmentMode_DeliversAfterLogin(t *testing.T) {
	client, user, password := newDeferralClient(t)
	httpClient := createHttpClient(t)

	resp := driveDeferral(t, httpClient,
		deferralAuthorizeURL(client.ClientIdentifier, "fragment"), user, password)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	location := resp.Header.Get("Location")

	assert.Equal(t,
		deferralRedirectURI+"#error=invalid_scope"+
			"&error_description="+url.QueryEscape(invalidScopeDescription)+
			"&state="+deferralStateEscaped,
		location)
}

// TestAuthorize_Deferred_FormPostMode_DeliversAfterLogin is the mode that proves the wiring.
//
// form_post is the only response mode that parses a template, so it is the only one that needs the
// templateFS the delivery point did not take before #213 (decision 2 accepted that new parameter).
// A delivery point wired without it answers 500 here and redirects perfectly well in the other two
// modes, which is why this case exists and why it is not folded into the one above.
//
// The state is read from the rendered input rather than off a URL, so it is asserted unescaped:
// what the client's parser receives is the form field, and the escaping in the two cases above is
// the wire form of the same value.
func TestAuthorize_Deferred_FormPostMode_DeliversAfterLogin(t *testing.T) {
	client, user, password := newDeferralClient(t)
	httpClient := createHttpClient(t)

	resp := driveDeferral(t, httpClient,
		deferralAuthorizeURL(client.ClientIdentifier, "form_post"), user, password)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, deferralRedirectURI, doc.Find("form").AttrOr("action", ""))
	assert.Equal(t, "invalid_scope", doc.Find("input[name='error']").AttrOr("value", ""))
	assert.Equal(t, invalidScopeDescription, doc.Find("input[name='error_description']").AttrOr("value", ""))
	assert.Equal(t, deferralState, doc.Find("input[name='state']").AttrOr("value", ""))
	assert.Equal(t, 0, doc.Find("input[name='code']").Length(),
		"an error response must not carry an authorization code")
}

// TestAuthorize_Deferred_NonConformingDescriptionMatchesTheImmediatePath belongs to decision 10
// rather than to the deferral, and it is the one assertion that spans both.
//
// RFC 6749 Appendix A.8 confines error_description to %x20-21 / %x23-5B / %x5D-7E, so a rejected
// scope carrying an emoji is filtered on its way out. The filter runs at two places on the deferred
// path, once when the description is parked in the cookie and once at the emitter, and it is
// idempotent so that the two paths cannot diverge. This drives the same request both ways and
// requires the answers to be the same bytes: a bound or a replacement applied at only one of the two
// sites passes every single-path test in the tree and fails here.
func TestAuthorize_Deferred_NonConformingDescriptionMatchesTheImmediatePath(t *testing.T) {
	client, user, password := newDeferralClient(t)

	const emojiScope = "emoji💣scope"
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(deferralRedirectURI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + gofakeit.LetterN(43) +
		"&state=" + url.QueryEscape(deferralState) +
		"&scope=" + url.QueryEscape(emojiScope)

	deferred := driveDeferral(t, createHttpClient(t), destUrl, user, password)
	defer func() { _ = deferred.Body.Close() }()
	require.Equal(t, http.StatusFound, deferred.StatusCode)

	// The immediate path, for the same client and the same request, from a browser that already
	// holds a session. The session was minted for a different client, which is fine: it belongs to
	// the browser.
	immediateResp, err := createAuthenticatedHttpClient(t).Get(destUrl)
	require.NoError(t, err)
	defer func() { _ = immediateResp.Body.Close() }()
	require.Equal(t, http.StatusFound, immediateResp.StatusCode)

	deferredDescription := errorDescriptionFromLocation(t, deferred)
	immediateDescription := errorDescriptionFromLocation(t, immediateResp)

	assert.Equal(t,
		"Invalid scope format: 'emoji?scope'. Scopes must adhere to the "+
			"resource-identifier:permission-identifier format. For instance: backend-service:create-product.",
		immediateDescription)
	assert.Equal(t, immediateDescription, deferredDescription,
		"the deferred and the immediate answer must be the same bytes")

	for _, r := range deferredDescription {
		assert.True(t, (r >= 0x20 && r <= 0x21) || (r >= 0x23 && r <= 0x5B) || (r >= 0x5D && r <= 0x7E),
			"character %q is outside RFC 6749 Appendix A.8's NQSCHAR", r)
	}
}

// TestAuthorizePost_Deferred_CookielessRequestIsSentToLogin covers the other wire form of the same
// endpoint. §2's property names GET and POST alike, and the deferral reads its inputs through
// r.FormValue, which resolves from the query on one and from the body on the other.
//
// The foreign Origin header mirrors authorize_post_test.go, so the /auth/authorize CSRF exemption
// (#67) stays on the path this test drives rather than being quietly stepped around.
func TestAuthorizePost_Deferred_CookielessRequestIsSentToLogin(t *testing.T) {
	client, _, _ := newDeferralClient(t)

	form := url.Values{}
	form.Set("client_id", client.ClientIdentifier)
	form.Set("redirect_uri", deferralRedirectURI)
	form.Set("response_type", "code")
	form.Set("code_challenge_method", "S256")
	form.Set("code_challenge", gofakeit.LetterN(43))
	form.Set("scope", "not_a_valid_scope")
	form.Set("state", deferralState)

	req, err := http.NewRequest(http.MethodPost,
		config.GetAuthServer().BaseURL+"/auth/authorize", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://www.certification.openid.net")

	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	location := assertRedirect(t, resp, "/auth/level1")
	assert.NotContains(t, location, "deferred.example.com",
		"the client's redirect URI must not be emitted to an unauthenticated browser, got %q", location)
}

// TestAuthorize_Deferred_LeavesNoUserSession pins the cost decision 2 accepted when it chose
// /auth/level1completed as the delivery point: the user session row is created at /auth/completed,
// which a deferral never reaches, so a visitor who logged in only to be handed an error is not
// signed in afterwards.
//
// Asserted through behaviour rather than by counting rows. What matters to the visitor is that the
// next authorization request asks for the password again, and a browser holding a valid session is
// sent to /auth/level1completed by the handler instead, so the two outcomes are distinguishable
// from outside.
func TestAuthorize_Deferred_LeavesNoUserSession(t *testing.T) {
	client, user, password := newDeferralClient(t)
	httpClient := createHttpClient(t)

	resp := driveDeferral(t, httpClient,
		deferralAuthorizeURL(client.ClientIdentifier, "query"), user, password)
	require.Equal(t, http.StatusFound, resp.StatusCode)
	_ = resp.Body.Close()

	// A second request, this time a perfectly valid one, on the same cookie jar.
	valid := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(deferralRedirectURI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + gofakeit.LetterN(43) +
		"&scope=" + url.QueryEscape("openid profile email")

	second, err := httpClient.Get(valid)
	require.NoError(t, err)
	defer func() { _ = second.Body.Close() }()

	assertRedirect(t, second, "/auth/level1")
}

// deferralAuthorizeURL builds an authorization request that fails ValidateScopes and nothing else:
// the response type, the challenge and the challenge method are all valid, so the first four
// validations pass and the scope is what the client is answered about. responseMode is omitted from
// the URL when empty, which is the query default.
func deferralAuthorizeURL(clientIdentifier string, responseMode string) string {
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + clientIdentifier +
		"&redirect_uri=" + url.QueryEscape(deferralRedirectURI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + gofakeit.LetterN(43) +
		"&state=" + url.QueryEscape(deferralState) +
		"&scope=not_a_valid_scope"

	if responseMode != "" {
		destUrl += "&response_mode=" + responseMode
	}
	return destUrl
}

// driveDeferral walks the whole ceremony a deferred error creates: the authorization request that
// is refused, the login the visitor is sent to instead, and the return to /auth/level1completed
// where the client is finally answered. It returns the response /auth/level1completed produced,
// which is the one carrying that answer, and the caller closes it.
//
// Every hop is asserted rather than followed blindly, so a ceremony that goes somewhere unexpected
// fails at the hop that went wrong instead of at an assertion about a response it never reached.
func driveDeferral(t *testing.T, httpClient *http.Client, destUrl string,
	user *models.User, password string) *http.Response {

	t.Helper()

	resp, err := httpClient.Get(destUrl)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, user.Email, password)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	return loadPage(t, httpClient, redirectLocation)
}

// errorDescriptionFromLocation reads error_description out of an error redirect, from the query or
// from the fragment, whichever the response used.
func errorDescriptionFromLocation(t *testing.T, resp *http.Response) string {
	t.Helper()

	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)

	if location.Fragment != "" {
		values, err := url.ParseQuery(location.Fragment)
		require.NoError(t, err)
		return values.Get("error_description")
	}
	return location.Query().Get("error_description")
}

// newDeferralClient creates a client the deferral applies to, plus a user able to complete a level 1
// ceremony for it.
//
// Administrator registered, which is what makes this the case #213 is about: a client created
// through dynamic registration is refused a redirect outright by #108's provenance gate, so it never
// reaches the question of who is at the browser. It lives here rather than in utils_test.go because
// this file is its only reader, as newRegisteredQueryClient does for its own.
func newDeferralClient(t *testing.T) (*models.Client, *models.User, string) {
	t.Helper()

	client := &models.Client{
		ClientIdentifier:         "deferral-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel1,
	}
	err := database.CreateClient(nil, client)
	require.NoError(t, err)

	err = database.CreateRedirectURI(nil, &models.RedirectURI{
		ClientId: client.Id,
		URI:      deferralRedirectURI,
	})
	require.NoError(t, err)

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	require.NoError(t, err)

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}
	err = database.CreateUser(nil, user)
	require.NoError(t, err)

	return client, user, password
}
