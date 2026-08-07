package integrationtests

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to get a user access token with account scope and also the auth code details (client, redirect, sid)
// Returns (httpClientWithCookies, accessToken, code)
func getUserAccessTokenAndCodeForAccountScope(t *testing.T) (*http.Client, string, *models.Code) {
	scope := "openid profile email " + constants.AuthServerResourceIdentifier + ":" + constants.ManageAccountPermissionIdentifier
	clientSecret := gofakeit.LetterN(32)
	httpClient, code := createAuthCodeEnsuringUserScope(t, clientSecret, scope)

	// Exchange code for tokens using the same client to preserve cookies for session
	tokenEndpoint := config.GetAuthServer().BaseURL + "/auth/token/"
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
	}
	data := postToTokenEndpoint(t, httpClient, tokenEndpoint, form)
	accessToken, ok := data["access_token"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, accessToken)
	return httpClient, accessToken, code
}

func TestAPIAccountLogoutRequest_Success_And_LogoutFlow_WithAndWithoutCookie(t *testing.T) {
	// Arrange: create session and token with account scope
	httpClientWithCookies, accessToken, code := getUserAccessTokenAndCodeForAccountScope(t)

	// Request logout URL
	reqBody := api.AccountLogoutRequest{
		PostLogoutRedirectUri: code.RedirectURI,
		State:                 gofakeit.LetterN(12),
		ResponseMode:          "redirect",
	}
	urlLogoutReq := config.GetAuthServer().BaseURL + "/api/v1/account/logout-request"
	resp := makeAPIRequest(t, "POST", urlLogoutReq, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var out api.AccountLogoutRedirectResponse
	err := json.NewDecoder(resp.Body).Decode(&out)
	assert.NoError(t, err)
	assert.NotEmpty(t, out.LogoutUrl)

	// Parse returned logout URL and verify parameters
	u, err := url.Parse(out.LogoutUrl)
	assert.NoError(t, err)
	assert.Equal(t, "/auth/logout", u.Path)
	q := u.Query()
	assert.NotEmpty(t, q.Get("id_token_hint"))
	assert.Equal(t, code.RedirectURI, q.Get("post_logout_redirect_uri"))
	assert.Equal(t, reqBody.State, q.Get("state"))

	// 1) Call /auth/logout with cookies: expect 302 to post_logout_redirect, carrying state and
	// nothing else this specification does not define
	req1, _ := http.NewRequest("GET", out.LogoutUrl, nil)
	resp1, err := httpClientWithCookies.Do(req1)
	assert.NoError(t, err)
	defer func() { _ = resp1.Body.Close() }()
	assert.Equal(t, http.StatusFound, resp1.StatusCode)
	loc1, err := url.Parse(resp1.Header.Get("Location"))
	assert.NoError(t, err)
	assert.Equal(t, code.RedirectURI, loc1.Scheme+"://"+loc1.Host+loc1.Path)
	assert.Equal(t, reqBody.State, loc1.Query().Get("state"))
	// RP-Initiated Logout 1.0 defines exactly one parameter on the way back to the RP. sid belongs to
	// Front-Channel Logout, a different endpoint travelling the other direction, and no RP is told to
	// read it here, so sending it only leaked the identifier into the RP's URL bar, history and access
	// logs (#109 decision 5).
	assert.NotContains(t, loc1.RawQuery, "sid=", "sid is not a parameter RP-initiated logout defines")

	// 2) Call /auth/logout without cookies (new client): the hint's own sid names the session, which
	// is what makes RP-initiated logout work from a relying party that cannot reach the browser session
	httpClientNoCookies := createHttpClient(t)
	req2, _ := http.NewRequest("GET", out.LogoutUrl, nil)
	resp2, err := httpClientNoCookies.Do(req2)
	assert.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusFound, resp2.StatusCode)
	loc2, err := url.Parse(resp2.Header.Get("Location"))
	assert.NoError(t, err)
	assert.Equal(t, code.RedirectURI, loc2.Scheme+"://"+loc2.Host+loc2.Path)
	assert.Equal(t, reqBody.State, loc2.Query().Get("state"))
	assert.NotContains(t, loc2.RawQuery, "sid=", "sid is not a parameter RP-initiated logout defines")
}

// TestLogout_WithIdTokenHint_NoRedirectTarget_LogsTheUserOut is #109 item 1, the defect the issue is
// named for, at the tier where it is observable end to end.
//
// post_logout_redirect_uri is OPTIONAL in RP-Initiated Logout 1.0 and this endpoint treated it as
// required. The check returned before both the database teardown and the cookie wipe, so the most
// ordinary conforming request in the specification, a valid hint and nothing else, rendered an error
// page and left the End-User signed in believing they had signed out.
//
// The session row going is the assertion that matters. The page is the visible half; the row is the
// half a user could not have checked.
func TestLogout_WithIdTokenHint_NoRedirectTarget_LogsTheUserOut(t *testing.T) {
	grant := createOfflineGrant(t)
	idToken, _ := sessionBoundGrantOnSameSession(t, grant)

	before, err := database.GetUserSessionBySessionIdentifier(nil, grant.sessionIdentifier)
	require.NoError(t, err)
	require.NotNil(t, before, "the ceremony should have left a session row to tear down")

	resp, err := grant.httpClient.Get(config.GetAuthServer().BaseURL +
		"/auth/logout?id_token_hint=" + url.QueryEscape(idToken))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"), "no target was asked for, so there is nothing to redirect to")
	// No note, because the RP asked for no return: being told that a return failed would be worse than
	// saying nothing.
	assertSignedOutPage(t, resp, signedOutEnglish, false)

	after, err := database.GetUserSessionBySessionIdentifier(nil, grant.sessionIdentifier)
	require.NoError(t, err)
	assert.Nil(t, after, "a hinted logout with no redirect target must still tear the session down")
}

// TestLogout_RejectedHint_AsksTheEndUserAndRefusesTheRedirect is decision 15 driven through the real
// stack, and it is deliberately the same request as TestLogout_Hintless_ClientIdAuthorizesTheRedirect
// with one parameter added: an id_token_hint that cannot be confirmed.
//
// Without the hint those parameters redirect. With it they must not, because RP-Initiated Logout 1.0
// section 4 forbids using information that failed to validate and forbids redirecting once an error is
// detected. The mechanism is that the consent page a rejected hint renders drops client_id, so the
// confirming POST has nothing left to authorize a target with, and the note appears instead.
//
// The teardown still happens, which is the property the whole change turns on: a hint the OP cannot
// confirm costs the RP its redirect and costs the End-User nothing.
func TestLogout_RejectedHint_AsksTheEndUserAndRefusesTheRedirect(t *testing.T) {
	grant := createOfflineGrant(t)

	// Rejected at the parse gate. Seam 2's unit table owns every other way a hint fails; what this tier
	// adds is that a rejected hint reaches a consent page a browser can actually submit.
	resp := logoutThroughConsentPage(t, grant.httpClient, url.Values{
		"id_token_hint":            {"not.a.token"},
		"post_logout_redirect_uri": {grant.redirectURI},
		"client_id":                {grant.client.ClientIdentifier},
		"state":                    {gofakeit.LetterN(8)},
	})
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"),
		"a rejected hint earns no redirect, however good the client_id beside it looks")
	assertSignedOutPage(t, resp, signedOutEnglish, true)

	gone, err := database.GetUserSessionBySessionIdentifier(nil, grant.sessionIdentifier)
	require.NoError(t, err)
	assert.Nil(t, gone, "the consent page precedes the teardown, it does not replace it")
}

// The two cases below pin that #129 changed NOTHING about RP-initiated logout (decision 3). The
// dividing line is intent: "end this session" is a security action aimed at a device, logout is
// navigation, and the fact that logout happens to delete the session row when the departing client
// was the only one on it is bookkeeping rather than a revocation decision.
//
// THEY ARE DRIVEN THROUGH REQUEST SHAPES #109 IS NOT REWRITING, per decision 13. Both supply
// id_token_hint AND post_logout_redirect_uri, because #109's first item is that the second is wrongly
// treated as required and its check returns before the teardown. They assert only what #129 cares
// about, that no grant was revoked, and nothing about whether that parameter should be required, how
// the redirect was built, or whether the session row survives, which is #109 divergence B's business.
//
// The hint comes from the token exchange's own id_token rather than from /api/v1/account/logout-request,
// so these cases do not depend on that endpoint's client resolution, which is also #109's surface.

// logoutWithHint performs the RP-initiated logout for a grant's client and returns nothing but a
// completed teardown: it fails the test unless the server redirected to the post-logout URI, which is
// what stops a "nothing was revoked" assertion passing because logout did nothing at all.
func logoutWithHint(t *testing.T, grant *offlineGrant, idToken string) {
	t.Helper()

	state := gofakeit.LetterN(10)
	logoutURL := config.GetAuthServer().BaseURL + "/auth/logout?id_token_hint=" + url.QueryEscape(idToken) +
		"&post_logout_redirect_uri=" + url.QueryEscape(grant.redirectURI) +
		"&state=" + state

	resp, err := grant.httpClient.Get(logoutURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode, "logout should redirect")

	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	require.Equal(t, grant.redirectURI, location.Scheme+"://"+location.Host+location.Path,
		"the teardown must have run to completion, not stopped at an error page")
	require.Equal(t, state, location.Query().Get("state"))
}

// sessionBoundGrantOnSameSession runs a second authorization on the grant's live session WITHOUT
// offline_access and returns its id_token and refresh token. The id_token is what logout matches
// against the session, and the refresh token is session bound, so it is the one whose survival
// decision 3's second claim is about.
func sessionBoundGrantOnSameSession(t *testing.T, grant *offlineGrant) (string, string) {
	t.Helper()

	const codeVerifier = "code-verifier-logout"
	scope := "openid " + constants.AuthServerResourceIdentifier + ":" + constants.ManageAccountPermissionIdentifier
	exchanged := grant.exchange(t, grant.codeFromSameSession(t, scope, codeVerifier), codeVerifier)

	idToken, ok := exchanged["id_token"].(string)
	require.True(t, ok, "expected an id_token to use as the logout hint: %v", exchanged)
	require.Equal(t, grant.sessionIdentifier, claimString(t, idToken, "sid"),
		"the hint must name the session logout is being asked to tear down")

	refreshToken, ok := exchanged["refresh_token"].(string)
	require.True(t, ok, "a session-bound auth code grant must yield a refresh token: %v", exchanged)
	return idToken, refreshToken
}

// TestLogout_WithIdTokenHint_RevokesNoGrants is decision 3's first claim: an offline grant survives
// logout in every case, including the one where logout deletes the session row because the departing
// client was the only one on it.
func TestLogout_WithIdTokenHint_RevokesNoGrants(t *testing.T) {
	grant := createOfflineGrant(t)

	first := grant.refresh(t)
	require.NotEmpty(t, first["access_token"], "the grant should refresh before logout: %v", first)
	grant.refreshToken = first["refresh_token"].(string)

	idToken, _ := sessionBoundGrantOnSameSession(t, grant)
	logoutWithHint(t, grant, idToken)

	after := grant.refresh(t)
	assert.NotEmpty(t, after["access_token"],
		"logout must revoke nothing, decision 3: %v", after)
}

// TestLogout_WithIdTokenHint_OtherClientOnSession_KeepsSessionBoundTokensWorking is decision 3's
// second claim, which is the more surprising one and the reason it is pinned: the client that just
// logged out keeps a working session-bound refresh token, because the session row survives while
// another client remains on it and nothing in refresh validation reads the client-session link.
//
// Pinned so #135, "disconnect this application", has to change it deliberately rather than by
// accident.
func TestLogout_WithIdTokenHint_OtherClientOnSession_KeepsSessionBoundTokensWorking(t *testing.T) {
	grant := createOfflineGrant(t)
	idToken, sessionBoundRefresh := sessionBoundGrantOnSameSession(t, grant)

	session, err := database.GetUserSessionBySessionIdentifier(nil, grant.sessionIdentifier)
	require.NoError(t, err)
	require.NotNil(t, session)

	// A second client on the same session, created directly as this suite already does for its
	// session listings. What handleExistingSessionOnLogout reads is the NUMBER of clients on the
	// session, not how each got there.
	otherClient := &models.Client{
		ClientIdentifier:         "logout-other-" + gofakeit.LetterN(8),
		ClientSecretEncrypted:    []byte("encrypted-secret"),
		Description:              "Second client sharing the session",
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}
	require.NoError(t, database.CreateClient(nil, otherClient))
	defer func() { _ = database.DeleteClient(nil, otherClient.Id) }()

	now := time.Now().UTC()
	require.NoError(t, database.CreateUserSessionClient(nil, &models.UserSessionClient{
		UserSessionId: session.Id,
		ClientId:      otherClient.Id,
		Started:       now.Add(-time.Hour),
		LastAccessed:  now.Add(-5 * time.Minute),
	}))

	logoutWithHint(t, grant, idToken)

	data := postToTokenEndpoint(t, createHttpClient(t), config.GetAuthServer().BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {grant.client.ClientIdentifier},
		"client_secret": {grant.clientSecret},
		"refresh_token": {sessionBoundRefresh},
	})
	assert.NotEmpty(t, data["access_token"],
		"the logged-out client's session-bound refresh token must keep working while another client shares the session: %v", data)
}

func TestAPIAccountLogoutRequest_ValidationErrors_And_Scope(t *testing.T) {
	_, accessToken, _ := getUserAccessTokenAndCodeForAccountScope(t)
	urlLogoutReq := config.GetAuthServer().BaseURL + "/api/v1/account/logout-request"

	// Missing postLogoutRedirectUri
	resp1 := makeAPIRequest(t, "POST", urlLogoutReq, accessToken, map[string]string{})
	defer func() { _ = resp1.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp1.StatusCode)
	var err1 api.ErrorResponse
	_ = json.NewDecoder(resp1.Body).Decode(&err1)
	assert.Equal(t, "postLogoutRedirectUri is required", err1.ErrorDescription)

	// Unresolvable postLogoutRedirectUri (no client matches)
	badReq := api.AccountLogoutRequest{PostLogoutRedirectUri: "https://invalid.example/"}
	resp2 := makeAPIRequest(t, "POST", urlLogoutReq, accessToken, badReq)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
	var err2 api.ErrorResponse
	_ = json.NewDecoder(resp2.Body).Decode(&err2)
	assert.Equal(t, "Unable to resolve client from postLogoutRedirectUri; supply clientIdentifier.", err2.ErrorDescription)

	// Scope and auth checks
	// No token
	reqNoTok, _ := http.NewRequest("POST", urlLogoutReq, nil)
	httpClient := createHttpClient(t)
	resp3, err := httpClient.Do(reqNoTok)
	assert.NoError(t, err)
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp3.StatusCode)

	// Insufficient scope
	tok := createClientCredentialsTokenWithScope(t, constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
	resp4 := makeAPIRequest(t, "POST", urlLogoutReq, tok, api.AccountLogoutRequest{PostLogoutRedirectUri: "https://example.com/"})
	defer func() { _ = resp4.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp4.StatusCode)
}

// What logoutThroughConsentPage models while it reproduces the browser's submission of the consent
// form, and, because the refusals below are easy to mistake for more than they are, what it does not.
// Anything outside these sets fails the test rather than being skipped: a browser acts on every
// element, every attribute and every class the form's subtree carries, so a helper that silently
// ignores the ones nobody taught it lets a page no browser can submit keep the cases below green.
//
// What it establishes is the payload a browser would submit from this form, and that nothing the
// document declares sends that payload elsewhere or forbids it outright. Four dimensions, because a
// page can be spoiled along each independently and closing one leaves the others open. An earlier
// version closed only the second, and three mutations walked straight through it: a <fieldset
// disabled> wrapped round the Yes button, which is an element nobody had declared; "hidden" added to
// that button's class, which is a hostile value of a permitted attribute; and the Yes and No labels
// swapped, which changes nothing structural at all.
//
//  1. consentFormTags: the element types allowed anywhere inside the form. A <fieldset> disables
//     every control it wraps, a <select> or <textarea> goes out in a browser's payload and not in
//     this one, and a <script> cancels the submission outright. None of them is a tag below.
//  2. The attribute sets: what each of those elements may carry. Deliberately absent, each honoured
//     by a browser: disabled makes a control unsubmittable, so a disabled Yes button leaves the page
//     dead and a disabled hidden field drops a parameter; formaction, formmethod, formenctype and
//     formnovalidate let the submitter override where, how and whether the form goes; form reassigns
//     which form a control belongs to; required blocks submission until a field is filled; hidden
//     removes the control from the page.
//  3. consentClassTokens: every class token logout_consent.html actually uses inside its form. A
//     class is styling until it is "hidden", and then it is a control the End-User cannot reach, so
//     an allowlist of keys that never looks at values is not a boundary. Restyling the page means
//     adding the new tokens here.
//  4. The document around the form, which decides where the submission goes and whether it happens at
//     all, and none of which is anywhere near the form: no <base> element, since that is the one thing
//     that moves what a relative action resolves against; no <style> block, which is the only CSS a
//     parsed document carries; consentAncestorTags for the element types the form may sit inside;
//     consentMetaEquivs for what the head may instruct the browser to do, a refresh being enough to
//     navigate the page away before the End-User could confirm; and consentCSPDirectives for the
//     policy the response header and that head may carry.
//
// Adding an element, an attribute or a class to logout_consent.html means teaching this helper what
// a browser does with it (#109).
//
// What it does not establish is that a browser can use this page. Three inputs to that are outside a
// parsed document altogether and no refusal here reaches them:
//
//   - Style from an external stylesheet. The layout links /static/main.css and two CDN stylesheets,
//     any of which can hide a control this helper has just read and approved. What the document
//     declares itself is refused, the style attribute above the form and inside it and a <style>
//     block anywhere in it; what another file declares needs a CSS engine.
//   - Script. A handler registered from /static/utils.js or from the layout's JSBootstrap block can
//     cancel the submit event. The sets below refuse an inline handler on the form and on the
//     affirmative control, and refuse a <script> inside the form, which is the part the template
//     declares; the rest needs a JavaScript engine.
//   - An ancestor attribute outside consentHidingAttrs, which is a denylist for the reason recorded
//     on it, so its tail is open by construction where every other set here is closed.
//
// Closing those three means running the page in a browser, which is a decision about this
// repository's test dependencies rather than something this file can settle (#109).
var (
	consentFormAttrs   = map[string]bool{"action": true, "method": true, "class": true}
	consentInputAttrs  = map[string]bool{"type": true, "name": true, "value": true, "class": true}
	consentButtonAttrs = map[string]bool{"type": true, "name": true, "value": true, "class": true, "onclick": true}
	consentLayoutAttrs = map[string]bool{"class": true}

	consentFormTags = map[string]map[string]bool{
		"input":  consentInputAttrs,
		"button": consentButtonAttrs,
		"div":    consentLayoutAttrs,
		"p":      consentLayoutAttrs,
	}

	consentClassTokens = map[string]bool{
		"mt-2": true, "mt-5": true, "mt-6": true, "mt-8": true,
		"text-center": true, "text-error": true,
		"grid": true, "grid-cols-2": true, "gap-3": true,
		"w-full": true, "btn": true, "btn-primary": true, "btn-secondary": true,
	}

	// The element types the form may sit inside, which is the auth layout's own structure. An
	// allowlist works here where it does not for the layout's attributes, because a wrapper element
	// is exactly the kind of thing that decides whether the controls inside it can be reached at all:
	// a closed <details> collapses its contents to the summary alone, a <dialog> without open is not
	// rendered, a <template>'s contents are inert markup a browser never lays out, and a <fieldset>
	// disables every control it wraps. Naming the four the layout uses refuses all of them, and the
	// next wrapper nobody has thought of with them.
	consentAncestorTags = map[string]bool{"html": true, "body": true, "main": true, "div": true}

	// Applied to the form's ancestors, and the one denylist here rather than an allowlist: the auth
	// layout is shared by every page in the app and its styling is none of this test's business, so
	// refusing an attribute it has not declared would fail this test for edits that cannot affect
	// logout. The cost of that choice is that this set alone has an open tail, which the comment on
	// the helper records as a residual rather than leaving implied.
	//
	// Each entry stops the End-User reaching the controls below it. hidden and inert are honoured on
	// any element, inert additionally making everything inside it unclickable while still visible;
	// popover renders its element hidden until something shows it; disabled is honoured only on
	// form-associated elements, and is refused anyway because it costs nothing to refuse. style is
	// refused whatever it contains, because reading a declaration properly means implementing CSS and
	// the layout carries no inline style today, so the strict form is also the cheap one.
	// A slice rather than a set, so a page carrying two of these always fails on the same one and the
	// message a run reports is reproducible.
	consentHidingAttrs = []string{"hidden", "inert", "popover", "disabled", "style"}

	// Tailwind's screen-reader-only utility is deliberately absent, for two reasons that agree. It
	// positions a container off-screen without disabling it, so the form still submits and assistive
	// technology still reaches it, which makes it the one candidate that does not render the page
	// unusable. And naming it here would ship a stylesheet rule for it: the CSS build harvests
	// class-name candidates from this whole module rather than only from web/template as
	// tailwind.config.js says, so a token spelled out in this file, comments included, appears in the
	// generated web/static/main.css even though no template asks for it (#109).
	consentHidingClasses = map[string]bool{"hidden": true, "invisible": true, "collapse": true}

	// The Content-Security-Policy directives this helper has been taught, checked against both places
	// a policy can arrive: the response header, which MiddlewareSecurityHeaders sets on every
	// response, and a meta http-equiv in the document head. Those two are the whole of it, so an
	// allowlist over the directives closes the question rather than sampling it.
	//
	// frame-ancestors is what the deployment sends today and it governs framing, not submission. The
	// two that would refuse this POST outright are form-action, which names where a form may submit,
	// and sandbox, which forbids submission entirely unless it carries allow-forms. Both would leave
	// every case below green while no browser could log out, because this helper builds the POST
	// itself and no policy applies to a Go http.Client. Hardening the deployment means deciding here
	// whether the new directive permits this form's submission.
	consentCSPDirectives = map[string]bool{"frame-ancestors": true}

	// The http-equiv values the document head may carry, an allowlist for the same reason
	// consentCSPDirectives is one: a meta http-equiv is an instruction to the browser and the set of
	// them that does anything is not this test's to enumerate. The one that would leave every case
	// below green while no End-User could ever confirm is "refresh", which navigates the document away
	// on a timer this helper never waits for.
	//
	// x-ua-compatible is what both layouts carry today and it does nothing to submission.
	// content-security-policy is admitted here and then read against consentCSPDirectives, because the
	// deployment sends a policy and refusing the channel outright would fail on a header it already
	// sets (#109).
	consentMetaEquivs = map[string]bool{"x-ua-compatible": true, "content-security-policy": true}
)

// consentLabels is what the two answer buttons must read in one locale, which is what ties each
// button to the answer it gives. Without it the affirmative control is identified structurally, by
// being the one with no cancelling script, and swapping the two translation references leaves the
// page submitting on visible No and cancelling on visible Yes with every case still green.
type consentLabels struct{ yes, no string }

// Keyed by the ui_locales the case asks for, empty meaning the default locale, so a case that drives
// the page in a language nobody recorded labels for fails rather than skipping the check.
var consentLabelsByLocale = map[string]consentLabels{
	"":      {yes: "Yes", no: "No"},
	"pt-BR": {yes: "Sim", no: "Não"},
}

// unmodelledAttrs names every attribute across the selection that the given set does not cover, each
// tagged with the element carrying it so a failure says which control to go and look at.
func unmodelledAttrs(sel *goquery.Selection, modelled map[string]bool) []string {
	found := []string{}
	for _, node := range sel.Nodes {
		for _, attr := range node.Attr {
			if !modelled[strings.ToLower(attr.Key)] {
				found = append(found, node.Data+"["+attr.Key+"]")
			}
		}
	}
	return found
}

// unmodelledClasses names every class token across the selection that consentClassTokens does not
// cover. Same contract as unmodelledAttrs, one level down: the attribute is permitted, its value is
// what has to be read.
func unmodelledClasses(sel *goquery.Selection) []string {
	found := []string{}
	for _, node := range sel.Nodes {
		for _, attr := range node.Attr {
			if strings.ToLower(attr.Key) != "class" {
				continue
			}
			for _, token := range strings.Fields(attr.Val) {
				if !consentClassTokens[token] {
					found = append(found, node.Data+"."+token)
				}
			}
		}
	}
	return found
}

// unmodelledCSPDirectives names every Content-Security-Policy directive in the given policy that
// consentCSPDirectives does not cover. An empty policy yields nothing, which is also the answer when
// that delivery channel carried no policy at all.
func unmodelledCSPDirectives(policy string) []string {
	found := []string{}
	for _, directive := range strings.Split(policy, ";") {
		fields := strings.Fields(directive)
		if len(fields) == 0 {
			continue
		}
		if name := strings.ToLower(fields[0]); !consentCSPDirectives[name] {
			found = append(found, name)
		}
	}
	return found
}

// logoutThroughConsentPage drives a hintless logout the way a browser does: GET /auth/logout, read
// the consent page, then submit exactly the fields that page carries. It returns the raw response to
// the confirming POST, because what the End-User lands on is what the cases below are about.
//
// Submitting the page's own fields rather than a hand-built form is the point. The hidden fields are
// how post_logout_redirect_uri, client_id, state and ui_locales survive a form action that
// deliberately drops the query string it was served with, and the id_token_hint's absence from that
// set is the invariant the POST binding's CSRF exemption rests on: a hintless POST had to pass CSRF,
// so it came from this page (#109).
//
// It submits the page the way the page says to submit it, and refuses to submit a page whose rules it
// does not know. The method and action come off the form, the payload is the successful controls only,
// the affirmative control has to be one a browser would submit with and has to be the one the
// End-User reads as Yes, and every element, attribute and class token outside the sets above is a
// failure rather than an omission. A helper that builds its own POST regardless is precisely what
// lets a form drifted to GET, an inert Yes button, a Yes button no browser would show, or a submitter
// overriding the form's destination keep every case below green while no browser can log out.
//
// It still builds the POST itself, so what it establishes is bounded by what a parsed document shows.
// The three inputs outside that boundary are listed above consentFormAttrs, and stylesheets are the
// one to keep in mind when reading a green run: this helper reads the class tokens the markup carries
// and cannot know what a stylesheet does with them.
func logoutThroughConsentPage(t *testing.T, httpClient *http.Client, query url.Values) *http.Response {
	t.Helper()

	labels, labelled := consentLabelsByLocale[query.Get("ui_locales")]
	require.True(t, labelled,
		"no Yes/No labels recorded for ui_locales=%q, so which button means which answer is unknown",
		query.Get("ui_locales"))

	logoutURL := config.GetAuthServer().BaseURL + "/auth/logout"
	if len(query) > 0 {
		logoutURL += "?" + query.Encode()
	}
	resp, err := httpClient.Get(logoutURL)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"a request with no id_token_hint must render the consent page, which the spec makes a MUST")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	require.NoError(t, err)

	// Where the form's action resolves to, which is its real destination however local the attribute
	// reads. A <base href> moves the document's base URL, so "/auth/logout" would resolve against
	// whatever origin that names and a browser would deliver this form's payload, CSRF token included,
	// to that origin while the action assertion below still passed. HTML gives a document exactly one
	// way to move its base URL, so refusing the element settles this rather than sampling it: with no
	// <base>, the base URL is the response's own URL, which is what the POST below is built against
	// (#109).
	require.Equal(t, 0, doc.Find("base").Length(),
		"a <base> moves what the form's relative action resolves against, so a browser would submit this page to an origin this helper does not")

	// The one CSS this helper can see. A declaration can hide the form or any control inside it, and
	// reading one properly means implementing CSS, so the element is refused whatever it contains,
	// exactly as the style attribute is: no template in either app carries one, which makes the strict
	// form the cheap one too. A linked stylesheet stays outside this boundary and is recorded above as a
	// residual, because that one needs a fetch and an engine rather than a parse (#109).
	require.Equal(t, 0, doc.Find("style").Length(),
		"a <style> block can hide the form or its controls, and this helper does not implement CSS")

	// And what the head instructs the browser to do, including whether the submission is permitted at
	// all. Both CSP delivery channels, because a policy from either applies in a browser and neither
	// applies to the Go client below: see consentCSPDirectives and consentMetaEquivs.
	require.Empty(t, unmodelledCSPDirectives(resp.Header.Get("Content-Security-Policy")),
		"the response carries a Content-Security-Policy directive this helper does not model, and a browser may refuse this form's submission because of it")
	doc.Find("meta[http-equiv]").Each(func(_ int, meta *goquery.Selection) {
		equiv := strings.ToLower(strings.TrimSpace(meta.AttrOr("http-equiv", "")))
		require.True(t, consentMetaEquivs[equiv],
			"the document head carries <meta http-equiv=%q>, whose effect on this page this helper does not model", equiv)
		if equiv != "content-security-policy" {
			return
		}
		require.Empty(t, unmodelledCSPDirectives(meta.AttrOr("content", "")),
			"the document head carries a Content-Security-Policy directive this helper does not model, and a browser may refuse this form's submission because of it")
	})

	// One form, so which form owns a control is never ambiguous, and nothing anywhere on the page
	// names a form owner of its own, which is how a browser would be told to submit a control this
	// helper cannot see or to leave out one it reads.
	require.Equal(t, 1, doc.Find("form").Length(), "the consent page carries exactly one form")
	require.Equal(t, 0, doc.Find("[form]").Length(),
		"no control may name a form owner, which would change what a browser submits")
	formSel := doc.Find("form")

	require.Empty(t, unmodelledAttrs(formSel, consentFormAttrs),
		"the form carries an attribute this helper does not model, so a browser and these cases would disagree about how the page submits")
	require.Empty(t, unmodelledClasses(formSel), "the form carries a class token this helper does not model")

	// The whole subtree, not just the controls. A browser reads every element between the form and
	// its buttons, so an element type nobody declared is an unknown rule rather than decoration:
	// <fieldset disabled> is the shortest way to render the affirmative control unusable without
	// touching it, and it is invisible to any check that starts from Find("input, button").
	formSel.Find("*").Each(func(_ int, el *goquery.Selection) {
		tag := goquery.NodeName(el)
		modelled, known := consentFormTags[tag]
		require.True(t, known,
			"the consent form contains a <%s>, whose effect on submission this helper does not model", tag)
		require.Empty(t, unmodelledAttrs(el, modelled),
			"an element inside the form carries an attribute this helper does not model, and a browser would act on it")
		require.Empty(t, unmodelledClasses(el),
			"an element inside the form carries a class token this helper does not model; a class that hides or disables it would leave the page unusable with these cases green")
	})

	// Above the form, where a container can still hide or disable everything inside it without the form
	// itself changing at all. An allowlist on the element types, per consentAncestorTags, and a
	// denylist on the attributes and class tokens, per consentHidingAttrs and consentHidingClasses,
	// which is where this helper's one open tail is.
	formSel.Parents().Each(func(_ int, ancestor *goquery.Selection) {
		tag := goquery.NodeName(ancestor)
		require.True(t, consentAncestorTags[tag],
			"the form sits inside a <%s>, whose effect on reaching the controls this helper does not model", tag)
		for _, attr := range consentHidingAttrs {
			_, present := ancestor.Attr(attr)
			require.False(t, present,
				"a container above the form carries %q, which stops the End-User reaching every control inside it", attr)
		}
		for _, token := range strings.Fields(ancestor.AttrOr("class", "")) {
			require.False(t, consentHidingClasses[token],
				"a container above the form carries %q, which hides every control inside it", token)
		}
	})

	action, ok := formSel.Attr("action")
	require.True(t, ok)
	require.Equal(t, "/auth/logout", action,
		`an explicit action, because action="" would carry the query string and with it the hint`)

	// A GET form would defeat this path twice over, which is why the method is asserted here and then
	// used below rather than assumed: the GET binding renders the consent page again instead of
	// tearing anything down, so no End-User could ever confirm a logout, and a GET carries no CSRF
	// token, which is the only thing that makes a hintless teardown trustworthy without a confirmable
	// hint. An absent method attribute means GET, so it fails here too (#109).
	method := formSel.AttrOr("method", "")
	require.True(t, strings.EqualFold("post", method),
		"the confirming request must be a POST, got method=%q", method)

	form := url.Values{}
	formSel.Find("input").Each(func(_ int, input *goquery.Selection) {
		require.Equal(t, "hidden", strings.ToLower(input.AttrOr("type", "")),
			"every input on this form is hidden; any other type brings submission rules of its own")
		name, hasName := input.Attr("name")
		require.True(t, hasName, "a nameless control is never submitted, so one here would be a mistake")
		require.False(t, form.Has(name),
			"two controls named %q would both reach the handler from a browser and only one from here", name)
		form.Set(name, input.AttrOr("value", ""))
	})
	require.NotEmpty(t, form.Get("gorilla.csrf.Token"), "the confirming POST is CSRF protected")

	// Which button gives which answer, read the way the End-User reads it. Identifying the affirmative
	// control structurally is not enough on its own: swap the two translation references and the
	// unscripted submit button is the one labelled No, so visible No logs the user out, visible Yes
	// cancels, and every case below still passes.
	buttons := formSel.Find("button")
	require.Equal(t, 2, buttons.Length(),
		"the consent form asks one question and carries one button per answer")
	affirmative := buttons.FilterFunction(func(_ int, button *goquery.Selection) bool {
		return strings.TrimSpace(button.Text()) == labels.yes
	})
	declining := buttons.FilterFunction(func(_ int, button *goquery.Selection) bool {
		return strings.TrimSpace(button.Text()) == labels.no
	})
	require.Equal(t, 1, affirmative.Length(), "exactly one button must read %q", labels.yes)
	require.Equal(t, 1, declining.Length(), "exactly one button must read %q", labels.no)

	// The affirmative control must be one a browser would submit with, or the page is unusable however
	// correct the handler is: no cancelling handler of its own, and a type that submits, which a button
	// carrying no type attribute already is per HTML's missing-value default. That it is enabled, shown
	// and overrides none of the form's action, method or encoding follows from the sets above rather
	// than from checks of its own (#109).
	require.Empty(t, affirmative.AttrOr("onclick", ""),
		"the button labelled %q must not be the one wired to cancel the submission", labels.yes)
	require.True(t, strings.EqualFold("submit", affirmative.AttrOr("type", "submit")),
		"the affirmative control must be able to submit the form, got type=%q", affirmative.AttrOr("type", ""))

	// And the declining control must not be able to submit it. Today an inline handler calls
	// preventDefault(), since a button with no type attribute is a submit control; an explicit
	// type="button" would do the same without script, and either satisfies this.
	require.True(t,
		!strings.EqualFold("submit", declining.AttrOr("type", "submit")) || declining.AttrOr("onclick", "") != "",
		`the button labelled %q must not submit the form: give it type="button" or keep its cancelling handler`,
		labels.no)

	// A named submitter is itself a successful control, so a browser would send it too.
	if name, hasName := affirmative.Attr("name"); hasName {
		require.False(t, form.Has(name),
			"the submitter is named %q, which a hidden field already carries; a browser would send both", name)
		form.Set(name, affirmative.AttrOr("value", ""))
	}

	// Read off the finished payload rather than off the markup, because the invariant is about what
	// reaches the handler and any control can carry a parameter: a submit button named id_token_hint
	// puts one in the body just as a hidden input does. A hintless POST is what the CSRF exemption for
	// the POST binding rests on, so this is decision 13's invariant and not a tidiness check (#109).
	require.False(t, form.Has("id_token_hint"),
		"the confirming POST must not carry an id_token_hint back, whichever control would have carried it")

	// The default encoding, which is what the absent enctype leaves in force: it is modelled on
	// neither the form nor the submitter, so any attempt to change it fails above rather than here.
	destURL := config.GetAuthServer().BaseURL + action
	req, err := http.NewRequest(strings.ToUpper(method), destURL, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", destURL)
	req.Header.Set("Origin", config.GetAuthServer().BaseURL)
	resp, err = httpClient.Do(req)
	require.NoError(t, err)
	return resp
}

// signedOutTexts is what the terminal page must render in one locale. It is a struct rather than a
// bare string per assertion because every field is a separate translation reference in
// logged_out.html, and i18n.T renders a missing key as the key itself, so a reference that goes stale
// is visible only to an assertion that looks where it belongs. page_title and title carry the same
// string in both locales, which is exactly why a substring search over the body cannot tell a broken
// page_title from a broken title: one lives in <title> and the other in the page heading (#109).
type signedOutTexts struct {
	pageTitle string
	heading   string
	message   string
	declined  string
}

var (
	signedOutEnglish = signedOutTexts{
		pageTitle: "Logged out",
		heading:   "Logged out",
		message:   "You have been logged out.",
		declined:  "We could not return you to the application that logged you out.",
	}
	signedOutPortuguese = signedOutTexts{
		pageTitle: "Sessão encerrada",
		heading:   "Sessão encerrada",
		message:   "Você saiu da sua conta.",
		declined:  "Não foi possível retornar você ao aplicativo que solicitou a saída.",
	}
)

// assertSignedOutPage reads the terminal page through its rendered markup and checks all four of the
// template's translation references plus both sides of its one conditional.
//
// declined says whether a post-logout target was refused. Both directions are asserted because the
// note is the page's only variable part and each direction fails for its own reason: missing when a
// target was refused, the RP's user is left with no idea why they are still here; present when none
// was asked for, they are told a return failed that nobody requested.
func assertSignedOutPage(t *testing.T, resp *http.Response, texts signedOutTexts, declined bool) {
	t.Helper()

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(bodyString(t, resp)))
	require.NoError(t, err)

	assert.Contains(t, doc.Find("title").Text(), texts.pageTitle, "the browser tab title")
	require.Equal(t, 1, doc.Find("h2").Length(), "the page has one heading, which the next line names")
	assert.Equal(t, texts.heading, strings.TrimSpace(doc.Find("h2").Text()), "the page heading")

	rendered := doc.Text()
	assert.Contains(t, rendered, texts.message,
		"the signed-out page renders, rather than a redirect to the auth server root")
	if declined {
		assert.Contains(t, rendered, texts.declined, "a target that was refused must say so")
	} else {
		assert.NotContains(t, rendered, texts.declined,
			"a user who asked for no return must not be told that a return failed")
	}
}

// TestLogout_Hintless_DeletesTheSessionRowAndSparesOfflineGrants is what the endpoint used to get
// wrong on this path: confirming the consent page cleared the browser cookie and wrote nothing to
// user_sessions, so session-bound refresh tokens kept working and the row was orphaned from a
// browser that could no longer name it.
//
// Both halves are asserted together because each is the other's control. Deleting the row is the fix;
// the offline grant still refreshing afterwards is decision 2's boundary, and it is why the teardown
// deletes the row rather than calling the whole-session termination #129 built, which would revoke
// offline grants too.
func TestLogout_Hintless_DeletesTheSessionRowAndSparesOfflineGrants(t *testing.T) {
	grant := createOfflineGrant(t)

	first := grant.refresh(t)
	require.NotEmpty(t, first["access_token"], "the grant should refresh before logout: %v", first)
	grant.refreshToken = first["refresh_token"].(string)

	before, err := database.GetUserSessionBySessionIdentifier(nil, grant.sessionIdentifier)
	require.NoError(t, err)
	require.NotNil(t, before, "the ceremony should have left a session row to tear down")

	resp := logoutThroughConsentPage(t, grant.httpClient, url.Values{})
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"with no post_logout_redirect_uri the confirmation ends on the signed-out page")
	assertSignedOutPage(t, resp, signedOutEnglish, false)

	after, err := database.GetUserSessionBySessionIdentifier(nil, grant.sessionIdentifier)
	require.NoError(t, err)
	assert.Nil(t, after, "confirming the consent page must delete the session row, not just clear the cookie")

	refreshed := grant.refresh(t)
	assert.NotEmpty(t, refreshed["access_token"],
		"an offline grant survives logout, decision 2: %v", refreshed)
}

// TestLogout_Hintless_ClientIdAuthorizesTheRedirect covers the shape that got no redirect at all
// before: post_logout_redirect_uri and client_id with no id_token_hint. The spec calls that
// client_id's most common use, and it is the "other means of confirming the legitimacy of the
// post-logout redirection target" section 3 requires.
//
// The state is the one string that broke every part of the concatenation this replaced: "+" arrived
// as a space, "/" and "=" went out raw, "#" turned the tail into a fragment the RP's server never
// saw, and "&injected=1" arrived as a real parameter. Asserting it byte-identical through the real
// stack is the whole point of doing this at the HTTP tier.
func TestLogout_Hintless_ClientIdAuthorizesTheRedirect(t *testing.T) {
	grant := createOfflineGrant(t)
	const state = "aB+cd/efgh==#&injected=1"

	resp := logoutThroughConsentPage(t, grant.httpClient, url.Values{
		"post_logout_redirect_uri": {grant.redirectURI},
		"client_id":                {grant.client.ClientIdentifier},
		"state":                    {state},
	})
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, grant.redirectURI, location.Scheme+"://"+location.Host+location.Path)
	assert.Equal(t, []string{state}, location.Query()["state"],
		"exactly one state reaches the RP, byte-identical to what it sent")
	assert.Empty(t, location.Fragment, `the "#" in state must stay in the query, not become a fragment`)
	assert.Empty(t, location.Query().Get("injected"), "state must not be able to inject parameters")
	assert.NotContains(t, location.RawQuery, "sid=",
		"RP-Initiated Logout defines state and nothing else on the way back, decision 5")

	gone, err := database.GetUserSessionBySessionIdentifier(nil, grant.sessionIdentifier)
	require.NoError(t, err)
	assert.Nil(t, gone, "the redirect does not replace the teardown, it follows it")
}

// TestLogout_Hintless_AbsentAndEmptyStateAreDifferentRedirects drives the real consent page twice
// and reads what reaches the RP, because absent and empty state is a contract no mocked assertion
// can prove. It lives at this tier for one specific reason: the distinction is carried by the
// template's {{if .statePresent}} guard, and the handler unit test can only see the flag it binds.
// Make that hidden field unconditional and the handler is still correct, the bind assertion still
// passes, and every RP that sent no state starts receiving "state=" it never asked for.
//
// The two rows have to be read together. Neither alone catches the mutation: the empty case passes
// with an unconditional field, and the absent case passes with no field at all.
func TestLogout_Hintless_AbsentAndEmptyStateAreDifferentRedirects(t *testing.T) {

	t.Run("no state sent means no state key comes back", func(t *testing.T) {
		grant := createOfflineGrant(t)

		resp := logoutThroughConsentPage(t, grant.httpClient, url.Values{
			"post_logout_redirect_uri": {grant.redirectURI},
			"client_id":                {grant.client.ClientIdentifier},
		})
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusFound, resp.StatusCode)
		location, err := url.Parse(resp.Header.Get("Location"))
		require.NoError(t, err)
		_, present := location.Query()["state"]
		assert.False(t, present,
			"an RP that sent no state must not have one invented for it by the consent form: %q",
			location.RawQuery)
	})

	t.Run("state sent empty comes back empty", func(t *testing.T) {
		grant := createOfflineGrant(t)

		resp := logoutThroughConsentPage(t, grant.httpClient, url.Values{
			"post_logout_redirect_uri": {grant.redirectURI},
			"client_id":                {grant.client.ClientIdentifier},
			"state":                    {""},
		})
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusFound, resp.StatusCode)
		location, err := url.Parse(resp.Header.Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, []string{""}, location.Query()["state"],
			"exactly one state, empty, because the RP asked for one and left it empty: %q",
			location.RawQuery)
	})
}

// TestLogout_Hintless_UnregisteredTargetIsDeclinedButTheLogoutHappens is the property the whole
// change turns on, at the tier where it is observable: a target the OP may not redirect to costs the
// RP its redirect and nothing else. The user is signed out either way, which is what the seven error
// returns this replaced got wrong.
//
// It also renders the one extra sentence the signed-out page carries in this case, which the unit
// tier cannot see because it mocks the template away.
func TestLogout_Hintless_UnregisteredTargetIsDeclinedButTheLogoutHappens(t *testing.T) {
	grant := createOfflineGrant(t)

	resp := logoutThroughConsentPage(t, grant.httpClient, url.Values{
		"post_logout_redirect_uri": {"https://example.com/not-registered"},
		"client_id":                {grant.client.ClientIdentifier},
		"state":                    {gofakeit.LetterN(8)},
	})
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"), "a target that fails validation must never be redirected to")
	assertSignedOutPage(t, resp, signedOutEnglish, true)

	gone, err := database.GetUserSessionBySessionIdentifier(nil, grant.sessionIdentifier)
	require.NoError(t, err)
	assert.Nil(t, gone, "the teardown reads nothing the redirect resolution produced")
}

// TestLogout_Hintless_UILocalesSurvivesTheConsentForm pins decision 17. The global locale middleware
// reads the query only, deliberately, so it cannot see the confirming POST's body. Without the
// handler's own refinement the user would read a consent page in one language and a signed-out page
// in another, which this change would have introduced rather than fixed.
func TestLogout_Hintless_UILocalesSurvivesTheConsentForm(t *testing.T) {
	grant := createOfflineGrant(t)

	resp := logoutThroughConsentPage(t, grant.httpClient, url.Values{"ui_locales": {"pt-BR"}})
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	// Every reference on the page, in pt-BR: the whole template has to follow the locale the consent
	// page was read in, not only the line this case used to check.
	assertSignedOutPage(t, resp, signedOutPortuguese, false)
}
