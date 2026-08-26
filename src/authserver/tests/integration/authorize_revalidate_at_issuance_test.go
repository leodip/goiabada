package integrationtests

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
)

// The cases in this file are one window seen several ways. /auth/completed establishes that
// the session is valid, that the user holds the permissions behind the requested scopes, and
// (back at /auth/authorize) that the redirect URI is registered; the consent screen then holds
// the ceremony for as long as a person takes to read it; and /auth/issue re-establishes all
// three immediately before it mints anything (#241).
//
// Each one mutates exactly the thing its check is about while the ceremony is held, and asserts
// what the client did not get. Most mutate between the consent submission and the last hop, which
// is the window the gate at /auth/issue closes; two mutate before the submission instead, because
// a Cancel and the consent record are both decided by HandleConsentPost and never reach another
// hop. TestSessionEndedOnConsentScreen_NoCodeIsIssued in session_deletion_test.go is the sibling
// these are written to match: it deletes the session row, which is the case #129 already
// closed, and these are what a row that survives can still be wrong about.

// parkedCeremony is a ceremony stopped on its consent screen, with everything a case needs to
// mutate the world and then let it finish.
type parkedCeremony struct {
	httpClient  *http.Client
	client      *models.Client
	redirectURI *models.RedirectURI
	user        *models.User
	consentURL  string
	consentPage *http.Response
	state       string
}

// parkOnConsentScreen runs a full ceremony as far as the consent screen and stops there, which is
// where the window these cases are about opens.
//
// It is not navigateToConsentScreen: that helper requests "openid profile email" with no resource
// scope, so a case about a REVOKED PERMISSION would have nothing to revoke, and it derives its
// code challenge from no verifier, so a case that has to redeem the code cannot prove possession.
// Both are needed here, so the scope and the verifier are the caller's.
//
// The caller closes consentPage.
func parkOnConsentScreen(t *testing.T, requestScope string, clientSecret string,
	codeVerifier string, grantScopes []string) *parkedCeremony {

	t.Helper()

	clientSecretEncrypted, err := encryption.EncryptData(clientSecret)
	assert.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "revalidate-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		// The consent screen is what holds the ceremony still between /auth/completed and
		// /auth/issue, which is the whole window these cases are about.
		ConsentRequired:       true,
		DefaultAcrLevel:       enums.AcrLevel1,
		ClientSecretEncrypted: clientSecretEncrypted,
	}
	err = database.CreateClient(nil, client)
	assert.NoError(t, err)

	redirectURI := &models.RedirectURI{ClientId: client.Id, URI: gofakeit.URL()}
	err = database.CreateRedirectURI(nil, redirectURI)
	assert.NoError(t, err)

	password := gofakeit.Password(true, true, true, true, false, 10)
	passwordHashed, err := hashutil.HashPassword(password)
	assert.NoError(t, err)

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}
	err = database.CreateUser(nil, user)
	assert.NoError(t, err)

	for _, scope := range grantScopes {
		parts := strings.Split(scope, ":")
		assert.Len(t, parts, 2, "a grantable scope is resource:permission")
		resource, err := database.GetResourceByResourceIdentifier(nil, parts[0])
		assert.NoError(t, err)
		assert.NotNil(t, resource)
		permissions, err := database.GetPermissionsByResourceId(nil, resource.Id)
		assert.NoError(t, err)
		granted := false
		for i := range permissions {
			if permissions[i].PermissionIdentifier == parts[1] {
				err = database.CreateUserPermission(nil,
					&models.UserPermission{UserId: user.Id, PermissionId: permissions[i].Id})
				assert.NoError(t, err)
				granted = true
				break
			}
		}
		assert.True(t, granted, "permission %s must exist to be granted", scope)
	}

	// One HTTP client throughout, so the cookie is shared and this is one browser's ceremony
	// rather than two.
	httpClient := createHttpClient(t)

	state := gofakeit.LetterN(8)
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + oauth.GeneratePKCECodeChallenge(codeVerifier) +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + state +
		"&nonce=" + gofakeit.LetterN(8)

	resp, err := httpClient.Get(destUrl)
	assert.NoError(t, err)

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)

	pwdPage := resp
	resp = authenticateWithPassword(t, httpClient, redirectLocation, pwdPage, user.Email, password)
	_ = pwdPage.Body.Close()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)

	// Consent, not /auth/issue: the ceremony now waits for a person, and everything these cases
	// do happens while it waits.
	consentURL := assertRedirect(t, resp, "/auth/consent")
	_ = resp.Body.Close()

	return &parkedCeremony{
		httpClient:  httpClient,
		client:      client,
		redirectURI: redirectURI,
		user:        user,
		consentURL:  consentURL,
		consentPage: loadPage(t, httpClient, consentURL),
		state:       state,
	}
}

// TestSessionExpiredOnConsentScreen_NoCodeIsIssued is the case the liveness check cannot reach.
//
// TestSessionEndedOnConsentScreen_NoCodeIsIssued deletes the session row, so the identifier is
// gone from the request context and /auth/issue refuses on a row that does not resolve. Here the
// row survives and still belongs to this ceremony's user: both of the older checks pass it, and
// only the idle timeout refuses. Before #241 this yielded a usable code, the access token worked,
// and the first refresh answered invalid_grant.
func TestSessionExpiredOnConsentScreen_NoCodeIsIssued(t *testing.T) {
	parked := parkOnConsentScreen(t, "openid profile email", gofakeit.LetterN(32), "code-verifier", nil)
	defer func() { _ = parked.consentPage.Body.Close() }()

	sessions, err := database.GetUserSessionsByUserId(nil, parked.user.Id)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(sessions), "the ceremony should have created one session before consent")
	session := &sessions[0]

	// Backdated rather than deleted, which is the whole point of this case against its sibling:
	// the row is still there, it still belongs to this user, and the only thing wrong with it is
	// the clock. A year covers any idle timeout and any maximum lifetime an installation might
	// have configured.
	longAgo := time.Now().UTC().AddDate(-1, 0, 0)
	session.Started = longAgo
	session.LastAccessed = longAgo
	err = database.UpdateUserSession(nil, session)
	assert.NoError(t, err)

	resp := postConsent(t, parked.httpClient, parked.consentURL, parked.consentPage, []int{0, 1, 2, 3, 4})
	defer func() { _ = resp.Body.Close() }()

	// The consent submission itself succeeds: it reads no session row, so the expiry is
	// invisible to it. That is what makes the next hop the load-bearing one.
	redirectLocation := assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, parked.httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1")
	assert.NotContains(t, redirectLocation, "code=",
		"no authorization code may reach the client on a session that has timed out")
	assert.NotContains(t, redirectLocation, parked.redirectURI.URI,
		"the refusal is a restart, not a response to the client")

	// And the restart is a real one: the user is asked for a password again.
	resp = loadPage(t, parked.httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()
	assertRedirect(t, resp, "/auth/pwd")
}

// TestPermissionRevokedOnConsentScreen_TokenLosesTheScope is the second fact.
//
// The revocation happens AFTER the consent POST and before /auth/issue is loaded, and that is
// deliberate rather than incidental: a revocation before the POST is caught by the filter on the
// consent submission, so putting it there would leave this check a no-op and the case would pass
// with the gate at /auth/issue removed.
func TestPermissionRevokedOnConsentScreen_TokenLosesTheScope(t *testing.T) {
	resource := createResource(t)
	readPermission := createPermission(t, resource.Id)
	writePermission := createPermission(t, resource.Id)

	readScope := resource.ResourceIdentifier + ":" + readPermission.PermissionIdentifier
	writeScope := resource.ResourceIdentifier + ":" + writePermission.PermissionIdentifier

	clientSecret := gofakeit.LetterN(32)
	parked := parkOnConsentScreen(t, "openid profile "+readScope+" "+writeScope,
		clientSecret, "code-verifier", []string{readScope, writeScope})
	defer func() { _ = parked.consentPage.Body.Close() }()

	resp := postConsent(t, parked.httpClient, parked.consentURL, parked.consentPage, []int{0, 1, 2, 3, 4})
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/issue")

	// The window: the consent is recorded, the ceremony is one hop from a code, and the
	// administrator takes the write permission away.
	permissions, err := database.GetUserPermissionsByUserId(nil, parked.user.Id)
	assert.NoError(t, err)
	revoked := false
	for _, permission := range permissions {
		if permission.PermissionId == writePermission.Id {
			err = database.DeleteUserPermission(nil, permission.Id)
			assert.NoError(t, err)
			revoked = true
		}
	}
	assert.True(t, revoked, "the write permission must have been granted before it can be revoked")

	resp = loadPage(t, parked.httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// A narrowed grant is issued rather than refused, which is RFC 6749 section 3.3 and what
	// /auth/completed's own filter does with the same removal seconds earlier.
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, parked.state, stateVal)

	data := postToTokenEndpoint(t, parked.httpClient, config.GetAuthServer().BaseURL+"/auth/token/",
		url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {codeVal},
			"redirect_uri":  {parked.redirectURI.URI},
			"code_verifier": {"code-verifier"},
			"client_id":     {parked.client.ClientIdentifier},
			"client_secret": {clientSecret},
		})

	assert.NotNil(t, data["access_token"], "the narrowed grant is still a grant: %v", data)
	grantedScope, _ := data["scope"].(string)
	assert.Contains(t, grantedScope, readScope,
		"the permission the user still holds must survive the re-filter")
	assert.NotContains(t, grantedScope, writeScope,
		"a permission revoked while the consent screen was open must not reach the client")

	// The consent RECORD still names it, and that is not a defect. The user held the permission
	// when they ticked the box, so the record is a true account of what they agreed to; it grants
	// nothing on its own, because every reader pairs it with a live permission check. The filter
	// on the consent submission has a different window, which its own case covers.
	consent, err := database.GetConsentByUserIdAndClientId(nil, parked.user.Id, parked.client.Id)
	assert.NoError(t, err)
	assert.NotNil(t, consent)
	assert.Contains(t, consent.Scope, writeScope,
		"a consent given while the user held the permission is recorded as given")
}

// TestRedirectURIDeletedOnConsentScreen_NothingIsDelivered is the third fact, and the one whose
// refusal reaches the client with nothing at all.
//
// The destination is exactly what this server may no longer navigate a browser to, so an error
// redirect would be as wrong as a code (RFC 9700 section 4.11.2). The refusal is therefore
// rendered locally, on the page the error emitter already withholds a redirect through.
func TestRedirectURIDeletedOnConsentScreen_NothingIsDelivered(t *testing.T) {
	parked := parkOnConsentScreen(t, "openid profile email", gofakeit.LetterN(32), "code-verifier", nil)
	defer func() { _ = parked.consentPage.Body.Close() }()

	resp := postConsent(t, parked.httpClient, parked.consentURL, parked.consentPage, []int{0, 1, 2, 3, 4})
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/issue")

	// The window: the administrator removes the callback while the ceremony is one hop from a
	// code. Nothing else about the client changes, so it is still enabled, still administrator
	// registered, and its stored redirect URI is still an absolute URI naming a host, which is
	// what makes the registration check the only thing that can refuse this.
	err := database.DeleteRedirectURI(nil, parked.redirectURI.Id)
	assert.NoError(t, err)

	resp = loadPage(t, parked.httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"the refusal is rendered, not redirected")
	assert.Empty(t, resp.Header.Get("Location"),
		"a withheld redirect must never become a Location")

	document := parseHTMLResponse(t, resp)
	page := document.Text()
	assert.Contains(t, page, "You have not been sent anywhere")

	deletedHost, err := url.Parse(parked.redirectURI.URI)
	assert.NoError(t, err)
	assert.Contains(t, page, deletedHost.Host,
		"the page names the destination the request was stopped from reaching")

	// The refusal also has to leave the browser with no ceremony to replay, and only a second
	// request can see that. Clearing the auth context persists through a Set-Cookie, so it
	// reaches this jar only if the handler cleared before committing the response; clearing
	// afterwards would render the page again here, from a context still reading
	// ready_to_issue_code. With the context gone the handler has nothing to resume and sends the
	// browser to the account profile instead.
	resp = loadPage(t, parked.httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	replayLocation := resp.Header.Get("Location")
	assert.Contains(t, replayLocation, "/account/profile",
		"the refusal must clear the auth context in the browser, so a replayed /auth/issue has no ceremony left")
	assert.NotContains(t, replayLocation, parked.redirectURI.URI,
		"a cleared ceremony must not reach the deregistered callback on a replay either")
}

// TestRedirectURIDeletedOnConsentScreen_CancelIsNotDeliveredEither is the same deletion answered by
// a different door, and it is the one #241 decision 11 was raised about.
//
// The case above lets the ceremony reach /auth/issue, where the gate refuses. This one never gets
// there: the user clicks Cancel, and HandleConsentPost answers access_denied through
// redirToClientWithError, the emitter six ceremony refusals share. Its gates weighed where the
// redirect URI came from and whether the string names a host, both of which this client still
// passes, so before the registration gate it answered
// 302 Location: <deleted callback>?error=access_denied and navigated the browser to a host the
// operator had just disowned. That is RFC 9700 section 4.11.2's harm, and an error response
// carries it as surely as a code does.
//
// The two cases together are the property: whatever a ceremony in progress has to say to a client,
// it says nothing at all to a callback the client no longer has.
func TestRedirectURIDeletedOnConsentScreen_CancelIsNotDeliveredEither(t *testing.T) {
	parked := parkOnConsentScreen(t, "openid profile email", gofakeit.LetterN(32), "code-verifier", nil)
	defer func() { _ = parked.consentPage.Body.Close() }()

	// The window opens before the submission here rather than after it, because this refusal is
	// answered by the consent handler itself and never reaches another hop.
	err := database.DeleteRedirectURI(nil, parked.redirectURI.Id)
	assert.NoError(t, err)

	// No consent indices is a Cancel, per postConsent.
	resp := postConsent(t, parked.httpClient, parked.consentURL, parked.consentPage, []int{})
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"the refusal is rendered, not redirected")
	assert.Empty(t, resp.Header.Get("Location"),
		"a withheld redirect must never become a Location")

	document := parseHTMLResponse(t, resp)
	page := document.Text()
	assert.Contains(t, page, "You have not been sent anywhere")
	assert.NotContains(t, page, "error=access_denied",
		"the refusal must not carry the error response it replaced")

	deletedHost, err := url.Parse(parked.redirectURI.URI)
	assert.NoError(t, err)
	assert.Contains(t, page, deletedHost.Host,
		"the page names the destination the request was stopped from reaching")
}

// TestPermissionRevokedBeforeConsentSubmission_ConsentRecordNeverHasIt is the other side of the
// window TestPermissionRevokedOnConsentScreen_TokenLosesTheScope covers, and the two are
// deliberately not the same test twice.
//
// There the revocation lands AFTER the consent POST, so the user still held the permission when
// they ticked the box and the consent record is a true account of what they agreed to. Here it
// lands BEFORE, while the browser is parked on a screen that was rendered from the permissions
// they had a moment ago. The tick is still submitted, because the checkbox is on a page the
// revocation cannot reach, and the filter on the submission is the only thing between it and a
// stored grant.
//
// The record grants nothing on its own, since every reader pairs it with a live permission check.
// What it does is suppress the consent screen on later ceremonies, so a row naming a permission
// the user did not hold would let a permission granted back months later ride in on a tick made
// when it was gone (#241 decision 3).
func TestPermissionRevokedBeforeConsentSubmission_ConsentRecordNeverHasIt(t *testing.T) {
	resource := createResource(t)
	readPermission := createPermission(t, resource.Id)
	writePermission := createPermission(t, resource.Id)

	readScope := resource.ResourceIdentifier + ":" + readPermission.PermissionIdentifier
	writeScope := resource.ResourceIdentifier + ":" + writePermission.PermissionIdentifier

	clientSecret := gofakeit.LetterN(32)
	parked := parkOnConsentScreen(t, "openid profile "+readScope+" "+writeScope,
		clientSecret, "code-verifier", []string{readScope, writeScope})
	defer func() { _ = parked.consentPage.Body.Close() }()

	// The window: the consent screen is rendered and on it, with both boxes offered, and the
	// administrator takes the write permission away before the user clicks Submit.
	permissions, err := database.GetUserPermissionsByUserId(nil, parked.user.Id)
	assert.NoError(t, err)
	revoked := false
	for _, permission := range permissions {
		if permission.PermissionId == writePermission.Id {
			err = database.DeleteUserPermission(nil, permission.Id)
			assert.NoError(t, err)
			revoked = true
		}
	}
	assert.True(t, revoked, "the write permission must have been granted before it can be revoked")

	// Every box, the revoked one included: the page was built before the revocation and the
	// browser has no way to know.
	resp := postConsent(t, parked.httpClient, parked.consentURL, parked.consentPage, []int{0, 1, 2, 3})
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, parked.httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, parked.state, stateVal)

	data := postToTokenEndpoint(t, parked.httpClient, config.GetAuthServer().BaseURL+"/auth/token/",
		url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {codeVal},
			"redirect_uri":  {parked.redirectURI.URI},
			"code_verifier": {"code-verifier"},
			"client_id":     {parked.client.ClientIdentifier},
			"client_secret": {clientSecret},
		})

	assert.NotNil(t, data["access_token"], "the narrowed grant is still a grant: %v", data)
	grantedScope, _ := data["scope"].(string)
	assert.Contains(t, grantedScope, readScope,
		"the permission the user still holds must survive the filter")
	assert.NotContains(t, grantedScope, writeScope,
		"a permission revoked before the consent submission must not reach the client")

	// The half this case exists for, and the half its sibling asserts the opposite of.
	consent, err := database.GetConsentByUserIdAndClientId(nil, parked.user.Id, parked.client.Id)
	assert.NoError(t, err)
	assert.NotNil(t, consent)
	assert.Contains(t, consent.Scope, readScope)
	assert.NotContains(t, consent.Scope, writeScope,
		"a tick on a permission the user had already lost must not be recorded as a consent")
}
