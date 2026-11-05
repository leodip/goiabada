package integration

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Sign-outs, a sign-in's removal of the user's other sessions, and a reused authorization code, as
// an app sees them at its back-channel logout URI (#784 decisions 1 and 2). Each case signs a real
// browser in through the fixture's client, whose URI points at a receiver, and ends the session
// through the endpoint that ends it.

// quietPeriod is how long a case waits before it says nothing arrived: a delivery's first attempt
// starts at once, so one that was going to come has come by then.
const quietPeriod = 2 * time.Second

// tellFixtureClient points the fixture's client, a confidential one an administrator created, at a
// new receiver answering 200.
func tellFixtureClient(t *testing.T, f *deviceFixture) *logoutReceiver {
	t.Helper()
	rc := newLogoutReceiver(t, http.StatusOK)
	require.NoError(t, database.SetClientBackchannelLogout(context.Background(), nil, f.client.Id, rc.uri(), false))
	return rc
}

// A sign-out with a confirmed id_token_hint ends the app's part of the session, and that app is told
// with a token naming the user and the session. Another app on the same session keeps its part and
// is told nothing (#784 decision 2).
func TestBackchannelLogout_AHintedSignOutTellsOnlyTheAppThatSignedOut(t *testing.T) {
	f := newDeviceFixture(t)
	signedOut := tellFixtureClient(t, f)
	browser := newDeviceBrowser(t)
	tokens := f.signInForTokens(t, browser)
	sessions := f.storedSessions(t)
	require.Len(t, sessions, 1)
	other := newLogoutReceiver(t, http.StatusOK)
	onSession(t, &sessions[0], backchannelClient(t, f.adminToken, other.uri()))

	idToken, ok := tokens["id_token"].(string)
	require.True(t, ok, "the sign-in yields an id token: %v", tokens)
	resp := loadPage(t, browser.Client, appConfig.AuthServer.BaseURL+"/auth/logout?id_token_hint="+url.QueryEscape(idToken))
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "the hint is confirmed and the signed-out page answers")

	posts := signedOut.waitFor(t, 1, 10*time.Second)
	require.Len(t, posts, 1)
	assertLogoutToken(t, posts[0], f.client.ClientIdentifier, f.user.Subject, sessions[0].SessionIdentifier)

	time.Sleep(quietPeriod)
	assert.Empty(t, other.received(), "the other app's part of the session did not end")
	assert.Len(t, f.storedSessions(t), 1, "the session stays for the other app")
	assert.Len(t, signedOut.received(), 1)
}

// A hinted sign-out by the last app on the session ends the session too, and that app is the only
// one told.
func TestBackchannelLogout_AHintedSignOutByTheLastAppTellsIt(t *testing.T) {
	f := newDeviceFixture(t)
	rc := tellFixtureClient(t, f)
	browser := newDeviceBrowser(t)
	tokens := f.signInForTokens(t, browser)
	sessions := f.storedSessions(t)
	require.Len(t, sessions, 1)

	idToken, ok := tokens["id_token"].(string)
	require.True(t, ok, "the sign-in yields an id token: %v", tokens)
	resp := loadPage(t, browser.Client, appConfig.AuthServer.BaseURL+"/auth/logout?id_token_hint="+url.QueryEscape(idToken))
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	posts := rc.waitFor(t, 1, 10*time.Second)
	assertLogoutToken(t, posts[0], f.client.ClientIdentifier, f.user.Subject, sessions[0].SessionIdentifier)
	assert.Empty(t, f.storedSessions(t), "the session ended with its last app")
	time.Sleep(quietPeriod)
	assert.Len(t, rc.received(), 1)
}

// A sign-out with no id_token_hint ends the whole session, and every app on it with a back-channel
// logout URI is told (#784 decisions 1 and 2).
func TestBackchannelLogout_AHintlessSignOutTellsEveryAppOnTheSession(t *testing.T) {
	f := newDeviceFixture(t)
	first := tellFixtureClient(t, f)
	browser := newDeviceBrowser(t)
	f.signIn(t, browser)
	sessions := f.storedSessions(t)
	require.Len(t, sessions, 1)
	second := newLogoutReceiver(t, http.StatusOK)
	secondClient := backchannelClient(t, f.adminToken, second.uri())
	onSession(t, &sessions[0], secondClient)

	resp := logoutThroughConsentPage(t, browser.Client, nil)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	posts := first.waitFor(t, 1, 10*time.Second)
	require.Len(t, posts, 1)
	assertLogoutToken(t, posts[0], f.client.ClientIdentifier, f.user.Subject, sessions[0].SessionIdentifier)
	posts = second.waitFor(t, 1, 10*time.Second)
	require.Len(t, posts, 1)
	assertLogoutToken(t, posts[0], secondClient.ClientIdentifier, f.user.Subject, sessions[0].SessionIdentifier)
	assert.Empty(t, f.storedSessions(t), "the whole session ended")
}

// A sign-out with no id_token_hint of a session already past its idle timeout or maximum lifetime
// still removes it, and tells nobody (#784 decision 1).
func TestBackchannelLogout_AHintlessSignOutOfAnExpiredSessionTellsNobody(t *testing.T) {
	for _, dead := range deadSessionCases(t) {
		t.Run(dead.name, func(t *testing.T) {
			f := newDeviceFixture(t)
			rc := tellFixtureClient(t, f)
			browser := newDeviceBrowser(t)
			f.signIn(t, browser)
			sessions := f.storedSessions(t)
			require.Len(t, sessions, 1)
			sessions[0].Started = dead.started
			sessions[0].LastAccessed = dead.lastAccessed
			require.NoError(t, database.UpdateUserSession(context.Background(), nil, &sessions[0]))

			resp := logoutThroughConsentPage(t, browser.Client, nil)
			_ = resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)

			assert.Empty(t, f.storedSessions(t), "the sign-out removed the expired session")
			time.Sleep(quietPeriod)
			assert.Empty(t, rc.received())
		})
	}
}

// A browser signing in again on the same device ends the user's earlier session there, which is
// still valid, and its app is told that session ended (#784 decision 1, same_device).
func TestBackchannelLogout_ASignInOnTheSameDeviceTellsTheEarlierSessionsApps(t *testing.T) {
	f := newDeviceFixture(t)
	rc := tellFixtureClient(t, f)
	before := newDeviceBrowser(t)
	f.signIn(t, before)
	device := theDeviceCookieSet(t, before).cookie.Value
	earlier := f.storedSessions(t)
	require.Len(t, earlier, 1)

	// The same browser with its session cookie gone: a jar holding the device cookie alone.
	after := newDeviceBrowser(t)
	baseURL, err := url.Parse(appConfig.AuthServer.BaseURL)
	require.NoError(t, err)
	after.Jar.SetCookies(baseURL, []*http.Cookie{{
		Name: deviceCookieName(), Value: device, Path: "/", Secure: appConfig.AuthServer.IsCookieSecure(),
	}})
	f.signIn(t, after)

	posts := rc.waitFor(t, 1, 10*time.Second)
	require.Len(t, posts, 1)
	assertLogoutToken(t, posts[0], f.client.ClientIdentifier, f.user.Subject, earlier[0].SessionIdentifier)
	time.Sleep(quietPeriod)
	assert.Len(t, rc.received(), 1, "the new session's app is told nothing about the new session")
}

// A sign-in over the per-user cap ends the least recently used session, still valid, and its app is
// told (#784 decision 1, session_cap).
func TestBackchannelLogout_ASignInOverTheCapTellsTheEndedSessionsApps(t *testing.T) {
	f := newDeviceFixture(t)
	withSessionCap(t, 2)
	rc := tellFixtureClient(t, f)

	f.signIn(t, newDeviceBrowser(t))
	first := f.storedSessions(t)
	require.Len(t, first, 1)
	f.signIn(t, newDeviceBrowser(t))
	f.signIn(t, newDeviceBrowser(t))

	posts := rc.waitFor(t, 1, 10*time.Second)
	require.Len(t, posts, 1)
	assertLogoutToken(t, posts[0], f.client.ClientIdentifier, f.user.Subject, first[0].SessionIdentifier)
	time.Sleep(quietPeriod)
	assert.Len(t, rc.received(), 1)
}

// A sign-in over the cap that ends an expired session tells nobody (#784 decision 1).
func TestBackchannelLogout_ASignInOverTheCapEndingAnExpiredSessionTellsNobody(t *testing.T) {
	f := newDeviceFixture(t)
	settings := withSessionCap(t, 2)
	rc := tellFixtureClient(t, f)

	f.signIn(t, newDeviceBrowser(t))
	f.signIn(t, newDeviceBrowser(t))
	sessions := f.storedSessions(t)
	require.Len(t, sessions, 2)
	expired := sessions[0]
	expired.Started = time.Now().UTC().Add(-time.Duration(settings.UserSessionMaxLifetimeInSeconds+3600) * time.Second)
	require.NoError(t, database.UpdateUserSession(context.Background(), nil, &expired))

	f.signIn(t, newDeviceBrowser(t))

	assert.NotContains(t, storedSessionIds(f.storedSessions(t)), expired.Id, "the expired session is the one ended")
	time.Sleep(quietPeriod)
	assert.Empty(t, rc.received())
}

// An authorization code redeemed twice ends the session it was issued through, and the session's app
// is told (#784 decision 1).
func TestBackchannelLogout_AReusedCodeTellsTheSessionsApps(t *testing.T) {
	f := newDeviceFixture(t)
	rc := tellFixtureClient(t, f)
	browser := newDeviceBrowser(t)
	code := signInWithPassword(t, browser.Client,
		f.authorizeURLFor("openid", oauth.GeneratePKCECodeChallenge(testCodeVerifier)), f.user.Email, f.password, false, "")
	require.NotEmpty(t, code)
	sessions := f.storedSessions(t)
	require.Len(t, sessions, 1)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {f.client.ClientIdentifier},
		"client_secret": {f.clientSecret},
		"code":          {code},
		"redirect_uri":  {f.redirectURI.URI},
		"code_verifier": {testCodeVerifier},
	}
	tokenURL := appConfig.AuthServer.BaseURL + "/auth/token/"
	first := postToTokenEndpoint(t, browser.Client, tokenURL, form)
	require.NotEmpty(t, first["refresh_token"], "the first redemption issues a refresh token: %v", first)
	time.Sleep(quietPeriod)
	require.Empty(t, rc.received(), "redeeming the code once ends nothing")

	second := postToTokenEndpoint(t, browser.Client, tokenURL, form)
	require.Equal(t, "invalid_grant", second["error"])

	posts := rc.waitFor(t, 1, 10*time.Second)
	require.Len(t, posts, 1)
	assertLogoutToken(t, posts[0], f.client.ClientIdentifier, f.user.Subject, sessions[0].SessionIdentifier)
	assert.Empty(t, f.storedSessions(t), "the reuse ended the session")
}
