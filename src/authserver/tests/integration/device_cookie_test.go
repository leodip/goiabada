package integration

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The device cookie (#564 decision 4): a sign-in that starts a new session gives the browser an
// identifier of its own, and ends the user's earlier sessions recorded with the same one rather than
// those of every browser sending the same user agent from the same address. This tier is where the
// cookie a browser holds is real, so the whole sign-in is driven here.

// deviceCookieName is the device cookie's name for the deployment under test: the __Host- prefix
// on https, as the session cookie's, and the bare name on plain http.
func deviceCookieName() string {
	if strings.HasPrefix(strings.ToLower(appConfig.AuthServer.BaseURL), "https://") {
		return "__Host-authserver_device"
	}
	return "authserver_device"
}

// sameBrowserUserAgent is the header every browser of these tests sends, so the address and the
// user agent are the same for all of them and only the cookie tells them apart.
const sameBrowserUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// observedDeviceCookie is one Set-Cookie of the device cookie, and the path that answered with it.
type observedDeviceCookie struct {
	path   string
	cookie *http.Cookie
}

// deviceBrowser is a browser of its own, a cookie jar, sending sameBrowserUserAgent and a request
// id the test names on every request, and noting every device cookie the server sets.
type deviceBrowser struct {
	*http.Client
	requestId string
	observed  []observedDeviceCookie
}

type deviceBrowserTransport struct {
	base    http.RoundTripper
	browser *deviceBrowser
}

func (d *deviceBrowserTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", sameBrowserUserAgent)
	req.Header.Set("X-Request-Id", d.browser.requestId)
	resp, err := d.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == deviceCookieName() {
			d.browser.observed = append(d.browser.observed, observedDeviceCookie{path: req.URL.Path, cookie: cookie})
		}
	}
	return resp, nil
}

func newDeviceBrowser(t *testing.T) *deviceBrowser {
	t.Helper()
	browser := &deviceBrowser{Client: createHttpClient(t)}
	browser.Transport = &deviceBrowserTransport{base: browser.Transport, browser: browser}
	return browser
}

// deviceFixture is a user who signs in at a level 1 client that asks no consent, so a sign-in goes
// from the password straight to a code. The client is confidential, so signInForTokens can redeem
// the code.
type deviceFixture struct {
	client       *record.Client
	clientSecret string
	redirectURI  *record.RedirectURI
	user         *record.User
	password     string
	adminToken   string
}

func newDeviceFixture(t *testing.T) *deviceFixture {
	t.Helper()
	requireDatabaseAuditLogs(t)
	adminToken, adminClient := createAdminClientWithToken(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, adminClient.Id) })

	clientSecret := fake.LetterN(32)
	clientSecretEncrypted, err := dataCipher.Encrypt(clientSecret)
	require.NoError(t, err)
	client := &record.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		DefaultAcrLevel:          record.AcrLevel1,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })

	redirectURI := &record.RedirectURI{ClientId: client.Id, URI: fake.URL()}
	require.NoError(t, database.CreateRedirectURI(context.Background(), nil, redirectURI))

	password := fake.Password(10)
	passwordHashed, err := passwordhash.Hash(password)
	require.NoError(t, err)
	user := &record.User{
		Subject:      fake.UUID(),
		Enabled:      true,
		Email:        fake.Email(),
		PasswordHash: passwordHashed,
	}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.Id) })

	return &deviceFixture{client: client, clientSecret: clientSecret, redirectURI: redirectURI, user: user,
		password: password, adminToken: adminToken}
}

func (f *deviceFixture) authorizeURL() string {
	return f.authorizeURLFor("openid", fake.LetterN(43))
}

func (f *deviceFixture) authorizeURLFor(scope, codeChallenge string) string {
	return appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + f.client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(f.redirectURI.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + codeChallenge +
		"&scope=" + url.QueryEscape(scope) +
		"&state=" + fake.LetterN(8) +
		"&nonce=" + fake.LetterN(8)
}

// deviceAccountScope is the scope signInForTokens asks for: an id token to sign out with, and an
// access token the account API accepts.
const deviceAccountScope = "openid " + builtin.AuthServerResourceIdentifier + ":" + builtin.ManageAccountPermissionIdentifier

// signInForTokens signs the user in on browser as signIn does, asking for deviceAccountScope, and
// redeems the code. It grants the user the account permission and the consent to it first, which no
// client but the admin console's obtains without (#509).
func (f *deviceFixture) signInForTokens(t *testing.T, browser *deviceBrowser) map[string]interface{} {
	t.Helper()
	resource, err := database.GetResourceByResourceIdentifier(context.Background(), nil, builtin.AuthServerResourceIdentifier)
	require.NoError(t, err)
	require.NotNil(t, resource)
	perms, err := database.GetPermissionsByResourceId(context.Background(), nil, resource.Id)
	require.NoError(t, err)
	idx := slices.IndexFunc(perms, func(p record.Permission) bool {
		return p.PermissionIdentifier == builtin.ManageAccountPermissionIdentifier
	})
	require.GreaterOrEqual(t, idx, 0, "the account permission is seeded")
	assignPermissionToUser(t, f.user.Id, perms[idx].Id)
	require.NoError(t, database.CreateUserConsent(context.Background(), nil, &record.UserConsent{
		UserId: f.user.Id, ClientId: f.client.Id, Scope: deviceAccountScope,
		GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}))

	browser.requestId = "device-" + fake.LetterN(16)
	browser.observed = nil
	code := signInWithPassword(t, browser.Client,
		f.authorizeURLFor(deviceAccountScope, oauth.GeneratePKCECodeChallenge(testCodeVerifier)),
		f.user.Email, f.password, false, "")
	require.NotEmpty(t, code, "the sign-in reaches the client with a code")
	return postToTokenEndpoint(t, browser.Client, appConfig.AuthServer.BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {f.client.ClientIdentifier},
		"client_secret": {f.clientSecret},
		"code":          {code},
		"redirect_uri":  {f.redirectURI.URI},
		"code_verifier": {testCodeVerifier},
	})
}

// signIn signs the user in on browser with the password, under a request id of its own, and
// returns that id, so the audit rows this sign-in left can be read back by it.
func (f *deviceFixture) signIn(t *testing.T, browser *deviceBrowser) string {
	t.Helper()
	browser.requestId = "device-" + fake.LetterN(16)
	browser.observed = nil
	code := signInWithPassword(t, browser.Client, f.authorizeURL(), f.user.Email, f.password, false, "")
	require.NotEmpty(t, code, "the sign-in reaches the client with a code")
	return browser.requestId
}

// storedSessions is the user's sessions as the database holds them, device identifiers included,
// which the APIs never return.
func (f *deviceFixture) storedSessions(t *testing.T) []record.UserSession {
	t.Helper()
	sessions, err := database.GetUserSessionsByUserId(context.Background(), nil, f.user.Id)
	require.NoError(t, err)
	return sessions
}

// theDeviceCookieSet is the one device cookie the browser was given since its last sign-in began.
func theDeviceCookieSet(t *testing.T, browser *deviceBrowser) observedDeviceCookie {
	t.Helper()
	require.Len(t, browser.observed, 1, "a sign-in that starts a session sets the device cookie once")
	return browser.observed[0]
}

func sha256OfDevice(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// A sign-in that starts a session sets the device cookie on /auth/completed, with the session
// cookie's attributes and 400 days to live, and records its digest, which no API returns. A later
// sign-in that reuses the session writes no cookie.
func TestDeviceCookie_ASignInThatStartsASessionSetsIt(t *testing.T) {
	f := newDeviceFixture(t)
	browser := newDeviceBrowser(t)

	f.signIn(t, browser)

	set := theDeviceCookieSet(t, browser)
	assert.Equal(t, "/auth/completed", set.path, "the session is started there")
	cookie := set.cookie
	assert.Regexp(t, `^[0-9a-f]{64}$`, cookie.Value, "32 random bytes, hex encoded")
	assert.Equal(t, "/", cookie.Path)
	assert.Empty(t, cookie.Domain, "a host-only cookie")
	assert.True(t, cookie.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
	assert.Equal(t, appConfig.AuthServer.IsCookieSecure(), cookie.Secure, "Secure exactly on https")
	assert.Equal(t, 34560000, cookie.MaxAge, "400 days")

	sessions := f.storedSessions(t)
	require.Len(t, sessions, 1)
	assert.Equal(t, sha256OfDevice(cookie.Value), sessions[0].DeviceId, "the session stores the value's SHA-256")

	t.Run("no API returns the identifier or its digest", func(t *testing.T) {
		for _, path := range []string{
			"/api/v1/admin/users/" + strconv.FormatInt(f.user.Id, 10) + "/sessions",
			"/api/v1/admin/user-sessions/" + strconv.FormatInt(sessions[0].Id, 10),
		} {
			resp := makeAPIRequest(t, "GET", appConfig.AuthServer.BaseURL+path, f.adminToken, nil)
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode, path)
			assert.NotContains(t, string(body), cookie.Value, path)
			assert.NotContains(t, string(body), sessions[0].DeviceId, path)
		}
	})

	t.Run("reusing the session writes no device cookie", func(t *testing.T) {
		browser.observed = nil
		location := f.authorizeURL()
		for hop := 0; hop < 6; hop++ {
			resp := loadPage(t, browser.Client, location)
			_ = resp.Body.Close()
			require.Equal(t, http.StatusFound, resp.StatusCode, location)
			location = resp.Header.Get("Location")
			if strings.HasPrefix(location, f.redirectURI.URI) {
				break
			}
			require.True(t, strings.HasPrefix(location, appConfig.AuthServer.BaseURL),
				"the reuse stays on the auth server until it answers the client, at %v", location)
			require.NotContains(t, location, "/auth/pwd", "the session is reused, with no password asked")
		}
		require.True(t, strings.HasPrefix(location, f.redirectURI.URI), "the reuse answers the client")
		assert.Empty(t, browser.observed)
		assert.Len(t, f.storedSessions(t), 1)
	})
}

// Two browsers on one address sending one user agent are two devices: the second sign-in keeps the
// first browser's session, where the user-agent-and-address rule ended it, and removes nothing.
func TestDeviceCookie_TwoBrowsersWithOneUserAgentKeepBothSessions(t *testing.T) {
	f := newDeviceFixture(t)
	first, second := newDeviceBrowser(t), newDeviceBrowser(t)

	f.signIn(t, first)
	requestId := f.signIn(t, second)

	sessions := f.storedSessions(t)
	require.Len(t, sessions, 2, "both browsers stay signed in")
	assert.Equal(t, sessions[0].UserAgent, sessions[1].UserAgent, "the two send the same header")
	assert.Equal(t, sameBrowserUserAgent, sessions[0].UserAgent)
	assert.Equal(t, sessions[0].IpAddress, sessions[1].IpAddress, "from the same address")
	assert.NotEqual(t, sessions[0].DeviceId, sessions[1].DeviceId, "and are two devices")
	assert.NotEqual(t, theDeviceCookieSet(t, second).cookie.Value, deviceCookieIn(t, first.Client).Value,
		"each browser holds an identifier of its own")

	assert.Empty(t, auditRows(t, f.adminToken, "deleted_user_session", requestId), "the second sign-in removed nothing")
	assert.Len(t, sessionsThroughAdminAPI(t, f.adminToken, f.user.Id), 2)
}

// One browser that lost its session cookie but kept its device cookie signs in again: it gets the
// same identifier back with a fresh lifetime, and its earlier session, which no cookie names any
// more, is removed as the same device's.
func TestDeviceCookie_ABrowserThatLostItsSessionCookieReplacesItsOwnSession(t *testing.T) {
	f := newDeviceFixture(t)
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

	requestId := f.signIn(t, after)

	set := theDeviceCookieSet(t, after)
	assert.Equal(t, device, set.cookie.Value, "the browser keeps its identifier")
	assert.Equal(t, 34560000, set.cookie.MaxAge, "with a fresh lifetime")

	sessions := f.storedSessions(t)
	require.Len(t, sessions, 1, "the browser's earlier session is gone")
	assert.NotEqual(t, earlier[0].Id, sessions[0].Id, "and the one left is the new session")
	assert.Equal(t, sha256OfDevice(device), sessions[0].DeviceId)

	assert.Equal(t, []map[string]any{{
		"user_session_id": float64(earlier[0].Id),
		"logged_in_user":  "",
		"reason":          "same_device",
	}}, auditRows(t, f.adminToken, "deleted_user_session", requestId))
}

// Ending a session, by signing out or through either API, leaves the device cookie as it is: it
// names the browser, not the session (#564 decision 4). Every ending answers with no device cookie,
// neither a deletion nor a new value, and the browser's next sign-in gets the same identifier back,
// whose digest the new session stores. The API calls go through the browser's own client, so a
// Set-Cookie on their answers would reach its jar.
func TestDeviceCookie_EndingTheSessionKeepsIt(t *testing.T) {
	endings := []struct {
		name string
		end  func(t *testing.T, f *deviceFixture, browser *deviceBrowser, session record.UserSession, tokens map[string]interface{})
	}{
		{
			name: "signing out with no id_token_hint",
			end: func(t *testing.T, _ *deviceFixture, browser *deviceBrowser, _ record.UserSession, _ map[string]interface{}) {
				resp := logoutThroughConsentPage(t, browser.Client, nil)
				_ = resp.Body.Close()
				require.Equal(t, http.StatusOK, resp.StatusCode)
			},
		},
		{
			name: "signing out with a confirmed id_token_hint",
			end: func(t *testing.T, _ *deviceFixture, browser *deviceBrowser, _ record.UserSession, tokens map[string]interface{}) {
				idToken, ok := tokens["id_token"].(string)
				require.True(t, ok, "the sign-in yields an id token: %v", tokens)
				resp := loadPage(t, browser.Client, appConfig.AuthServer.BaseURL+"/auth/logout?id_token_hint="+url.QueryEscape(idToken))
				_ = resp.Body.Close()
				require.Equal(t, http.StatusOK, resp.StatusCode, "the hint is confirmed and the signed-out page answers")
			},
		},
		{
			name: "the user ending it through the account API",
			end: func(t *testing.T, _ *deviceFixture, browser *deviceBrowser, session record.UserSession, tokens map[string]interface{}) {
				accessToken, ok := tokens["access_token"].(string)
				require.True(t, ok, "the sign-in yields an access token: %v", tokens)
				deleteThroughBrowser(t, browser, appConfig.AuthServer.BaseURL+"/api/v1/account/sessions/"+
					strconv.FormatInt(session.Id, 10), accessToken)
			},
		},
		{
			name: "an administrator ending it through the admin API",
			end: func(t *testing.T, f *deviceFixture, browser *deviceBrowser, session record.UserSession, _ map[string]interface{}) {
				deleteThroughBrowser(t, browser, appConfig.AuthServer.BaseURL+"/api/v1/admin/user-sessions/"+
					strconv.FormatInt(session.Id, 10), f.adminToken)
			},
		},
	}

	for _, ending := range endings {
		t.Run(ending.name, func(t *testing.T) {
			f := newDeviceFixture(t)
			browser := newDeviceBrowser(t)
			tokens := f.signInForTokens(t, browser)
			device := theDeviceCookieSet(t, browser).cookie.Value
			sessions := f.storedSessions(t)
			require.Len(t, sessions, 1)

			browser.observed = nil
			ending.end(t, f, browser, sessions[0], tokens)

			assert.Empty(t, f.storedSessions(t), "the session ended")
			assert.Empty(t, browser.observed, "ending the session sets no device cookie")
			assert.Equal(t, device, deviceCookieIn(t, browser.Client).Value, "the browser keeps its identifier")

			f.signIn(t, browser)
			assert.Equal(t, device, theDeviceCookieSet(t, browser).cookie.Value,
				"the next sign-in gets the same identifier back")
			after := f.storedSessions(t)
			require.Len(t, after, 1)
			assert.NotEqual(t, sessions[0].Id, after[0].Id, "on a new session")
			assert.Equal(t, sha256OfDevice(device), after[0].DeviceId, "which stores its digest")
		})
	}
}

// deleteThroughBrowser sends an API DELETE carrying accessToken from browser, and requires it to
// succeed.
func deleteThroughBrowser(t *testing.T, browser *deviceBrowser, target, accessToken string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, target, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := browser.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, target)
}

// deviceCookieIn is the device cookie httpClient's jar holds.
func deviceCookieIn(t *testing.T, httpClient *http.Client) *http.Cookie {
	t.Helper()
	for _, cookie := range browserCookies(t, httpClient) {
		if cookie.Name == deviceCookieName() {
			return cookie
		}
	}
	t.Fatalf("the browser holds no %v cookie", deviceCookieName())
	return nil
}
