package integrationtests

import (
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The browser session, observed from the browser's side.
//
// Everything here works from the cookie jar of a real ceremony and never looks at a
// browser_sessions row. Storage is the data tier's to own; what these cases are for is the
// three things a user or an attacker could notice, and each of them is a property #266
// exists to establish rather than one it inherits.

// TestBrowserSession_CostsExactlyOneSmallCookie is the issue's own acceptance test, in as
// many words: "a session that costs more than one cookie should be a failing test".
//
// Before this change an ordinary ceremony cost two to three cookies and about 2.6 KB of
// Cookie: header, an admin console session with large tokens 6 cookies and 17 KB, and the
// store advertised a ceiling of fifty cookies and ~190 KB that nothing enforced. That is
// what made four documentation pages tell operators to enlarge their proxy buffers. The
// size is now a function of nothing a deployment can configure, and this is the case that
// keeps it that way.
func TestBrowserSession_CostsExactlyOneSmallCookie(t *testing.T) {
	httpClient, _, _, _ := createSessionWithAcrLevel1(t)

	cookies := browserCookies(t, httpClient)
	require.Len(t, cookies, 1, "a signed-in browser must hold exactly one Goiabada cookie")
	assert.Equal(t, browserSessionCookieName(), cookies[0].Name)

	// What the browser puts in its single Cookie: header on the next request, counted the
	// way RFC 6265 section 4.2.1 has it serialised: name, "=", value, and "; " between
	// pairs. One cookie so there is one pair, and the measurement stays comparable with
	// the figures in the issue.
	wireBytes := len(cookies[0].Name) + 1 + len(cookies[0].Value) + 2
	assert.Less(t, wireBytes, 300,
		"the identifier is a fixed 64 hex characters, so this cannot grow with anything a "+
			"deployment configures; if it has, something other than an identifier is in the cookie")
}

// TestBrowserSession_IdentifierRotatesAtSignIn is the property that makes a server-side
// session store safe, and it is the one property a cookie store gave for free.
//
// A cookie store is structurally immune to session fixation because the cookie IS the
// state: an attacker's planted copy stays the attacker's own stale state and never becomes
// the victim's session. A row is not immune. If an attacker can plant a signed identifier
// in the victim's browser, then without rotation the victim's sign-in writes the victim's
// user session into the row that identifier names, and the attacker is signed in as the
// victim.
//
// Two assertions, because the second is the one an attacker cares about. The identifier
// changes across the ceremony; and a browser presenting the pre-authentication identifier
// afterwards is not signed in, which is that change having actually invalidated the old
// handle rather than merely issued a new one beside it.
func TestBrowserSession_IdentifierRotatesAtSignIn(t *testing.T) {
	client, redirectUri, user, password := newLevel1Actors(t)

	httpClient := createHttpClient(t)

	resp := beginAuthorize(t, httpClient, client, redirectUri)
	defer func() { _ = resp.Body.Close() }()

	// The ceremony saves its auth context before anything is verified, so there is a
	// browser session here already and it is the one an attacker would have planted.
	beforeCookie := requireSessionCookie(t, httpClient)
	beforeId := decodeSessionIdentifier(t, beforeCookie)

	completeLevel1(t, httpClient, resp, user.Email, password)

	afterId := decodeSessionIdentifier(t, requireSessionCookie(t, httpClient))
	assert.NotEqual(t, beforeId, afterId,
		"the identifier that existed before authentication must not name the session "+
			"authentication produced")

	assertIdentifierIsNotSignedIn(t, beforeCookie, client, redirectUri)
}

// TestBrowserSession_IdentifierRotatesAtStepUp covers the second privilege transition.
//
// Reaching it means fixation already failed, so this is not fixation defence. What it buys
// is that an identifier stolen while a session was at level 1 stops working the moment that
// session reaches level 2, which is OWASP's "regenerate on any privilege level change" read
// literally, and this server's ACR levels are privilege levels by construction.
//
// It also pins the ordering. BumpUserSession commits its own transaction before it returns,
// so a rotation attempted after it would leave a window in which the level 1 identifier
// names a session that is already level 2. The handler decides from the pre-bump session
// and rotates first.
func TestBrowserSession_IdentifierRotatesAtStepUp(t *testing.T) {
	level1Client, level1RedirectUri, user, password := newLevel1Actors(t)

	// The same person, with an authenticator already enrolled, so the second ceremony is a
	// step-up on the session the first one created rather than a fresh sign-in.
	otpKey, err := totp.Generate(totp.GenerateOpts{Issuer: "Goiabada", AccountName: user.Email})
	require.NoError(t, err)
	user.OTPSecret = otpKey.Secret()
	user.OTPSecretEncrypted = encryptOTPSecretForTest(t, otpKey.Secret())
	user.OTPEnabled = true
	require.NoError(t, database.UpdateUser(nil, user))

	httpClient := createHttpClient(t)

	resp := beginAuthorize(t, httpClient, level1Client, level1RedirectUri)
	defer func() { _ = resp.Body.Close() }()
	completeLevel1(t, httpClient, resp, user.Email, password)

	level1Cookie := requireSessionCookie(t, httpClient)
	level1Id := decodeSessionIdentifier(t, level1Cookie)

	// A second client, wanting level 2 from the same browser.
	level2Client, level2RedirectUri := newClientAndRedirectUri(t, enums.AcrLevel2Mandatory)

	resp = beginAuthorize(t, httpClient, level2Client, level2RedirectUri)
	defer func() { _ = resp.Body.Close() }()

	// The browser arrives with a valid session, so /auth/authorize skips the password entry
	// entirely and goes straight to /auth/level1completed, which is where the step-up to
	// level 2 is decided.
	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	otpCode, err := totp.GenerateCode(user.OTPSecret, time.Now())
	require.NoError(t, err)
	resp = authenticateWithOtp(t, httpClient, redirectLocation, resp, otpCode)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	assertRedirect(t, resp, "/auth/issue")

	steppedUpId := decodeSessionIdentifier(t, requireSessionCookie(t, httpClient))
	assert.NotEqual(t, level1Id, steppedUpId,
		"stepping a session up to level 2 must replace the identifier it was reachable by at level 1")

	assertIdentifierIsNotSignedIn(t, level1Cookie, level1Client, level1RedirectUri)
}

// TestBrowserSession_LogoutLeavesNoUsableSession is OWASP's "the web application must take
// active actions to invalidate the session on both sides".
//
// Emptying the values and saving was enough while the session WAS the cookie. Against a
// server-side store it would write an empty blob into a row that stays alive and stays
// reachable by the identifier the browser still holds, so logout has to delete the row.
// Observed the only way a user could: sign in, log out, ask to authorize again, and be
// asked for the password.
func TestBrowserSession_LogoutLeavesNoUsableSession(t *testing.T) {
	httpClient, client, redirectUri, _ := createSessionWithAcrLevel1(t)

	// The GET renders the consent page, because RP-Initiated Logout 1.0 section 2 makes the
	// OP ask when no id_token_hint was supplied. The confirming POST is the logout, and it
	// carries no fields: this browser asked for nothing to be redirected to.
	resp := loadPage(t, httpClient, config.GetAuthServer().BaseURL+logoutPath)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp = confirmLogout(t, httpClient)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp = beginAuthorize(t, httpClient, client, redirectUri)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	assertRedirect(t, resp, "/auth/pwd")
}

// --- helpers -----------------------------------------------------------------------

// logoutPath is the RP-initiated logout endpoint, which serves the consent page on GET and
// performs the logout on POST.
const logoutPath = "/auth/logout"

// confirmLogout submits the consent page's form: a hintless POST, which doLogout treats as
// the End-User answering yes.
func confirmLogout(t *testing.T, httpClient *http.Client) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost,
		config.GetAuthServer().BaseURL+logoutPath, strings.NewReader(""))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	return resp
}

// browserSessionCookieName is what the browser calls the cookie, which is not what the
// application calls it: the __Host- prefix is added whenever cookies are Secure, and a
// browser rejects the prefixed form over plain http. Derived from the same config value the
// store derives it from, so this test reads correctly in either kind of deployment.
func browserSessionCookieName() string {
	if config.GetAuthServer().IsCookieSecure() {
		return "__Host-" + constants.AuthServerSessionName
	}
	return constants.AuthServerSessionName
}

func browserCookies(t *testing.T, httpClient *http.Client) []*http.Cookie {
	t.Helper()
	baseURL, err := url.Parse(config.GetAuthServer().BaseURL)
	require.NoError(t, err)
	return httpClient.Jar.Cookies(baseURL)
}

func requireSessionCookie(t *testing.T, httpClient *http.Client) *http.Cookie {
	t.Helper()
	for _, cookie := range browserCookies(t, httpClient) {
		if cookie.Name == browserSessionCookieName() {
			return cookie
		}
	}
	t.Fatalf("the browser holds no %v cookie", browserSessionCookieName())
	return nil
}

// decodeSessionIdentifier reads the identifier out of the cookie with the deployment's own
// session keys.
//
// Comparing raw cookie values would prove nothing: securecookie stamps every encoding with
// a timestamp, so the value changes on every save whether the identifier did or not, and a
// test asserting the value moved would pass with rotation deleted entirely.
func decodeSessionIdentifier(t *testing.T, cookie *http.Cookie) string {
	t.Helper()

	authKey, err := hex.DecodeString(config.GetAuthServer().SessionAuthenticationKey)
	require.NoError(t, err)
	encKey, err := hex.DecodeString(config.GetAuthServer().SessionEncryptionKey)
	require.NoError(t, err)

	var id string
	require.NoError(t, securecookie.DecodeMulti(constants.AuthServerSessionName, cookie.Value,
		&id, securecookie.CodecsFromPairs(authKey, encKey)...))
	assert.Len(t, id, 64, "the identifier is 32 bytes of CSPRNG output, hex encoded")
	return id
}

// assertIdentifierIsNotSignedIn presents an old cookie from a browser that has nothing else
// and checks the server does not treat it as a session. This is the assertion that says a
// rotation invalidated the old handle rather than issuing a new one beside it.
func assertIdentifierIsNotSignedIn(t *testing.T, cookie *http.Cookie,
	client *models.Client, redirectUri *models.RedirectURI) {
	t.Helper()

	replay := createHttpClient(t)
	baseURL, err := url.Parse(config.GetAuthServer().BaseURL)
	require.NoError(t, err)
	replay.Jar.SetCookies(baseURL, []*http.Cookie{cookie})

	resp := beginAuthorize(t, replay, client, redirectUri)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, replay, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	assertRedirect(t, resp, "/auth/pwd")
}

// newLevel1Actors is the cast of a plain password ceremony: a client that wants level 1, a
// redirect URI, and a user with a known password.
func newLevel1Actors(t *testing.T) (*models.Client, *models.RedirectURI, *models.User, string) {
	t.Helper()

	client, redirectUri := newClientAndRedirectUri(t, enums.AcrLevel1)

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	require.NoError(t, err)

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}
	require.NoError(t, database.CreateUser(nil, user))

	return client, redirectUri, user, password
}

func newClientAndRedirectUri(t *testing.T, acrLevel enums.AcrLevel) (*models.Client, *models.RedirectURI) {
	t.Helper()

	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultAcrLevel:          acrLevel,
	}
	require.NoError(t, database.CreateClient(nil, client))

	redirectUri := &models.RedirectURI{ClientId: client.Id, URI: gofakeit.URL()}
	require.NoError(t, database.CreateRedirectURI(nil, redirectUri))

	return client, redirectUri
}

func beginAuthorize(t *testing.T, httpClient *http.Client,
	client *models.Client, redirectUri *models.RedirectURI) *http.Response {
	t.Helper()

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + gofakeit.LetterN(43) +
		"&scope=" + url.QueryEscape("openid profile email") +
		"&state=" + gofakeit.LetterN(8) +
		"&nonce=" + gofakeit.LetterN(8)

	resp, err := httpClient.Get(destUrl)
	require.NoError(t, err)
	return resp
}

// completeLevel1 walks the password half of the ceremony and stops at /auth/issue, which is
// where the browser session has finished being written.
func completeLevel1(t *testing.T, httpClient *http.Client, authorizeResp *http.Response,
	email string, password string) {
	t.Helper()

	redirectLocation := assertRedirect(t, authorizeResp, "/auth/level1")
	resp := loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, email, password)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	assertRedirect(t, resp, "/auth/issue")
}
