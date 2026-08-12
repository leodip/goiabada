package integrationtests

import (
	"database/sql"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #106 stage 5's integration tests. Thin by design, one case per property: enumerating input
// shapes is what the unit tables in stages 1 to 4 are for. What only these can show is the
// advertised behaviour actually happening against a real database, through the real HTTP surface,
// with real signed tokens.
//
// What only this tier can prove is that the generation claim survives a full round trip: emitted
// as JSON at issuance, parsed back as a float64, read through GetIntClaim and enforced by the
// middleware, against real signed tokens.
//
// What this tier does NOT own, despite the temptation to assert it here: that the `dont-update`
// field tag stops a full-row write from regressing a stored generation. That is a property of the
// SQL the query builder emits, and it belongs to the data tests, which run against all four
// engines. See TestUpdateRefreshToken_DoesNotClobberAuthStateGeneration and its three siblings.
// An earlier version of the rotation test below claimed to cover it and did not: removing the tag
// left that test passing, because rotation loads the parent AFTER the sweep promoted it and so
// writes the promoted value back either way.

// userAgentTransport stamps a User-Agent on every request a client makes, including the ones made
// through helpers that build their own requests.
type userAgentTransport struct {
	base      http.RoundTripper
	userAgent string
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", t.userAgent)
	return t.base.RoundTrip(req)
}

// createHttpClientWithUserAgent is createHttpClient plus a fixed User-Agent, so the server records
// a different device for this client's sessions.
func createHttpClientWithUserAgent(t *testing.T, userAgent string) *http.Client {
	t.Helper()
	client := createHttpClient(t)
	client.Transport = &userAgentTransport{base: client.Transport, userAgent: userAgent}
	return client
}

// offlineGrant is what an offline_access ceremony yields, plus the pieces later steps need.
type offlineGrant struct {
	client       *models.Client
	clientSecret string
	user         *models.User
	password     string
	redirectURI  string
	accessToken  string
	refreshToken string
	// sessionIdentifier is the browser session the ceremony created. An offline refresh token's
	// own session_identifier column is empty, so this comes from the codes row.
	sessionIdentifier string
	// httpClient holds the session cookie, so a second authorize request rides the same session.
	httpClient *http.Client
}

// codeFromSameSession runs a second authorization on the SAME browser session and returns an
// unredeemed code. prompt=none is used deliberately: with a live session and consent already
// recorded it goes straight to /auth/issue, so the assertion does not depend on the exact
// redirect chain of the interactive path.
//
// Call it WITHOUT offline_access to obtain a session-bound grant, which is the only way to get a
// bearer carrying a sid for a user whose other grant is offline. Refreshing the offline family
// with a down-scoped request does NOT work for that: grantIsOffline reads the grant rather than
// the request, so the refreshed access token stays sid-less by design (stage 2, decision 9).
func (g *offlineGrant) codeFromSameSession(t *testing.T, scope string, codeVerifier string) string {
	t.Helper()

	destURL := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + g.client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(g.redirectURI) +
		"&response_type=code&code_challenge_method=S256" +
		"&code_challenge=" + oauth.GeneratePKCECodeChallenge(codeVerifier) +
		"&scope=" + url.QueryEscape(scope) +
		"&state=" + gofakeit.LetterN(8) + "&nonce=" + gofakeit.LetterN(8) +
		"&prompt=none"

	resp, err := g.httpClient.Get(destURL)
	require.NoError(t, err)
	_ = resp.Body.Close()

	location := assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, g.httpClient, location)
	code, _ := getCodeAndStateFromUrl(t, resp)
	_ = resp.Body.Close()
	require.NotEmpty(t, code, "expected a code from the SSO path")
	return code
}

// secondSessionFor logs the SAME user in again through a FRESH cookie jar, producing a second
// browser session, and returns a session-bound access token plus that session's sid.
//
// A separate cookie jar is the whole point: reusing grant.httpClient would SSO onto the existing
// session and prove nothing about a second device. The scope deliberately omits offline_access, so
// the resulting grant is session-bound and its access token carries a sid.
//
// password must be the user's CURRENT password, so call this after any setUserPassword.
func secondSessionFor(t *testing.T, grant *offlineGrant, password string) (string, string) {
	t.Helper()

	// A DISTINCT User-Agent is required, not cosmetic. StartNewUserSession deletes other sessions
	// of the same user that share device name, type, OS and IP address, and two logins from one
	// test process share all four by default: the second login would silently delete the first and
	// the test would then be asserting against a session that no longer existed. Varying the UA
	// makes this a genuinely different device, which is what the case is about.
	httpClient := createHttpClientWithUserAgent(t,
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1")
	const codeVerifier = "code-verifier-second-device"
	scope := "openid " +
		constants.AuthServerResourceIdentifier + ":" + constants.ManageAccountPermissionIdentifier

	destURL := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + grant.client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(grant.redirectURI) +
		"&response_type=code&code_challenge_method=S256" +
		"&code_challenge=" + oauth.GeneratePKCECodeChallenge(codeVerifier) +
		"&scope=" + url.QueryEscape(scope) +
		"&state=" + gofakeit.LetterN(8) + "&nonce=" + gofakeit.LetterN(8)

	resp, err := httpClient.Get(destURL)
	require.NoError(t, err)
	_ = resp.Body.Close()

	location := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, location)
	_ = resp.Body.Close()

	location = assertRedirect(t, resp, "/auth/pwd")
	// The password page is held rather than closed here: the submission reads the ceremony id
	// out of it, and a closed body cannot be read (#79).
	pwdPage := loadPage(t, httpClient, location)

	resp = authenticateWithPassword(t, httpClient, location, pwdPage, grant.user.Email, password)
	_ = pwdPage.Body.Close()
	_ = resp.Body.Close()

	location = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, location)
	_ = resp.Body.Close()

	location = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, location)
	_ = resp.Body.Close()

	location = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, location)
	code, _ := getCodeAndStateFromUrl(t, resp)
	_ = resp.Body.Close()
	require.NotEmpty(t, code)

	data := postToTokenEndpoint(t, httpClient, config.GetAuthServer().BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {grant.client.ClientIdentifier},
		"client_secret": {grant.clientSecret},
		"code":          {code},
		"redirect_uri":  {grant.redirectURI},
		"code_verifier": {codeVerifier},
	})
	accessToken, ok := data["access_token"].(string)
	require.True(t, ok, "expected a session-bound access token: %v", data)

	sid := extractSidClaim(t, accessToken)
	require.NotEmpty(t, sid, "a non-offline grant must carry a sid")
	return accessToken, sid
}

// secondOfflineGrantForSameUser is secondSessionFor with the offline scope: it logs the SAME user in
// again through a fresh cookie jar and returns a second, independent offline grant on the same
// client. Added by #129 stage 4, whose termination cases need a grant that must SURVIVE while
// another session of the same user is ended. Varying only the session is what makes it reject a
// table-wide sweep and a user-scoped one at once.
//
// A DISTINCT User-Agent is required rather than cosmetic, for the reason secondSessionFor states:
// StartNewUserSession deletes other sessions of the same user sharing device name, type, OS and IP
// address, so without it the second login silently deletes the first.
//
// The consent screen is reached unconditionally rather than conditionally, and that is a property of
// the server rather than an assumption: both HandleAuthCompletedGet and HandleConsentGet route an
// offline_access request to consent regardless of what the user already consented to, deliberately,
// to re-confirm the refresh token grant every time.
//
// password must be the user's CURRENT password.
func secondOfflineGrantForSameUser(t *testing.T, base *offlineGrant, password string) *offlineGrant {
	t.Helper()

	httpClient := createHttpClientWithUserAgent(t,
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36")
	const codeVerifier = "code-verifier-second-offline"
	scope := "openid offline_access " +
		constants.AuthServerResourceIdentifier + ":" + constants.ManageAccountPermissionIdentifier

	destURL := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + base.client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(base.redirectURI) +
		"&response_type=code&code_challenge_method=S256" +
		"&code_challenge=" + oauth.GeneratePKCECodeChallenge(codeVerifier) +
		"&scope=" + url.QueryEscape(scope) +
		"&state=" + gofakeit.LetterN(8) + "&nonce=" + gofakeit.LetterN(8)

	resp, err := httpClient.Get(destURL)
	require.NoError(t, err)
	_ = resp.Body.Close()

	location := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, location)
	_ = resp.Body.Close()

	location = assertRedirect(t, resp, "/auth/pwd")
	// The password page is held rather than closed here: the submission reads the ceremony id
	// out of it, and a closed body cannot be read (#79).
	pwdPage := loadPage(t, httpClient, location)

	resp = authenticateWithPassword(t, httpClient, location, pwdPage, base.user.Email, password)
	_ = pwdPage.Body.Close()
	_ = resp.Body.Close()

	location = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, location)
	_ = resp.Body.Close()

	location = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, location)
	_ = resp.Body.Close()

	location = assertRedirect(t, resp, "/auth/consent")
	consentPage := loadPage(t, httpClient, location)

	// Through the shared helper rather than a hand-built body, so the ceremony id comes off the
	// rendered page. A form built by hand here would name no ceremony and be refused (#79).
	resp = postConsent(t, httpClient, location, consentPage, []int{0, 1, 2, 3})
	_ = consentPage.Body.Close()
	_ = resp.Body.Close()

	location = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, location)
	code, _ := getCodeAndStateFromUrl(t, resp)
	_ = resp.Body.Close()
	require.NotEmpty(t, code)

	// The sid comes off the codes row, not the token: an offline refresh token's own
	// session_identifier column is empty.
	codeHash, err := hashutil.HashString(code)
	require.NoError(t, err)
	codeEntity, err := database.GetCodeByCodeHash(nil, codeHash, false)
	require.NoError(t, err)
	require.NotNil(t, codeEntity)
	require.NotEmpty(t, codeEntity.SessionIdentifier)

	data := postToTokenEndpoint(t, httpClient, config.GetAuthServer().BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {base.client.ClientIdentifier},
		"client_secret": {base.clientSecret},
		"code":          {code},
		"redirect_uri":  {base.redirectURI},
		"code_verifier": {codeVerifier},
	})
	accessToken, ok := data["access_token"].(string)
	require.True(t, ok, "expected an access token: %v", data)
	refreshToken, ok := data["refresh_token"].(string)
	require.True(t, ok, "offline_access must yield a refresh token: %v", data)

	return &offlineGrant{
		client:            base.client,
		clientSecret:      base.clientSecret,
		user:              base.user,
		password:          password,
		redirectURI:       base.redirectURI,
		accessToken:       accessToken,
		refreshToken:      refreshToken,
		sessionIdentifier: codeEntity.SessionIdentifier,
		httpClient:        httpClient,
	}
}

// exchange redeems a code for tokens on this grant's client.
func (g *offlineGrant) exchange(t *testing.T, code string, codeVerifier string) map[string]interface{} {
	t.Helper()
	return postToTokenEndpoint(t, g.httpClient, config.GetAuthServer().BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {g.client.ClientIdentifier},
		"client_secret": {g.clientSecret},
		"code":          {code},
		"redirect_uri":  {g.redirectURI},
		"code_verifier": {codeVerifier},
	})
}

// createOfflineGrant runs a complete authorization code ceremony with offline_access, through the
// real login and consent screens, and exchanges the code.
//
// It grants the user authserver:userinfo and authserver:manage-account so the resulting token can
// exercise both /userinfo and the account API, which is where the middleware's generation check
// lives.
func createOfflineGrant(t *testing.T) *offlineGrant {
	t.Helper()

	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	clientSecretEncrypted, err := encryption.EncryptData(clientSecret)
	require.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "revoke-client-" + gofakeit.LetterN(8),
		ClientSecretEncrypted:    clientSecretEncrypted,
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		// offline_access forces the consent screen on its own, so the first ceremony still
		// submits consent. Leaving this false is what lets a LATER request on the same session
		// (one without offline_access) skip consent and SSO straight through, which is how the
		// session-bound bearer below is obtained.
		ConsentRequired:                         false,
		DefaultAcrLevel:                         enums.AcrLevel1,
		TokenExpirationInSeconds:                300,
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 86400,
	}
	require.NoError(t, database.CreateClient(nil, client))

	redirectURI := &models.RedirectURI{ClientId: client.Id, URI: "https://example.com/callback"}
	require.NoError(t, database.CreateRedirectURI(nil, redirectURI))

	password := gofakeit.Password(true, true, true, true, false, 12)
	passwordHashed, err := hashutil.HashPassword(password)
	require.NoError(t, err)

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        strings.ToLower(gofakeit.LetterN(12)) + "@example.com",
		PasswordHash: passwordHashed,
	}
	require.NoError(t, database.CreateUser(nil, user))

	// Only manage-account is granted. authserver:userinfo is deliberately NOT granted and NOT
	// requested: the authorize validator rejects it explicitly, because an OpenID Connect scope
	// causes the server to inject it into the access token itself. That injection is what lets
	// the resulting token call /userinfo below.
	authserverResource, err := database.GetResourceByResourceIdentifier(nil, constants.AuthServerResourceIdentifier)
	require.NoError(t, err)
	permissions, err := database.GetPermissionsByResourceId(nil, authserverResource.Id)
	require.NoError(t, err)
	for i := range permissions {
		if permissions[i].PermissionIdentifier == constants.ManageAccountPermissionIdentifier {
			assignPermissionToUser(t, user.Id, permissions[i].Id)
			break
		}
	}

	scope := "openid offline_access " +
		constants.AuthServerResourceIdentifier + ":" + constants.ManageAccountPermissionIdentifier

	httpClient := createHttpClient(t)
	codeVerifier := "code-verifier"
	codeChallenge := oauth.GeneratePKCECodeChallenge(codeVerifier)

	destURL := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + codeChallenge +
		"&scope=" + url.QueryEscape(scope) +
		"&state=" + gofakeit.LetterN(8) +
		"&nonce=" + gofakeit.LetterN(8)

	resp, err := httpClient.Get(destURL)
	require.NoError(t, err)
	_ = resp.Body.Close()

	location := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, location)
	_ = resp.Body.Close()

	location = assertRedirect(t, resp, "/auth/pwd")
	// The password page is held rather than closed here: the submission reads the ceremony id
	// out of it, and a closed body cannot be read (#79).
	pwdPage := loadPage(t, httpClient, location)

	resp = authenticateWithPassword(t, httpClient, location, pwdPage, user.Email, password)
	_ = pwdPage.Body.Close()
	_ = resp.Body.Close()

	location = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, location)
	_ = resp.Body.Close()

	location = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, location)
	_ = resp.Body.Close()

	location = assertRedirect(t, resp, "/auth/consent")
	consentPage := loadPage(t, httpClient, location)

	// Through the shared helper rather than a hand-built body, so the ceremony id comes off the
	// rendered page. A form built by hand here would name no ceremony and be refused (#79).
	resp = postConsent(t, httpClient, location, consentPage, []int{0, 1, 2, 3})
	_ = consentPage.Body.Close()
	_ = resp.Body.Close()

	location = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, location)
	code, _ := getCodeAndStateFromUrl(t, resp)
	_ = resp.Body.Close()
	require.NotEmpty(t, code)

	// The sid the ceremony established, read off the codes row: an offline refresh token does not
	// carry it, which is the whole reason the sweep needs a sid-scoped query (finding 3).
	codeHash, err := hashutil.HashString(code)
	require.NoError(t, err)
	codeEntity, err := database.GetCodeByCodeHash(nil, codeHash, false)
	require.NoError(t, err)
	require.NotNil(t, codeEntity)
	sessionIdentifier := codeEntity.SessionIdentifier
	require.NotEmpty(t, sessionIdentifier)

	data := postToTokenEndpoint(t, httpClient, config.GetAuthServer().BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {code},
		"redirect_uri":  {redirectURI.URI},
		"code_verifier": {codeVerifier},
	})
	accessToken, ok := data["access_token"].(string)
	require.True(t, ok, "expected an access token: %v", data)
	refreshToken, ok := data["refresh_token"].(string)
	require.True(t, ok, "offline_access must yield a refresh token: %v", data)

	return &offlineGrant{
		client:            client,
		clientSecret:      clientSecret,
		user:              user,
		password:          password,
		redirectURI:       redirectURI.URI,
		accessToken:       accessToken,
		refreshToken:      refreshToken,
		sessionIdentifier: sessionIdentifier,
		httpClient:        httpClient,
	}
}

// refresh presents the grant's refresh token and returns the raw token endpoint response.
func (g *offlineGrant) refresh(t *testing.T) map[string]interface{} {
	t.Helper()
	return postToTokenEndpoint(t, createHttpClient(t), config.GetAuthServer().BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {g.client.ClientIdentifier},
		"client_secret": {g.clientSecret},
		"refresh_token": {g.refreshToken},
	})
}

// resetPasswordFor drives the forgot-password reset to completion for a user, which is call site 1
// and the only one reachable without a bearer token.
//
// It seeds the code directly rather than going through POST /forgot-password and mailpit, because
// what these tests are about is what a completed reset does to sessions and tokens, not how the code
// was issued. The link itself comes from the shared builder, so this fixture cannot drift from the
// shape the handler redirects to; and the code hash is seeded beside the encrypted code because that
// is what the link is looked up by now (#112).
func resetPasswordFor(t *testing.T, user *models.User, newPassword string) {
	t.Helper()

	code := gofakeit.LetterN(32)
	encrypted, err := encryption.EncryptData(code)
	require.NoError(t, err)
	codeHash, err := hashutil.HashString(code)
	require.NoError(t, err)

	fresh, err := database.GetUserById(nil, user.Id)
	require.NoError(t, err)
	fresh.ForgotPasswordCodeEncrypted = encrypted
	fresh.ForgotPasswordCodeHash = codeHash
	fresh.ForgotPasswordCodeIssuedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
	require.NoError(t, database.UpdateUser(nil, fresh))

	httpClient := createHttpClient(t)
	cleanURL := followResetLink(t, httpClient, handlers.ResetPasswordLink(code))

	// The form is rendered first, because the submission has to carry the continuation id
	// the form held, exactly as a browser does.
	resp := postCleanReset(t, httpClient, cleanURL, newPassword, loadResetForm(t, httpClient, cleanURL))
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "reset should succeed, got: %s", string(body))

	// Confirm the reset landed, so a later assertion cannot pass because the reset silently
	// failed and left everything untouched.
	after, err := database.GetUserById(nil, user.Id)
	require.NoError(t, err)
	require.True(t, hashutil.VerifyPasswordHash(after.PasswordHash, newPassword),
		"the reset must have replaced the password hash")
}

// claimString reads one string claim out of a token without verifying its signature, the same
// approach extractSidClaim takes.
func claimString(t *testing.T, token string, claim string) string {
	t.Helper()
	parsed, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	require.NoError(t, err)
	claims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)
	value, _ := claims[claim].(string)
	return value
}

func generationOf(t *testing.T, userId int64) int64 {
	t.Helper()
	user, err := database.GetUserById(nil, userId)
	require.NoError(t, err)
	require.NotNil(t, user)
	return user.AuthStateGeneration
}

// TestCredentialChange_OfflineGrantWithNoSessionStopsRefreshing is the issue's headline case, and
// the one the issue's own proposed fix could not reach.
//
// The stolen-laptop shape: an offline grant whose browser session has been reaped, which at seeded
// defaults is the normal resting state of an offline grant. A session walk finds nothing to revoke
// there, because the refresh token's link to the session lives on a codes row and the session row
// is gone. The generation boundary reaches it anyway.
func TestCredentialChange_OfflineGrantWithNoSessionStopsRefreshing(t *testing.T) {
	grant := createOfflineGrant(t)

	// Refreshing works to begin with, so a later failure is attributable to the reset.
	first := grant.refresh(t)
	require.NotEmpty(t, first["access_token"], "refresh should work before the reset: %v", first)
	grant.refreshToken = first["refresh_token"].(string)

	// Reap the session, leaving the offline grant with no session row at all.
	session, err := database.GetUserSessionBySessionIdentifier(nil, grant.sessionIdentifier)
	require.NoError(t, err)
	require.NotNil(t, session)
	require.NoError(t, database.DeleteUserSession(nil, session.Id))

	before := generationOf(t, grant.user.Id)
	resetPasswordFor(t, grant.user, "R3setP4ss!word")
	assert.Equal(t, before+1, generationOf(t, grant.user.Id),
		"the reset must advance the generation")

	after := grant.refresh(t)
	assert.Equal(t, "invalid_grant", after["error"],
		"the offline refresh token must stop working after the reset: %v", after)
	assert.Empty(t, after["access_token"])
}

// TestCredentialChange_ROPCGrantStopsRefreshing covers the other linkage shape. A ROPC refresh
// token has no code row at all, so it is unreachable by any session-based walk, and it is reached
// through refresh_tokens.user_id instead.
//
// THE UNSPENT CHILD IS THE POINT. An earlier version of this test rotated the family and then
// presented the ROTATED PARENT after the reset, which rotation had already revoked. It passed, and
// would have passed with no revocation logic whatsoever, because a spent refresh token is refused
// on its own account. The pre-reset rotation is still here, to establish that refreshing worked
// before the reset, but what is presented afterwards is the CHILD it produced, and the child's row
// is asserted unrevoked first so the later rejection cannot be attributed to revocation.
func TestCredentialChange_ROPCGrantStopsRefreshing(t *testing.T) {
	_, user, refreshToken := userAccessTokenViaROPC(t)

	creds, ok := ropcRefreshCredentials[refreshToken]
	require.True(t, ok)

	refreshOnce := func(token string) map[string]interface{} {
		return postToTokenEndpoint(t, createHttpClient(t), config.GetAuthServer().BaseURL+"/auth/token/", url.Values{
			"grant_type":    {"refresh_token"},
			"client_id":     {creds.clientIdentifier},
			"client_secret": {creds.clientSecret},
			"refresh_token": {token},
		})
	}

	// Rotate once, so the pre-reset state is known good, and KEEP the child.
	rotated := refreshOnce(refreshToken)
	require.NotEmpty(t, rotated["access_token"], "ROPC refresh should work before the reset: %v", rotated)
	child, ok := rotated["refresh_token"].(string)
	require.True(t, ok, "rotation must return a child refresh token: %v", rotated)

	// The child is live at this point. Without this assertion the test below could not tell a
	// generation rejection from a revoked-token rejection.
	childJti := claimString(t, child, "jti")
	require.NotEmpty(t, childJti)
	childRow, err := database.GetRefreshTokenByJti(nil, childJti)
	require.NoError(t, err)
	require.NotNil(t, childRow)
	require.False(t, childRow.Revoked, "the child must be unspent before the reset")

	resetPasswordFor(t, user, "R3setP4ss!word")

	data := refreshOnce(child)
	assert.Equal(t, "invalid_grant", data["error"],
		"an unspent ROPC refresh token must stop working after the reset: %v", data)
	assert.Empty(t, data["access_token"])
}

// TestCredentialChange_SelfServicePreservesTheCallersSession is decision 4 end to end: the
// caller's own session survives a self-service password change and ANOTHER SESSION OF THE SAME
// USER does not. Both halves matter, and the second is the one an earlier version of this test
// only appeared to cover.
//
// The bearer used for the change is chosen deliberately. It must be SESSION-BOUND, so the request
// carries a sid and exceptSid is non-empty. An offline bearer would not do: after decision 9 it has
// no sid, so the change would preserve nothing while the test appeared to exercise preservation.
//
// What is asserted to survive is a separate OFFLINE family originating from that same session.
// That is the case a straightforward implementation gets wrong, because such a token cannot be
// recognised as belonging to the session from the user-scoped rows alone.
//
// THE SECOND SESSION MUST BELONG TO THE SAME USER. An earlier version used
// createUserAccessTokenWithScope, which creates a FRESH user, so it proved only that another
// user is unaffected: a much weaker property that would hold even if the sweep were scoped to a
// single session. secondSessionFor logs the same user in through a separate cookie jar, and the two
// sid values are asserted different so an accidental SSO onto the same session cannot pass.
func TestCredentialChange_SelfServicePreservesTheCallersSession(t *testing.T) {
	grant := createOfflineGrant(t)

	// Set the known current password first, so the second login below can use it.
	current := "Curr3ntP4ss!"
	fresh, err := database.GetUserById(nil, grant.user.Id)
	require.NoError(t, err)
	setUserPassword(t, fresh, current)

	// A second device for the SAME user: separate cookie jar, separate session.
	otherDeviceToken, otherSid := secondSessionFor(t, grant, current)
	require.NotEqual(t, grant.sessionIdentifier, otherSid,
		"the second login must create a DIFFERENT session, or this test proves nothing")

	// The caller's own session-bound bearer, on the session the offline family came from.
	const verifier = "code-verifier-session-bound"
	sessionScope := "openid " +
		constants.AuthServerResourceIdentifier + ":" + constants.ManageAccountPermissionIdentifier
	exchanged := grant.exchange(t, grant.codeFromSameSession(t, sessionScope, verifier), verifier)
	callerToken, ok := exchanged["access_token"].(string)
	require.True(t, ok, "expected a session-bound access token: %v", exchanged)
	require.Equal(t, grant.sessionIdentifier, extractSidClaim(t, callerToken),
		"the caller's bearer must be bound to the ceremony's session")

	profileURL := config.GetAuthServer().BaseURL + "/api/v1/account/profile"

	// Both devices work before the change, so a later rejection is attributable to it.
	pre := makeAPIRequest(t, "GET", profileURL, otherDeviceToken, nil)
	_ = pre.Body.Close()
	require.Equal(t, http.StatusOK, pre.StatusCode, "the other device should work before the change")

	resp := makeAPIRequest(t, "PUT", config.GetAuthServer().BaseURL+"/api/v1/account/password",
		callerToken, api.UpdateAccountPasswordRequest{
			CurrentPassword: current,
			NewPassword:     "N3wP4ss!word",
		})
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "password change should succeed: %s", string(body))

	// PRESERVED: the caller's own session, and its offline refresh family.
	preserved := grant.refresh(t)
	assert.NotEmpty(t, preserved["access_token"],
		"the caller's own session and its offline tokens must survive: %v", preserved)

	session, err := database.GetUserSessionBySessionIdentifier(nil, grant.sessionIdentifier)
	require.NoError(t, err)
	require.NotNil(t, session, "the caller's session must not be deleted")
	assert.Equal(t, generationOf(t, grant.user.Id), session.AuthStateGeneration,
		"the preserved session must be promoted to the new generation")

	// TERMINATED: the same user's other session. This is the half the plan calls central.
	otherSession, err := database.GetUserSessionBySessionIdentifier(nil, otherSid)
	require.NoError(t, err)
	assert.Nil(t, otherSession, "the user's other session must be deleted")

	post := makeAPIRequest(t, "GET", profileURL, otherDeviceToken, nil)
	defer func() { _ = post.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, post.StatusCode,
		"the other device's bearer must be rejected after the change")
	assert.Contains(t, post.Header.Get("WWW-Authenticate"), "Session has been terminated")

	// And the caller's own bearer still works, which is what makes the preservation useful rather
	// than merely recorded.
	callerAfter := makeAPIRequest(t, "GET", profileURL, callerToken, nil)
	_ = callerAfter.Body.Close()
	assert.Equal(t, http.StatusOK, callerAfter.StatusCode,
		"the caller's own bearer must keep working")
}

// TestCredentialChange_AnotherUserIsUnaffected keeps the cross-user isolation assertion that the
// preservation test above used to conflate with "another device". Weaker than the same-user case
// and worth having on its own: the sweep is per user, and a bug scoping it too broadly would show
// up here and nowhere else in this file.
func TestCredentialChange_AnotherUserIsUnaffected(t *testing.T) {
	victimToken, _ := createUserAccessTokenWithScope(t,
		"openid "+constants.AuthServerResourceIdentifier+":"+constants.ManageAccountPermissionIdentifier)

	grant := createOfflineGrant(t)
	resetPasswordFor(t, grant.user, "R3setP4ss!word")

	resp := makeAPIRequest(t, "GET",
		config.GetAuthServer().BaseURL+"/api/v1/account/profile", victimToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"an unrelated user's session must be unaffected by this user's reset")
}

// TestCredentialChange_OutstandingAuthCodeIsRejected covers a credential ceremony that straddles
// the change. The code exists but has not been redeemed, so it is invisible to any sweep of
// existing tokens and sessions: only the generation stamped on the code catches it.
//
// ORDERING IS LOAD-BEARING: request the code, then reset, then redeem. Redeeming first would spend
// the code, and the final assertion would then pass because the code was used rather than because
// the generation moved.
func TestCredentialChange_OutstandingAuthCodeIsRejected(t *testing.T) {
	grant := createOfflineGrant(t)

	// A second authorization on the live session, stopping at the code rather than exchanging it.
	const verifier = "code-verifier-outstanding"
	scope := "openid " +
		constants.AuthServerResourceIdentifier + ":" + constants.ManageAccountPermissionIdentifier
	code := grant.codeFromSameSession(t, scope, verifier)

	// NOW reset, with the code still outstanding.
	resetPasswordFor(t, grant.user, "R3setP4ss!word")

	data := grant.exchange(t, code, verifier)
	assert.Equal(t, "invalid_grant", data["error"],
		"an outstanding code must not be redeemable after a reset: %v", data)
	assert.Empty(t, data["access_token"])
}

// TestCredentialChange_DisabledUserSidlessTokenIsRejectedImmediately covers decision 6. Before
// this change a disabled user's access token kept working against the account API until it
// expired, because the middleware only checked the session and a sid-less token has none.
//
// A ROPC token is the vehicle because it is structurally sid-less.
func TestCredentialChange_DisabledUserSidlessTokenIsRejectedImmediately(t *testing.T) {
	accessToken, user, _ := userAccessTokenViaROPC(t)
	require.Empty(t, extractSidClaim(t, accessToken), "a ROPC access token must carry no sid")

	profileURL := config.GetAuthServer().BaseURL + "/api/v1/account/profile"

	resp := makeAPIRequest(t, "GET", profileURL, accessToken, nil)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "the token should work while the user is enabled")

	transitioned, err := database.TrySetUserEnabled(nil, user.Id, true, false)
	require.NoError(t, err)
	require.True(t, transitioned)

	resp2 := makeAPIRequest(t, "GET", profileURL, accessToken, nil)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode,
		"a disabled user's sid-less token must be rejected immediately, not at expiry")
	assert.Contains(t, resp2.Header.Get("WWW-Authenticate"), "Session has been terminated")
}

// TestCredentialChange_OfflineTokenWorksAfterSessionDeletion is decision 9's fix, and it fails
// before this change rather than after: an offline access token used to carry a sid whose session
// the background worker deletes, so the middleware rejected legitimate offline clients.
//
// It is also the counterweight to every other case here. Without it, "reject when the session is
// gone" would look like the whole story, and the fix that makes offline grants work would look
// like a hole.
func TestCredentialChange_OfflineTokenWorksAfterSessionDeletion(t *testing.T) {
	grant := createOfflineGrant(t)

	require.Empty(t, extractSidClaim(t, grant.accessToken),
		"an access token on an offline grant must not carry a sid (decision 9)")

	session, err := database.GetUserSessionBySessionIdentifier(nil, grant.sessionIdentifier)
	require.NoError(t, err)
	require.NotNil(t, session)
	require.NoError(t, database.DeleteUserSession(nil, session.Id))

	resp := makeAPIRequest(t, "GET", config.GetAuthServer().BaseURL+"/userinfo", grant.accessToken, nil)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"an offline access token must survive its session being reaped: %s", string(body))
}

// TestCredentialChange_GenerationRoundTripsThroughTheToken is the case finding 25 asks for, and
// the only one that exercises the new mechanism end to end.
//
// The token carries NO sid, so a generation mismatch is the only reason it can be rejected. That
// makes this single case cover claim emission at issuance, the JSON float64 round trip, parsing
// through GetIntClaim, and the middleware's sid-less branch, none of which the unit tables can
// establish together.
func TestCredentialChange_GenerationRoundTripsThroughTheToken(t *testing.T) {
	grant := createOfflineGrant(t)
	require.Empty(t, extractSidClaim(t, grant.accessToken))

	userinfoURL := config.GetAuthServer().BaseURL + "/userinfo"
	profileURL := config.GetAuthServer().BaseURL + "/api/v1/account/profile"

	resp := makeAPIRequest(t, "GET", userinfoURL, grant.accessToken, nil)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "the token should work before the change")

	resetPasswordFor(t, grant.user, "R3setP4ss!word")

	// Same token, both surfaces, immediately.
	resp2 := makeAPIRequest(t, "GET", userinfoURL, grant.accessToken, nil)
	_ = resp2.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode,
		"a superseded sid-less access token must be rejected at /userinfo")

	resp3 := makeAPIRequest(t, "GET", profileURL, grant.accessToken, nil)
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp3.StatusCode,
		"and at the account API")
	assert.Contains(t, resp3.Header.Get("WWW-Authenticate"), "Session has been terminated")
}

// TestCredentialChange_PreservedFamilyKeepsRotating asserts the user-visible consequence of
// decision 4: a preserved session's offline family does not merely survive the sweep unrevoked, it
// remains USABLE, and the child it rotates into is usable in turn.
//
// The distinction matters because preservation could be half-done. If the sweep left the family
// unrevoked but at the old generation, refreshing would fail on the generation check, and the user
// who changed their own password would be logged out of the very client they did it from, which is
// exactly the outcome decision 4 exists to prevent. So the child's generation is read from the
// database rather than inferred.
//
// This does NOT prove the `dont-update` tag, which the data tests own. See the note at the top of
// this file: rotation loads the parent after the promotion, so the tag is not exercised here.
func TestCredentialChange_PreservedFamilyKeepsRotating(t *testing.T) {
	grant := createOfflineGrant(t)

	// A session-bound bearer on the SAME session as the offline family: a second grant, without
	// offline_access, obtained by SSO.
	const verifier = "code-verifier-session-bound"
	sessionScope := "openid " +
		constants.AuthServerResourceIdentifier + ":" + constants.ManageAccountPermissionIdentifier
	exchanged := grant.exchange(t, grant.codeFromSameSession(t, sessionScope, verifier), verifier)
	callerToken, ok := exchanged["access_token"].(string)
	require.True(t, ok, "expected a session-bound access token: %v", exchanged)
	require.Equal(t, grant.sessionIdentifier, extractSidClaim(t, callerToken),
		"the second grant must be session-bound to the ceremony's session")

	current := "Curr3ntP4ss!"
	fresh, err := database.GetUserById(nil, grant.user.Id)
	require.NoError(t, err)
	setUserPassword(t, fresh, current)

	resp := makeAPIRequest(t, "PUT", config.GetAuthServer().BaseURL+"/api/v1/account/password",
		callerToken, api.UpdateAccountPasswordRequest{
			CurrentPassword: current,
			NewPassword:     "N3wP4ss!word",
		})
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "password change should succeed: %s", string(body))

	generation := generationOf(t, grant.user.Id)

	// Rotate the preserved family. This is the write that could regress the promotion.
	rotated := grant.refresh(t)
	require.NotEmpty(t, rotated["access_token"], "the preserved family must still rotate: %v", rotated)
	childJwt := rotated["refresh_token"].(string)

	// The child row must carry the new generation, read from the database rather than inferred.
	childJti := claimString(t, childJwt, "jti")
	require.NotEmpty(t, childJti)

	child, err := database.GetRefreshTokenByJti(nil, childJti)
	require.NoError(t, err)
	require.NotNil(t, child)
	assert.Equal(t, generation, child.AuthStateGeneration,
		"the rotated child must carry the promoted generation, not the pre-sweep one")

	// The parent was promoted by the sweep and then revoked by the rotation, which is the
	// expected end state for a rotated family member.
	parentJti := claimString(t, grant.refreshToken, "jti")
	parent, err := database.GetRefreshTokenByJti(nil, parentJti)
	require.NoError(t, err)
	require.NotNil(t, parent)
	assert.Equal(t, generation, parent.AuthStateGeneration,
		"the sweep must have promoted the preserved parent")
	assert.True(t, parent.Revoked, "the parent must be revoked by rotation")

	// The child works, which is the user-visible consequence of all of the above.
	grant.refreshToken = childJwt
	again := grant.refresh(t)
	assert.NotEmpty(t, again["access_token"],
		"the child of a preserved family must itself be usable: %v", again)
}

// TestCredentialChange_ResidualRacingChildIsFailClosed pins the #131 residual as FAIL-CLOSED,
// without needing to win a race.
//
// A refresh rotating concurrently with the sweep can commit a child the sweep never saw, leaving
// it unrevoked at the PREVIOUS generation while the user has advanced. That state is what this
// test constructs directly: rotate a family, let a reset sweep it, then put one row back into
// exactly the racing child's shape, unrevoked and one generation behind.
//
// Reconstructing rather than racing is deliberate and is the honest thing to assert. What matters
// for #106 is not the probability of the interleaving but that its outcome cannot be a usable
// credential, and that is fully determined by the row's state. #131 owns making the interleaving
// impossible; its acceptance criteria include the cross-engine coordination this cannot show.
func TestCredentialChange_ResidualRacingChildIsFailClosed(t *testing.T) {
	grant := createOfflineGrant(t)

	first := grant.refresh(t)
	require.NotEmpty(t, first["access_token"], "refresh should work initially: %v", first)
	grant.refreshToken = first["refresh_token"].(string)

	beforeGeneration := generationOf(t, grant.user.Id)
	resetPasswordFor(t, grant.user, "R3setP4ss!word")
	afterGeneration := generationOf(t, grant.user.Id)
	require.Equal(t, beforeGeneration+1, afterGeneration)

	jti := claimString(t, grant.refreshToken, "jti")
	row, err := database.GetRefreshTokenByJti(nil, jti)
	require.NoError(t, err)
	require.NotNil(t, row)
	require.True(t, row.Revoked, "the sweep should have revoked it")

	// Rebuild the racing child's exact state: unrevoked, and one generation behind the user.
	// Un-revoking first is required because PromoteRefreshTokenGenerations only touches unrevoked
	// rows; it is used here to move the value DOWN, which is a test tool rather than a production
	// path.
	row.Revoked = false
	require.NoError(t, database.UpdateRefreshToken(nil, row))
	require.NoError(t, database.PromoteRefreshTokenGenerations(nil, []int64{row.Id}, beforeGeneration))

	check, err := database.GetRefreshTokenByJti(nil, jti)
	require.NoError(t, err)
	require.False(t, check.Revoked, "the fixture must be unrevoked, or the rejection proves nothing")
	require.Equal(t, beforeGeneration, check.AuthStateGeneration,
		"the fixture must be one generation behind the user")

	// The whole point: a token in that state is refused.
	data := grant.refresh(t)
	assert.Equal(t, "invalid_grant", data["error"],
		"a racing child at the previous generation must be refused: %v", data)
	assert.Empty(t, data["access_token"],
		"and no new credential may be minted from it")
}
