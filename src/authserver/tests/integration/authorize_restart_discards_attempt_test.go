package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A restarted ceremony keeps the request and discards the attempt (#436). The cases here are the
// two things that used to survive a restart and reach somebody: the methods of the attempt, which
// reached the amr of the tokens and the auth_methods of the session the second pass created (#140),
// and the scope the attempt narrowed to its user, which reached whoever signed in next.
//
// Every session is ended through the admin API, which is how an administrator ends one and what
// the restart routes exist to answer, and every session read goes through the same API rather than
// the table, so the cases pass only if the endpoint a caller reads says the right thing.

// restartFixture is a confidential level 1 client and a user who holds a password and an enrolled
// authenticator, so the browser can hold a session whose methods are "pwd otp".
type restartFixture struct {
	client       *models.Client
	clientSecret string
	redirectURI  *models.RedirectURI
	user         *models.User
	password     string
	otpSecret    string
	adminToken   string
}

func newRestartFixture(t *testing.T, consentRequired bool) *restartFixture {
	t.Helper()

	clientSecret := fake.LetterN(32)
	clientSecretEncrypted, err := dataCipher.Encrypt(clientSecret)
	require.NoError(t, err)
	client := &models.Client{
		ClientIdentifier:         "restart-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          consentRequired,
		DefaultAcrLevel:          models.AcrLevel1,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))

	redirectURI := &models.RedirectURI{ClientId: client.Id, URI: fake.URL()}
	require.NoError(t, database.CreateRedirectURI(context.Background(), nil, redirectURI))

	user, password, otpSecret := createRestartUser(t)
	adminToken, _ := createAdminClientWithToken(t)

	return &restartFixture{
		client:       client,
		clientSecret: clientSecret,
		redirectURI:  redirectURI,
		user:         user,
		password:     password,
		otpSecret:    otpSecret,
		adminToken:   adminToken,
	}
}

// createRestartUser is an enabled user with a password and an enrolled authenticator.
func createRestartUser(t *testing.T) (*models.User, string, string) {
	t.Helper()

	password := fake.Password(10)
	passwordHashed, err := passwordhash.Hash(password)
	require.NoError(t, err)

	email := fake.Email()
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Goiabada", AccountName: email})
	require.NoError(t, err)

	user := &models.User{
		Subject:            fake.UUID(),
		Enabled:            true,
		Email:              email,
		PasswordHash:       passwordHashed,
		OTPEnabled:         true,
		OTPSecretEncrypted: encryptOTPSecretForTest(t, key.Secret()),
	}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	return user, password, key.Secret()
}

// authorizeURL is an authorization request for the fixture's client. acrValues may be empty.
func (f *restartFixture) authorizeURL(scope, state, codeVerifier, acrValues string) string {
	destURL := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + f.client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(f.redirectURI.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + oauth.GeneratePKCECodeChallenge(codeVerifier) +
		"&scope=" + url.QueryEscape(scope) +
		"&state=" + state +
		"&nonce=" + fake.LetterN(8)
	if acrValues != "" {
		destURL += "&acr_values=" + url.QueryEscape(acrValues)
	}
	return destURL
}

// signInWithPasswordAndOtp runs a whole level 2 ceremony in the browser, which leaves it holding a
// session whose methods are "pwd otp". The code it ends with is not redeemed.
func (f *restartFixture) signInWithPasswordAndOtp(t *testing.T, httpClient *http.Client) {
	t.Helper()

	resp := loadPage(t, httpClient, f.authorizeURL("openid", fake.LetterN(8), fake.LetterN(43),
		models.AcrLevel2Mandatory.String()))
	defer func() { _ = resp.Body.Close() }()
	resp = loadPage(t, httpClient, assertRedirect(t, resp, "/auth/level1"))
	defer func() { _ = resp.Body.Close() }()
	pwdURL := assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, pwdURL)
	defer func() { _ = resp.Body.Close() }()
	resp = authenticateWithPassword(t, httpClient, pwdURL, resp, f.user.Email, f.password)
	defer func() { _ = resp.Body.Close() }()
	resp = loadPage(t, httpClient, assertRedirect(t, resp, "/auth/level1completed"))
	defer func() { _ = resp.Body.Close() }()
	resp = loadPage(t, httpClient, assertRedirect(t, resp, "/auth/level2"))
	defer func() { _ = resp.Body.Close() }()
	otpURL := assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, otpURL)
	defer func() { _ = resp.Body.Close() }()
	otpCode, err := totp.GenerateCode(f.otpSecret, time.Now())
	require.NoError(t, err)
	resp = authenticateWithOtp(t, httpClient, otpURL, resp, otpCode)
	defer func() { _ = resp.Body.Close() }()
	resp = loadPage(t, httpClient, assertRedirect(t, resp, "/auth/completed"))
	defer func() { _ = resp.Body.Close() }()
	resp = loadPage(t, httpClient, assertRedirect(t, resp, "/auth/issue"))
	defer func() { _ = resp.Body.Close() }()
	code, _ := getCodeAndStateFromUrl(t, resp)
	require.NotEmpty(t, code)

	sessions := sessionsThroughAdminAPI(t, f.adminToken, f.user.Id)
	require.Len(t, sessions, 1)
	require.Equal(t, "pwd otp", sessions[0].AuthMethods, "the browser must hold a session carrying otp")
}

// passwordAfterRestart answers the restart: from /auth/level1 through the password form to the
// code, for a ceremony that needs no consent. It returns the code.
func passwordAfterRestart(t *testing.T, httpClient *http.Client, level1URL, email, password string) string {
	t.Helper()

	resp := loadPage(t, httpClient, level1URL)
	defer func() { _ = resp.Body.Close() }()
	pwdURL := assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, pwdURL)
	defer func() { _ = resp.Body.Close() }()
	resp = authenticateWithPassword(t, httpClient, pwdURL, resp, email, password)
	defer func() { _ = resp.Body.Close() }()
	resp = loadPage(t, httpClient, assertRedirect(t, resp, "/auth/level1completed"))
	defer func() { _ = resp.Body.Close() }()
	resp = loadPage(t, httpClient, assertRedirect(t, resp, "/auth/completed"))
	defer func() { _ = resp.Body.Close() }()
	resp = loadPage(t, httpClient, assertRedirect(t, resp, "/auth/issue"))
	defer func() { _ = resp.Body.Close() }()
	code, _ := getCodeAndStateFromUrl(t, resp)
	return code
}

// redeem exchanges the code and returns the claims of the id token and of the access token.
func (f *restartFixture) redeem(t *testing.T, httpClient *http.Client, code, codeVerifier string) (
	idClaims map[string]interface{}, accessClaims map[string]interface{}) {
	t.Helper()

	data := postToTokenEndpoint(t, httpClient, appConfig.AuthServer.BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {f.client.ClientIdentifier},
		"code":          {code},
		"redirect_uri":  {f.redirectURI.URI},
		"code_verifier": {codeVerifier},
		"client_secret": {f.clientSecret},
	})
	idToken, ok := data["id_token"].(string)
	require.True(t, ok, "the exchange must return an id token, got %v", data)
	accessToken, ok := data["access_token"].(string)
	require.True(t, ok, "the exchange must return an access token, got %v", data)
	return decodeJWTPayload(t, idToken), decodeJWTPayload(t, accessToken)
}

func sessionsThroughAdminAPI(t *testing.T, adminToken string, userId int64) []api.UserSessionDetailResponse {
	t.Helper()

	resp := makeAPIRequest(t, "GET", appConfig.AuthServer.BaseURL+"/api/v1/admin/users/"+
		strconv.FormatInt(userId, 10)+"/sessions", adminToken, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var sessions api.GetUserSessionsResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&sessions))
	return sessions.Sessions
}

// endSessionsThroughAdminAPI ends every session the user holds, the way an administrator does.
func endSessionsThroughAdminAPI(t *testing.T, adminToken string, userId int64) {
	t.Helper()

	sessions := sessionsThroughAdminAPI(t, adminToken, userId)
	require.NotEmpty(t, sessions, "there must be a session to end")
	for _, session := range sessions {
		resp := makeAPIRequest(t, "DELETE", appConfig.AuthServer.BaseURL+"/api/v1/admin/user-sessions/"+
			strconv.FormatInt(session.Id, 10), adminToken, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()
	}
	require.Empty(t, sessionsThroughAdminAPI(t, adminToken, userId))
}

// assertOnlyPasswordWasEarned is #140's claim, read from both places it reaches: the amr of both
// tokens, and the auth_methods of the one session the second pass created, through the admin API.
func (f *restartFixture) assertOnlyPasswordWasEarned(t *testing.T, idClaims, accessClaims map[string]interface{}) {
	t.Helper()

	assert.Equal(t, []interface{}{"pwd"}, idClaims["amr"],
		"the id token's amr names only what the second pass verified")
	assert.Equal(t, []interface{}{"pwd"}, accessClaims["amr"],
		"the access token's amr names only what the second pass verified")
	assert.Equal(t, models.AcrLevel1.String(), idClaims["acr"])

	sessions := sessionsThroughAdminAPI(t, f.adminToken, f.user.Id)
	require.Len(t, sessions, 1, "the second pass creates exactly one session")
	assert.Equal(t, "pwd", sessions[0].AuthMethods,
		"the session the second pass created carries only the password it verified")
	assert.Equal(t, models.AcrLevel1.String(), sessions[0].AcrLevel)
}

// TestRestartRoute1_TheSecondPassEarnsOnlyWhatItVerified carries otp into a ceremony by SSO and
// ends the session before /auth/completed. With no reusable session and no password entered in
// this ceremony, /auth/completed restarts it (route 1). Before #436 the methods copied off the
// ended session survived that restart, so a password alone minted amr ["pwd","otp"] (#140).
func TestRestartRoute1_TheSecondPassEarnsOnlyWhatItVerified(t *testing.T) {
	f := newRestartFixture(t, false)
	httpClient := createHttpClient(t)
	f.signInWithPasswordAndOtp(t, httpClient)

	codeVerifier := fake.LetterN(43)
	resp := loadPage(t, httpClient, f.authorizeURL("openid", fake.LetterN(8), codeVerifier, ""))
	defer func() { _ = resp.Body.Close() }()
	// SSO: the session covers level 1, so no password is asked for and its methods are copied.
	resp = loadPage(t, httpClient, assertRedirect(t, resp, "/auth/level1completed"))
	defer func() { _ = resp.Body.Close() }()
	completedURL := assertRedirect(t, resp, "/auth/completed")

	endSessionsThroughAdminAPI(t, f.adminToken, f.user.Id)

	resp = loadPage(t, httpClient, completedURL)
	defer func() { _ = resp.Body.Close() }()
	level1URL := assertRedirect(t, resp, "/auth/level1")

	code := passwordAfterRestart(t, httpClient, level1URL, f.user.Email, f.password)
	idClaims, accessClaims := f.redeem(t, httpClient, code, codeVerifier)
	f.assertOnlyPasswordWasEarned(t, idClaims, accessClaims)
}

// TestRestartRoute2_TheSecondPassEarnsOnlyWhatItVerified is the same claim through the other door:
// the SSO ceremony reaches /auth/completed with its session alive, is bound to it, and the session
// is ended before /auth/issue, which restarts it (route 2).
func TestRestartRoute2_TheSecondPassEarnsOnlyWhatItVerified(t *testing.T) {
	f := newRestartFixture(t, false)
	httpClient := createHttpClient(t)
	f.signInWithPasswordAndOtp(t, httpClient)

	codeVerifier := fake.LetterN(43)
	resp := loadPage(t, httpClient, f.authorizeURL("openid", fake.LetterN(8), codeVerifier, ""))
	defer func() { _ = resp.Body.Close() }()
	resp = loadPage(t, httpClient, assertRedirect(t, resp, "/auth/level1completed"))
	defer func() { _ = resp.Body.Close() }()
	resp = loadPage(t, httpClient, assertRedirect(t, resp, "/auth/completed"))
	defer func() { _ = resp.Body.Close() }()
	issueURL := assertRedirect(t, resp, "/auth/issue")

	endSessionsThroughAdminAPI(t, f.adminToken, f.user.Id)

	resp = loadPage(t, httpClient, issueURL)
	defer func() { _ = resp.Body.Close() }()
	level1URL := assertRedirect(t, resp, "/auth/level1")
	assert.NotContains(t, level1URL, "code=")

	code := passwordAfterRestart(t, httpClient, level1URL, f.user.Email, f.password)
	idClaims, accessClaims := f.redeem(t, httpClient, code, codeVerifier)
	f.assertOnlyPasswordWasEarned(t, idClaims, accessClaims)
}

// consentScopes reads the scopes a consent page offers, in order.
func consentScopes(t *testing.T, consentPage *http.Response) []string {
	t.Helper()
	var scopes []string
	parseHTMLResponse(t, consentPage).Find(`label[for^="consent"]`).Each(func(_ int, label *goquery.Selection) {
		scopes = append(scopes, strings.TrimSpace(label.Text()))
	})
	return scopes
}

// TestRestartRoute2_ADifferentPersonGetsTheirOwnScopeAndConsent is the case a narrowed Scope
// reached. Person A, holding one of the two permissions the client asks for, signs in and consents;
// A's session is ended before /auth/issue and the ceremony restarts (route 2); person B, holding
// the other permission, signs in on the same browser. Before #436 B was filtered against A's
// narrowing, so B could never be granted the permission B holds and A does not. Now the scope is
// put back from the request and B is asked about, and granted, B's own.
func TestRestartRoute2_ADifferentPersonGetsTheirOwnScopeAndConsent(t *testing.T) {
	f := newRestartFixture(t, true)
	resource := createResource(t)
	permissionA := createPermission(t, resource.Id)
	permissionB := createPermission(t, resource.Id)
	scopeA := resource.ResourceIdentifier + ":" + permissionA.PermissionIdentifier
	scopeB := resource.ResourceIdentifier + ":" + permissionB.PermissionIdentifier
	assignPermissionToUser(t, f.user.Id, permissionA.Id)
	personB, passwordB, _ := createRestartUser(t)
	assignPermissionToUser(t, personB.Id, permissionB.Id)

	httpClient := createHttpClient(t)
	codeVerifier := fake.LetterN(43)
	resp := loadPage(t, httpClient, f.authorizeURL("openid "+scopeA+" "+scopeB, fake.LetterN(8), codeVerifier, ""))
	defer func() { _ = resp.Body.Close() }()
	resp = loadPage(t, httpClient, assertRedirect(t, resp, "/auth/level1"))
	defer func() { _ = resp.Body.Close() }()
	pwdURL := assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, pwdURL)
	defer func() { _ = resp.Body.Close() }()
	resp = authenticateWithPassword(t, httpClient, pwdURL, resp, f.user.Email, f.password)
	defer func() { _ = resp.Body.Close() }()
	resp = loadPage(t, httpClient, assertRedirect(t, resp, "/auth/level1completed"))
	defer func() { _ = resp.Body.Close() }()
	resp = loadPage(t, httpClient, assertRedirect(t, resp, "/auth/completed"))
	defer func() { _ = resp.Body.Close() }()
	consentURL := assertRedirect(t, resp, "/auth/consent")
	consentPage := loadPage(t, httpClient, consentURL)
	defer func() { _ = consentPage.Body.Close() }()
	require.Equal(t, []string{"openid", scopeA}, consentScopes(t, consentPage), "A is asked about A's own scope")
	resp = postConsent(t, httpClient, consentURL, consentPage, []int{0, 1})
	defer func() { _ = resp.Body.Close() }()
	issueURL := assertRedirect(t, resp, "/auth/issue")

	endSessionsThroughAdminAPI(t, f.adminToken, f.user.Id)

	resp = loadPage(t, httpClient, issueURL)
	defer func() { _ = resp.Body.Close() }()
	resp = loadPage(t, httpClient, assertRedirect(t, resp, "/auth/level1"))
	defer func() { _ = resp.Body.Close() }()
	pwdURL = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, pwdURL)
	defer func() { _ = resp.Body.Close() }()
	resp = authenticateWithPassword(t, httpClient, pwdURL, resp, personB.Email, passwordB)
	defer func() { _ = resp.Body.Close() }()
	resp = loadPage(t, httpClient, assertRedirect(t, resp, "/auth/level1completed"))
	defer func() { _ = resp.Body.Close() }()
	resp = loadPage(t, httpClient, assertRedirect(t, resp, "/auth/completed"))
	defer func() { _ = resp.Body.Close() }()

	// B is asked, because A's consent went with the attempt, and asked about B's own scope.
	consentURL = assertRedirect(t, resp, "/auth/consent")
	consentPage = loadPage(t, httpClient, consentURL)
	defer func() { _ = consentPage.Body.Close() }()
	assert.Equal(t, []string{"openid", scopeB}, consentScopes(t, consentPage),
		"B is asked about the scope the request names and B holds, not A's narrowing of it")
	resp = postConsent(t, httpClient, consentURL, consentPage, []int{0, 1})
	defer func() { _ = resp.Body.Close() }()
	resp = loadPage(t, httpClient, assertRedirect(t, resp, "/auth/issue"))
	defer func() { _ = resp.Body.Close() }()
	code, _ := getCodeAndStateFromUrl(t, resp)

	idClaims, accessClaims := f.redeem(t, httpClient, code, codeVerifier)
	assert.Equal(t, personB.Subject, idClaims["sub"])
	grantedScopes := strings.Fields(accessClaims["scope"].(string))
	assert.Contains(t, grantedScopes, scopeB, "B is granted the permission B holds")
	assert.NotContains(t, grantedScopes, scopeA, "and nothing A held")
}
