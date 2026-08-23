package integrationtests

import (
	"io"
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
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// A second user signing in on a browser that already holds a session (#133)
// =============================================================================
//
// User A is signed in and the browser holds A's session cookie. User B then authenticates in the
// same browser. Three requests reach that handover, and each takes a different route out of
// HandleAuthorizeGet while leaving A's cookie in place:
//
//   - prompt=login, which returns before the session is even loaded;
//   - an id_token_hint naming somebody other than the session's owner, which returns from inside
//     the valid-session block;
//   - max_age=0, which is neither of those: the session loads, HasValidUserSession refuses it, and
//     the request leaves at the function's final return.
//
// The rule this file proves is one sentence: a ceremony binds only to a session belonging to the
// user it authenticated. Before it held, B's authorization code carried A's session identifier, A's
// session row was rewritten with B's authentication methods, B's token claimed the ACR A had
// reached, and the browser was left signed in as A afterwards.
//
// This is the only tier where the cookie jar is real, which is why the whole chain is driven here
// rather than asserted one handler at a time. The per-handler tables live beside the handlers.

// crossUserCodeVerifier is a fixed PKCE verifier, so every code minted here can actually be
// redeemed. The shared fixtures in utils_test.go send a random 43-character string as an S256
// challenge, which no verifier matches, so their codes can never reach /auth/token and this file
// needs the tokens.
const crossUserCodeVerifier = "cross-user-session-code-verifier"

const crossUserScope = "openid profile email"

// crossUserBrowser is one browser that user A signed in on, plus everything needed to run user B's
// ceremony through the same cookie jar.
type crossUserBrowser struct {
	jar          *http.Client
	client       *models.Client
	clientSecret string
	redirectUri  *models.RedirectURI
	userA        *models.User
	passwordA    string
	userB        *models.User
	passwordB    string
	// sessionA is S_A as it stood before B arrived, read back from the database.
	sessionA *models.UserSession
}

// createCrossUserUser makes a user this file can sign in. withOtp enrols a real TOTP secret, kept in
// plaintext on the model so a case can generate a passcode from it, and encrypted at rest the way
// production stores it.
func createCrossUserUser(t *testing.T, withOtp bool) (*models.User, string) {
	password := gofakeit.Password(true, true, true, true, false, 10)
	passwordHashed, err := hashutil.HashPassword(password)
	require.NoError(t, err)

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}

	if withOtp {
		key, err := totp.Generate(totp.GenerateOpts{Issuer: "Goiabada", AccountName: user.Email})
		require.NoError(t, err)
		user.OTPSecret = key.Secret()
		user.OTPSecretEncrypted = encryptOTPSecretForTest(t, key.Secret())
		user.OTPEnabled = true
	}

	require.NoError(t, database.CreateUser(nil, user))
	return user, password
}

// createCrossUserBrowser builds the confidential client, both users, and a browser with user A
// already signed in on it.
//
// defaultAcrLevel is the client's. aSessionAcrLevel is the level A's session ends up holding, and
// the two are separate parameters rather than one because a case needing A's session to sit ABOVE
// the target B will later face cannot get there from the client's level alone: the client's level
// is a floor under every ceremony on that client, B's included, so raising it to lift A's session
// lifts B's target with it and the two stop differing (#240).
//
// A reaches aSessionAcrLevel by asking for it with acr_values, which is a step-up the floor still
// permits, so this is the same route a real user takes rather than a level written onto the row
// behind the server's back.
//
// A enrols in OTP exactly when A's own level asks for a second factor, and B never does. That
// asymmetry is the point rather than a detail: A's session then records "pwd otp" while B's ceremony
// records "pwd", so an assertion that B's grant carries "pwd" is evidence about whose authentication
// it came from. Give both users the same methods and that assertion passes whether the value was B's
// or copied off A's session, which is the shape a cross-user regression would take (#133).
//
// A session at level1 never asks A for a second factor, so a fixture built with aSessionAcrLevel at
// level1 cannot make the two differ. There the methods assertions are consistency checks; the
// provenance is carried by the cases where A reaches level2_optional.
func createCrossUserBrowser(t *testing.T, defaultAcrLevel enums.AcrLevel,
	aSessionAcrLevel enums.AcrLevel) *crossUserBrowser {

	require.False(t, defaultAcrLevel.IsHigherThan(aSessionAcrLevel),
		"the client's level is a floor under A's ceremony too, so A's session cannot end up below it")

	clientSecret := gofakeit.LetterN(32)
	clientSecretEncrypted, err := encryption.EncryptData(clientSecret)
	require.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 false,
		ConsentRequired:          false,
		DefaultAcrLevel:          defaultAcrLevel,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}
	require.NoError(t, database.CreateClient(nil, client))

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      "https://example.com/callback",
	}
	require.NoError(t, database.CreateRedirectURI(nil, redirectUri))

	// A presents a second factor whenever A's own level asks for one; B never does.
	aPresentsOtp := aSessionAcrLevel.IsHigherThan(enums.AcrLevel1)
	userA, passwordA := createCrossUserUser(t, aPresentsOtp)
	userB, passwordB := createCrossUserUser(t, false)

	b := &crossUserBrowser{
		jar:          createHttpClient(t),
		client:       client,
		clientSecret: clientSecret,
		redirectUri:  redirectUri,
		userA:        userA,
		passwordA:    passwordA,
		userB:        userB,
		passwordB:    passwordB,
	}

	// A signs in, stepping up with acr_values when A's level is above the client's, which is what
	// puts that level on S_A. At or below the client's level the parameter would be redundant, since
	// the floor supplies it.
	aExtra := ""
	if aSessionAcrLevel.IsHigherThan(defaultAcrLevel) {
		aExtra = "&acr_values=" + url.QueryEscape(aSessionAcrLevel.String())
	}
	signInWithPassword(t, b.jar, crossUserAuthorizeUrl(b, aExtra),
		userA.Email, passwordA, aPresentsOtp, userA.OTPSecret)

	sessionsA, err := database.GetUserSessionsByUserId(nil, userA.Id)
	require.NoError(t, err)
	require.Len(t, sessionsA, 1, "user A should be signed in on exactly one session")
	require.Equal(t, aSessionAcrLevel.String(), sessionsA[0].AcrLevel)

	// Pin what A's session records, because every provenance assertion downstream is only worth
	// anything while it differs from B's "pwd". If a change to this fixture ever stopped A presenting
	// a second factor, those assertions would keep passing while proving nothing, so the fixture says
	// out loud what it set up.
	expectedMethodsA := enums.AuthMethodPassword.String()
	if aPresentsOtp {
		expectedMethodsA += " " + enums.AuthMethodOTP.String()
	}
	require.Equal(t, expectedMethodsA, sessionsA[0].AuthMethods,
		"the fixture's whole value is that the previous user's session records methods of its own")

	b.sessionA = &sessionsA[0]

	return b
}

// crossUserAuthorizeUrl builds an authorization request for this fixture's client. extra is
// appended verbatim, already query-escaped, and is where a case puts prompt, acr_values, max_age or
// an id_token_hint.
func crossUserAuthorizeUrl(b *crossUserBrowser, extra string) string {
	return config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + b.client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(b.redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + oauth.GeneratePKCECodeChallenge(crossUserCodeVerifier) +
		"&scope=" + url.QueryEscape(crossUserScope) +
		"&state=" + gofakeit.LetterN(8) +
		"&nonce=" + gofakeit.LetterN(8) +
		extra
}

// signInWithPassword drives a password ceremony from /auth/authorize to the client's callback and
// returns the authorization code.
//
// expectLevel2 asserts in both directions, which is the point of naming it rather than following
// whatever comes back: assertRedirect fails when the location is not the path it was given, so a
// missing /auth/level2 hop and an unexpected one are equally loud. That is what carries the
// second-factor half of this change in the prompt=login case below.
//
// otpSecret is empty for a user without OTP, whose level2 hop skips straight onward. When it is set
// the ceremony is expected to reach /auth/otp and answer it, which is the only way "otp" reaches the
// session's authentication methods.
func signInWithPassword(t *testing.T, jar *http.Client, destUrl string,
	email string, password string, expectLevel2 bool, otpSecret string) string {

	t.Helper()

	require.False(t, otpSecret != "" && !expectLevel2,
		"a user with OTP can only present it on a ceremony that reaches level 2")

	resp, err := jar.Get(destUrl)
	require.NoError(t, err)
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)

	// The first hop is an assertion in its own right: it says the request did not reuse whatever
	// session the browser arrived with. Reusing one answers /auth/level1completed instead.
	loc := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, jar, loc)
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)

	loc = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, jar, loc)
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)

	resp = authenticateWithPassword(t, jar, loc, resp, email, password)
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)

	loc = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, jar, loc)
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)

	if expectLevel2 {
		loc = assertRedirect(t, resp, "/auth/level2")
		resp = loadPage(t, jar, loc)
		defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)
	}

	if otpSecret != "" {
		loc = assertRedirect(t, resp, "/auth/otp")
		resp = loadPage(t, jar, loc)
		defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)

		otpCode, err := totp.GenerateCode(otpSecret, time.Now())
		require.NoError(t, err)
		resp = authenticateWithOtp(t, jar, loc, resp, otpCode)
		defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)
	}

	loc = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, jar, loc)
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)

	loc = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, jar, loc)
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)

	codeVal, _ := getCodeAndStateFromUrl(t, resp)
	return codeVal
}

// redeemCrossUserCode exchanges a code for tokens on the fixture's confidential client.
func redeemCrossUserCode(t *testing.T, b *crossUserBrowser, jar *http.Client, codeVal string) map[string]interface{} {
	t.Helper()

	return postToTokenEndpoint(t, jar, config.GetAuthServer().BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {b.client.ClientIdentifier},
		"client_secret": {b.clientSecret},
		"code":          {codeVal},
		"redirect_uri":  {b.redirectUri.URI},
		"code_verifier": {crossUserCodeVerifier},
	})
}

// assertCeremonyBoundToUserB is the whole rule, asserted once and shared by all three cases.
//
// Everything the ceremony produced has to name B's own session and nothing may still name A's, and
// the browser has to belong to B afterwards. codeVal is the code B's ceremony minted, and it is
// redeemed here rather than by the caller because the tokens carry half of the claim.
func assertCeremonyBoundToUserB(t *testing.T, b *crossUserBrowser, codeVal string) {
	t.Helper()

	code := loadCodeFromDatabase(t, codeVal)
	assert.Equal(t, b.userB.Id, code.UserId, "the code belongs to the user who authenticated")
	assert.NotEmpty(t, code.SessionIdentifier, "the code is bound to a session")
	assert.NotEqual(t, b.sessionA.SessionIdentifier, code.SessionIdentifier,
		"the code must not carry the session identifier of the user who was signed in before")

	// Decision 4: the browser changed hands, so the session it was carrying is ended rather than
	// left orphaned with its grants alive and nobody able to reach it.
	survivingA, err := database.GetUserSessionBySessionIdentifier(nil, b.sessionA.SessionIdentifier)
	require.NoError(t, err)
	assert.Nil(t, survivingA, "the previous user's session must be terminated, not left behind")

	sessionsA, err := database.GetUserSessionsByUserId(nil, b.userA.Id)
	require.NoError(t, err)
	assert.Empty(t, sessionsA, "the previous user should have no sessions left from this browser")

	sessionsB, err := database.GetUserSessionsByUserId(nil, b.userB.Id)
	require.NoError(t, err)
	require.Len(t, sessionsB, 1, "the authenticating user should hold exactly one session")
	assert.Equal(t, code.SessionIdentifier, sessionsB[0].SessionIdentifier,
		"the code names the session the ceremony created")

	// B never enrols in OTP, so B's own evidence is a password and nothing else. A's session records
	// "pwd otp" wherever the fixture's level allows it, which is what makes this an assertion about
	// provenance: the forbidden value is a value that actually exists in this database, on the row the
	// ceremony was cookied to. Exact equality rather than Contains, since the failure being pinned is
	// an extra method arriving from somewhere else.
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods,
		"the code's methods must be what this ceremony proved, not what the browser's previous session held")

	tokenData := redeemCrossUserCode(t, b, b.jar, codeVal)

	idToken, ok := tokenData["id_token"].(string)
	require.True(t, ok, "expected an id_token, got %v", tokenData)
	idClaims := decodeJWTPayload(t, idToken)
	assert.Equal(t, b.userB.Subject.String(), idClaims["sub"])
	assert.Equal(t, code.SessionIdentifier, idClaims["sid"],
		"the id_token's sid must name the session this ceremony bound to")

	// Goal 4 is about the tokens as well as the code, and the tokens are what a relying party
	// actually reads. amr is a JSON array per OIDC Core 1.0 section 2.
	accessToken, ok := tokenData["access_token"].(string)
	require.True(t, ok, "expected an access_token, got %v", tokenData)
	accessClaims := decodeJWTPayload(t, accessToken)

	for _, token := range []struct {
		name   string
		claims map[string]interface{}
	}{
		{"id_token", idClaims},
		{"access_token", accessClaims},
	} {
		assert.Equal(t, []interface{}{enums.AuthMethodPassword.String()}, token.claims["amr"],
			"%s must carry only the methods this ceremony proved", token.name)
		assert.Equal(t, code.AcrLevel, token.claims["acr"],
			"%s must carry the acr the ceremony recorded on its own code", token.name)
	}

	// The refresh token carries the identifier too, and it is the durable half: it keeps resolving
	// against that session on every rotation, long after the redirect it came from.
	refreshToken, ok := tokenData["refresh_token"].(string)
	require.True(t, ok, "expected a refresh_token, got %v", tokenData)
	refreshClaims := decodeJWTPayload(t, refreshToken)
	assert.Equal(t, code.SessionIdentifier, refreshClaims["sid"])

	assertNextRequestAuthenticatesAsUserB(t, b, code.SessionIdentifier)
}

// assertNextRequestAuthenticatesAsUserB is goal 5, and it is the consequence a person would notice.
// Before this change the browser was still cookied to A afterwards, so the next ordinary
// authorization request signed in as A without asking anyone.
func assertNextRequestAuthenticatesAsUserB(t *testing.T, b *crossUserBrowser, expectedSessionIdentifier string) {
	t.Helper()

	resp, err := b.jar.Get(crossUserAuthorizeUrl(b, ""))
	require.NoError(t, err)
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)

	// Straight to level1completed means a session was reused, and the assertions below say whose.
	loc := assertRedirect(t, resp, "/auth/level1completed")

	// The hops after this one depend on the ACR the ceremony left on B's session against the
	// client's default, which differs per case and is not what this assertion is about. Walk until
	// the redirect leaves the authorization server, which is the callback.
	for i := 0; i < 8; i++ {
		resp = loadPage(t, b.jar, loc)
		defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)

		require.Equal(t, http.StatusFound, resp.StatusCode)
		parsed, err := url.Parse(resp.Header.Get("Location"))
		require.NoError(t, err)
		if !strings.HasPrefix(parsed.Path, "/auth/") {
			break
		}
		loc = parsed.String()
	}

	codeVal, _ := getCodeAndStateFromUrl(t, resp)
	code := loadCodeFromDatabase(t, codeVal)
	assert.Equal(t, b.userB.Id, code.UserId,
		"the browser must now authenticate as the user who took it over")
	assert.Equal(t, expectedSessionIdentifier, code.SessionIdentifier,
		"and on the session that ceremony created")
}

// TestCrossUser_PromptLogin_BindsToTheAuthenticatingUsersSession covers the first entry path, and it
// is the one that also carries the second factor.
//
// The client asks for level2_optional and A's session already holds level2_optional, so before this
// change /auth/level1completed compared B's target against A's session, found no step-up owed and
// sent B to /auth/completed having presented a password only. That is why the chain assertion below
// names /auth/level2: reaching it is what says the decision was made from B's own authentication.
// B has no OTP, so level2 is satisfied immediately and the ceremony completes, which is what lets
// the rest of the rule be asserted in the same pass.
func TestCrossUser_PromptLogin_BindsToTheAuthenticatingUsersSession(t *testing.T) {
	b := createCrossUserBrowser(t, enums.AcrLevel2Optional, enums.AcrLevel2Optional)

	codeVal := signInWithPassword(t, b.jar, crossUserAuthorizeUrl(b, "&prompt=login"),
		b.userB.Email, b.passwordB, true, "")

	assertCeremonyBoundToUserB(t, b, codeVal)
}

// TestCrossUser_IdTokenHintNamingTheNewUser_DoesNotInheritTheOldSessionsAcr covers the second entry
// path, and it is the shape that minted a cross-bound code.
//
// An id_token_hint naming a third party is refused at /auth/issue, where the hint's subject is
// compared with the authenticated user. A hint naming B is the ordinary use of the parameter, a
// relying party saying who should sign in, so nothing refuses it and a code really is issued.
//
// Its own assertion is decision 3, the ACR. The ceremony asks for level1 while A's session holds
// level2_optional, and the ACR used to be the maximum taken against whatever session the browser
// carried, so B left with a token claiming a second factor B never presented and A's session was
// the only evidence for it.
//
// A really did present that second factor here, so A's session records "pwd otp" against B's "pwd".
// The methods assertions in the shared block are therefore about provenance and not only about
// value: the thing they forbid is a value sitting on the row this ceremony was cookied to.
func TestCrossUser_IdTokenHintNamingTheNewUser_DoesNotInheritTheOldSessionsAcr(t *testing.T) {
	// A level1 client, with A stepping up to level2_optional by asking for it. The client has to
	// stay at level1 for this case to keep discriminating: B's ceremony asks for level1, and the
	// floor would otherwise raise B's target to the client's level, making the value the test
	// expects and the value it forbids the same string (#240, decision 5).
	b := createCrossUserBrowser(t, enums.AcrLevel1, enums.AcrLevel2Optional)

	// B's ID token has to come from somewhere, so B signs in once on a browser of their own. That
	// session is swept away when B's ceremony below mints its own, since StartNewUserSession deletes
	// the new user's other sessions on the same device and address, which is why the shared block
	// can still insist B holds exactly one session at the end.
	level1 := "&acr_values=" + url.QueryEscape(enums.AcrLevel1.String())
	otherBrowser := createHttpClient(t)
	hintCodeVal := signInWithPassword(t, otherBrowser, crossUserAuthorizeUrl(b, level1),
		b.userB.Email, b.passwordB, false, "")
	hintTokenData := redeemCrossUserCode(t, b, otherBrowser, hintCodeVal)
	idTokenUserB, ok := hintTokenData["id_token"].(string)
	require.True(t, ok, "expected an id_token for the hint, got %v", hintTokenData)

	codeVal := signInWithPassword(t, b.jar,
		crossUserAuthorizeUrl(b, level1+"&id_token_hint="+url.QueryEscape(idTokenUserB)),
		b.userB.Email, b.passwordB, false, "")

	code := loadCodeFromDatabase(t, codeVal)
	assert.Equal(t, enums.AcrLevel1.String(), code.AcrLevel,
		"the acr must describe this ceremony, not the session the browser arrived with")

	assertCeremonyBoundToUserB(t, b, codeVal)
}

// TestCrossUser_ExpiredForeignSession_BindsToTheAuthenticatingUsersSession covers the third entry
// path, the one neither prompt=login nor an id_token_hint reaches.
//
// max_age=0 makes HasValidUserSession refuse a session that is otherwise perfectly alive: the
// request carries no prompt, so HandleAuthorizeGet loads A's session, finds it too old for the
// requested max_age and leaves at its final return. The row survives and so does the cookie, so the
// handover happens with an invalid foreign session rather than a valid one, which decision 4 treats
// the same way and for the same reason: a row nobody can resume is worth nothing to A and its
// grants are still live.
//
// The chain is the assertion that pins the path. Send the same request without max_age=0 and A's
// session is reused, so /auth/authorize answers /auth/level1completed and B never sees a password
// form; here it answers /auth/level1.
func TestCrossUser_ExpiredForeignSession_BindsToTheAuthenticatingUsersSession(t *testing.T) {
	b := createCrossUserBrowser(t, enums.AcrLevel1, enums.AcrLevel1)

	codeVal := signInWithPassword(t, b.jar, crossUserAuthorizeUrl(b, "&max_age=0"),
		b.userB.Email, b.passwordB, false, "")

	assertCeremonyBoundToUserB(t, b, codeVal)
}
