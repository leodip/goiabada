package integrationtests

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/testutil/fake"
	"github.com/stretchr/testify/assert"
)

// browserPause is how long the ceremony sits after the password is accepted and before the
// redirect chain that completes it. It is the whole instrument of this file: the credential's
// instant and the completion's instant are the same number until something separates them, so
// without a pause a token carrying either one passes.
//
// Two seconds rather than something longer because auth_time is emitted as Unix seconds and the
// assertions compare on that grid: one second of truncation has to be small against the gap. It
// is also two seconds added to the integration tier, so it buys the separation and no more.
const browserPause = 2 * time.Second

// pausedCeremony is what one such ceremony observed: the claim, and the two windows it has to be
// told apart from.
type pausedCeremony struct {
	authTime  time.Time
	sid       string
	pwdBefore time.Time // just before the password POST
	pwdAfter  time.Time // just after it returned
	resumedAt time.Time // after the pause, when the browser went on to /auth/level1completed
}

// TestAuthTime_IsTheInstantTheCredentialWasAccepted drives the whole stack, both session arms,
// and asserts the ID token's auth_time names the moment the password was accepted rather than
// the moment the ceremony finished.
//
// OIDC Core 1.0 section 3.1.2.1 defines max_age as "the allowable elapsed time in seconds since
// the last time the End-User was actively authenticated by the OP", and section 2 defines
// auth_time as the "Time when the End-User authentication occurred". A relying party that wants
// a guaranteed-fresh sign-in before something sensitive sends max_age and then reads auth_time
// out of the token to check it got one.
//
// The two instants are milliseconds apart until a browser pauses, and the browser owns that gap:
// /auth/pwd accepts the credential, then the browser is redirected onward to /auth/completed,
// which is where the session row is written. A tab left sitting after the password was accepted
// and resumed later used to produce a token saying the user had actively authenticated just now,
// so a relying party asking for a fresh sign-in was told it got one, about whoever was holding
// that browser when it resumed (#252 decision 8).
//
// Unit coverage for the two writes is in handler_auth_completed_test.go and
// usersession_manager_start_test.go. This test exists because those mock the layer below them:
// only a real ceremony shows the value surviving the AuthContext, the code row and the token
// issuer to reach the claim a relying party actually reads.
func TestAuthTime_IsTheInstantTheCredentialWasAccepted(t *testing.T) {
	clientSecret := fake.Password(32)
	clientSecretEncrypted, err := encryption.EncryptData(clientSecret)
	if err != nil {
		t.Fatal(err)
	}

	client := &models.Client{
		ClientIdentifier:                        "test-client-" + fake.LetterN(8),
		ClientSecretEncrypted:                   clientSecretEncrypted,
		Enabled:                                 true,
		AuthorizationCodeEnabled:                true,
		ConsentRequired:                         false,
		DefaultAcrLevel:                         enums.AcrLevel1,
		TokenExpirationInSeconds:                300,
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 86400,
	}
	if err := database.CreateClient(nil, client); err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      "https://example.com/callback",
	}
	if err := database.CreateRedirectURI(nil, redirectUri); err != nil {
		t.Fatal(err)
	}

	password := fake.Password(8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      fake.UUID(),
		Enabled:      true,
		Email:        fake.Email(),
		PasswordHash: passwordHashed,
	}
	if err := database.CreateUser(nil, user); err != nil {
		t.Fatal(err)
	}

	// One client for both ceremonies, so the second arrives carrying the first's cookie, which
	// is what makes it the reuse arm.
	httpClient := createHttpClient(t)

	// The create arm: nothing in the jar yet, so /auth/completed mints a session and
	// StartNewUserSession stamps AuthTime.
	created := runPausedCeremony(t, httpClient, client.ClientIdentifier, clientSecret,
		redirectUri.URI, user.Email, password, "")
	assertAuthTimeIsTheCredentialInstant(t, created, "create arm")

	// The reuse arm: the same browser, prompt=login, so the ceremony re-authenticates against
	// the session it already holds and /auth/completed refreshes that row's AuthTime instead.
	reused := runPausedCeremony(t, httpClient, client.ClientIdentifier, clientSecret,
		redirectUri.URI, user.Email, password, "&prompt=login")
	assertAuthTimeIsTheCredentialInstant(t, reused, "reuse arm")

	// sid is the user session's identifier, and a bump leaves it alone where a fresh session
	// mints a new one. Equal here is what says the second ceremony really took the reuse arm
	// rather than quietly exercising the create arm twice.
	assert.NotEmpty(t, created.sid, "the ID token must carry sid for this comparison to mean anything")
	assert.Equal(t, created.sid, reused.sid,
		"prompt=login in the same browser must reuse the session, so that the second ceremony "+
			"exercises the bump arm of /auth/completed and not the create arm again")

	// And the refresh really moved: the two ceremonies are at least a pause apart, so a reuse
	// arm that failed to write at all would show up here as an unchanged claim.
	assert.True(t, reused.authTime.After(created.authTime),
		"re-authenticating must move auth_time forward (first=%v, second=%v)",
		created.authTime, reused.authTime)
}

// assertAuthTimeIsTheCredentialInstant holds the claim to the window the password was accepted
// in, and away from the window the ceremony completed in.
func assertAuthTimeIsTheCredentialInstant(t *testing.T, c pausedCeremony, arm string) {
	t.Helper()

	// auth_time is emitted as Unix seconds, so every comparison is on that grid: truncation
	// only ever moves a value down, which keeps both bounds below honest.
	assert.GreaterOrEqual(t, c.authTime.Unix(), c.pwdBefore.Unix(),
		"%s: auth_time %v must not predate the password submission at %v", arm, c.authTime, c.pwdBefore)
	assert.LessOrEqual(t, c.authTime.Unix(), c.pwdAfter.Unix(),
		"%s: auth_time %v must be the instant the password was accepted, and the POST had "+
			"returned by %v", arm, c.authTime, c.pwdAfter)

	// The one that fails if the handler reads its own clock: the ceremony did not resume until
	// resumedAt, so a completion-time stamp lands at or after it.
	assert.Less(t, c.authTime.Unix(), c.resumedAt.Unix(),
		"%s: auth_time %v names the completion of the ceremony rather than the credential; the "+
			"browser only resumed at %v, so a relying party sending max_age would be told this "+
			"sign-in was %v fresher than it is",
		arm, c.authTime, c.resumedAt, c.resumedAt.Sub(c.authTime))
}

// runPausedCeremony drives one authorization code ceremony to a token, pausing between the
// password being accepted and the redirect chain that completes it. prompt is appended to the
// authorization request verbatim, so "" is a plain sign-in and "&prompt=login" forces one.
func runPausedCeremony(t *testing.T, httpClient *http.Client, clientIdentifier string,
	clientSecret string, redirectUri string, email string, password string,
	prompt string) pausedCeremony {

	t.Helper()

	codeVerifier := "code-verifier-" + fake.LetterN(16)
	codeChallenge := oauth.GeneratePKCECodeChallenge(codeVerifier)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + clientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + codeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + fake.LetterN(8) +
		"&nonce=" + fake.LetterN(8) +
		prompt

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// The credential's window. Bracketing the POST rather than reading the clock once is what
	// makes the assertions exact without depending on how long the hash took.
	pwdBefore := time.Now().UTC()
	resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, email, password)
	pwdAfter := time.Now().UTC()
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")

	// The browser pauses here, holding a redirect it has not followed. Everything after this
	// point runs at least browserPause after the password was accepted.
	time.Sleep(browserPause)
	resumedAt := time.Now().UTC()

	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	code, _ := getCodeAndStateFromUrl(t, resp)

	data := postToTokenEndpoint(t, httpClient, config.GetAuthServer().BaseURL+"/auth/token",
		url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {clientIdentifier},
			"client_secret": {clientSecret},
			"code":          {code},
			"redirect_uri":  {redirectUri},
			"code_verifier": {codeVerifier},
		})

	idToken, ok := data["id_token"].(string)
	if !ok {
		t.Fatalf("the token response carried no id_token: %v", data)
	}
	claims := decodeJWTPayload(t, idToken)

	authTime, ok := claims["auth_time"].(float64)
	if !ok {
		t.Fatalf("the ID token carried no auth_time claim: %v", claims)
	}
	sid, _ := claims["sid"].(string)

	return pausedCeremony{
		authTime:  time.Unix(int64(authTime), 0).UTC(),
		sid:       sid,
		pwdBefore: pwdBefore,
		pwdAfter:  pwdAfter,
		resumedAt: resumedAt,
	}
}
