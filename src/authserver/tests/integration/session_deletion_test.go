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
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

// TestSessionDeletedDuringAuthFlow_LoginSucceeds tests that when a user's database session
// is deleted while they are in the middle of an auth flow (e.g., on the password page),
// submitting credentials still succeeds because the AuthContext is preserved in the
// session cookie.
//
// This is a regression test for GitHub issue #46:
// "Login fails silently when database session is deleted during auth flow"
//
// The bug scenario:
// 1. User has a session cookie with SessionKeySessionIdentifier pointing to a DB session
// 2. That DB session gets deleted (expired, deployment, manual cleanup)
// 3. User starts a new auth flow - browser still has the old session cookie
// 4. Middleware clears session identifier but previously also cleared AuthContext (bug)
// 5. User submits credentials on /auth/pwd
// 6. Before fix: Login failed silently (AuthContext was cleared)
// 7. After fix: Login succeeds (AuthContext preserved)
func TestSessionDeletedDuringAuthFlow_LoginSucceeds(t *testing.T) {
	// Step 1: Create a client and user for testing
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel1,
	}
	err := database.CreateClient(nil, client)
	assert.NoError(t, err)

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}
	err = database.CreateRedirectURI(nil, redirectUri)
	assert.NoError(t, err)

	password := gofakeit.Password(true, true, true, true, false, 8)
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

	// Step 2: Complete a full login to create a session in the database
	httpClient := createHttpClient(t)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	resp, err := httpClient.Get(destUrl)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// Verify login succeeded
	_, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	// Step 3: Verify a session was created in the database
	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(userSessions), "Should have exactly one session after login")

	userSession := userSessions[0]

	// Step 4: Delete the session from the database (simulating expiry/deployment)
	err = database.DeleteUserSession(nil, userSession.Id)
	assert.NoError(t, err)

	// Verify session is deleted
	deletedSession, err := database.GetUserSessionBySessionIdentifier(nil, userSession.SessionIdentifier)
	assert.NoError(t, err)
	assert.Nil(t, deletedSession, "Session should be deleted from database")

	// Step 5: Start a NEW auth flow with the same httpClient (which still has the old session cookie)
	// This simulates the user clicking "Login" again after their DB session was deleted
	requestCodeChallenge2 := gofakeit.LetterN(43)
	requestState2 := gofakeit.LetterN(8)
	requestNonce2 := gofakeit.LetterN(8)

	destUrl2 := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge2 +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState2 +
		"&nonce=" + requestNonce2

	resp2, err := httpClient.Get(destUrl2)
	assert.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()

	// Should redirect to /auth/level1 (starting the auth flow)
	redirectLocation2 := assertRedirect(t, resp2, "/auth/level1")
	resp2 = loadPage(t, httpClient, redirectLocation2)
	defer func() { _ = resp2.Body.Close() }()

	// Should redirect to /auth/pwd (password page)
	redirectLocation2 = assertRedirect(t, resp2, "/auth/pwd")
	resp2 = loadPage(t, httpClient, redirectLocation2)
	defer func() { _ = resp2.Body.Close() }()

	// Step 6: Submit credentials

	resp2 = authenticateWithPassword(t, httpClient, redirectLocation2, user.Email, password)
	defer func() { _ = resp2.Body.Close() }()

	// Step 7: CRITICAL TEST - After the fix, login should succeed
	// Before the fix, this would redirect back to /auth/pwd (silent failure)
	// After the fix, this should redirect to /auth/level1completed
	redirectLocation2 = assertRedirect(t, resp2, "/auth/level1completed")
	resp2 = loadPage(t, httpClient, redirectLocation2)
	defer func() { _ = resp2.Body.Close() }()

	// Continue the flow to verify it completes successfully
	redirectLocation2 = assertRedirect(t, resp2, "/auth/completed")
	resp2 = loadPage(t, httpClient, redirectLocation2)
	defer func() { _ = resp2.Body.Close() }()

	redirectLocation2 = assertRedirect(t, resp2, "/auth/issue")
	resp2 = loadPage(t, httpClient, redirectLocation2)
	defer func() { _ = resp2.Body.Close() }()

	// Step 8: Verify the second login also succeeded and we got a code
	codeVal2, stateVal2 := getCodeAndStateFromUrl(t, resp2)
	assert.Equal(t, requestState2, stateVal2)
	assert.NotEmpty(t, codeVal2)

	// Verify a new session was created
	userSessions2, err := database.GetUserSessionsByUserId(nil, user.Id)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(userSessions2), "Should have a new session after second login")
}

// TestSessionEndedOnConsentScreen_NoCodeIsIssued is the third of this file's paired
// ceremonies, and it covers the half of #129 gap 3 that the gate at /auth/completed cannot
// reach (decision 6's second half, plus decision 12).
//
// Here the session is alive all the way through /auth/completed, which bumps or creates it,
// so that gate passes legitimately. The user is then parked on the consent screen, which is
// where the window widens from milliseconds to however long a person takes to click, and the
// session is ended while they sit there. HandleConsentPost reads no session row, so the
// submission proceeds exactly as always and hands off to /auth/issue.
//
// Nothing written at termination can reach the code /auth/issue would mint, because that row
// does not exist yet when RevokeCodesBySessionIdentifier runs. Only the liveness check at
// /auth/issue stops it, and the code is worth stopping: an empty session identifier alone
// makes grantIsOffline true, so the refresh token that code yields would be stored as an
// Offline one, with a max lifetime and no session for the validator to consult, whether or
// not offline_access was ever requested.
//
// The pairing with the two tests around it is the point. This one varies the window rather
// than the credential: a password really was entered in this ceremony, so a predicate keyed
// on authentication passes and only one keyed on the session refuses.
func TestSessionEndedOnConsentScreen_NoCodeIsIssued(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		// The consent screen is what holds the ceremony still between /auth/completed and
		// /auth/issue, which is the whole window this case is about.
		ConsentRequired: true,
		DefaultAcrLevel: enums.AcrLevel1,
	}
	err := database.CreateClient(nil, client)
	assert.NoError(t, err)

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}
	err = database.CreateRedirectURI(nil, redirectUri)
	assert.NoError(t, err)

	password := gofakeit.Password(true, true, true, true, false, 8)
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

	// One HTTP client throughout, so the cookie is shared and this is one browser's ceremony
	// rather than two.
	httpClient := createHttpClient(t)

	requestState := gofakeit.LetterN(8)
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + gofakeit.LetterN(43) +
		"&scope=" + url.QueryEscape("openid profile email") +
		"&state=" + requestState +
		"&nonce=" + gofakeit.LetterN(8)

	resp, err := httpClient.Get(destUrl)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// A password IS entered here, unlike the OTP case below. That is what makes this ceremony
	// legitimate up to the consent screen and what makes /auth/issue the only hop that can
	// refuse it.
	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// Consent, not /auth/issue: the ceremony now waits for a person.
	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// The session exists at this point, created by /auth/completed while it was legitimately
	// reached. Ending it is what the rest of the case turns on.
	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(userSessions), "the ceremony should have created one session before consent")

	// Deleting the row directly, as this file's other tests do: that the two DELETE endpoints
	// also revoke the session's grants is covered by api_users_sessions_test.go and
	// api_account_sessions_test.go, and what this case needs is the session gone.
	err = database.DeleteUserSession(nil, userSessions[0].Id)
	assert.NoError(t, err)

	consentEndpoint := config.GetAuthServer().BaseURL + "/auth/consent"
	consentForm := url.Values{
		"btnSubmit": {"submit"},
		"consent0":  {"on"},
		"consent1":  {"on"},
		"consent2":  {"on"},
	}
	consentReq, err := http.NewRequest("POST", consentEndpoint, strings.NewReader(consentForm.Encode()))
	assert.NoError(t, err)
	consentReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	consentReq.Header.Set("Referer", consentEndpoint)
	consentReq.Header.Set("Origin", config.GetAuthServer().BaseURL)

	resp, err = httpClient.Do(consentReq)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// The consent submission itself succeeds, and asserting that is deliberate: it reads no
	// session row, so the termination is invisible to it. This is what makes the next hop the
	// load-bearing one rather than an incidental one.
	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// The liveness check. Before #129 stage 6 this redirected to the client with a usable code
	// bound to a session that no longer existed.
	redirectLocation = assertRedirect(t, resp, "/auth/level1")
	assert.NotContains(t, redirectLocation, "code=",
		"no authorization code may reach the client once the session backing the ceremony is gone")

	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// And the restart is a real one: the user is asked for a password again.
	assertRedirect(t, resp, "/auth/pwd")

	userSessionsAfter, err := database.GetUserSessionsByUserId(nil, user.Id)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(userSessionsAfter),
		"the ended session must not be recreated by a ceremony waiting on the consent screen")
}

// TestSessionEndedDuringStepUp_OtpAloneDoesNotRecreateTheSession is the pair of the test
// above, and the case that decided #129 decision 15.
//
// The ceremony here never enters a password. It reuses an existing level 1 session, is sent
// to /auth/otp because the client asks for level2_mandatory, and the session is ended while
// it sits on the OTP form. HandleAuthOtpPost reads no session row, so the termination is
// invisible to it: it verifies the code and hands off to /auth/completed with
// AuthenticatedAt set. Only the gate there stops the ceremony, and only because it reads
// Level1AuthCompleted rather than AuthenticatedAt.
//
// Without that distinction the ended session is silently recreated, which is the defect
// #129 exists to close. The sub-case that makes it serious is a user without OTP on a
// level2_mandatory client: the enrollment page hands the browser the secret it will be
// tested on, so a stolen session cookie alone is enough to reach here.
//
// This is the same shape as TestSessionDeletedDuringAuthFlow_LoginSucceeds above, varying
// exactly one thing: whether a password was entered in this ceremony. That pairing is what
// pins the predicate as "this ceremony did level 1" rather than "no valid session".
func TestSessionEndedDuringStepUp_OtpAloneDoesNotRecreateTheSession(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel1(t)

	// Give the user OTP, so /auth/level2 sends the step-up to the OTP form rather than
	// to enrollment. Either arrives at the same gate; this is the shorter route.
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Goiabada",
		AccountName: user.Email,
	})
	if err != nil {
		t.Fatal(err)
	}
	user.OTPEnabled = true
	user.OTPSecret = key.Secret()
	user.OTPSecretEncrypted = encryptOTPSecretForTest(t, key.Secret())
	err = database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(userSessions), "the level 1 login should have left one session")
	userSession := userSessions[0]

	// A second authorization request on the same browser, asking for level 2. The session
	// is reused, so this ceremony never reaches the password handler.
	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel2Mandatory.String()

	resp, err := httpClient.Get(destUrl)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Straight to level1completed: the session covers level 1, no password is asked for.
	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// The session is ended while the ceremony waits on the OTP form. Deleting the row is
	// what the gate keys on, and it is how this file's other test ends a session too; that
	// the two DELETE endpoints revoke the session's grants as well is covered by
	// api_users_sessions_test.go and api_account_sessions_test.go.
	err = database.DeleteUserSession(nil, userSession.Id)
	assert.NoError(t, err)

	otpCode, err := totp.GenerateCode(user.OTPSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = authenticateWithOtp(t, httpClient, redirectLocation, otpCode)
	defer func() { _ = resp.Body.Close() }()

	// The OTP itself is accepted: the handler reads no session row, so it cannot see the
	// termination. Asserting this rather than a failure here is deliberate, because it is
	// what makes the next hop the load-bearing one.
	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// The gate. Before #129 this went to /auth/issue with a recreated session behind it.
	redirectLocation = assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// And the restart is a real one: the user is asked for a password.
	assertRedirect(t, resp, "/auth/pwd")

	userSessionsAfter, err := database.GetUserSessionsByUserId(nil, user.Id)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(userSessionsAfter),
		"the ended session must not be recreated by a ceremony that only verified OTP")
}

// TestSessionEndedBeforeIssue_PromptNoneGetsLoginRequired is the fourth of this file's
// ceremonies, and the case that decided #129 decision 16.
//
// It is the same window as TestSessionEndedOnConsentScreen_NoCodeIsIssued, entered by the
// other door. handlePromptNone runs its silent checks, bumps the session and redirects to
// /auth/issue; the session is ended in that one hop; and the liveness check at /auth/issue
// finds the identifier gone exactly as it does for the consent-screen ceremony.
//
// What differs is the outcome, and that is the point of the pairing. The consent-screen
// ceremony is restarted at level 1 and arrives at a password form. This one must never see a
// page at all: prompt=none forbids UI, and nothing between /auth/issue and /auth/pwd reads
// the prompt, so a restart would hand a silent-renewal iframe a login screen and no error,
// which it cannot tell from a hang. It gets login_required instead, which is what
// handlePromptNone itself returns when its own session lookup finds no row.
func TestSessionEndedBeforeIssue_PromptNoneGetsLoginRequired(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel1(t)

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(userSessions), "the level 1 login should have left one session")
	userSession := userSessions[0]

	// A second authorization on the same browser, silent this time. The client does not
	// require consent, so with a live session behind it this goes straight to /auth/issue.
	requestState := gofakeit.LetterN(8)
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + gofakeit.LetterN(43) +
		"&scope=" + url.QueryEscape("openid profile email") +
		"&state=" + requestState +
		"&nonce=" + gofakeit.LetterN(8) +
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// handlePromptNone accepted the session and handed off. Asserting that rather than an
	// error here is deliberate: it is what puts the whole window in the next hop.
	redirectLocation := assertRedirect(t, resp, "/auth/issue")

	// The session is ended between the 302 and the browser following it. This is the narrowest
	// window in gap 3 and the only one prompt=none can sit in, since it never waits for a
	// person.
	err = database.DeleteUserSession(nil, userSession.Id)
	assert.NoError(t, err)

	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// Back to the client with an error, rather than on to a password form.
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	location := resp.Header.Get("Location")
	assert.Contains(t, location, redirectUri.URI,
		"a silent ceremony must be answered at the client's redirect URI, not with a page")
	assert.NotContains(t, location, "/auth/level1",
		"prompt=none must not be restarted into the interactive flow")

	errorCode, _, state := getErrorFromUrl(t, resp)
	assert.Equal(t, "login_required", errorCode)
	assert.Equal(t, requestState, state, "the client's state must survive the error response")

	parsedLocation, err := url.Parse(location)
	assert.NoError(t, err)
	assert.Empty(t, parsedLocation.Query().Get("code"),
		"no authorization code may reach the client once the session backing the ceremony is gone")

	userSessionsAfter, err := database.GetUserSessionsByUserId(nil, user.Id)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(userSessionsAfter),
		"a refused silent ceremony must not recreate the ended session")

	// The refusal also has to leave the browser with no ceremony to replay, and only a
	// second request can see that. Clearing the auth context persists through a Set-Cookie,
	// so it reaches this jar only if the handler cleared before committing the redirect;
	// clearing afterwards would answer login_required again here, from a context still
	// reading ready_to_issue_code. With the context gone the handler has nothing to resume
	// and sends the browser to the account profile instead.
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	replayLocation := resp.Header.Get("Location")
	assert.Contains(t, replayLocation, "/account/profile",
		"the refusal must clear the auth context in the browser, so a replayed /auth/issue has no ceremony left")
	assert.NotContains(t, replayLocation, redirectUri.URI,
		"a cleared ceremony must not answer the client a second time")
}
