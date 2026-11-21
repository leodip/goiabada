package integration

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/otp/otptest"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
)

// createConsentClient makes a client whose authorization always reaches the consent screen.
func createConsentClient(t *testing.T) (*record.Client, *record.RedirectURI) {
	return createLevel1Client(t, true)
}

// createLevel1Client makes a password-only client. Without consent it is the sharpest second tab
// for the password case: its authorization needs no screen after the password, so under the defect
// a stale login form finished it and the code was issued with nothing shown to the user at all.
func createLevel1Client(t *testing.T, consentRequired bool) (*record.Client, *record.RedirectURI) {
	client := &record.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          consentRequired,
		DefaultACRLevel:          record.ACRLevel1,
	}
	if err := database.CreateClient(context.Background(), nil, client); err != nil {
		t.Fatal(err)
	}

	redirectURI := &record.RedirectURI{
		ClientID: client.ID,
		URI:      fake.URL(),
	}
	if err := database.CreateRedirectURI(context.Background(), nil, redirectURI); err != nil {
		t.Fatal(err)
	}
	return client, redirectURI
}

// createCeremonyUser makes an enabled user with a password, and returns that password.
func createCeremonyUser(t *testing.T) (*record.User, string) {
	password := fake.Password(8)
	passwordHashed, err := passwordhash.Hash(password)
	if err != nil {
		t.Fatal(err)
	}

	user := &record.User{
		Subject:      fake.UUID(),
		Enabled:      true,
		Email:        fake.Email(),
		PasswordHash: passwordHashed,
	}
	if err := database.CreateUser(context.Background(), nil, user); err != nil {
		t.Fatal(err)
	}
	return user, password
}

// assertCeremonyMismatchPage asserts a submission drew the refusal decision 5 promises: the 400
// error page, and no redirect at all, least of all to /auth/issue.
func assertCeremonyMismatchPage(t *testing.T, resp *http.Response, what string) {
	t.Helper()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"%s of a sign-in the browser no longer holds must be refused", what)
	assert.Empty(t, resp.Header.Get("Location"),
		"the refusal must not redirect anywhere, least of all to /auth/issue")

	doc := parseHTMLResponse(t, resp)
	assert.NotEmpty(t, doc.Find("#errorMsg").Text(), "the refusal renders the auth error page")
}

// assertNothingWasCompleted asserts the refused submission advanced no ceremony. A session is
// created at /auth/completed, which is past both bound forms, so a user session existing at this
// point means a stale form finished somebody's authorization.
func assertNothingWasCompleted(t *testing.T, userID int64) {
	t.Helper()

	sessions, err := database.GetUserSessionsByUserID(context.Background(), nil, userID)
	if err != nil {
		t.Fatal(err)
	}
	assert.Empty(t, sessions, "the refused submission must not have authenticated anybody")
}

func authorizeURLFor(client *record.Client, redirectURI *record.RedirectURI, scope string,
	state string) string {
	return appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + randomCodeChallenge() +
		"&scope=" + url.QueryEscape(scope) +
		"&state=" + state +
		"&nonce=" + fake.LetterN(8)
}

// assertCodeFor follows a step's redirect to /auth/issue and asserts the code it issues answers the
// request state was sent with, for client at redirectURI, and nothing else.
func assertCodeFor(t *testing.T, httpClient *http.Client, issueLocation string, client *record.Client,
	redirectURI *record.RedirectURI, state string) *record.Code {
	t.Helper()

	resp := loadPage(t, httpClient, issueLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromURL(t, resp)
	assert.Equal(t, state, stateVal, "the code answers its own request, and no other")

	code := loadCodeFromDatabase(t, codeVal)
	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, redirectURI.URI, code.RedirectURI)
	return code
}

// TestAuthorize_ConsentFormsOfTwoSignInsInOneBrowserEachFinishTheirOwn walks two consent screens of
// one browser end to end.
//
// Client A's consent screen is on the user's screen when client B's authorization runs in another
// tab of the same browser and reaches its own. Both screens post to the same URL, and the checkbox
// names are positional, so the boxes ticked on A's screen must resolve against A's scope list and
// no other: before #79 a browser held one sign-in and A's ticks were applied to B's request. Now the
// browser holds both, and each form finishes the sign-in it belongs to, with the scopes ticked on
// its own screen (#246).
func TestAuthorize_ConsentFormsOfTwoSignInsInOneBrowserEachFinishTheirOwn(t *testing.T) {
	clientA, redirectURIA := createConsentClient(t)
	clientB, redirectURIB := createConsentClient(t)

	user, password := createCeremonyUser(t)

	httpClient := createHTTPClient(t)

	// Client A's authorization, all the way to its consent screen.
	stateA := fake.LetterN(8)
	resp, err := httpClient.Get(authorizeURLFor(clientA, redirectURIA, "openid profile email", stateA))
	if err != nil {
		t.Fatal(err)
	}
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, user.Email, password)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	consentURL := assertRedirect(t, resp, "/auth/consent")
	consentPageA := loadPage(t, httpClient, consentURL)
	defer func() { _ = consentPageA.Body.Close() }()

	ceremonyA := getCeremonyIDFromPage(t, consentPageA)

	// The second tab. Client B's authorization runs on the same browser, reusing the session A's
	// ceremony created, and its sign-in is held beside A's. A's consent screen is still on screen.
	stateB := fake.LetterN(8)
	resp, err = httpClient.Get(authorizeURLFor(clientB, redirectURIB, "openid profile", stateB))
	if err != nil {
		t.Fatal(err)
	}
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	consentURLB := assertRedirect(t, resp, "/auth/consent")
	consentPageB := loadPage(t, httpClient, consentURLB)
	defer func() { _ = consentPageB.Body.Close() }()

	ceremonyB := getCeremonyIDFromPage(t, consentPageB)
	assert.NotEqual(t, ceremonyA, ceremonyB,
		"each authorization request must render its own ceremony id, or nothing is bound")

	// The user, still looking at A's screen, submits it, with the first and third boxes ticked: on
	// A's list openid and email, a position B's two-scope list does not even have.
	resp = postConsent(t, httpClient, consentURL, consentPageA, []int{0, 2})
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	codeA := assertCodeFor(t, httpClient, assertRedirect(t, resp, "/auth/issue"), clientA, redirectURIA, stateA)
	assert.Equal(t, "openid email", codeA.Scope, "A's ticks resolved against A's own scope list")

	// And B's own screen completes, in its own tab, with exactly the scopes ticked on it.
	resp = postConsent(t, httpClient, consentURLB, consentPageB, []int{0, 1})
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	codeB := assertCodeFor(t, httpClient, assertRedirect(t, resp, "/auth/issue"), clientB, redirectURIB, stateB)
	assert.Equal(t, "openid profile", codeB.Scope)

	for client, scope := range map[*record.Client]string{clientA: "openid email", clientB: "openid profile"} {
		consent, getConsentErr := database.GetConsentByUserIDAndClientID(context.Background(), nil, user.ID, client.ID)
		if getConsentErr != nil {
			t.Fatal(getConsentErr)
		}
		if assert.NotNil(t, consent, "%s was consented to on its own screen", client.ClientIdentifier) {
			assert.Equal(t, scope, consent.Scope, "%s holds the scopes ticked on its own screen", client.ClientIdentifier)
		}
	}
}

// TestAuthorize_PasswordFormsOfTwoSignInsInOneBrowserEachFinishTheirOwn is the more direct path #79
// decision 6 was settled on, and the reason the binding is not the consent form's alone.
//
// The user is at client A's login screen when client B opens in another tab of the same browser and
// reaches its own. The user types their password into A's screen. Before #79 that authenticated them
// against B's request, the one the browser then held, and B was handed a code with no screen ever
// shown for it. Now the browser holds both: A's form finishes A's request, and B's own form, loaded
// before A's was submitted, still finishes B's (#246).
func TestAuthorize_PasswordFormsOfTwoSignInsInOneBrowserEachFinishTheirOwn(t *testing.T) {
	clientA, redirectURIA := createLevel1Client(t, false)
	clientB, redirectURIB := createLevel1Client(t, false)
	user, password := createCeremonyUser(t)

	httpClient := createHTTPClient(t)

	stateA := fake.LetterN(8)
	pwdURLA, pwdPageA := walkToPasswordPage(t, httpClient, clientA, redirectURIA, stateA)
	defer func() { _ = pwdPageA.Body.Close() }()
	ceremonyA := getCeremonyIDFromPage(t, pwdPageA)

	// The second tab, on the same browser. A's login screen is still on the user's screen.
	stateB := fake.LetterN(8)
	pwdURLB, pwdPageB := walkToPasswordPage(t, httpClient, clientB, redirectURIB, stateB)
	defer func() { _ = pwdPageB.Body.Close() }()

	ceremonyB := getCeremonyIDFromPage(t, pwdPageB)
	assert.NotEqual(t, ceremonyA, ceremonyB,
		"each authorization request must render its own ceremony id, or nothing is bound")

	// The user, still looking at A's screen, signs in there, and A's request gets its code.
	for _, signIn := range []struct {
		pwdURL      string
		pwdPage     *http.Response
		client      *record.Client
		redirectURI *record.RedirectURI
		state       string
	}{
		{pwdURLA, pwdPageA, clientA, redirectURIA, stateA},
		{pwdURLB, pwdPageB, clientB, redirectURIB, stateB},
	} {
		resp := authenticateWithPassword(t, httpClient, signIn.pwdURL, signIn.pwdPage, user.Email, password)
		defer func(r *http.Response) { _ = r.Body.Close() }(resp)

		location := assertRedirect(t, resp, "/auth/level1completed")
		resp = loadPage(t, httpClient, location)
		defer func(r *http.Response) { _ = r.Body.Close() }(resp)

		location = assertRedirect(t, resp, "/auth/completed")
		resp = loadPage(t, httpClient, location)
		defer func(r *http.Response) { _ = r.Body.Close() }(resp)

		assertCodeFor(t, httpClient, assertRedirect(t, resp, "/auth/issue"), signIn.client, signIn.redirectURI, signIn.state)
	}
}

// walkToOTPPrompt drives one authorization request from /auth/authorize to the OTP prompt, on an
// http client the caller owns. startOTPCeremony cannot be used here: it creates a fresh cookie jar
// per call, and this case needs two ceremonies in ONE browser, which is the whole defect.
func walkToOTPPrompt(t *testing.T, httpClient *http.Client, client *record.Client,
	redirectURI *record.RedirectURI, state string, user *record.User, password string) (string, *http.Response) {

	t.Helper()

	resp, err := httpClient.Get(authorizeURLFor(client, redirectURI, "openid profile email", state))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	_ = resp.Body.Close()

	pwdURL := assertRedirect(t, resp, "/auth/pwd")
	pwdPage := loadPage(t, httpClient, pwdURL)

	resp = authenticateWithPassword(t, httpClient, pwdURL, pwdPage, user.Email, password)
	_ = pwdPage.Body.Close()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)

	otpURL := assertRedirect(t, resp, "/auth/otp")
	_ = resp.Body.Close()

	// Caller closes this one.
	return otpURL, loadPage(t, httpClient, otpURL)
}

// TestAuthorize_OTPFormsOfTwoSignInsInOneBrowserEachFinishTheirOwn is the same one factor up.
//
// The user is at client A's OTP prompt when client B's authorization reaches its own in another tab
// of the same browser. A code entered on A's prompt finishes A's request, and the next code, entered
// on B's prompt, finishes B's: neither tab took anything away from the other (#246).
func TestAuthorize_OTPFormsOfTwoSignInsInOneBrowserEachFinishTheirOwn(t *testing.T) {
	clientA, redirectURIA, user, password, otpSecret := createLevel2MandatoryUser(t, true)
	clientB, redirectURIB := createLevel2MandatoryClient(t)

	httpClient := createHTTPClient(t)

	stateA := fake.LetterN(8)
	otpURLA, otpPageA := walkToOTPPrompt(t, httpClient, clientA, redirectURIA, stateA, user, password)
	defer func() { _ = otpPageA.Body.Close() }()

	ceremonyA := getCeremonyIDFromPage(t, otpPageA)

	// The second tab, on the same browser. A's OTP prompt is still on the user's screen.
	stateB := fake.LetterN(8)
	otpURLB, otpPageB := walkToOTPPrompt(t, httpClient, clientB, redirectURIB, stateB, user, password)
	defer func() { _ = otpPageB.Body.Close() }()

	ceremonyB := getCeremonyIDFromPage(t, otpPageB)
	assert.NotEqual(t, ceremonyA, ceremonyB,
		"each authorization request must render its own ceremony id, or nothing is bound")

	// Two codes of two steps, since a step's code is spent once: the previous one, which the window
	// still accepts, and the current one.
	codes := []string{otptest.PreviousStepCode(t, otpSecret), otptest.Code(t, otpSecret, time.Now())}
	for i, signIn := range []struct {
		otpURL      string
		otpPage     *http.Response
		client      *record.Client
		redirectURI *record.RedirectURI
		state       string
	}{
		{otpURLA, otpPageA, clientA, redirectURIA, stateA},
		{otpURLB, otpPageB, clientB, redirectURIB, stateB},
	} {
		otpCode := codes[i]

		resp := authenticateWithOTP(t, httpClient, signIn.otpURL, signIn.otpPage, otpCode)
		defer func(r *http.Response) { _ = r.Body.Close() }(resp)

		location := assertRedirect(t, resp, "/auth/completed")
		resp = loadPage(t, httpClient, location)
		defer func(r *http.Response) { _ = r.Body.Close() }(resp)

		assertCodeFor(t, httpClient, assertRedirect(t, resp, "/auth/issue"), signIn.client, signIn.redirectURI, signIn.state)
	}
}

// TestAuthorize_AnotherUsersSignInEndsOneAbandonedAtItsEnrolment: user A types their password and
// walks away from the browser at the enrolment of an authenticator, its key on the screen. User B
// then signs in on the same browser. A's sign-in does not carry on into B's session: once B has
// finished, the browser holds no sign-in at all, so A's enrolment page, submitted with a code from
// the key it shows, is sent to the account page, and A neither enrols that key nor gets a session.
// Before, whoever used the browser next could scan A's key, enrol it and be signed in as A without
// A's password (#246).
func TestAuthorize_AnotherUsersSignInEndsOneAbandonedAtItsEnrolment(t *testing.T) {
	clientA, redirectURIA, userA, passwordA, _ := createLevel2MandatoryUser(t, false)
	clientB, redirectURIB, userB, passwordB, otpSecretB := createLevel2MandatoryUser(t, true)

	httpClient := createHTTPClient(t)

	enrolURLA, enrolPageA := walkToOTPPrompt(t, httpClient, clientA, redirectURIA, fake.LetterN(8), userA, passwordA)
	defer func() { _ = enrolPageA.Body.Close() }()
	codeFromAsKey := otptest.Code(t, getOTPSecretFromEnrollmentPage(t, enrolPageA), time.Now())

	stateB := fake.LetterN(8)
	otpURLB, otpPageB := walkToOTPPrompt(t, httpClient, clientB, redirectURIB, stateB, userB, passwordB)
	defer func() { _ = otpPageB.Body.Close() }()
	codeB := otptest.Code(t, otpSecretB, time.Now())

	resp := authenticateWithOTP(t, httpClient, otpURLB, otpPageB, codeB)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)
	location := assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, location)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)
	assertCodeFor(t, httpClient, assertRedirect(t, resp, "/auth/issue"), clientB, redirectURIB, stateB)

	// A's enrolment page, still in its tab, submitted with a code from the key it shows.
	resp = authenticateWithOTP(t, httpClient, enrolURLA, enrolPageA, codeFromAsKey)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)
	location = assertRedirect(t, resp, "/account/profile")
	assert.Equal(t, appConfig.AdminConsole.BaseURL+"/account/profile", location,
		"a browser holding no sign-in is sent to the account page")
	assertNothingWasCompleted(t, userA.ID)

	storedA, err := database.GetUserByID(context.Background(), nil, userA.ID)
	if err != nil {
		t.Fatal(err)
	}
	assert.False(t, storedA.OTPEnabled, "the key A's page showed is enrolled for nobody")
}
