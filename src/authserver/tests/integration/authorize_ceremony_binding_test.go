package integrationtests

import (
	"net/http"
	"net/url"
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

// createConsentClient makes a client whose authorization always reaches the consent screen.
func createConsentClient(t *testing.T) (*models.Client, *models.RedirectURI) {
	return createLevel1Client(t, true)
}

// createLevel1Client makes a password-only client. Without consent it is the sharpest second tab
// for the password case: its authorization needs no screen after the password, so under the defect
// a stale login form finished it and the code was issued with nothing shown to the user at all.
func createLevel1Client(t *testing.T, consentRequired bool) (*models.Client, *models.RedirectURI) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          consentRequired,
		DefaultAcrLevel:          enums.AcrLevel1,
	}
	if err := database.CreateClient(nil, client); err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}
	if err := database.CreateRedirectURI(nil, redirectUri); err != nil {
		t.Fatal(err)
	}
	return client, redirectUri
}

// createCeremonyUser makes an enabled user with a password, and returns that password.
func createCeremonyUser(t *testing.T) (*models.User, string) {
	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}
	if err := database.CreateUser(nil, user); err != nil {
		t.Fatal(err)
	}
	return user, password
}

// assertCeremonyMismatchPage asserts a submission drew the refusal decision 5 promises: the 400
// error page, and no redirect at all, least of all to /auth/issue.
func assertCeremonyMismatchPage(t *testing.T, resp *http.Response, what string) {
	t.Helper()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"%s from a replaced ceremony must be refused", what)
	assert.Empty(t, resp.Header.Get("Location"),
		"the refusal must not redirect anywhere, least of all to /auth/issue")

	doc := parseHTMLResponse(t, resp)
	assert.NotEmpty(t, doc.Find("#errorMsg").Text(), "the refusal renders the auth error page")
}

// assertNothingWasCompleted asserts the refused submission advanced no ceremony. A session is
// created at /auth/completed, which is past both bound forms, so a user session existing at this
// point means a stale form finished somebody's authorization.
func assertNothingWasCompleted(t *testing.T, userId int64) {
	t.Helper()

	sessions, err := database.GetUserSessionsByUserId(nil, userId)
	if err != nil {
		t.Fatal(err)
	}
	assert.Empty(t, sessions, "the refused submission must not have authenticated anybody")
}

func authorizeUrlFor(client *models.Client, redirectUri *models.RedirectURI, scope string,
	state string) string {
	return config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + gofakeit.LetterN(43) +
		"&scope=" + url.QueryEscape(scope) +
		"&state=" + state +
		"&nonce=" + gofakeit.LetterN(8)
}

// TestAuthorize_ConsentFormFromAReplacedCeremonyIsRefused walks the defect end to end.
//
// A browser holds ONE auth context, so a second /auth/authorize replaces the first while the first
// client's consent screen is still on the user's screen. Both screens post to the same URL, and the
// checkbox names are positional, so before this change the boxes the user ticked on client A's
// screen resolved against client B's scope list: B was granted, and a consent row was persisted for
// B, off a screen naming A that the user never saw for B (#79 decision 7).
//
// The three things this asserts are the three decision 5 promises: the stale submission is refused
// with a 400, nothing at all is issued or persisted for it, and the ceremony that is actually
// current is untouched and still completable in its own tab.
func TestAuthorize_ConsentFormFromAReplacedCeremonyIsRefused(t *testing.T) {
	clientA, redirectUriA := createConsentClient(t)
	clientB, redirectUriB := createConsentClient(t)

	user, password := createCeremonyUser(t)

	httpClient := createHttpClient(t)

	// Client A's authorization, all the way to its consent screen.
	stateA := gofakeit.LetterN(8)
	resp, err := httpClient.Get(authorizeUrlFor(clientA, redirectUriA, "openid profile email", stateA))
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

	resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, user.Email, password)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	consentUrl := assertRedirect(t, resp, "/auth/consent")
	consentPageA := loadPage(t, httpClient, consentUrl)
	defer func() { _ = consentPageA.Body.Close() }()

	ceremonyA := getCeremonyIdFromPage(t, consentPageA)

	// The second tab. Client B's authorization runs on the same browser, reusing the session A's
	// ceremony created, and its auth context replaces A's. A's consent screen is still on screen.
	stateB := gofakeit.LetterN(8)
	resp, err = httpClient.Get(authorizeUrlFor(clientB, redirectUriB, "openid profile", stateB))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	consentUrlB := assertRedirect(t, resp, "/auth/consent")
	consentPageB := loadPage(t, httpClient, consentUrlB)
	defer func() { _ = consentPageB.Body.Close() }()

	ceremonyB := getCeremonyIdFromPage(t, consentPageB)
	assert.NotEqual(t, ceremonyA, ceremonyB,
		"each authorization request must render its own ceremony id, or nothing is bound")

	// The user, still looking at A's screen, submits it. Two boxes ticked, which under the defect
	// would have granted client B the scopes at those positions.
	resp = postConsent(t, httpClient, consentUrl, consentPageA, []int{0, 1})
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"a consent form from a replaced ceremony must be refused")
	assert.Empty(t, resp.Header.Get("Location"),
		"the refusal must not redirect anywhere, least of all to /auth/issue")

	doc := parseHTMLResponse(t, resp)
	assert.NotEmpty(t, doc.Find("#errorMsg").Text(), "the refusal renders the auth error page")

	// Nothing was issued and nothing was persisted, for either client.
	for _, c := range []*models.Client{clientA, clientB} {
		consent, err := database.GetConsentByUserIdAndClientId(nil, user.Id, c.Id)
		if err != nil {
			t.Fatal(err)
		}
		assert.Nil(t, consent, "the refused submission must persist no consent for %s", c.ClientIdentifier)
	}

	// And the ceremony that is actually current is untouched: B's own screen still completes, in
	// its own tab, with exactly the scopes ticked on it.
	resp = postConsent(t, httpClient, consentUrlB, consentPageB, []int{0, 1})
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, stateB, stateVal, "the code belongs to client B's request, not to A's")

	code := loadCodeFromDatabase(t, codeVal)
	assert.Equal(t, clientB.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, "openid profile", code.Scope)
	assert.Equal(t, redirectUriB.URI, code.RedirectURI)

	consentA, err := database.GetConsentByUserIdAndClientId(nil, user.Id, clientA.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, consentA, "client A was never consented to, so it must hold no consent row")

	consentB, err := database.GetConsentByUserIdAndClientId(nil, user.Id, clientB.Id)
	if err != nil {
		t.Fatal(err)
	}
	if assert.NotNil(t, consentB) {
		assert.Equal(t, "openid profile", consentB.Scope)
	}
}

// TestAuthorize_PasswordFormFromAReplacedCeremonyIsRefused is the more direct path decision 6 was
// settled on, and the reason the binding is not the consent form's alone.
//
// The user is at client A's login screen. Client B opens in another tab and its auth context
// replaces A's. The user types their password into A's screen and submits it. Before this change
// that authenticated them against B's request: B requires no consent, so the flow ran straight
// through to /auth/issue and B was handed a code with no screen ever shown for it.
//
// The password submitted here is the correct one, deliberately. A refusal that only held for wrong
// credentials would be no refusal at all.
func TestAuthorize_PasswordFormFromAReplacedCeremonyIsRefused(t *testing.T) {
	clientA, redirectUriA := createConsentClient(t)
	clientB, redirectUriB := createLevel1Client(t, false)
	user, password := createCeremonyUser(t)

	httpClient := createHttpClient(t)

	// Client A's authorization, as far as its login screen.
	stateA := gofakeit.LetterN(8)
	resp, err := httpClient.Get(authorizeUrlFor(clientA, redirectUriA, "openid profile email", stateA))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	pwdUrlA := assertRedirect(t, resp, "/auth/pwd")
	pwdPageA := loadPage(t, httpClient, pwdUrlA)
	defer func() { _ = pwdPageA.Body.Close() }()

	ceremonyA := getCeremonyIdFromPage(t, pwdPageA)

	// The second tab. Client B's authorization replaces A's context, and A's login screen is still
	// on the user's screen.
	stateB := gofakeit.LetterN(8)
	resp, err = httpClient.Get(authorizeUrlFor(clientB, redirectUriB, "openid profile", stateB))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	pwdUrlB := assertRedirect(t, resp, "/auth/pwd")
	pwdPageB := loadPage(t, httpClient, pwdUrlB)
	defer func() { _ = pwdPageB.Body.Close() }()

	ceremonyB := getCeremonyIdFromPage(t, pwdPageB)
	assert.NotEqual(t, ceremonyA, ceremonyB,
		"each authorization request must render its own ceremony id, or nothing is bound")

	// The user, still looking at A's screen, signs in there.
	resp = authenticateWithPassword(t, httpClient, pwdUrlA, pwdPageA, user.Email, password)
	defer func() { _ = resp.Body.Close() }()

	assertCeremonyMismatchPage(t, resp, "a login form")
	assertNothingWasCompleted(t, user.Id)

	// And the ceremony that is actually current is untouched: B's own screen still signs in, in its
	// own tab, and receives a code for B's request.
	resp = authenticateWithPassword(t, httpClient, pwdUrlB, pwdPageB, user.Email, password)
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

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, stateB, stateVal, "the code belongs to client B's request, and to no other")

	code := loadCodeFromDatabase(t, codeVal)
	assert.Equal(t, clientB.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, redirectUriB.URI, code.RedirectURI)
}

// walkToOtpPrompt drives one authorization request from /auth/authorize to the OTP prompt, on an
// http client the caller owns. startOtpCeremony cannot be used here: it creates a fresh cookie jar
// per call, and this case needs two ceremonies in ONE browser, which is the whole defect.
func walkToOtpPrompt(t *testing.T, httpClient *http.Client, client *models.Client,
	redirectUri *models.RedirectURI, state string, user *models.User, password string) (string, *http.Response) {

	t.Helper()

	resp, err := httpClient.Get(authorizeUrlFor(client, redirectUri, "openid profile email", state))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	_ = resp.Body.Close()

	pwdUrl := assertRedirect(t, resp, "/auth/pwd")
	pwdPage := loadPage(t, httpClient, pwdUrl)

	resp = authenticateWithPassword(t, httpClient, pwdUrl, pwdPage, user.Email, password)
	_ = pwdPage.Body.Close()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)

	otpUrl := assertRedirect(t, resp, "/auth/otp")
	_ = resp.Body.Close()

	// Caller closes this one.
	return otpUrl, loadPage(t, httpClient, otpUrl)
}

// TestAuthorize_OtpFormFromAReplacedCeremonyIsRefused is the same defect one factor up, and it
// carries the assertion neither other case can make.
//
// The user is at client A's OTP prompt when client B's authorization replaces the context. They
// enter a valid code on A's prompt: that is refused. The same code is then entered on B's prompt,
// in its own tab, and it works. That is what pins the refusal running before otp.MatchStep and
// TryConsumeUserOTPStep: if the stale submission had reached the claim it would have consumed the
// step, and the passcode in front of the user would have stopped working for the request they were
// actually on, which is a forgotten tab breaking a live sign-in (#79 decision 5, #111 decision 3).
func TestAuthorize_OtpFormFromAReplacedCeremonyIsRefused(t *testing.T) {
	clientA, redirectUriA, user, password := createLevel2MandatoryUser(t, true)
	clientB, redirectUriB := createLevel2MandatoryClient(t)

	httpClient := createHttpClient(t)

	stateA := gofakeit.LetterN(8)
	otpUrlA, otpPageA := walkToOtpPrompt(t, httpClient, clientA, redirectUriA, stateA, user, password)
	defer func() { _ = otpPageA.Body.Close() }()

	ceremonyA := getCeremonyIdFromPage(t, otpPageA)

	// The second tab, on the same browser. A's OTP prompt is still on the user's screen.
	stateB := gofakeit.LetterN(8)
	otpUrlB, otpPageB := walkToOtpPrompt(t, httpClient, clientB, redirectUriB, stateB, user, password)
	defer func() { _ = otpPageB.Body.Close() }()

	ceremonyB := getCeremonyIdFromPage(t, otpPageB)
	assert.NotEqual(t, ceremonyA, ceremonyB,
		"each authorization request must render its own ceremony id, or nothing is bound")

	otpCode, err := totp.GenerateCode(user.OTPSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// The user, still looking at A's prompt, enters the code there.
	resp := authenticateWithOtp(t, httpClient, otpUrlA, otpPageA, otpCode)
	defer func() { _ = resp.Body.Close() }()

	assertCeremonyMismatchPage(t, resp, "an OTP prompt")
	assertNothingWasCompleted(t, user.Id)

	// The same code, on the prompt the user is actually on. It still works, so the refusal took
	// nothing away from the live ceremony.
	resp = authenticateWithOtp(t, httpClient, otpUrlB, otpPageB, otpCode)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, stateB, stateVal, "the code belongs to client B's request, and to no other")

	code := loadCodeFromDatabase(t, codeVal)
	assert.Equal(t, clientB.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, redirectUriB.URI, code.RedirectURI)
}
