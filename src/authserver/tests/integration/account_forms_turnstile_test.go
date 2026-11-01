package integration

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Turnstile challenge on the forgot-password and registration forms against the real
// siteverify, with Cloudflare's published test secret keys and dummy token (#642 decision 6), as
// auth_pwd_turnstile_test.go drives the sign-in form. The always-pass secret key lets each form
// proceed; the always-fail and already-spent ones are refused before the handler, which every
// well-formed address otherwise reaches; an empty token is refused without a call; and a secret key
// Cloudflare does not know fails open as misconfigured.
//
// None of them is parallel: the challenge is on in the settings row every test shares.

// accountForm is one of the two forms, as these tests drive it.
type accountForm struct {
	name string
	path string
	// The widget's action, and the counter's form label.
	action, label string
	// The notice a refusal is drawn in.
	errorSelector string
	// open makes the form available, as the baseline may not have it, until the test ends.
	open func(t *testing.T)
}

var accountForms = []accountForm{
	{
		name: "forgot-password", path: "/forgot-password", action: "forgot-password", label: "forgot_password",
		errorSelector: "#forgot-error p",
		open:          useMailpitSMTP,
	},
	{
		name: "registration", path: "/account/register", action: "register", label: "register",
		errorSelector: "#register-error p",
		// Without verification, so a submission that reaches the handler creates the account at once.
		open: func(t *testing.T) { setRegSettings(t, true, false, false) },
	},
}

// post submits the form with values, and token in cf-turnstile-response when there is one, and
// returns the response, whose body the caller closes.
func (f accountForm) post(t *testing.T, values url.Values, token string) *http.Response {
	t.Helper()
	if token != "" {
		values.Set("cf-turnstile-response", token)
	}
	target := appConfig.AuthServer.BaseURL + f.path
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(values.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", target)
	req.Header.Set("Origin", appConfig.AuthServer.BaseURL)
	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	return resp
}

// count is the counter's value for this form and outcome, at this scrape.
func (f accountForm) count(t *testing.T, outcome string) int {
	t.Helper()
	return int(sampleValue(t, scrapeMetrics(t),
		`goiabada_challenge_verifications_total{form="`+f.label+`",outcome="`+outcome+`"}`))
}

// assertRefusal checks resp is the form redrawn beside the challenge's refusal, with the address
// typed and a fresh widget with the form's action, under the widened policy.
func (f accountForm) assertRefusal(t *testing.T, resp *http.Response, email string) {
	t.Helper()
	require.Equal(t, http.StatusOK, resp.StatusCode, "a refusal redraws the form")
	assert.Equal(t, turnstileWidenedPolicy, resp.Header.Get("Content-Security-Policy"))
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, turnstileRefusal, strings.TrimSpace(doc.Find(f.errorSelector).Text()))
	assert.Equal(t, email, doc.Find(`form input[name="email"]`).AttrOr("value", ""))
	assert.Equal(t, turnstileTestSiteKey, doc.Find(`form div.cf-turnstile[data-action="`+f.action+`"]`).AttrOr("data-sitekey", ""))
}

// submission is what each form is submitted with: an address of no account for forgot-password,
// answered with the page every well-formed address gets, and a new account's address and password
// for registration.
func submission(f accountForm, email string) url.Values {
	if f.path == "/account/register" {
		password := fake.Password(20)
		return url.Values{"email": {email}, "password": {password}, "passwordConfirmation": {password}}
	}
	return url.Values{"email": {email}}
}

// assertReached checks resp is what the form's handler answers a well-formed submission with: the
// "link sent" page, or the account created.
func assertReached(t *testing.T, f accountForm, resp *http.Response, email string) {
	t.Helper()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := bodyString(t, resp)
	assert.NotContains(t, body, turnstileRefusal)
	if f.path == "/account/register" {
		assert.Contains(t, body, "Your account is ready.")
		user, err := database.GetUserByEmail(context.Background(), nil, email)
		require.NoError(t, err)
		if assert.NotNil(t, user, "the account was created") {
			t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.Id) })
		}
		return
	}
	assert.Contains(t, body, linkSentText)
}

// assertNoAccount checks a refused registration created nothing.
func assertNoAccount(t *testing.T, f accountForm, email string) {
	t.Helper()
	if f.path != "/account/register" {
		return
	}
	user, err := database.GetUserByEmail(context.Background(), nil, email)
	require.NoError(t, err)
	assert.Nil(t, user, "no account was created")
}

func TestAccountFormsTurnstile_TheFormCarriesTheWidgetUnderTheWidenedPolicy(t *testing.T) {
	for _, f := range accountForms {
		t.Run(f.name, func(t *testing.T) {
			f.open(t)
			turnOnTurnstile(t, turnstileAlwaysPassSecretKey)

			resp := loadPage(t, createHttpClient(t), appConfig.AuthServer.BaseURL+f.path)
			defer func() { _ = resp.Body.Close() }()

			require.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, turnstileWidenedPolicy, resp.Header.Get("Content-Security-Policy"))
			doc, err := goquery.NewDocumentFromReader(resp.Body)
			require.NoError(t, err)
			widget := doc.Find("form div.cf-turnstile")
			assert.Equal(t, turnstileTestSiteKey, widget.AttrOr("data-sitekey", ""))
			assert.Equal(t, f.action, widget.AttrOr("data-action", ""))
			assertWidgetLoader(t, doc)
		})
	}
}

func TestAccountFormsTurnstile_TheAlwaysPassSecretKeyLetsTheFormProceed(t *testing.T) {
	for _, f := range accountForms {
		t.Run(f.name, func(t *testing.T) {
			f.open(t)
			turnOnTurnstile(t, turnstileAlwaysPassSecretKey)
			email := registerAddress()
			passed := f.count(t, "passed")

			resp := f.post(t, submission(f, email), turnstileDummyToken)
			defer func() { _ = resp.Body.Close() }()

			assertReached(t, f, resp, email)
			assert.Equal(t, passed+1, f.count(t, "passed"))
		})
	}
}

// The always-fail and already-spent secret keys are Cloudflare's verdict against the token: the
// form is redrawn rather than answered by its handler, so no account is created and no link sent.
func TestAccountFormsTurnstile_AVerdictAgainstTheTokenIsRefusedBeforeTheHandler(t *testing.T) {
	for _, f := range accountForms {
		for _, tt := range []struct{ name, secretKey string }{
			{"always fail", turnstileAlwaysFailSecretKey},
			{"already spent", turnstileSpentSecretKey},
		} {
			t.Run(f.name+"/"+tt.name, func(t *testing.T) {
				f.open(t)
				turnOnTurnstile(t, tt.secretKey)
				email := registerAddress()
				refused := f.count(t, "refused")

				resp := f.post(t, submission(f, email), turnstileDummyToken)
				defer func() { _ = resp.Body.Close() }()

				f.assertRefusal(t, resp, email)
				assertNoAccount(t, f, email)
				assert.Equal(t, refused+1, f.count(t, "refused"))
			})
		}
	}
}

// A submission with no token is refused without a call, which the always-pass secret key would
// otherwise have passed.
func TestAccountFormsTurnstile_ASubmissionWithoutATokenIsRefusedWithoutACall(t *testing.T) {
	for _, f := range accountForms {
		t.Run(f.name, func(t *testing.T) {
			f.open(t)
			turnOnTurnstile(t, turnstileAlwaysPassSecretKey)
			email := registerAddress()
			missing, passed := f.count(t, "missing"), f.count(t, "passed")

			resp := f.post(t, submission(f, email), "")
			defer func() { _ = resp.Body.Close() }()

			f.assertRefusal(t, resp, email)
			assertNoAccount(t, f, email)
			assert.Equal(t, missing+1, f.count(t, "missing"))
			assert.Equal(t, passed, f.count(t, "passed"))
		})
	}
}

// A secret key siteverify does not know is a fault in the configuration: the form goes on as with
// the challenge off, counted as misconfigured.
func TestAccountFormsTurnstile_AnUnknownSecretKeyFailsOpenAsMisconfigured(t *testing.T) {
	for _, f := range accountForms {
		t.Run(f.name, func(t *testing.T) {
			f.open(t)
			turnOnTurnstile(t, turnstileUnknownSecretKey)
			email := registerAddress()
			misconfigured := f.count(t, "misconfigured")

			resp := f.post(t, submission(f, email), turnstileDummyToken)
			defer func() { _ = resp.Body.Close() }()

			assertReached(t, f, resp, email)
			assert.Equal(t, misconfigured+1, f.count(t, "misconfigured"))
		})
	}
}
