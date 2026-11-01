package integration

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Turnstile challenge on the sign-in form against the real siteverify, with Cloudflare's
// published test secret keys and dummy token (#642 decision 6). The always-pass secret key lets the
// form proceed; the always-fail and already-spent ones are refused, comparing no password, so the
// account's budget is unspent; an empty token is refused without a call; and a secret key Cloudflare
// does not know fails open as misconfigured. A Cloudflare outage fails these tests, the price of
// testing against the real service.
//
// None of them is parallel: the challenge is on in the settings row every test shares, and on, it
// would refuse every other test's sign-in.

const (
	turnstileAlwaysPassSecretKey = "1x0000000000000000000000000000000AA"
	turnstileAlwaysFailSecretKey = "2x0000000000000000000000000000000AA"
	turnstileSpentSecretKey      = "3x0000000000000000000000000000000AA"
	// A secret key of no widget: siteverify answers invalid-input-secret.
	turnstileUnknownSecretKey = "0x0000000000000000000000000000000AA"
	turnstileTestSiteKey      = "1x00000000000000000000AA"
	turnstileDummyToken       = "XXXX.DUMMY.TOKEN.XXXX"

	turnstileRefusal = "Complete the security check, then try again. The check needs JavaScript."

	turnstileWidenedPolicy = "script-src 'self' https://challenges.cloudflare.com; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
)

// turnOnTurnstile turns the challenge on in the settings row with secretKey, restoring the row when
// the test ends.
func turnOnTurnstile(t *testing.T, secretKey string) {
	t.Helper()
	sealed, err := dataCipher.Encrypt(secretKey)
	require.NoError(t, err)
	changeSettings(t, func(settings *record.Settings) {
		settings.TurnstileEnabled = true
		settings.TurnstileSiteKey = turnstileTestSiteKey
		settings.TurnstileSecretKeyEncrypted = sealed
	})
}

// turnstileUser is an enabled user whose password is password.
func turnstileUser(t *testing.T, password string) *record.User {
	t.Helper()
	hashed, err := passwordhash.Hash(password)
	require.NoError(t, err)
	user := &record.User{Subject: fake.UUID(), Enabled: true, Email: strings.ToLower(fake.Email()), PasswordHash: hashed}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.Id) })
	return user
}

// submitWithToken posts the form with token in cf-turnstile-response, when there is one, under a
// request id of its own, and returns the response, whose body the caller closes, and that id.
func (f *passwordFormSubmission) submitWithToken(t *testing.T, email, password, token string) (*http.Response, string) {
	t.Helper()
	form := url.Values{"email": {email}, "password": {password}, "ceremonyId": {f.ceremonyId}}
	if token != "" {
		form.Set("cf-turnstile-response", token)
	}
	req, err := http.NewRequest(http.MethodPost, f.pwdURL, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", f.pwdURL)
	req.Header.Set("Origin", appConfig.AuthServer.BaseURL)
	requestId := "turnstile-" + fake.LetterN(16)
	req.Header.Set("X-Request-Id", requestId)

	resp, err := f.httpClient.Do(req)
	require.NoError(t, err)
	return resp, requestId
}

// challengeCount is the counter's value for the sign-in form and outcome, at this scrape.
func challengeCount(t *testing.T, outcome string) int {
	t.Helper()
	return int(sampleValue(t, scrapeMetrics(t), `goiabada_challenge_verifications_total{form="login",outcome="`+outcome+`"}`))
}

// assertChallengeRefusal checks resp is the sign-in form redrawn beside the challenge's refusal,
// with the address typed and a fresh widget, under the widened policy.
func assertChallengeRefusal(t *testing.T, resp *http.Response, email string) {
	t.Helper()
	require.Equal(t, http.StatusOK, resp.StatusCode, "a refusal redraws the form")
	assert.Equal(t, turnstileWidenedPolicy, resp.Header.Get("Content-Security-Policy"))
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, turnstileRefusal, strings.TrimSpace(doc.Find("#pwd-error p").Text()))
	assert.Equal(t, email, doc.Find(`input[name="email"]`).AttrOr("value", ""))
	assert.Equal(t, turnstileTestSiteKey, doc.Find(`form div.cf-turnstile[data-action="login"]`).AttrOr("data-sitekey", ""))
}

func TestAuthPwdTurnstile_TheFormCarriesTheWidgetUnderTheWidenedPolicy(t *testing.T) {
	turnOnTurnstile(t, turnstileAlwaysPassSecretKey)
	form := reachPasswordForm(t)

	resp := loadPage(t, form.httpClient, form.pwdURL)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, turnstileWidenedPolicy, resp.Header.Get("Content-Security-Policy"),
		"the security headers' policy, widened by the form on its own response")
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	require.NoError(t, err)
	widget := doc.Find("form div.cf-turnstile")
	assert.Equal(t, turnstileTestSiteKey, widget.AttrOr("data-sitekey", ""))
	assert.Equal(t, "login", widget.AttrOr("data-action", ""))
	assert.Equal(t, 1, doc.Find(`script[src="https://challenges.cloudflare.com/turnstile/v0/api.js"]`).Length())
}

func TestAuthPwdTurnstile_TheAlwaysPassSecretKeyLetsTheSignInProceed(t *testing.T) {
	turnOnTurnstile(t, turnstileAlwaysPassSecretKey)
	user := turnstileUser(t, "the right password 1")
	passed := challengeCount(t, "passed")

	resp, _ := reachPasswordForm(t).submitWithToken(t, user.Email, "the right password 1", turnstileDummyToken)
	defer func() { _ = resp.Body.Close() }()

	assertRedirect(t, resp, "/auth/level1completed")
	assert.Equal(t, passed+1, challengeCount(t, "passed"))
}

// The always-fail and already-spent secret keys are Cloudflare's verdict against the token: the
// submission is refused before the password is compared, so a wrong password records no failed
// sign-in, which is what spends an account's budget, and a right one signs nobody in.
func TestAuthPwdTurnstile_AVerdictAgainstTheTokenIsRefusedBeforeThePassword(t *testing.T) {
	requireDatabaseAuditLogs(t)
	adminToken, adminClient := createAdminClientWithToken(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, adminClient.Id) })

	for _, tt := range []struct{ name, secretKey string }{
		{"always fail", turnstileAlwaysFailSecretKey},
		{"already spent", turnstileSpentSecretKey},
	} {
		t.Run(tt.name, func(t *testing.T) {
			turnOnTurnstile(t, tt.secretKey)
			user := turnstileUser(t, "the right password 2")
			refused := challengeCount(t, "refused")

			wrong, requestId := reachPasswordForm(t).submitWithToken(t, strings.ToUpper(user.Email), "a wrong password", turnstileDummyToken)
			defer func() { _ = wrong.Body.Close() }()
			assertChallengeRefusal(t, wrong, user.Email)
			assert.Empty(t, auditRows(t, adminToken, "auth_failed_pwd", requestId),
				"no password compared, so no failure recorded and no budget spent")

			right, requestId := reachPasswordForm(t).submitWithToken(t, user.Email, "the right password 2", turnstileDummyToken)
			defer func() { _ = right.Body.Close() }()
			assertChallengeRefusal(t, right, user.Email)
			assert.Empty(t, auditRows(t, adminToken, "auth_success_pwd", requestId))

			assert.Equal(t, refused+2, challengeCount(t, "refused"))
		})
	}
}

// A submission with no token, a visitor without JavaScript or a script, is refused without a call,
// which the always-pass secret key would otherwise have passed.
func TestAuthPwdTurnstile_ASubmissionWithoutATokenIsRefusedWithoutACall(t *testing.T) {
	turnOnTurnstile(t, turnstileAlwaysPassSecretKey)
	user := turnstileUser(t, "the right password 3")
	missing, passed := challengeCount(t, "missing"), challengeCount(t, "passed")

	resp, _ := reachPasswordForm(t).submitWithToken(t, user.Email, "the right password 3", "")
	defer func() { _ = resp.Body.Close() }()

	assertChallengeRefusal(t, resp, user.Email)
	assert.Equal(t, missing+1, challengeCount(t, "missing"))
	assert.Equal(t, passed, challengeCount(t, "passed"))
}

// A secret key siteverify does not know is a fault in the configuration: the sign-in goes on as with
// the challenge off, counted as misconfigured.
func TestAuthPwdTurnstile_AnUnknownSecretKeyFailsOpenAsMisconfigured(t *testing.T) {
	turnOnTurnstile(t, turnstileUnknownSecretKey)
	user := turnstileUser(t, "the right password 4")
	misconfigured := challengeCount(t, "misconfigured")

	resp, _ := reachPasswordForm(t).submitWithToken(t, user.Email, "the right password 4", turnstileDummyToken)
	defer func() { _ = resp.Body.Close() }()

	assertRedirect(t, resp, "/auth/level1completed")
	assert.Equal(t, misconfigured+1, challengeCount(t, "misconfigured"))
}
