package server

import (
	"context"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/turnstile"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/httpmw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The Turnstile challenge on the sign-in form, composed with the rate limiter as initRoutes
// composes them, with the check doubled through its port (#642). The seam where "before any
// budget" and "before any password" are observable without the network: a refused submission
// redraws the form with the challenge's message and the address typed, and leaves every tier of
// the limiter as it was and the account unread; a pass or a fail-open goes on to the limiter and
// the password check; and every render of the form, and no other page, admits Cloudflare's script.

const (
	// Cloudflare's always-pass test site key, which the widget is rendered with.
	turnstileTestSiteKey = "1x00000000000000000000AA"
	turnstileTestToken   = "XXXX.DUMMY.TOKEN.XXXX"

	// What the refusal says, from the English catalog.
	challengeRefusal = "Complete the security check, then try again. The check needs JavaScript."
	// What the password check's own refusal says.
	passwordRefusal = "Authentication failed."
	// The "no longer active" page's message, which a submission naming a ceremony the browser no
	// longer holds is answered with.
	ceremonyNoLongerActive = "This page belongs to a sign-in that can no longer continue."

	// The policy every page is sent, and the one the challenge's pages are sent while it is on.
	plainPolicy   = "script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
	widenedPolicy = "script-src 'self' https://challenges.cloudflare.com; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"

	// pwd_account_net: failures per 15 minutes per account per client block.
	pwdAccountNetBudget = 10
	pwdAccountNetWindow = 900
)

// doubledVerifier answers every check with outcome and records what it was asked. A check while
// forbidden fails the test.
type doubledVerifier struct {
	t *testing.T

	mu        sync.Mutex
	outcome   turnstile.Outcome
	forbidden bool
	checks    []doubledCheck
}

type doubledCheck struct {
	Form  turnstile.Form
	Token string
}

func (v *doubledVerifier) Check(_ context.Context, settings *record.Settings, form turnstile.Form, token string) turnstile.Outcome {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.forbidden {
		v.t.Errorf("the challenge was checked (form %s), but nothing should have reached it", form)
	}
	assert.True(v.t, settings.TurnstileEnabled, "the check is handed the request's settings")
	v.checks = append(v.checks, doubledCheck{Form: form, Token: token})
	return v.outcome
}

func (v *doubledVerifier) answer(outcome turnstile.Outcome) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.outcome = outcome
}

func (v *doubledVerifier) checked() []doubledCheck {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]doubledCheck(nil), v.checks...)
}

// newTurnstileRoutesTestServer is newRoutesTestServer, the limiter on, with the check doubled.
func newTurnstileRoutesTestServer(t *testing.T, outcome turnstile.Outcome) (*Server, *doubledVerifier) {
	t.Helper()
	verifier := &doubledVerifier{t: t, outcome: outcome}
	return newRoutesTestServerVerifying(t, nil, newTestSessionStore(), verifier), verifier
}

// turnstileSettings is routesTestSettings with the challenge on, as the admin API stores it.
func turnstileSettings() *record.Settings {
	settings := routesTestSettings()
	settings.TurnstileEnabled = true
	settings.TurnstileSiteKey = turnstileTestSiteKey
	settings.TurnstileSecretKeyEncrypted = []byte("sealed secret key")
	return settings
}

// challenged puts the challenge's settings on r, as middleware.Settings would.
func challenged(r *http.Request) *http.Request {
	return r.WithContext(reqctx.WithSettings(r.Context(), turnstileSettings()))
}

// signInForm is a submission of the sign-in form inside the ceremony cookie holds, carrying token
// in cf-turnstile-response, under the challenge's settings.
func signInForm(cookie *http.Cookie, email, password, token string) *http.Request {
	form := url.Values{"ceremonyId": {routesTestCeremonyId}, "email": {email}, "password": {password}}
	if token != "" {
		form.Set(turnstile.ResponseField, token)
	}
	r := challenged(browserForm(http.MethodPost, "/auth/pwd", form.Encode()))
	r.AddCookie(cookie)
	return r
}

// serveSecured serves r through the security headers both servers mount ahead of every route, so a
// response's policy is the one a browser is sent.
func serveSecured(s *Server, r *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	httpmw.SecurityHeaders(false)(s.router).ServeHTTP(recorder, r)
	return recorder
}

// assertSignInFormRedrawn checks rr is the sign-in form shown again beside refusal, with the
// address typed, the widget and the widened policy.
func assertSignInFormRedrawn(t *testing.T, rr *httptest.ResponseRecorder, refusal, email string) {
	t.Helper()
	require.Equal(t, http.StatusOK, rr.Code)
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(rr.Body.String()))
	require.NoError(t, err)
	assert.Equal(t, refusal, strings.TrimSpace(doc.Find("#pwd-error p").Text()))
	assert.Equal(t, email, doc.Find(`input[name="email"]`).AttrOr("value", ""), "the address typed is kept")
	assert.Equal(t, 1, doc.Find(`form div.cf-turnstile[data-action="login"][data-size="compact"]`).Length(), "a fresh widget on the redrawn form")
	assert.Equal(t, widenedPolicy, rr.Header().Get("Content-Security-Policy"))
}

func databaseOf(s *Server) *datamocks.Database {
	return s.database.(*datamocks.Database)
}

func TestTurnstileChallenge_ARefusedSignInRedrawsTheFormAndSpendsNothing(t *testing.T) {
	for _, outcome := range []turnstile.Outcome{turnstile.Refused, turnstile.Missing} {
		t.Run(string(outcome), func(t *testing.T) {
			server, verifier := newTurnstileRoutesTestServer(t, outcome)
			cookie := pwdCeremonyCookie(t, server)

			rr := serveSecured(server, signInForm(cookie, "  Victim@Example.com ", "the account's real password", turnstileTestToken))

			assertSignInFormRedrawn(t, rr, challengeRefusal, "victim@example.com")
			assert.Equal(t, []doubledCheck{{Form: turnstile.FormLogin, Token: turnstileTestToken}}, verifier.checked())
			databaseOf(server).AssertNotCalled(t, "GetUserByEmail", mock.Anything, mock.Anything, mock.Anything)
		})
	}

	// Past every tier of the sign-in form's limiter, counted by the client's block and by the
	// address typed alike: the ceiling of 120 checks a minute, pwd_ip's 30 failures, pwd_account_net's
	// 10 and pwd_account's 100. Then, the challenge passing, each tier still has its whole budget.
	const refusals = 2 * pwdIpCeiling

	t.Run("the address's tiers are whole after the refusals", func(t *testing.T) {
		server, verifier := newTurnstileRoutesTestServer(t, turnstile.Refused)
		cookie := pwdCeremonyCookie(t, server)
		for i := 0; i < refusals; i++ {
			rr := serve(server, signInForm(cookie, "victim@example.com", routesTestWrongPassword, turnstileTestToken))
			require.Equal(t, http.StatusOK, rr.Code, "refusal %d", i+1)
			require.Contains(t, rr.Body.String(), challengeRefusal, "refusal %d", i+1)
		}
		databaseOf(server).AssertNotCalled(t, "GetUserByEmail", mock.Anything, mock.Anything, mock.Anything)

		verifier.answer(turnstile.Passed)
		assertRefused(t, exhaust(t, server, pwdAccountNetBudget, func(int) *http.Request {
			return signInForm(cookie, "victim@example.com", routesTestWrongPassword, turnstileTestToken)
		}), pwdAccountNetWindow, shapeBrowser)
	})

	t.Run("the client block's failure tier is whole after the refusals", func(t *testing.T) {
		server, verifier := newTurnstileRoutesTestServer(t, turnstile.Missing)
		cookie := pwdCeremonyCookie(t, server)
		guess := func(attempt int) *http.Request {
			return signInForm(cookie, "user"+strconv.Itoa(attempt)+"@example.com", routesTestWrongPassword, turnstileTestToken)
		}
		for i := 0; i < refusals; i++ {
			require.Contains(t, serve(server, guess(i)).Body.String(), challengeRefusal, "refusal %d", i+1)
		}

		verifier.answer(turnstile.Passed)
		assertRefused(t, exhaust(t, server, pwdIpBudget, guess), pwdIpWindow, shapeBrowser)
	})

	t.Run("the client block's ceiling on every check is whole after the refusals", func(t *testing.T) {
		server, verifier := newTurnstileRoutesTestServer(t, turnstile.Refused)
		cookie := pwdCeremonyCookie(t, server)
		noPassword := func(int) *http.Request {
			return signInForm(cookie, "victim@example.com", "", turnstileTestToken)
		}
		for i := 0; i < refusals; i++ {
			require.Contains(t, serve(server, noPassword(i)).Body.String(), challengeRefusal, "refusal %d", i+1)
		}

		verifier.answer(turnstile.Passed)
		assertRefused(t, exhaust(t, server, pwdIpCeiling, noPassword), pwdIpWindow, shapeBrowser)
	})
}

// A pass, and each way the challenge fails open, go on to the limiter and the password check
// exactly as with the challenge off: the wrong password is compared, refused with the password
// check's own message, and spends the account's budget.
func TestTurnstileChallenge_APassOrAFailOpenGoesOnToThePasswordCheck(t *testing.T) {
	for _, outcome := range []turnstile.Outcome{turnstile.Passed, turnstile.Unavailable, turnstile.Misconfigured} {
		t.Run(string(outcome), func(t *testing.T) {
			server, verifier := newTurnstileRoutesTestServer(t, outcome)
			cookie := pwdCeremonyCookie(t, server)

			rr := serveSecured(server, signInForm(cookie, "victim@example.com", routesTestWrongPassword, turnstileTestToken))

			assertSignInFormRedrawn(t, rr, passwordRefusal, "victim@example.com")
			assert.Equal(t, []doubledCheck{{Form: turnstile.FormLogin, Token: turnstileTestToken}}, verifier.checked())
			databaseOf(server).AssertCalled(t, "GetUserByEmail", mock.Anything, mock.Anything, "victim@example.com")

			// The one guess spent one of the account's ten.
			assertRefused(t, exhaust(t, server, pwdAccountNetBudget-1, func(int) *http.Request {
				return signInForm(cookie, "victim@example.com", routesTestWrongPassword, turnstileTestToken)
			}), pwdAccountNetWindow, shapeBrowser)
		})
	}
}

// The token is read from the request body: one in the query string is not the submission's, which
// is then checked as carrying none.
func TestTurnstileChallenge_TheTokenIsReadFromTheBodyOnly(t *testing.T) {
	server, verifier := newTurnstileRoutesTestServer(t, turnstile.Missing)
	cookie := pwdCeremonyCookie(t, server)
	r := signInForm(cookie, "victim@example.com", routesTestWrongPassword, "")
	r.URL.RawQuery = url.Values{turnstile.ResponseField: {turnstileTestToken}}.Encode()

	rr := serve(server, r)

	assert.Contains(t, rr.Body.String(), challengeRefusal)
	assert.Equal(t, []doubledCheck{{Form: turnstile.FormLogin, Token: ""}}, verifier.checked())
}

// A submission naming a ceremony the browser no longer holds still gets the "no longer active"
// page, and is not checked.
func TestTurnstileChallenge_ASubmissionNamingAnotherCeremonyIsNoLongerActiveUnchecked(t *testing.T) {
	server, verifier := newTurnstileRoutesTestServer(t, turnstile.Passed)
	verifier.forbidden = true
	cookie := pwdCeremonyCookie(t, server)
	form := url.Values{
		"ceremonyId": {"0b9c8d7e-6f5a-4b3c-9d2e-1f0a9b8c7d6e"}, "email": {"victim@example.com"},
		"password": {routesTestWrongPassword}, turnstile.ResponseField: {turnstileTestToken},
	}
	r := challenged(browserForm(http.MethodPost, "/auth/pwd", form.Encode()))
	r.AddCookie(cookie)

	rr := serve(server, r)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), ceremonyNoLongerActive)
	databaseOf(server).AssertNotCalled(t, "GetUserByEmail", mock.Anything, mock.Anything, mock.Anything)
}

// With the challenge off, nothing changes: the check is never reached, the form carries no widget
// and loads nothing from Cloudflare, and the policy is today's.
func TestTurnstileChallenge_OffChangesNothing(t *testing.T) {
	server, verifier := newTurnstileRoutesTestServer(t, turnstile.Refused)
	verifier.forbidden = true
	cookie := pwdCeremonyCookie(t, server)

	// The challenge's keys stay stored while it is off, and do not turn it on.
	off := func(r *http.Request) *http.Request {
		settings := turnstileSettings()
		settings.TurnstileEnabled = false
		return r.WithContext(reqctx.WithSettings(r.Context(), settings))
	}

	get := off(browserRequest(http.MethodGet, "/auth/pwd?ceremony="+routesTestCeremonyId))
	get.AddCookie(cookie)
	post := off(signInForm(cookie, "victim@example.com", routesTestWrongPassword, ""))

	for name, r := range map[string]*http.Request{"the form": get, "a refusal": post} {
		rr := serveSecured(server, r)
		require.Equal(t, http.StatusOK, rr.Code, name)
		assert.Equal(t, plainPolicy, rr.Header().Get("Content-Security-Policy"), name)
		assert.NotContains(t, rr.Body.String(), "challenges.cloudflare.com", name)
		assert.NotContains(t, rr.Body.String(), "cf-turnstile", name)
	}
	assert.Contains(t, serve(server, off(signInForm(cookie, "victim@example.com", routesTestWrongPassword, ""))).Body.String(),
		passwordRefusal, "the password is checked as today")
}

// Every render of the sign-in form carries the widget, with the site key, the action login and the
// page's language, and admits Cloudflare's script; the other pages keep today's policy while the
// challenge is on (#642 decision 9).
func TestTurnstileChallenge_TheFormCarriesTheWidgetAndOnlyItsPagesAdmitCloudflare(t *testing.T) {
	server, _ := newTurnstileRoutesTestServer(t, turnstile.Refused)
	cookie := pwdCeremonyCookie(t, server)

	get := challenged(browserRequest(http.MethodGet, "/auth/pwd?ceremony="+routesTestCeremonyId))
	get.AddCookie(cookie)
	rr := serveSecured(server, get)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, widenedPolicy, rr.Header().Get("Content-Security-Policy"))
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(rr.Body.String()))
	require.NoError(t, err)
	widget := doc.Find("form div.cf-turnstile")
	require.Equal(t, 1, widget.Length(), "one widget, inside the form, so its token is submitted with it")
	assert.Equal(t, turnstileTestSiteKey, widget.AttrOr("data-sitekey", ""))
	assert.Equal(t, "login", widget.AttrOr("data-action", ""))
	assert.Equal(t, "compact", widget.AttrOr("data-size", ""), "the size that fits the form at 320 pixels")
	assert.Equal(t, "en", widget.AttrOr("data-language", ""))
	script := doc.Find(`script[src="https://challenges.cloudflare.com/turnstile/v0/api.js"]`)
	require.Equal(t, 1, script.Length(), "the widget's script")
	assert.Empty(t, strings.TrimSpace(script.Text()), "a script with no body, which the policy allows from its origin")

	t.Run("in the page's language", func(t *testing.T) {
		r := challenged(browserRequest(http.MethodGet, "/auth/pwd?ceremony="+routesTestCeremonyId))
		r.Header.Set("Accept-Language", "pt-BR")
		r.AddCookie(cookie)
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(serve(server, r).Body.String()))
		require.NoError(t, err)
		assert.Equal(t, doc.Find("html").AttrOr("lang", "?"), doc.Find("div.cf-turnstile").AttrOr("data-language", ""))
	})

	t.Run("another page keeps today's policy", func(t *testing.T) {
		r := challenged(browserRequest(http.MethodGet, "/auth/otp?ceremony="+routesTestCeremonyId))
		r.AddCookie(otpCeremonyCookie(t, server))
		rr := serveSecured(server, r)
		require.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, plainPolicy, rr.Header().Get("Content-Security-Policy"))
		assert.NotContains(t, rr.Body.String(), "challenges.cloudflare.com")
	})
}

// overlaidTemplates is the built-in templates with files laid over them.
type overlaidTemplates struct {
	fs.FS
	files fstest.MapFS
}

func (o overlaidTemplates) Open(name string) (fs.File, error) {
	if _, laid := o.files[name]; laid {
		return o.files.Open(name)
	}
	return o.FS.Open(name)
}

// A form the challenge is on that fails to render is replaced by the error page, which carries no
// widget, so it is sent today's policy rather than the widened one the form would have been sent
// (#642 decision 9).
func TestTurnstileChallenge_AFormThatFailsToRenderIsReplacedUnderTodaysPolicy(t *testing.T) {
	for _, tt := range []struct {
		name     string
		template string
		request  func(*Server) *http.Request
	}{
		{"sign-in", "auth_pwd.html", func(s *Server) *http.Request {
			r := challenged(browserRequest(http.MethodGet, "/auth/pwd?ceremony="+routesTestCeremonyId))
			r.AddCookie(pwdCeremonyCookie(t, s))
			return r
		}},
		{"forgot-password", "forgot_password.html", func(*Server) *http.Request {
			return challenged(browserRequest(http.MethodGet, "/forgot-password"))
		}},
		{"registration", "account_register.html", func(*Server) *http.Request {
			return challenged(browserRequest(http.MethodGet, "/account/register"))
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// The form's own template fails as it executes, after the policy was widened for it.
			failing := overlaidTemplates{FS: web.TemplateFS(), files: fstest.MapFS{tt.template: {Data: []byte(
				`{{define "title"}}t{{end}}{{define "head"}}{{end}}{{define "body"}}{{template "no-such-template" .}}{{end}}`)}}}
			verifier := &doubledVerifier{t: t, forbidden: true}
			server := newRoutesTestServerRendering(t, nil, newTestSessionStore(), verifier, failing)

			rr := serveSecured(server, tt.request(server))

			require.Equal(t, http.StatusInternalServerError, rr.Code)
			doc, err := goquery.NewDocumentFromReader(strings.NewReader(rr.Body.String()))
			require.NoError(t, err)
			assert.Contains(t, doc.Find(".auth-status p").First().Text(), "The server couldn't complete your request",
				"the error page replaced the form")
			assert.NotContains(t, rr.Body.String(), "cf-turnstile")
			assert.NotContains(t, rr.Body.String(), "challenges.cloudflare.com")
			assert.Equal(t, plainPolicy, rr.Header().Get("Content-Security-Policy"))
		})
	}
}
