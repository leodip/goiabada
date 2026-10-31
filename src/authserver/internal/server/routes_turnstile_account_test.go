package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/turnstile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The Turnstile challenge on the forgot-password and registration forms, composed with their
// availability refusals and their rate limiters as initRoutes composes them, with the check doubled
// through its port (#642). As on the sign-in form: a refused submission redraws the form with the
// challenge's message and the address typed, and leaves every tier of the form's limiter as it was
// and the address unlooked-up; a pass or a fail-open goes on to the limiter and the handler; and
// every render of the form, and no page without it, admits Cloudflare's script. The availability
// refusals still answer first, unchecked.

const (
	// The page a well-formed forgot-password request is answered with, which only the handler draws.
	forgotPasswordLinkSent = "Check your email"
	// What registration without verification answers an address with no password, which only the
	// handler draws.
	registrationPasswordRequired = "Password is required."
)

// challengedForm is one of the two forms, as the tests below drive it.
type challengedForm struct {
	name string
	// The widget's action, and the form the check is asked about.
	form turnstile.Form
	path string
	// The notice a refusal is drawn in.
	errorSelector string
	// The address the redrawn form keeps, from the one typed: each form keeps it as its own
	// handler's refusals do.
	kept func(typed string) string
	// What the handler alone answers the submissions below with, proof the submission reached it.
	reached string
	// The form's per-address and per-block budgets, over one window.
	emailBudget, ipBudget, window int
}

var challengedForms = []challengedForm{
	{
		name: "forgot-password", form: turnstile.FormForgotPassword, path: "/forgot-password",
		errorSelector: "#forgot-error p",
		// Drawn back as typed, as the handler draws back a malformed address.
		kept:        func(typed string) string { return typed },
		reached:     forgotPasswordLinkSent,
		emailBudget: forgotPwdEmailBudget, ipBudget: forgotPwdIpBudget, window: forgotPwdWindow,
	},
	{
		name: "registration", form: turnstile.FormRegister, path: "/account/register",
		errorSelector: "#register-error p",
		// Trimmed and lowercased, as the handler redraws every refusal.
		kept:        func(typed string) string { return strings.ToLower(strings.TrimSpace(typed)) },
		reached:     registrationPasswordRequired,
		emailBudget: registerEmailBudget, ipBudget: registerBudget, window: registerWindow,
	},
}

// submission is a submission of the form with the address alone, carrying token in
// cf-turnstile-response when there is one, under the challenge's settings.
func (f challengedForm) submission(email, token string) *http.Request {
	form := url.Values{"email": {email}}
	if token != "" {
		form.Set(turnstile.ResponseField, token)
	}
	return challenged(browserForm(http.MethodPost, f.path, form.Encode()))
}

// assertRedrawn checks rr is the form shown again beside refusal, with the address kept, a fresh
// widget with the form's action and the widened policy.
func (f challengedForm) assertRedrawn(t *testing.T, rr *httptest.ResponseRecorder, refusal, email string) {
	t.Helper()
	require.Equal(t, http.StatusOK, rr.Code)
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(rr.Body.String()))
	require.NoError(t, err)
	assert.Equal(t, refusal, strings.TrimSpace(doc.Find(f.errorSelector).Text()))
	assert.Equal(t, email, doc.Find(`form input[name="email"]`).AttrOr("value", ""), "the address typed is kept")
	widget := doc.Find(`form div.cf-turnstile`)
	require.Equal(t, 1, widget.Length(), "a fresh widget on the redrawn form")
	assert.Equal(t, string(f.form), widget.AttrOr("data-action", ""))
	assert.Equal(t, turnstileTestSiteKey, widget.AttrOr("data-sitekey", ""))
	assert.Equal(t, widenedPolicy, rr.Header().Get("Content-Security-Policy"))
}

// assertAddressUnread checks the handler never looked an address up, which each form's handler
// does for every well-formed address it is given.
func assertAddressUnread(t *testing.T, s *Server) {
	t.Helper()
	databaseOf(s).AssertNotCalled(t, "GetUserByEmail", mock.Anything, mock.Anything, mock.Anything)
	databaseOf(s).AssertNotCalled(t, "GetPreRegistrationByEmail", mock.Anything, mock.Anything, mock.Anything)
}

func TestTurnstileChallenge_ARefusedForgotPasswordOrRegistrationRedrawsTheFormAndSpendsNothing(t *testing.T) {
	for _, f := range challengedForms {
		t.Run(f.name, func(t *testing.T) {
			for _, outcome := range []turnstile.Outcome{turnstile.Refused, turnstile.Missing} {
				t.Run(string(outcome), func(t *testing.T) {
					server, verifier := newTurnstileRoutesTestServer(t, outcome)

					rr := serveSecured(server, f.submission("  Victim@Example.com ", turnstileTestToken))

					f.assertRedrawn(t, rr, challengeRefusal, f.kept("  Victim@Example.com "))
					assert.Equal(t, []doubledCheck{{Form: f.form, Token: turnstileTestToken}}, verifier.checked())
					assertAddressUnread(t, server)
				})
			}

			// Twice past the form's per-block budget, the larger of its two. Then, the challenge
			// passing, each tier still has its whole budget.
			refusals := 2 * f.ipBudget

			t.Run("the address's tier is whole after the refusals", func(t *testing.T) {
				server, verifier := newTurnstileRoutesTestServer(t, turnstile.Refused)
				for i := 0; i < refusals; i++ {
					rr := serve(server, f.submission("victim@example.com", turnstileTestToken))
					require.Equal(t, http.StatusOK, rr.Code, "refusal %d", i+1)
					require.Contains(t, rr.Body.String(), challengeRefusal, "refusal %d", i+1)
				}
				assertAddressUnread(t, server)

				verifier.answer(turnstile.Passed)
				assertRefused(t, exhaust(t, server, f.emailBudget, func(int) *http.Request {
					return f.submission("victim@example.com", turnstileTestToken)
				}), f.window, shapeBrowser)
			})

			t.Run("the client block's tier is whole after the refusals", func(t *testing.T) {
				server, verifier := newTurnstileRoutesTestServer(t, turnstile.Missing)
				another := func(attempt int) *http.Request {
					return f.submission("user"+strconv.Itoa(attempt)+"@example.com", turnstileTestToken)
				}
				for i := 0; i < refusals; i++ {
					require.Contains(t, serve(server, another(i)).Body.String(), challengeRefusal, "refusal %d", i+1)
				}

				verifier.answer(turnstile.Passed)
				assertRefused(t, exhaust(t, server, f.ipBudget, func(attempt int) *http.Request {
					return another(refusals + attempt)
				}), f.window, shapeBrowser)
			})
		})
	}
}

// A pass, and each way the challenge fails open, go on to the limiter and the handler exactly as
// with the challenge off: the handler answers, and the submission spends one of the address's
// budget.
func TestTurnstileChallenge_APassOrAFailOpenGoesOnToTheForgotPasswordOrRegistrationHandler(t *testing.T) {
	for _, f := range challengedForms {
		for _, outcome := range []turnstile.Outcome{turnstile.Passed, turnstile.Unavailable, turnstile.Misconfigured} {
			t.Run(f.name+"/"+string(outcome), func(t *testing.T) {
				server, verifier := newTurnstileRoutesTestServer(t, outcome)

				rr := serve(server, f.submission("victim@example.com", turnstileTestToken))

				require.Equal(t, http.StatusOK, rr.Code)
				assert.Contains(t, rr.Body.String(), f.reached)
				assert.NotContains(t, rr.Body.String(), challengeRefusal)
				assert.Equal(t, []doubledCheck{{Form: f.form, Token: turnstileTestToken}}, verifier.checked())
				databaseOf(server).AssertCalled(t, "GetUserByEmail", mock.Anything, mock.Anything, "victim@example.com")

				assertRefused(t, exhaust(t, server, f.emailBudget-1, func(int) *http.Request {
					return f.submission("victim@example.com", turnstileTestToken)
				}), f.window, shapeBrowser)
			})
		}
	}
}

// The token is read from the request body: one in the query string is not the submission's, which
// is then checked as carrying none.
func TestTurnstileChallenge_TheForgotPasswordAndRegistrationTokenIsReadFromTheBodyOnly(t *testing.T) {
	for _, f := range challengedForms {
		t.Run(f.name, func(t *testing.T) {
			server, verifier := newTurnstileRoutesTestServer(t, turnstile.Missing)
			r := f.submission("victim@example.com", "")
			r.URL.RawQuery = url.Values{turnstile.ResponseField: {turnstileTestToken}}.Encode()

			rr := serve(server, r)

			assert.Contains(t, rr.Body.String(), challengeRefusal)
			assert.Equal(t, []doubledCheck{{Form: f.form, Token: ""}}, verifier.checked())
		})
	}
}

// The availability refusals answer first, as they do with the challenge off: forgot-password with
// email off and registration while it is unavailable are the not-found page, and never checked.
func TestTurnstileChallenge_AnUnavailableFormIsNotFoundUnchecked(t *testing.T) {
	for name, tt := range map[string]struct {
		path        string
		unavailable func(*record.Settings)
	}{
		"forgot-password with email off": {"/forgot-password", func(s *record.Settings) { s.SMTPEnabled = false }},
		"registration off":               {"/account/register", func(s *record.Settings) { s.SelfRegistrationEnabled = false }},
		"registration with verification and email off": {"/account/register", func(s *record.Settings) {
			s.SelfRegistrationRequiresEmailVerification = true
			s.SMTPEnabled = false
		}},
	} {
		t.Run(name, func(t *testing.T) {
			server, verifier := newTurnstileRoutesTestServer(t, turnstile.Passed)
			verifier.forbidden = true
			settings := turnstileSettings()
			tt.unavailable(settings)
			form := url.Values{"email": {"victim@example.com"}, turnstile.ResponseField: {turnstileTestToken}}
			r := browserForm(http.MethodPost, tt.path, form.Encode())
			r = r.WithContext(reqctx.WithSettings(r.Context(), settings))

			rr := serve(server, r)

			assert.Equal(t, http.StatusNotFound, rr.Code)
			assertAddressUnread(t, server)
		})
	}
}

// With the challenge off, nothing changes on either form: the check is never reached, no render
// carries a widget or loads anything from Cloudflare, and the policy is today's.
func TestTurnstileChallenge_OffChangesNothingOnForgotPasswordOrRegistration(t *testing.T) {
	for _, f := range challengedForms {
		t.Run(f.name, func(t *testing.T) {
			server, verifier := newTurnstileRoutesTestServer(t, turnstile.Refused)
			verifier.forbidden = true

			// The challenge's keys stay stored while it is off, and do not turn it on.
			off := func(r *http.Request) *http.Request {
				settings := turnstileSettings()
				settings.TurnstileEnabled = false
				return r.WithContext(reqctx.WithSettings(r.Context(), settings))
			}

			for name, r := range map[string]*http.Request{
				"the form":              off(browserRequest(http.MethodGet, f.path)),
				"a malformed address":   off(f.submission("not-an-address", "")),
				"a well-formed address": off(f.submission("victim@example.com", "")),
			} {
				rr := serveSecured(server, r)
				require.Equal(t, http.StatusOK, rr.Code, name)
				assert.Equal(t, plainPolicy, rr.Header().Get("Content-Security-Policy"), name)
				assert.NotContains(t, rr.Body.String(), "challenges.cloudflare.com", name)
				assert.NotContains(t, rr.Body.String(), "cf-turnstile", name)
				assert.NotContains(t, rr.Body.String(), challengeRefusal, name)
			}
		})
	}
}

// Every render of either form carries the widget, with the site key, the form's action and the
// page's language, and admits Cloudflare's script: the form's first render, and each the handler
// redraws for a refusal of its own. A page without the form keeps today's policy (#642 decision 9).
func TestTurnstileChallenge_EveryForgotPasswordAndRegistrationFormCarriesTheWidget(t *testing.T) {
	for _, f := range challengedForms {
		t.Run(f.name, func(t *testing.T) {
			server, _ := newTurnstileRoutesTestServer(t, turnstile.Passed)

			rr := serveSecured(server, challenged(browserRequest(http.MethodGet, f.path)))

			require.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, widenedPolicy, rr.Header().Get("Content-Security-Policy"))
			doc, err := goquery.NewDocumentFromReader(strings.NewReader(rr.Body.String()))
			require.NoError(t, err)
			widget := doc.Find("form div.cf-turnstile")
			require.Equal(t, 1, widget.Length(), "one widget, inside the form, so its token is submitted with it")
			assert.Equal(t, turnstileTestSiteKey, widget.AttrOr("data-sitekey", ""))
			assert.Equal(t, string(f.form), widget.AttrOr("data-action", ""))
			assert.Equal(t, "en", widget.AttrOr("data-language", ""))
			script := doc.Find(`script[src="https://challenges.cloudflare.com/turnstile/v0/api.js"]`)
			require.Equal(t, 1, script.Length(), "the widget's script")
			assert.Empty(t, strings.TrimSpace(script.Text()), "a script with no body, which the policy allows from its origin")

			t.Run("in the page's language", func(t *testing.T) {
				r := challenged(browserRequest(http.MethodGet, f.path))
				r.Header.Set("Accept-Language", "pt-BR")
				doc, err := goquery.NewDocumentFromReader(strings.NewReader(serve(server, r).Body.String()))
				require.NoError(t, err)
				assert.Equal(t, doc.Find("html").AttrOr("lang", "?"), doc.Find("div.cf-turnstile").AttrOr("data-language", ""))
			})

			t.Run("the handler's own refusal", func(t *testing.T) {
				rr := serveSecured(server, f.submission("not-an-address", turnstileTestToken))
				f.assertRedrawn(t, rr, "Please enter a valid email address.", "not-an-address")
			})
		})
	}

	t.Run("registration's refusal of a password", func(t *testing.T) {
		server, _ := newTurnstileRoutesTestServer(t, turnstile.Passed)
		form := url.Values{
			"email": {"victim@example.com"}, "password": {"a-good-password"}, "passwordConfirmation": {"another-password"},
			turnstile.ResponseField: {turnstileTestToken},
		}
		rr := serveSecured(server, challenged(browserForm(http.MethodPost, "/account/register", form.Encode())))
		challengedForms[1].assertRedrawn(t, rr, "The passwords don't match.", "victim@example.com")
	})

	t.Run("forgot-password's answer, which has no form, keeps today's policy", func(t *testing.T) {
		server, _ := newTurnstileRoutesTestServer(t, turnstile.Passed)
		rr := serveSecured(server, challengedForms[0].submission("victim@example.com", turnstileTestToken))
		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), forgotPasswordLinkSent)
		assert.Equal(t, plainPolicy, rr.Header().Get("Content-Security-Policy"))
		assert.NotContains(t, rr.Body.String(), "challenges.cloudflare.com")
	})
}

// A registration refused by the challenge keeps the sign-in the visitor came from: the redrawn
// form's "Sign in" link carries the ceremony, as the handler's own refusals carry it.
func TestTurnstileChallenge_ARefusedRegistrationKeepsTheSignInItCameFrom(t *testing.T) {
	// An id of the shape ceremony.NewId draws, which the page alone echoes back.
	ceremonyId := ceremony.NewId()
	server, _ := newTurnstileRoutesTestServer(t, turnstile.Refused)
	r := challengedForms[1].submission("victim@example.com", turnstileTestToken)
	r.URL.RawQuery = url.Values{"ceremony": {ceremonyId}}.Encode()

	rr := serve(server, r)

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(rr.Body.String()))
	require.NoError(t, err)
	require.Contains(t, rr.Body.String(), challengeRefusal)
	assert.Equal(t, "/auth/pwd?ceremony="+ceremonyId, doc.Find("p.auth-footer a").AttrOr("href", ""))
}
