package server

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/afterresponse"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/otp"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/authserver/internal/tokenmetrics"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/routing"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestInitRoutes_LimitersAreRegisteredOnTheProductionRoutes makes the claim neither the
// limiter table in authserver/internal/middleware nor the handler seams can make: that every limiter
// is mounted on the route it is meant to protect.
//
// Both of those tiers compose a limiter around a handler by hand, which is exactly the
// arrangement that keeps passing when the registration in initRoutes loses its wrapper.
// Removing any one of the twelve wrappers from routes.go left the whole module suite green,
// so an endpoint could be shipped unprotected with every limiter and handler test still
// passing. One case per registration, so a wrapper cannot be dropped in silence (#219).
//
// It runs the real initRoutes on the real router, and the request goes through whatever
// chain that registration produced: for the account API that is the debug, bearer-token,
// scope, user-bound and session guards ahead of the limiter, in their production order.
// Only two things are supplied rather than performed. The bearer token is placed in the
// request context in the shape JwtAuthorizationHeaderToContext would leave it, since
// signature validation is not what this test claims; and the settings come from the context
// rather than from middleware.Settings, because initMiddleware is not what is under test.
//
// What the handler answers is deliberately not asserted, only that it is not a 429: these
// cases own the wiring, and asserting a handler's own response here would duplicate its
// tests and break on every unrelated change to them. The budgets belong to seam 1 and the
// failure-only semantics to seam 2, so each case spends the budget the published table
// gives its route and requires the next request to be refused.
//
// Presence is not identity, and the cases below pin both. Spending a budget and being
// refused says a limiter answered, never which one: eleven substitutions of one limiter
// method for another in initRoutes left the whole module tier green, because limiters
// publishing the same budget over the same window in the same class are indistinguishable
// from that distance. So every refusal is checked for the Retry-After its tier's own
// window produces and for the body class its caller parses, which separates every pair
// whose window or caller differs; and the pairs that agree on all three are separated by
// the one thing still observable from out here, that each holds its own counter, so
// spending one must leave its lookalike untouched (#219).

const (
	// The subject every account-API case presents, and therefore the key its limiter
	// buckets on.
	routesTestSubject = "8b0d8c7e-3a0f-4c8b-9d3a-0f4c8b9d3a0f"

	// What the caller submits where a credential is expected. Never the right one: these
	// tiers count failures, so a correct credential would spend nothing and the budget
	// would never fill.
	routesTestWrongPassword = "not the password"

	// Each budget is paired with the window it is spent over, because the window is what
	// the refusal carries as Retry-After and is therefore how a case tells one tier from
	// another that publishes the same number.
	registerBudget              = 20  // requests per 5 minutes per /64
	registerEmailBudget         = 5   // requests per 5 minutes per address
	registerWindow              = 300 // seconds
	activateBudget              = 30  // requests per 5 minutes per /64, shared by GET and POST
	activateWindow              = 300
	forgotPwdIpBudget           = 20 // requests per 5 minutes per /64
	forgotPwdEmailBudget        = 5  // requests per 5 minutes per address
	forgotPwdWindow             = 300
	emailVerificationBudget     = 5 // failures per 15 minutes per token subject
	emailVerificationWindow     = 900
	emailVerificationSendBudget = 5 // requests per 60 minutes per token subject
	emailVerificationSendWindow = 3600
	accountEmailChangeBudget    = 5 // requests per 60 minutes per token subject
	accountEmailChangeWindow    = 3600
	accountPasswordBudget       = 5 // failures per 15 minutes per token subject, shared by two routes
	accountPasswordWindow       = 900
	otpBudget                   = 5 // failures per 15 minutes per user id
	otpWindow                   = 900

	routesTestClientId = "test-client"
	// A public client the password grant is enabled for, so a password grant naming it reaches
	// the password check, and a wrong password spends the failures-only tiers there.
	routesTestROPCClientId = "ropc-client"
	// The two per-address password tiers: failures per minute per /64 (#564 decision 2).
	pwdIpBudget = 30
	pwdIpWindow = 60
	// The per-address ceiling in front of each: every password check per minute per /64 (#564).
	pwdIpCeiling = 120
	// The admission tier on the authorization endpoint: every request per minute per /64,
	// shared by the GET and the POST (#504).
	authorizeBudget      = 120
	authorizeWindow      = 60
	routesTestCeremonyId = "9f1c2c2f-2a0f-4a3b-8b6d-1f0a5c9e7d21"
	// A well-formed base32 TOTP secret, so the code the OTP case submits is refused for
	// being wrong rather than for the secret being unreadable.
	routesTestOTPSecret = "JBSWY3DPEHPK3PXP"
	// The ceremony carries the key as its otpauth:// URL and derives the secret from it,
	// so the cookie has to hold one the handler can parse (#247).
	routesTestOTPKeyURL = "otpauth://totp/Goiabada:routes@example.com" +
		"?algorithm=SHA1&digits=6&issuer=Goiabada&period=30&secret=" + routesTestOTPSecret
)

// routesTestSettings is what middleware.Settings would put in the context. Self-registration
// and SMTP are on, or two of the handlers below refuse before reaching their credential
// check. Both audit sinks are off, which keeps the real audit.Logger from writing rows the
// database mock was never asked for; that it reads settings at all is #212's finding, not
// this test's business.
func routesTestSettings() *record.Settings {
	return &record.Settings{
		Id:                         1,
		AppName:                    "Goiabada",
		SelfRegistrationEnabled:    true,
		SMTPEnabled:                true,
		AuditLogsInConsoleEnabled:  false,
		AuditLogsInDatabaseEnabled: false,
	}
}

// newRoutesTestServer builds a Server by hand and runs the real initRoutes on it, which is
// the convention server_request_logger_test.go established for initMiddleware. A fresh one
// per case, because the limiter it constructs holds the counters.
func newRoutesTestServer(t *testing.T) *Server {
	t.Helper()
	return newRoutesTestServerWith(t, nil)
}

// newRoutesTestServerWith is newRoutesTestServer with configure applied to the configuration
// initRoutes reads, after the limiter is switched on.
func newRoutesTestServerWith(t *testing.T, configure func(*config.Config)) *Server {
	t.Helper()
	return newRoutesTestServerOver(t, configure, newTestSessionStore())
}

// newRoutesTestServerOver is newRoutesTestServerWith over a session store the caller holds.
func newRoutesTestServerOver(t *testing.T, configure func(*config.Config), sessionStore *sessionstore.ConditionalStore) *Server {
	t.Helper()

	passwordHash, err := passwordhash.Hash("the account's real password")
	require.NoError(t, err)

	database := datamocks.NewDatabase(t)
	database.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).Return(routesTestSettings(), nil).Maybe()
	database.On("GetUserBySubject", mock.Anything, mock.Anything, routesTestSubject).Return(&record.User{
		Id:           1,
		Enabled:      true,
		Subject:      routesTestSubject,
		Email:        "victim@example.com",
		PasswordHash: passwordHash,
		// EmailVerified false with no stored code: the verification comparison is reached
		// and refuses, which is the branch that spends that budget.
		EmailVerified: false,
	}, nil).Maybe()
	// /forgot-password and /account/register look the address up before deciding what to
	// render. No account and nothing pending means no mail is sent, and registration without
	// verification then stops at the missing password, which keeps these cases about the
	// limiter alone.
	database.On("GetUserByEmail", mock.Anything, mock.Anything, mock.Anything).Return((*record.User)(nil), nil).Maybe()
	database.On("GetPreRegistrationByEmail", mock.Anything, mock.Anything, mock.Anything).
		Return((*record.PreRegistration)(nil), nil).Maybe()
	// What the OTP step reads: the user the auth context names, not yet enrolled, and the
	// client whose branding the form carries.
	database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).
		Return(&record.User{Id: 1, Enabled: true, OTPEnabled: false}, nil).Maybe()
	database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, routesTestClientId).
		Return(&record.Client{Id: 1, ClientIdentifier: routesTestClientId}, nil).Maybe()
	database.On("ClientHasLogo", mock.Anything, mock.Anything, int64(1)).Return(false, nil).Maybe()
	ropcEnabled := true
	database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, routesTestROPCClientId).
		Return(&record.Client{Id: 2, ClientIdentifier: routesTestROPCClientId, Enabled: true, IsPublic: true,
			ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled}, nil).Maybe()

	// The limiter on, which initRoutes reads when it builds the limiter.
	cfg := &config.Config{}
	cfg.AuthServer.RateLimiterEnabled = true
	if configure != nil {
		configure(cfg)
	}

	registry := metrics.NewRegistry()
	s := &Server{
		router:       routing.New(),
		database:     database,
		sessionStore: sessionStore,
		templateFS:   web.TemplateFS(),
		staticFS:     web.StaticFS(),
		cfg:          cfg,
		jobs:         afterresponse.New(registry),
		metrics:      registry,
		tokenMetrics: tokenmetrics.Register(registry),
	}
	// What a forgot-password request hands off runs against this test's mocks, so it is waited
	// for before they are torn down, as the server waits for it on shutdown.
	t.Cleanup(func() { s.jobs.Wait(10 * time.Second) })
	// Every branch is the bare router: these tests drive the registrations rather than the
	// application chain, and put the settings on each request's context themselves.
	s.initRoutes(appBranches{pages: s.router, protocol: s.router, api: s.router, token: s.router})
	return s
}

// withRoutesTestSettings puts in the context what middleware.Settings puts there in
// production. Both the handlers and the browser rejection page read it from there.
func withRoutesTestSettings(r *http.Request) *http.Request {
	return r.WithContext(reqctx.WithSettings(r.Context(), routesTestSettings()))
}

// browserRequest is an unauthenticated form post from one host, which is what the per-IP
// tiers bucket.
func browserRequest(method string, target string) *http.Request {
	return browserForm(method, target, "")
}

func browserForm(method string, target string, body string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return withRoutesTestSettings(r)
}

// apiRequest carries a bearer token in the context, in the shape
// JwtAuthorizationHeaderToContext leaves behind when it decodes a valid one: the scope the
// account API requires, an auth_time claim marking it a user token rather than a
// client_credentials one, and no sid, so the session check falls back to the generation
// claim the zero-valued user matches.
func apiRequest(method string, target string, body string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r = r.WithContext(reqctx.WithBearerToken(r.Context(), accountAPIToken()))
	return withRoutesTestSettings(r)
}

// accountAPIToken is the decoded bearer token apiRequest carries.
func accountAPIToken() oauth.JwtToken {
	return oauth.JwtToken{Claims: jwt.MapClaims{
		"sub":       routesTestSubject,
		"scope":     builtin.AuthServerResourceIdentifier + ":" + builtin.ManageAccountPermissionIdentifier,
		"auth_time": float64(time.Now().Add(-time.Minute).Unix()),
	}}
}

// otpCeremonyCookie mints the session cookie a user part way through the OTP step carries:
// an auth context at the level 2 state carrying the enrollment secret HandleAuthOtpGet left
// on it. Written through the ceremony store over the server's own session store, so what the
// handler reads back is what the store wrote rather than a shape this test invented.
func otpCeremonyCookie(t *testing.T, s *Server) *http.Cookie {
	t.Helper()

	r := httptest.NewRequest(http.MethodGet, "/auth/otp", nil)
	recorder := httptest.NewRecorder()
	require.NoError(t, ceremony.NewStore(s.sessionStore, sessionkeys.AuthServerSessionName).AddAuthContext(recorder, r,
		&ceremony.AuthContext{
			AuthState:  ceremony.AuthStateLevel2OTP,
			CeremonyId: routesTestCeremonyId,
			UserId:     1,
			ClientId:   routesTestClientId,
			OTPKeyURL:  routesTestOTPKeyURL,
		}))

	cookies := recorder.Result().Cookies()
	assert.Len(t, cookies, 1)
	return cookies[0]
}

func serve(s *Server, r *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, r)
	return recorder
}

// rejectShape is the body a refused caller on this route parses. Which one a registration
// answers in is chosen by the limiter method, so it is one of the two things a refusal
// says about the limiter's identity rather than merely its presence.
type rejectShape int

const (
	shapeBrowser rejectShape = iota
	shapeOAuth
	shapeAPI
)

// assertRefused checks the whole refusal rather than only that one arrived: the exact
// Retry-After, which is the refusing tier's own window in seconds, and the body, which is
// the class the registration was made for. A case asserting the status alone passes with
// the route wired to any limiter that happens to publish the same budget.
func assertRefused(t *testing.T, rr *httptest.ResponseRecorder, window int, shape rejectShape) {
	t.Helper()

	assert.Equal(t, http.StatusTooManyRequests, rr.Code)
	assert.Equal(t, strconv.Itoa(window), rr.Header().Get("Retry-After"),
		"Retry-After carries the window of the tier that refused")
	assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))

	switch shape {
	case shapeOAuth:
		assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
		assert.Contains(t, rr.Body.String(), `"error":"invalid_request"`)
	case shapeAPI:
		assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
		assert.Contains(t, rr.Body.String(), "TOO_MANY_REQUESTS")
	case shapeBrowser:
		assert.Contains(t, rr.Header().Get("Content-Type"), "text/html")
		assert.NotContains(t, rr.Body.String(), "TOO_MANY_REQUESTS",
			"a browser gets the error page, not either machine envelope")
	}
}

// exhaust spends a route's published budget, requiring every request to reach the handler,
// and returns the response to the one after it.
func exhaust(t *testing.T, s *Server, budget int, request func(attempt int) *http.Request) *httptest.ResponseRecorder {
	t.Helper()

	for i := 0; i < budget; i++ {
		assert.NotEqual(t, http.StatusTooManyRequests, serve(s, request(i)).Code,
			"request %d must reach the handler", i+1)
	}
	return serve(s, request(budget))
}

// registrationOf is a registration of a distinct address per attempt, which spends only the
// registration's per-IP tier.
func registrationOf(attempt int) *http.Request {
	return browserForm(http.MethodPost, "/account/register", fmt.Sprintf("email=candidate%d@example.com", attempt))
}

// reachesHandler reports whether one more request on this route is still allowed through.
// The isolation cases use it to show that a budget spent on one route was not the budget
// belonging to another.
func reachesHandler(s *Server, r *http.Request) bool {
	return serve(s, r).Code != http.StatusTooManyRequests
}

// routesTestWrongOTPCode is six digits the fixed secret refuses at this instant. Never a
// literal: TOTP emits every six-digit value, so any fixed one is the real code for about
// ninety seconds whenever the counter reaches it, and the case would then take the success
// path and fail for a reason that has nothing to do with what it asserts. A sweep of this
// secret finds 000000 at 2028-04-13T15:03:30Z. Confirmed against MatchStep, which is the
// three-step window the handler itself verifies in (#219).
func routesTestWrongOTPCode(t *testing.T) string {
	t.Helper()

	for _, candidate := range []string{"000000", "111111", "222222"} {
		if _, matched := otp.MatchStep(candidate, routesTestOTPSecret, time.Now().UTC()); !matched {
			return candidate
		}
	}
	t.Fatal("could not find a six-digit code that the secret refuses")
	return ""
}

func TestInitRoutes_LimitersAreRegisteredOnTheProductionRoutes(t *testing.T) {

	t.Run("POST /account/register is limited", func(t *testing.T) {
		server := newRoutesTestServer(t)

		// Every request counts here, failures and successes alike: the budget bounds
		// enumeration, outbound mail and pre_registration rows rather than guesses. A distinct
		// address per request, so the per-address tier cannot be what refuses.
		assertRefused(t, exhaust(t, server, registerBudget, registrationOf), registerWindow, shapeBrowser)

		// The GET beside it is deliberately unlimited, so the refusal above is attributable
		// to the registration POST's own wrapper rather than to something covering /account.
		assert.NotEqual(t, http.StatusTooManyRequests, serve(server, browserRequest(http.MethodGet, "/account/register")).Code,
			"the registration form itself is not rate limited")
	})

	t.Run("POST /api/v1/account/email/verification is limited", func(t *testing.T) {
		server := newRoutesTestServer(t)
		const wrongCode = `{"verificationCode":"ABCD1234"}`

		// The API reject class, which is what a caller on this route already parses.
		assertRefused(t, exhaust(t, server, emailVerificationBudget, func(int) *http.Request {
			return apiRequest(http.MethodPost, "/api/v1/account/email/verification", wrongCode)
		}), emailVerificationWindow, shapeAPI)
	})

	t.Run("POST /api/v1/account/email/verification/send is limited", func(t *testing.T) {
		server := newRoutesTestServer(t)

		// Every request counts. SMTP is off on these, so the handler answers each with
		// SMTP_NOT_ENABLED and sends nothing, which keeps the case about the limiter; the
		// hour's Retry-After is what no other tier answers with, so this is the send's own
		// limiter and not one of its lookalikes.
		sendRequest := func(int) *http.Request {
			r := apiRequest(http.MethodPost, "/api/v1/account/email/verification/send", "")
			settings := routesTestSettings()
			settings.SMTPEnabled = false
			return r.WithContext(reqctx.WithSettings(r.Context(), settings))
		}
		assertRefused(t, exhaust(t, server, emailVerificationSendBudget, sendRequest),
			emailVerificationSendWindow, shapeAPI)

		assert.True(t, reachesHandler(server, apiRequest(http.MethodPost, "/api/v1/account/email/verification",
			`{"verificationCode":"ABCD1234"}`)),
			"the verification check keeps its own budget when the send's is spent")
	})

	// One case for both routes, because one limiter instance covers them: five failures
	// against the password route must leave the OTP route refusing. Split into two cases it
	// would pass with two separate buckets, which is the arrangement decision 10 rejected
	// for handing an attacker ten guesses by alternating.
	t.Run("PUT /api/v1/account/password and PUT /api/v1/account/otp share one bucket", func(t *testing.T) {
		server := newRoutesTestServer(t)
		passwordBody := `{"currentPassword":"` + routesTestWrongPassword + `","newPassword":"a new password"}`
		otpBody := `{"password":"` + routesTestWrongPassword + `","enabled":false}`

		for i := 0; i < accountPasswordBudget; i++ {
			assert.NotEqual(t, http.StatusTooManyRequests,
				serve(server, apiRequest(http.MethodPut, "/api/v1/account/password", passwordBody)).Code,
				"guess %d must reach the handler", i+1)
		}

		assertRefused(t, serve(server, apiRequest(http.MethodPut, "/api/v1/account/otp", otpBody)),
			accountPasswordWindow, shapeAPI)
	})

	// The registrations this change did not add, driven the same way. Their wrappers were
	// already in routes.go, but nothing observed them either, and every one of these
	// middlewares was reworked here: the password gate became two tiers, ROPC's composite
	// key was split, and both keys were normalized. Each of these tiers counts every
	// request on the client block, so filling one needs no credential and no session.
	//
	for _, tc := range []struct {
		name    string
		budget  int
		window  int
		shape   rejectShape
		request func(attempt int) *http.Request
	}{
		{"POST /forgot-password", forgotPwdIpBudget, forgotPwdWindow, shapeBrowser, func(attempt int) *http.Request {
			// A distinct address per request, so the per-email tier of 5 cannot trip and
			// the refusal below is attributable to the per-IP tier this case names. The
			// email tier gets its own case further down.
			return browserForm(http.MethodPost, "/forgot-password",
				"email=user"+strconv.Itoa(attempt)+"@example.com")
		}},
		{"GET /reset-password", 30, 300, shapeBrowser, func(int) *http.Request {
			return browserRequest(http.MethodGet, "/reset-password")
		}},
		{"POST /reset-password", 30, 300, shapeBrowser, func(int) *http.Request {
			return browserRequest(http.MethodPost, "/reset-password")
		}},
		{"GET /account/activate", activateBudget, activateWindow, shapeBrowser, func(int) *http.Request {
			return browserRequest(http.MethodGet, "/account/activate")
		}},
		{"POST /account/activate", activateBudget, activateWindow, shapeBrowser, func(int) *http.Request {
			return browserRequest(http.MethodPost, "/account/activate")
		}},
		{"POST /connect/register", 10, 60, shapeOAuth, func(int) *http.Request {
			r := httptest.NewRequest(http.MethodPost, "/connect/register", strings.NewReader("{}"))
			r.Header.Set("Content-Type", "application/json")
			return withRoutesTestSettings(r)
		}},
		{"GET /auth/authorize", authorizeBudget, authorizeWindow, shapeBrowser, func(int) *http.Request {
			// No client_id and no cookie: the handler refuses the request at its first
			// validation and, finding no stored session to clear, writes no row (#581).
			// The tier counts it anyway, because what it bounds is the row every request
			// it admits may cost (#504).
			return browserRequest(http.MethodGet, "/auth/authorize")
		}},
		{"POST /auth/authorize", authorizeBudget, authorizeWindow, shapeBrowser, func(int) *http.Request {
			// No client_id, so the parking refuses the form before it writes one; the
			// tier counts it anyway, for the GET case's reason (#504).
			return browserForm(http.MethodPost, "/auth/authorize", "")
		}},
	} {
		t.Run(tc.name+" is limited", func(t *testing.T) {
			server := newRoutesTestServer(t)
			assertRefused(t, exhaust(t, server, tc.budget, tc.request), tc.window, tc.shape)
		})
	}

	// The two per-address password tiers count wrong passwords only (#564 decision 2), so each
	// is spent through a real password check that fails: a sign-in form inside a ceremony, and a
	// password grant from a public client the grant is enabled for. A distinct account per
	// guess, so the tight account tier of 10 cannot be what refuses.
	t.Run("POST /auth/pwd is limited", func(t *testing.T) {
		server := newRoutesTestServer(t)
		assertRefused(t, exhaust(t, server, pwdIpBudget, pwdGuess(t, server)), pwdIpWindow, shapeBrowser)
	})

	t.Run("POST /auth/token is limited", func(t *testing.T) {
		server := newRoutesTestServer(t)
		assertRefused(t, exhaust(t, server, pwdIpBudget, ropcGuess), pwdIpWindow, shapeOAuth)
	})

	// The ceiling in front of both counts every check, so it is spent here by checks that charge no
	// failure at all: a form and a grant with no password, which the handler answers without
	// guessing anything, as it answers a right password without charging one (#564).
	t.Run("POST /auth/pwd has a ceiling on every check", func(t *testing.T) {
		server := newRoutesTestServer(t)
		cookie := pwdCeremonyCookie(t, server)
		noPassword := func(attempt int) *http.Request {
			r := browserForm(http.MethodPost, "/auth/pwd", "ceremonyId="+routesTestCeremonyId+
				"&email=user"+strconv.Itoa(attempt)+"%40example.com&password=")
			r.AddCookie(cookie)
			return r
		}
		assertRefused(t, exhaust(t, server, pwdIpCeiling, noPassword), pwdIpWindow, shapeBrowser)
	})

	t.Run("POST /auth/token has a ceiling on every password grant", func(t *testing.T) {
		server := newRoutesTestServer(t)
		noPassword := func(attempt int) *http.Request {
			return browserForm(http.MethodPost, "/auth/token", "grant_type=password&client_id="+routesTestROPCClientId+
				"&username=user"+strconv.Itoa(attempt)+"%40example.com")
		}
		assertRefused(t, exhaust(t, server, pwdIpCeiling, noPassword), pwdIpWindow, shapeOAuth)
	})

	// The last registration, and the only one whose tier is keyed on something the request
	// cannot carry by itself: LimitOtp reads the user id out of the auth context and counts
	// failures, so filling it takes a session mid-ceremony and a code the handler rejects.
	// Driven on the enrollment branch, where the secret being verified comes from the
	// session rather than from the encrypted column, so the case needs no data cipher.
	t.Run("POST /auth/otp is limited", func(t *testing.T) {
		server := newRoutesTestServer(t)
		cookie := otpCeremonyCookie(t, server)
		wrongCode := routesTestWrongOTPCode(t)

		post := func(int) *http.Request {
			r := browserForm(http.MethodPost, "/auth/otp",
				"ceremonyId="+routesTestCeremonyId+"&otp="+wrongCode)
			r.AddCookie(cookie)
			return r
		}

		assertRefused(t, exhaust(t, server, otpBudget, post), otpWindow, shapeBrowser)
	})

	t.Run("PUT /api/v1/account/otp spends the same bucket", func(t *testing.T) {
		// The mirror of the case above, which alone would pass with the OTP route
		// unwrapped: there the OTP request only reads a budget the password route filled.
		server := newRoutesTestServer(t)
		otpBody := `{"password":"` + routesTestWrongPassword + `","enabled":false}`

		for i := 0; i < accountPasswordBudget; i++ {
			assert.NotEqual(t, http.StatusTooManyRequests,
				serve(server, apiRequest(http.MethodPut, "/api/v1/account/otp", otpBody)).Code,
				"guess %d must reach the handler", i+1)
		}

		passwordBody := `{"currentPassword":"` + routesTestWrongPassword + `","newPassword":"a new password"}`
		assertRefused(t, serve(server, apiRequest(http.MethodPut, "/api/v1/account/password", passwordBody)),
			accountPasswordWindow, shapeAPI)
	})

	t.Run("PUT /api/v1/account/email spends the same bucket", func(t *testing.T) {
		// The email change verifies the same password, so it is the third route in that
		// one bucket (#404 decision 3). Refusing the password route after the email route
		// spent the budget is what says the wrapper is that bucket's and not a lookalike's.
		server := newRoutesTestServer(t)
		emailBody := `{"email":"attacker@example.com","currentPassword":"` + routesTestWrongPassword + `"}`

		for i := 0; i < accountPasswordBudget; i++ {
			assert.NotEqual(t, http.StatusTooManyRequests,
				serve(server, apiRequest(http.MethodPut, "/api/v1/account/email", emailBody)).Code,
				"guess %d must reach the handler", i+1)
		}

		passwordBody := `{"currentPassword":"` + routesTestWrongPassword + `","newPassword":"a new password"}`
		assertRefused(t, serve(server, apiRequest(http.MethodPut, "/api/v1/account/password", passwordBody)),
			accountPasswordWindow, shapeAPI)
		// The sixth change has spent the email change's own budget too, and that tier is
		// mounted first, so it is the one that refuses: a request it refuses never reaches the
		// password check.
		assertRefused(t, serve(server, apiRequest(http.MethodPut, "/api/v1/account/email", emailBody)),
			accountEmailChangeWindow, shapeAPI)
	})

	t.Run("PUT /api/v1/account/email counts every change", func(t *testing.T) {
		// Past the password the change says whether an address is taken, so every request
		// counts, not only a wrong password. A blank password is refused before it is checked
		// and spends nothing on the shared bucket, which keeps the case about this tier: the
		// password route still reaches its handler once the email change's budget is gone.
		server := newRoutesTestServer(t)
		changeOf := func(attempt int) *http.Request {
			return apiRequest(http.MethodPut, "/api/v1/account/email",
				fmt.Sprintf(`{"email":"probe%d@example.com","currentPassword":""}`, attempt))
		}
		assertRefused(t, exhaust(t, server, accountEmailChangeBudget, changeOf),
			accountEmailChangeWindow, shapeAPI)

		passwordBody := `{"currentPassword":"` + routesTestWrongPassword + `","newPassword":"a new password"}`
		assert.True(t, reachesHandler(server, apiRequest(http.MethodPut, "/api/v1/account/password", passwordBody)),
			"the shared password bucket keeps its own budget when the email change's is spent")
	})

	// The cases above pin every registration whose window or reject class differs from its
	// neighbours'. Three pairs agree on both and so are still interchangeable from out
	// here: registration and activation, either of those and forgot-password's IP tier,
	// and email verification and the shared account-password bucket. Each of those
	// substitutions survived, and what refuses them is that a limiter holds its own
	// counter: spending one leaves its lookalike with its own budget intact (#219).

	t.Run("registration, activation and forgot-password hold separate budgets", func(t *testing.T) {
		// All three are 20 requests per 5 minutes on the client block, in the browser
		// class, so the only thing that tells them apart is whose counter moved. Wiring
		// /account/register to LimitActivate, or /forgot-password to either of the other
		// two, left every case above green.
		server := newRoutesTestServer(t)
		assertRefused(t, exhaust(t, server, registerBudget, registrationOf), registerWindow, shapeBrowser)

		assert.True(t, reachesHandler(server, browserRequest(http.MethodGet, "/account/activate")),
			"activation keeps its own budget when registration's is spent")
		assert.True(t, reachesHandler(server, browserForm(http.MethodPost, "/forgot-password",
			"email=untouched@example.com")),
			"forgot-password keeps its own budget when registration's is spent")
	})

	t.Run("activation holds a separate budget from registration", func(t *testing.T) {
		// The mirror, which the case above cannot make: there, registration is the route
		// whose wrapper was spent, so /account/activate wired to LimitRegister is caught
		// only by spending activation's budget and finding registration still open.
		server := newRoutesTestServer(t)
		assertRefused(t, exhaust(t, server, activateBudget, func(int) *http.Request {
			return browserRequest(http.MethodGet, "/account/activate")
		}), activateWindow, shapeBrowser)

		assert.True(t, reachesHandler(server, browserRequest(http.MethodPost, "/account/register")),
			"registration keeps its own budget when activation's is spent")
	})

	t.Run("registration bounds one address as well as one client block", func(t *testing.T) {
		// The second tier #207 decision 5 added, at forgot-password's per-address budget: the
		// same address five times is allowed and the sixth is refused, far below the 20 the IP
		// tier would take, while a second address is still let through.
		server := newRoutesTestServer(t)
		assertRefused(t, exhaust(t, server, registerEmailBudget, func(int) *http.Request {
			return browserForm(http.MethodPost, "/account/register", "email=one@example.com")
		}), registerWindow, shapeBrowser)

		assert.True(t, reachesHandler(server, browserForm(http.MethodPost, "/account/register",
			"email=another@example.com")),
			"a second address has its own budget, so what refused above was the per-address tier")
		assert.True(t, reachesHandler(server, browserForm(http.MethodPost, "/forgot-password",
			"email=one@example.com")),
			"forgot-password's per-address tier is its own, not registration's")
	})

	t.Run("forgot-password bounds one address as well as one client block", func(t *testing.T) {
		// Its second tier, which activation does not have at all: the same address five
		// times is allowed and the sixth is refused, far below the 20 the IP tier would take.
		// A route wired to LimitActivate answers the sixth normally; one wired to
		// LimitRegister, whose per-address tier has the same budget, is caught by the
		// separate-budget cases instead.
		server := newRoutesTestServer(t)
		assertRefused(t, exhaust(t, server, forgotPwdEmailBudget, func(int) *http.Request {
			return browserForm(http.MethodPost, "/forgot-password", "email=one@example.com")
		}), forgotPwdWindow, shapeBrowser)

		assert.True(t, reachesHandler(server, browserForm(http.MethodPost, "/forgot-password",
			"email=another@example.com")),
			"a second address has its own budget, so what refused above was the per-email tier")
	})

	t.Run("email verification and the account password check hold separate budgets", func(t *testing.T) {
		// Both are 5 failures per 15 minutes keyed on the token subject, in the API class,
		// so one bucket serving all three routes is invisible to every case above. It is
		// also the arrangement decision 10 rejected in the other direction: the two
		// account routes share on purpose, and email verification must not join them.
		server := newRoutesTestServer(t)
		assertRefused(t, exhaust(t, server, emailVerificationBudget, func(int) *http.Request {
			return apiRequest(http.MethodPost, "/api/v1/account/email/verification",
				`{"verificationCode":"ABCD1234"}`)
		}), emailVerificationWindow, shapeAPI)

		assert.True(t, reachesHandler(server, apiRequest(http.MethodPut, "/api/v1/account/password",
			`{"currentPassword":"`+routesTestWrongPassword+`","newPassword":"a new password"}`)),
			"the password check keeps its own budget when email verification's is spent")
	})

	t.Run("the account password budget is not the email verification budget", func(t *testing.T) {
		// The mirror again, and the one that catches both account-password registrations
		// being moved onto LimitEmailVerification together: they would still share with
		// each other, so the mirrored pair above stays green, and only a spent password
		// bucket leaving email verification open tells them apart.
		server := newRoutesTestServer(t)
		assertRefused(t, exhaust(t, server, accountPasswordBudget, func(int) *http.Request {
			return apiRequest(http.MethodPut, "/api/v1/account/password",
				`{"currentPassword":"`+routesTestWrongPassword+`","newPassword":"a new password"}`)
		}), accountPasswordWindow, shapeAPI)

		assert.True(t, reachesHandler(server, apiRequest(http.MethodPost, "/api/v1/account/email/verification",
			`{"verificationCode":"ABCD1234"}`)),
			"email verification keeps its own budget when the password check's is spent")
	})

	t.Run("both reset-password registrations share one bucket", func(t *testing.T) {
		// The positive half of the same property. One limiter instance covers the GET and
		// the POST on one client block, so the budget is spent jointly; giving either its
		// own limiter would be a wiring change nothing else here would see.
		server := newRoutesTestServer(t)
		assertRefused(t, exhaust(t, server, 30, func(int) *http.Request {
			return browserRequest(http.MethodGet, "/reset-password")
		}), 300, shapeBrowser)

		assert.False(t, reachesHandler(server, browserRequest(http.MethodPost, "/reset-password")),
			"the POST is refused by the budget the GET spent")
		assert.True(t, reachesHandler(server, browserRequest(http.MethodPost, "/auth/pwd")),
			"the password form is not in that bucket")
	})

	t.Run("both activation registrations share one bucket", func(t *testing.T) {
		// The same property for activation, whose POST joined its GET under one tier (#207
		// decision 9). The reset routes publish the same budget over the same window in the
		// same class, so the reset GET still answering is what says this is activation's own
		// bucket and not a lookalike's.
		server := newRoutesTestServer(t)
		assertRefused(t, exhaust(t, server, activateBudget, func(int) *http.Request {
			return browserRequest(http.MethodGet, "/account/activate")
		}), activateWindow, shapeBrowser)

		assert.False(t, reachesHandler(server, browserRequest(http.MethodPost, "/account/activate")),
			"the POST is refused by the budget the GET spent")
		assert.True(t, reachesHandler(server, browserRequest(http.MethodGet, "/reset-password")),
			"the reset routes are not in that bucket")
	})

	t.Run("the password form and the ROPC grant hold separate IP budgets", func(t *testing.T) {
		// Both are 30 failures per minute on the client block. The reject class already
		// separates them, browser against OAuth, and this says the counters are separate
		// too, which is what decision 7's split of the old composite key rests on.
		server := newRoutesTestServer(t)
		assertRefused(t, exhaust(t, server, pwdIpBudget, pwdGuess(t, server)), pwdIpWindow, shapeBrowser)

		assert.True(t, reachesHandler(server, ropcGuess(pwdIpBudget)),
			"the ROPC grant keeps its own budget when the password form's is spent")
	})

	// What the per-address tiers count since #564: a request whose password is not found wrong
	// spends nothing. Requests that check no password stand for it here, an empty sign-in form
	// and a password grant naming a client the grant is not enabled for, which this test server
	// can answer without a real account; the middleware's own tests drive successful checks.
	t.Run("password checks that do not fail spend no per-address budget", func(t *testing.T) {
		server := newRoutesTestServer(t)
		cookie := pwdCeremonyCookie(t, server)
		for i := 0; i < 2*pwdIpBudget; i++ {
			empty := browserForm(http.MethodPost, "/auth/pwd", "ceremonyId="+routesTestCeremonyId)
			empty.AddCookie(cookie)
			require.True(t, reachesHandler(server, empty), "empty sign-in form %d", i+1)
			require.True(t, reachesHandler(server, browserForm(http.MethodPost, "/auth/token",
				"grant_type=password&client_id="+routesTestClientId+"&username=user"+strconv.Itoa(i)+
					"%40example.com&password="+routesTestWrongPassword)), "unauthenticated password grant %d", i+1)
		}
		assertRefused(t, exhaust(t, server, pwdIpBudget, pwdGuess(t, server)), pwdIpWindow, shapeBrowser)
		assertRefused(t, exhaust(t, server, pwdIpBudget, ropcGuess), pwdIpWindow, shapeOAuth)
	})
}

// TestInitRoutes_TokenFormThatDoesNotParse drives POST /auth/token through the real registration,
// the limiter and the token handler with its real validator, and requires the same 400
// invalid_request whether the limiter is on or off, with nothing past the parse reached. The limiter
// parses the form first, on or off since the account-wide tier applies either way (#503), and it used
// to forward a failure: net/http kept the pairs
// that did parse, the handler's own ParseForm answered nil over them, and the request was validated
// as if those pairs were all it carried. A repeated parameter whose second copy was malformed passed
// as sent once, and a password grant beside one malformed pair reached the password check past both
// of the limiter's tiers (#228, #437).
//
// The client named is one the database mock has no answer for, so a request that reached the client
// lookup would fail the case on the mock as well as on the answer.
func TestInitRoutes_TokenFormThatDoesNotParse(t *testing.T) {
	const passwordGrant = "grant_type=password&username=victim%40example.com&password=" + routesTestWrongPassword
	const clientCredentials = "grant_type=client_credentials&client_id=unstubbed-client&client_secret=s"

	tests := []struct {
		name   string
		target string
		body   func() io.Reader
	}{
		{"a malformed second copy of client_id", "/auth/token", func() io.Reader {
			return strings.NewReader(clientCredentials + "&client_id=%zz")
		}},
		{"a malformed pair the endpoint ignores, beside a client credentials grant", "/auth/token", func() io.Reader {
			return strings.NewReader(clientCredentials + "&junk=%zz")
		}},
		{"a malformed pair the endpoint ignores, beside a password grant", "/auth/token", func() io.Reader {
			return strings.NewReader(passwordGrant + "&junk=%zz")
		}},
		{"a malformed query beside a well-formed body", "/auth/token?junk=%zz", func() io.Reader {
			return strings.NewReader(clientCredentials)
		}},
		{"a password grant cut one byte short by the request-body limit", "/auth/token", func() io.Reader {
			return http.MaxBytesReader(httptest.NewRecorder(), io.NopCloser(strings.NewReader(passwordGrant)),
				int64(len(passwordGrant)-1))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			answers := map[string]*httptest.ResponseRecorder{}
			for limiter, enabled := range map[string]bool{"on": true, "off": false} {
				server := newRoutesTestServerWith(t, func(cfg *config.Config) {
					cfg.AuthServer.RateLimiterEnabled = enabled
				})
				r := httptest.NewRequest(http.MethodPost, test.target, test.body())
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				answers[limiter] = serve(server, withRoutesTestSettings(r))
			}

			for limiter, rr := range answers {
				assert.Equal(t, http.StatusBadRequest, rr.Code, "limiter %s", limiter)
				assert.Equal(t, "application/json", rr.Header().Get("Content-Type"), "limiter %s", limiter)
				assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"), "limiter %s", limiter)
				assert.Equal(t, "no-cache", rr.Header().Get("Pragma"), "limiter %s", limiter)
				assert.JSONEq(t, `{"error":"invalid_request","error_description":"The request body could not be parsed."}`,
					rr.Body.String(), "limiter %s", limiter)
			}
			assert.Equal(t, answers["off"].Body.String(), answers["on"].Body.String(),
				"the limiter answers a form that does not parse byte for byte as the handler does")
		})
	}
}

// TestInitRoutes_TheCredentialTiersCountInTheDatabaseOnTheServerEngines is #394 decision 2's engine
// choice, made by initRoutes with no setting: on PostgreSQL, MySQL and SQL Server a wrong account
// password is counted in the database every replica shares, and on SQLite, which cannot have a
// second replica, in this process. The database mock is strict, so on SQLite a reservation reaching
// it is an unexpected call that fails the case by itself.
func TestInitRoutes_TheCredentialTiersCountInTheDatabaseOnTheServerEngines(t *testing.T) {
	passwordBody := `{"currentPassword":"` + routesTestWrongPassword + `","newPassword":"a new password"}`

	for _, engine := range []string{"postgres", "mysql", "mssql"} {
		t.Run(engine+" counts in the database", func(t *testing.T) {
			server := newRoutesTestServerWith(t, func(cfg *config.Config) { cfg.Database.Type = engine })
			database := server.database.(*datamocks.Database)
			database.On("ReserveRateLimitHit", mock.Anything, mock.Anything, mock.Anything, mock.Anything,
				mock.Anything, mock.Anything).Return(true, nil).Once()

			assert.NotEqual(t, http.StatusTooManyRequests,
				serve(server, apiRequest(http.MethodPut, "/api/v1/account/password", passwordBody)).Code)

			database.AssertNumberOfCalls(t, "ReserveRateLimitHit", 1)
		})
	}

	t.Run("sqlite counts in memory", func(t *testing.T) {
		server := newRoutesTestServerWith(t, func(cfg *config.Config) { cfg.Database.Type = "sqlite" })

		// The whole budget spent and refused, with the database never asked.
		assertRefused(t, exhaust(t, server, accountPasswordBudget, func(int) *http.Request {
			return apiRequest(http.MethodPut, "/api/v1/account/password", passwordBody)
		}), accountPasswordWindow, shapeAPI)
	})
}

// With email off, both forgot-password routes are a 404 ahead of the limiter: past the per-address
// budget the same address is still answered 404, never 429, and once email is on that address
// finds its whole budget unspent (#542). Behind the limiter, as the check first sat in the handlers,
// the sixth request was a 429 the page's 404 did not describe.
func TestInitRoutes_ForgotPasswordWithEmailOffSpendsNoBudget(t *testing.T) {
	server := newRoutesTestServer(t)
	emailOff := func(r *http.Request) *http.Request {
		settings := routesTestSettings()
		settings.SMTPEnabled = false
		return r.WithContext(reqctx.WithSettings(r.Context(), settings))
	}

	for i := 0; i < forgotPwdEmailBudget+3; i++ {
		assert.Equal(t, http.StatusNotFound,
			serve(server, emailOff(browserForm(http.MethodPost, "/forgot-password", "email=one@example.com"))).Code,
			"request %d", i+1)
	}
	assert.Equal(t, http.StatusNotFound, serve(server, emailOff(browserRequest(http.MethodGet, "/forgot-password"))).Code)

	assertRefused(t, exhaust(t, server, forgotPwdEmailBudget, func(int) *http.Request {
		return browserForm(http.MethodPost, "/forgot-password", "email=one@example.com")
	}), forgotPwdWindow, shapeBrowser)
}

// newDefaultRoutesTestServer is newRoutesTestServer with GOIABADA_AUTHSERVER_RATELIMITER_ENABLED at
// its zero value, which is its default and what the setup wizard writes for a Kubernetes install
// under the Cluster traffic policy.
func newDefaultRoutesTestServer(t *testing.T) *Server {
	t.Helper()
	return newRoutesTestServerWith(t, func(cfg *config.Config) {
		cfg.AuthServer.RateLimiterEnabled = false
	})
}

// pwdGuess is a wrong password at the sign-in form, inside a ceremony at the password step, for a
// distinct account per attempt. The database mock knows no account, so each takes the handler's
// unknown-address branch, which charges the failure as a wrong password does.
func pwdGuess(t *testing.T, s *Server) func(attempt int) *http.Request {
	t.Helper()
	cookie := pwdCeremonyCookie(t, s)
	return func(attempt int) *http.Request {
		r := browserForm(http.MethodPost, "/auth/pwd", "ceremonyId="+routesTestCeremonyId+
			"&email=user"+strconv.Itoa(attempt)+"%40example.com&password="+routesTestWrongPassword)
		r.AddCookie(cookie)
		return r
	}
}

// ropcGuess is a wrong password through the password grant, from the public client the grant is
// enabled for, for a distinct account per attempt: answered invalid_grant, which charges the
// failure.
func ropcGuess(attempt int) *http.Request {
	return browserForm(http.MethodPost, "/auth/token", "grant_type=password&client_id="+routesTestROPCClientId+
		"&username=user"+strconv.Itoa(attempt)+"%40example.com&password="+routesTestWrongPassword)
}

// pwdCeremonyCookie mints the session cookie a browser at the password form carries: an auth context
// at the level 1 password state, through the server's own session store as otpCeremonyCookie does.
func pwdCeremonyCookie(t *testing.T, s *Server) *http.Cookie {
	t.Helper()

	r := httptest.NewRequest(http.MethodGet, "/auth/pwd", nil)
	recorder := httptest.NewRecorder()
	require.NoError(t, ceremony.NewStore(s.sessionStore, sessionkeys.AuthServerSessionName).AddAuthContext(recorder, r,
		&ceremony.AuthContext{
			AuthState:  ceremony.AuthStateLevel1Password,
			CeremonyId: routesTestCeremonyId,
			ClientId:   routesTestClientId,
		}))
	cookies := recorder.Result().Cookies()
	require.Len(t, cookies, 1)
	return cookies[0]
}

// TestInitRoutes_TheDefaultConfigurationLimitsWhatAnEmailCounts drives the production routes with the
// rate limiter switch at its default, off, and requires the limits counted by a user or by an email to
// apply all the same (#503 decision 7). Off is #219's default and the wizard's Cluster default, and
// until #503 it left nothing bounding how many passwords anyone could guess against one account, which
// RFC 6749 section 4.3.2 makes a MUST for the password grant, nor how many reset mails or registration
// notices one address could be sent.
//
// Every request comes from one client address, which is what shows the tiers the switch governs are
// off: the hundred wrong passwords reaching the handler is past both pwd_ip's 30 a minute and
// pwd_account_net's 10, and the hundred and first refused with an hour's Retry-After is the account-wide
// tier and no other.
func TestInitRoutes_TheDefaultConfigurationLimitsWhatAnEmailCounts(t *testing.T) {
	const pwdAccountBudget = 100 // failures per 60 minutes per account, shared with the password grant
	const pwdAccountWindow = 3600

	t.Run("100 wrong passwords for one email from one address reach the handler, the 101st is refused, and so is the password grant", func(t *testing.T) {
		server := newDefaultRoutesTestServer(t)
		cookie := pwdCeremonyCookie(t, server)

		// The account is unknown to the database mock, so each guess takes the handler's
		// unknown-address branch, which charges the failure as a wrong password does.
		guess := func(int) *http.Request {
			r := browserForm(http.MethodPost, "/auth/pwd",
				"ceremonyId="+routesTestCeremonyId+"&email=victim%40example.com&password="+routesTestWrongPassword)
			r.AddCookie(cookie)
			return r
		}
		for i := 0; i < pwdAccountBudget; i++ {
			rr := serve(server, guess(i))
			require.Equal(t, http.StatusOK, rr.Code, "guess %d must reach the handler, which answers the form again", i+1)
			require.Contains(t, rr.Body.String(), routesTestCeremonyId,
				"guess %d must be answered by the password form, not refused before it", i+1)
		}
		assertRefused(t, serve(server, guess(pwdAccountBudget)), pwdAccountWindow, shapeBrowser)

		// The password grant spends the same account's bucket, so it is refused too, in the shape
		// the token endpoint's caller parses.
		assertRefused(t, serve(server, browserForm(http.MethodPost, "/auth/token",
			"grant_type=password&username=Victim%40Example.com&password="+routesTestWrongPassword)),
			pwdAccountWindow, shapeOAuth)

		// Another account is untouched, so what refused was the account's own tier.
		assert.True(t, reachesHandler(server, browserForm(http.MethodPost, "/auth/token",
			"grant_type=password&username=other%40example.com&password="+routesTestWrongPassword)),
			"another account keeps its budget")
	})

	t.Run("the 6th wrong one-time code is refused", func(t *testing.T) {
		server := newDefaultRoutesTestServer(t)
		cookie := otpCeremonyCookie(t, server)
		wrongCode := routesTestWrongOTPCode(t)

		assertRefused(t, exhaust(t, server, otpBudget, func(int) *http.Request {
			r := browserForm(http.MethodPost, "/auth/otp", "ceremonyId="+routesTestCeremonyId+"&otp="+wrongCode)
			r.AddCookie(cookie)
			return r
		}), otpWindow, shapeBrowser)
	})

	t.Run("the 6th forgot-password request for one address is refused", func(t *testing.T) {
		server := newDefaultRoutesTestServer(t)
		assertRefused(t, exhaust(t, server, forgotPwdEmailBudget, func(int) *http.Request {
			return browserForm(http.MethodPost, "/forgot-password", "email=one@example.com")
		}), forgotPwdWindow, shapeBrowser)

		assert.True(t, reachesHandler(server, browserForm(http.MethodPost, "/forgot-password",
			"email=another@example.com")),
			"a second address has its own budget, and the per-IP tier is off")
	})

	t.Run("the 6th registration for one address is refused", func(t *testing.T) {
		server := newDefaultRoutesTestServer(t)
		assertRefused(t, exhaust(t, server, registerEmailBudget, func(int) *http.Request {
			return browserForm(http.MethodPost, "/account/register", "email=one@example.com")
		}), registerWindow, shapeBrowser)

		assert.True(t, reachesHandler(server, browserForm(http.MethodPost, "/account/register",
			"email=another@example.com")),
			"a second address has its own budget, and the per-IP tier is off")
	})

	// The tiers the switch still governs, each spent well past its budget from one address with a
	// fresh account or address each time, so only a per-IP tier could refuse.
	t.Run("the tiers counted by an address stay off", func(t *testing.T) {
		server := newDefaultRoutesTestServer(t)
		for i := 0; i < 2*forgotPwdIpBudget; i++ {
			require.True(t, reachesHandler(server, browserForm(http.MethodPost, "/forgot-password",
				"email=user"+strconv.Itoa(i)+"@example.com")), "forgot-password request %d", i+1)
			require.True(t, reachesHandler(server, registrationOf(i)), "registration %d", i+1)
		}
		for i := 0; i < 2*activateBudget; i++ {
			require.True(t, reachesHandler(server, browserRequest(http.MethodGet, "/account/activate")), "activation %d", i+1)
			require.True(t, reachesHandler(server, browserRequest(http.MethodGet, "/reset-password")), "reset %d", i+1)
		}
		guess := pwdGuess(t, server)
		for i := 0; i < 2*pwdIpBudget; i++ {
			require.True(t, reachesHandler(server, guess(i)), "wrong password %d at the sign-in form", i+1)
			require.True(t, reachesHandler(server, ropcGuess(i)), "wrong password %d through the password grant", i+1)
		}
	})
}

// While registration is unavailable, both registration routes are a 404 ahead of the limiter, as
// forgot-password is without email: past both of LimitRegister's budgets, one address and one client
// block, every request is still answered 404 with its one Warn record and no audit entry, never 429,
// and once registration opens the same address and block find their budgets unspent (#526 decision 2).
// Behind the limiter, as the check first sat in the handlers, the sixth request for one address was a
// 429 with a rate_limit_exceeded entry, and five refusals spent the budget registration opened with.
func TestInitRoutes_UnavailableRegistrationSpendsNoBudget(t *testing.T) {
	budgets := []struct {
		name  string
		check func(t *testing.T, server *Server)
	}{
		{"the address's budget is unspent", func(t *testing.T, server *Server) {
			assertRefused(t, exhaust(t, server, registerEmailBudget, func(int) *http.Request {
				return browserForm(http.MethodPost, "/account/register", "email=one@example.com")
			}), registerWindow, shapeBrowser)
		}},
		{"the client block's budget is unspent", func(t *testing.T, server *Server) {
			assertRefused(t, exhaust(t, server, registerBudget, registrationOf), registerWindow, shapeBrowser)
		}},
	}

	for _, tc := range []struct {
		name    string
		message string
		edit    func(*record.Settings)
	}{
		{"self-registration off", "self-registration request refused because self-registration is disabled",
			func(s *record.Settings) { s.SelfRegistrationEnabled = false }},
		{"verification required with email off", "self-registration request refused because email is not set up",
			func(s *record.Settings) {
				s.SelfRegistrationRequiresEmailVerification = true
				s.SMTPEnabled = false
			}},
	} {
		for _, budget := range budgets {
			t.Run(tc.name+", "+budget.name, func(t *testing.T) {
				server := newRoutesTestServer(t)
				unavailable := func(r *http.Request) *http.Request {
					settings := routesTestSettings()
					// An audit entry would be a record of its own, so the one-record check refuses it.
					settings.AuditLogsInConsoleEnabled = true
					tc.edit(settings)
					return r.WithContext(reqctx.WithSettings(r.Context(), settings))
				}
				assertRefusedAsNotFound := func(r *http.Request, what string) {
					t.Helper()
					logs := logtest.CaptureSlog(t)
					assert.Equal(t, http.StatusNotFound, serve(server, unavailable(r)).Code, what)
					records := logs.Records()
					if assert.Len(t, records, 1, "%s: one record and no audit entry: %s", what, logs.Text()) {
						assert.Equal(t, slog.LevelWarn, records[0].Level, what)
						assert.Equal(t, tc.message, records[0].Message, what)
					}
				}

				// One address throughout, so by the end both tiers have seen more than their budget.
				for i := 0; i < registerBudget+3; i++ {
					assertRefusedAsNotFound(browserForm(http.MethodPost, "/account/register", "email=one@example.com"),
						fmt.Sprintf("submission %d", i+1))
				}
				assertRefusedAsNotFound(browserRequest(http.MethodGet, "/account/register"), "the page")

				budget.check(t, server)
			})
		}
	}
}
