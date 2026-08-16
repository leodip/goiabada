package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// TestInitRoutes_LimitersAreRegisteredOnTheProductionRoutes makes the claim neither the
// limiter table in src/core/middleware nor the handler seams can make: that every limiter
// is mounted on the route it is meant to protect.
//
// Both of those tiers compose a limiter around a handler by hand, which is exactly the
// arrangement that keeps passing when the registration in initRoutes loses its wrapper.
// Removing any one of the twelve wrappers from routes.go left the whole module suite green,
// so an endpoint could be shipped unprotected with every limiter and handler test still
// passing. One case per registration, so a wrapper cannot be dropped in silence (#219).
//
// It runs the real initRoutes on a real chi router, and the request goes through whatever
// chain that registration produced: for the account API that is the debug, bearer-token,
// scope, user-bound and session guards ahead of the limiter, in their production order.
// Only two things are supplied rather than performed. The bearer token is placed in the
// request context in the shape JwtAuthorizationHeaderToContext would leave it, since
// signature validation is not what this test claims; and the settings come from the context
// rather than from MiddlewareSettings, because initMiddleware is not what is under test.
//
// What the handler answers is deliberately not asserted, only that it is not a 429: these
// cases own the wiring, and asserting a handler's own response here would duplicate its
// tests and break on every unrelated change to them. The budgets belong to seam 1 and the
// failure-only semantics to seam 2, so each case spends the budget the published table
// gives its route and requires the next request to be refused.

const (
	// The subject every account-API case presents, and therefore the key its limiter
	// buckets on.
	routesTestSubject = "8b0d8c7e-3a0f-4c8b-9d3a-0f4c8b9d3a0f"

	// What the caller submits where a credential is expected. Never the right one: these
	// tiers count failures, so a correct credential would spend nothing and the budget
	// would never fill.
	routesTestWrongPassword = "not the password"

	registerBudget          = 20 // requests per 5 minutes per /64
	emailVerificationBudget = 5  // failures per 15 minutes per token subject
	accountPasswordBudget   = 5  // failures per 15 minutes per token subject, shared by two routes
	otpBudget               = 5  // failures per 15 minutes per user id

	routesTestClientId   = "test-client"
	routesTestCeremonyId = "9f1c2c2f-2a0f-4a3b-8b6d-1f0a5c9e7d21"
	// A well-formed base32 TOTP secret, so the code the OTP case submits is refused for
	// being wrong rather than for the secret being unreadable.
	routesTestOTPSecret = "JBSWY3DPEHPK3PXP"
)

// withRateLimiterEnabled turns the limiter on for the duration of the test and restores the
// previous value. It has to run before initRoutes, which is when the flag is read.
func withRateLimiterEnabled(t *testing.T) {
	t.Helper()
	previous := config.GetAuthServer().RateLimiterEnabled
	config.GetAuthServer().RateLimiterEnabled = true
	t.Cleanup(func() {
		config.GetAuthServer().RateLimiterEnabled = previous
	})
}

// routesTestSettings is what MiddlewareSettings would put in the context. Self-registration
// and SMTP are on, or two of the handlers below refuse before reaching their credential
// check. Both audit sinks are off, which keeps the real AuditLogger from writing rows the
// database mock was never asked for; that it reads settings at all is #212's finding, not
// this test's business.
func routesTestSettings() *models.Settings {
	return &models.Settings{
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
	withRateLimiterEnabled(t)

	passwordHash, err := hashutil.HashPassword("the account's real password")
	assert.NoError(t, err)

	subject, err := uuid.Parse(routesTestSubject)
	assert.NoError(t, err)

	database := mocks_data.NewDatabase(t)
	database.On("GetSettingsById", mock.Anything, int64(1)).Return(routesTestSettings(), nil).Maybe()
	database.On("GetUserBySubject", mock.Anything, routesTestSubject).Return(&models.User{
		Id:           1,
		Enabled:      true,
		Subject:      subject,
		Email:        "victim@example.com",
		PasswordHash: passwordHash,
		// EmailVerified false with no stored code: the verification comparison is reached
		// and refuses, which is the branch that spends that budget.
		EmailVerified: false,
	}, nil).Maybe()
	// /forgot-password looks the address up before deciding what to render. No account
	// means no mail is sent, which keeps these cases about the limiter alone.
	database.On("GetUserByEmail", mock.Anything, mock.Anything).Return((*models.User)(nil), nil).Maybe()
	// What the OTP step reads: the user the auth context names, not yet enrolled, and the
	// client whose branding the form carries.
	database.On("GetUserById", mock.Anything, int64(1)).
		Return(&models.User{Id: 1, Enabled: true, OTPEnabled: false}, nil).Maybe()
	database.On("GetClientByClientIdentifier", mock.Anything, routesTestClientId).
		Return(&models.Client{Id: 1, ClientIdentifier: routesTestClientId}, nil).Maybe()
	database.On("ClientHasLogo", mock.Anything, int64(1)).Return(false, nil).Maybe()

	s := &Server{
		router:       chi.NewRouter(),
		database:     database,
		sessionStore: sessions.NewCookieStore(securecookie.GenerateRandomKey(64)),
		templateFS:   web.TemplateFS(),
	}
	s.initRoutes()
	return s
}

// withRoutesTestSettings puts in the context what MiddlewareSettings puts there in
// production. Both the handlers and the browser rejection page read it from there.
func withRoutesTestSettings(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), constants.ContextKeySettings, routesTestSettings()))
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
	token := oauth.JwtToken{Claims: jwt.MapClaims{
		"sub":       routesTestSubject,
		"scope":     constants.AuthServerResourceIdentifier + ":" + constants.ManageAccountPermissionIdentifier,
		"auth_time": float64(time.Now().Add(-time.Minute).Unix()),
	}}
	r = r.WithContext(context.WithValue(r.Context(), constants.ContextKeyBearerToken, token))
	return withRoutesTestSettings(r)
}

// otpCeremonyCookie mints the session cookie a user part way through the OTP step carries:
// an auth context at the level 2 state, and the enrollment secret HandleAuthOtpGet left
// behind. Written through the server's own session store, so what the handler reads back is
// what gorilla wrote rather than a shape this test invented.
func otpCeremonyCookie(t *testing.T, s *Server) *http.Cookie {
	t.Helper()

	r := httptest.NewRequest(http.MethodGet, "/auth/otp", nil)
	sess, err := s.sessionStore.Get(r, constants.AuthServerSessionName)
	assert.NoError(t, err)

	authContext, err := json.Marshal(oauth.AuthContext{
		AuthState:  oauth.AuthStateLevel2OTP,
		CeremonyId: routesTestCeremonyId,
		UserId:     1,
		ClientId:   routesTestClientId,
	})
	assert.NoError(t, err)

	sess.Values[constants.SessionKeyAuthContext] = string(authContext)
	sess.Values[constants.SessionKeyOTPSecret] = routesTestOTPSecret
	sess.Values[constants.SessionKeyOTPImage] = "base64-image"

	recorder := httptest.NewRecorder()
	assert.NoError(t, s.sessionStore.Save(r, recorder, sess))

	cookies := recorder.Result().Cookies()
	assert.Len(t, cookies, 1)
	return cookies[0]
}

func serve(s *Server, r *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, r)
	return recorder
}

func TestInitRoutes_LimitersAreRegisteredOnTheProductionRoutes(t *testing.T) {

	t.Run("POST /account/register is limited", func(t *testing.T) {
		server := newRoutesTestServer(t)

		// Every request counts here, failures and successes alike: the budget bounds
		// enumeration, outbound mail and pre_registration rows rather than guesses.
		for i := 0; i < registerBudget; i++ {
			assert.NotEqual(t, http.StatusTooManyRequests, serve(server, browserRequest(http.MethodPost, "/account/register")).Code,
				"request %d must reach the handler", i+1)
		}
		assert.Equal(t, http.StatusTooManyRequests, serve(server, browserRequest(http.MethodPost, "/account/register")).Code,
			"request %d must be refused by the limiter", registerBudget+1)

		// The GET beside it is deliberately unlimited, so the refusal above is attributable
		// to the registration POST's own wrapper rather than to something covering /account.
		assert.NotEqual(t, http.StatusTooManyRequests, serve(server, browserRequest(http.MethodGet, "/account/register")).Code,
			"the registration form itself is not rate limited")
	})

	t.Run("POST /api/v1/account/email/verification is limited", func(t *testing.T) {
		server := newRoutesTestServer(t)
		const wrongCode = `{"verificationCode":"ABCD1234"}`

		for i := 0; i < emailVerificationBudget; i++ {
			assert.NotEqual(t, http.StatusTooManyRequests,
				serve(server, apiRequest(http.MethodPost, "/api/v1/account/email/verification", wrongCode)).Code,
				"guess %d must reach the handler", i+1)
		}

		refused := serve(server, apiRequest(http.MethodPost, "/api/v1/account/email/verification", wrongCode))
		assert.Equal(t, http.StatusTooManyRequests, refused.Code,
			"guess %d must be refused by the limiter", emailVerificationBudget+1)
		// The API reject class, which is what a caller on this route already parses.
		assert.Contains(t, refused.Body.String(), "TOO_MANY_REQUESTS")
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

		refused := serve(server, apiRequest(http.MethodPut, "/api/v1/account/otp", otpBody))
		assert.Equal(t, http.StatusTooManyRequests, refused.Code,
			"the OTP route must be refused by the budget the password route spent")
		assert.Contains(t, refused.Body.String(), "TOO_MANY_REQUESTS")
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
		request func(attempt int) *http.Request
	}{
		{"POST /auth/pwd", 30, func(int) *http.Request { return browserRequest(http.MethodPost, "/auth/pwd") }},
		{"POST /forgot-password", 20, func(attempt int) *http.Request {
			// A distinct address per request, so the per-email tier of 5 cannot trip and
			// the refusal below is attributable to the per-IP tier this case names.
			return browserForm(http.MethodPost, "/forgot-password",
				"email=user"+strconv.Itoa(attempt)+"@example.com")
		}},
		{"GET /reset-password", 30, func(int) *http.Request { return browserRequest(http.MethodGet, "/reset-password") }},
		{"POST /reset-password", 30, func(int) *http.Request { return browserRequest(http.MethodPost, "/reset-password") }},
		{"GET /account/activate", 20, func(int) *http.Request { return browserRequest(http.MethodGet, "/account/activate") }},
		{"POST /connect/register", 10, func(int) *http.Request {
			r := httptest.NewRequest(http.MethodPost, "/connect/register", strings.NewReader("{}"))
			r.Header.Set("Content-Type", "application/json")
			return withRoutesTestSettings(r)
		}},
		{"POST /auth/token", 30, func(int) *http.Request {
			// grant_type=password, or LimitROPC hands the request straight to the handler:
			// the other grants carry no resource-owner password for it to bound.
			return browserForm(http.MethodPost, "/auth/token",
				"grant_type=password&username=victim@example.com&password="+routesTestWrongPassword)
		}},
	} {
		t.Run(tc.name+" is limited", func(t *testing.T) {
			server := newRoutesTestServer(t)
			for i := 0; i < tc.budget; i++ {
				assert.NotEqual(t, http.StatusTooManyRequests, serve(server, tc.request(i)).Code,
					"request %d must reach the handler", i+1)
			}
			assert.Equal(t, http.StatusTooManyRequests, serve(server, tc.request(tc.budget)).Code,
				"request %d must be refused by the limiter", tc.budget+1)
		})
	}

	// The last registration, and the only one whose tier is keyed on something the request
	// cannot carry by itself: LimitOtp reads the user id out of the auth context and counts
	// failures, so filling it takes a session mid-ceremony and a code the handler rejects.
	// Driven on the enrollment branch, where the secret being verified comes from the
	// session rather than from the encrypted column, so the case needs no data cipher.
	t.Run("POST /auth/otp is limited", func(t *testing.T) {
		server := newRoutesTestServer(t)
		cookie := otpCeremonyCookie(t, server)

		post := func() int {
			r := browserForm(http.MethodPost, "/auth/otp",
				"ceremonyId="+routesTestCeremonyId+"&otp=000000")
			r.AddCookie(cookie)
			return serve(server, r).Code
		}

		for i := 0; i < otpBudget; i++ {
			assert.NotEqual(t, http.StatusTooManyRequests, post(), "guess %d must reach the handler", i+1)
		}
		assert.Equal(t, http.StatusTooManyRequests, post(),
			"guess %d must be refused by the limiter", otpBudget+1)
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
		assert.Equal(t, http.StatusTooManyRequests,
			serve(server, apiRequest(http.MethodPut, "/api/v1/account/password", passwordBody)).Code,
			"the password route must be refused by the budget the OTP route spent")
	})
}
