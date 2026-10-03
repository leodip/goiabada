package apihandlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	mocks_accounthandlers "github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	mocks_handlers "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// unusedRenderer satisfies the ErrorRenderer the limiter's constructor takes. The API reject
// class writes JSON and never renders, so a call here is a wiring defect rather than an
// outcome to assert on.
type unusedRenderer struct{ t *testing.T }

func (u unusedRenderer) RenderTemplate(w http.ResponseWriter, r *http.Request, layoutName string,
	templateName string, data map[string]interface{}) error {

	u.t.Errorf("the API reject class rendered %s instead of writing JSON", templateName)
	return nil
}

// verificationEnv is one handler wired to its limiter the way routes.go wires them, plus the
// user row the database hands back. The row is shared rather than rebuilt per request
// because the handler mutates it on success, exactly as the real row is mutated: a case
// driving repeated verifications resets it, which in production is a fresh code each time.
type verificationEnv struct {
	handler  http.Handler
	database *mocks_data.Database
	user     *models.User
}

const (
	verificationSubject = "33333333-3333-3333-3333-333333333333"
	verificationCode    = "ABCD1234"
)

// newVerificationEnv builds the handler behind a live, enabled RateLimiterMiddleware.
//
// Through the middleware rather than called directly, and that is the point of this seam:
// the reservation the handler converts is placed by the limiter and lives in the request
// context, so a handler invoked on a bare request has nothing to convert and
// RecordCredentialFailure is a no-op. A case written that way passes while proving nothing
// (#219).
func newVerificationEnv(t *testing.T) *verificationEnv {
	t.Helper()

	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	encrypted, err := testDataCipher.Encrypt(verificationCode)
	require.NoError(t, err)

	user := &models.User{
		Id:                             7,
		Enabled:                        true,
		Email:                          "someone@example.com",
		EmailVerificationCodeEncrypted: encrypted,
		EmailVerificationCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}

	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), verificationSubject).Return(user, nil).Maybe()
	database.On("UpdateUser", mock.Anything, (*sql.Tx)(nil), user).Return(nil).Maybe()
	auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Return().Maybe()

	rateLimiter := middleware.NewRateLimiterMiddleware(nil, unusedRenderer{t}, nil, nil, true)
	handler := HandleAPIAccountEmailVerificationPost(database, auditLogger, rateLimiter, testDataCipher)

	return &verificationEnv{
		handler:  rateLimiter.LimitEmailVerification(handler),
		database: database,
		user:     user,
	}
}

// reset puts the row back to "a code was sent and is still pending", which the handler
// clears on a successful verification.
func (e *verificationEnv) reset(t *testing.T) {
	t.Helper()
	encrypted, err := testDataCipher.Encrypt(verificationCode)
	require.NoError(t, err)
	e.user.EmailVerified = false
	e.user.EmailVerificationCodeEncrypted = encrypted
	e.user.EmailVerificationCodeIssuedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
}

// post submits one verification attempt and reports the status.
func (e *verificationEnv) post(t *testing.T, submitted string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(api.VerifyAccountEmailRequest{VerificationCode: submitted})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/account/email/verification", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.7:5000"
	// The handler reads SMTPEnabled straight off the context and panics on the type
	// assertion without it, and MiddlewareSettings puts it there in production.
	ctx := reqctx.WithSettings(req.Context(), &models.Settings{SMTPEnabled: true})
	req = setTokenContextWithClaims(req.WithContext(ctx),
		map[string]interface{}{"sub": verificationSubject})

	rr := httptest.NewRecorder()
	e.handler.ServeHTTP(rr, req)
	return rr
}

// TestHandleAPIAccountEmailVerificationPost_SpendsTheLimiterBudgetOnFailuresOnly is seam 2
// for the email verification check. The budget itself is pinned at seam 1 in authserver/internal/middleware;
// what is new here is the wiring, that a wrong code reaches the counter at all and that a
// right one does not.
func TestHandleAPIAccountEmailVerificationPost_SpendsTheLimiterBudgetOnFailuresOnly(t *testing.T) {
	const budget = 5 // failures per 15 minutes per token subject

	t.Run("wrong codes fill the budget and the next attempt is refused", func(t *testing.T) {
		env := newVerificationEnv(t)
		for i := 0; i < budget; i++ {
			rr := env.post(t, "ZZZZ9999")
			assert.Equal(t, http.StatusBadRequest, rr.Code, "attempt %d should reach the handler", i+1)
		}

		rr := env.post(t, "ZZZZ9999")
		assert.Equal(t, http.StatusTooManyRequests, rr.Code,
			"attempt %d should be refused by the limiter", budget+1)

		var body api.ErrorResponse
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
		assert.Equal(t, "TOO_MANY_REQUESTS", body.ErrorCode)

		// The refused request never reached the handler, so it never looked the account
		// up: 5 lookups for 6 attempts.
		env.database.AssertNumberOfCalls(t, "GetUserBySubject", budget)
	})

	t.Run("a correct code spends nothing", func(t *testing.T) {
		env := newVerificationEnv(t)
		// Well past the budget. A tier that counted every request would refuse the sixth,
		// which is a user locked out of verifying their own address by verifying it.
		for i := 0; i < budget*2; i++ {
			env.reset(t)
			assert.Equal(t, http.StatusOK, env.post(t, verificationCode).Code,
				"verification %d should succeed", i+1)
		}
		// And the whole budget is still there.
		env.reset(t)
		for i := 0; i < budget; i++ {
			assert.Equal(t, http.StatusBadRequest, env.post(t, "ZZZZ9999").Code,
				"failure %d should still reach the handler", i+1)
		}
		assert.Equal(t, http.StatusTooManyRequests, env.post(t, "ZZZZ9999").Code)
	})
}

// TestHandleAPIAccountEmailVerificationPost_CodeComparison pins what the move from
// strings.EqualFold to subtle.ConstantTimeCompare kept and what it narrowed.
//
// Kept: a code submitted in the wrong case still verifies, which the single-case alphabet
// relies on. Narrowed: an empty submission no longer verifies against a stored code that
// failed to decrypt, which EqualFold("", "") accepted (#219).
func TestHandleAPIAccountEmailVerificationPost_CodeComparison(t *testing.T) {
	t.Run("a lowercase submission still verifies", func(t *testing.T) {
		env := newVerificationEnv(t)
		rr := env.post(t, strings.ToLower(verificationCode))
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.True(t, env.user.EmailVerified, "the address should have been verified")
	})

	t.Run("surrounding whitespace still verifies", func(t *testing.T) {
		env := newVerificationEnv(t)
		assert.Equal(t, http.StatusOK, env.post(t, "  "+verificationCode+"\t").Code)
	})

	t.Run("an empty submission is refused when the stored code cannot be decrypted", func(t *testing.T) {
		env := newVerificationEnv(t)
		// A ciphertext this process cannot read, with a code issued a moment ago: the
		// shape a data-key rotation leaves behind. The stored code decrypts to "", and an
		// empty submission compared with EqualFold matched it, so the two checks behind
		// the comparison were the only thing left refusing the request, and both pass here.
		env.user.EmailVerificationCodeEncrypted = []byte("not a ciphertext this key can read")
		env.user.EmailVerificationCodeIssuedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

		rr := env.post(t, "")
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.False(t, env.user.EmailVerified, "an empty code must never verify an address")
	})

	t.Run("an empty submission is refused against a readable stored code", func(t *testing.T) {
		env := newVerificationEnv(t)
		assert.Equal(t, http.StatusBadRequest, env.post(t, "").Code)
		assert.False(t, env.user.EmailVerified)
	})
}

// The emailed verification link points at the admin console base URL the handler was handed,
// not at the configured one (#434).
func TestHandleAPIAccountEmailVerificationSendPost_LinksToTheAdminConsoleItWasHanded(t *testing.T) {
	pageRenderer := mocks_handlers.NewPageRenderer(t)
	database := mocks_data.NewDatabase(t)
	emailSender := mocks_accounthandlers.NewEmailSender(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleAPIAccountEmailVerificationSendPost(pageRenderer, database, emailSender, auditLogger,
		testDataCipher, testAdminConsoleBaseURL)

	user := &models.User{Id: 7, Subject: verificationSubject, Email: "someone@example.com"}
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), verificationSubject).Return(user, nil)
	database.On("UpdateUser", mock.Anything, (*sql.Tx)(nil), user).Return(nil)
	var emailedLink string
	pageRenderer.On("RenderTemplateToBuffer", mock.Anything, "/layouts/email_layout.html",
		"/emails/email_verification.html", mock.Anything).
		Run(func(args mock.Arguments) {
			emailedLink, _ = args.Get(3).(map[string]interface{})["link"].(string)
		}).Return(&bytes.Buffer{}, nil)
	emailSender.On("SendEmail", mock.Anything, emaildelivery.SMTPConfig{Host: "smtp.example.com"}, mock.Anything).Return(nil)
	auditLogger.On("Log", mock.Anything, audit.AuditSentEmailVerificationMessage, mock.Anything).Return()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/account/email/verification/send", nil)
	req = setTokenContextWithClaims(req, map[string]interface{}{"sub": verificationSubject})
	req = req.WithContext(reqctx.WithSettings(req.Context(), &models.Settings{SMTPEnabled: true, SMTPHost: "smtp.example.com"}))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, "https://admin.test/account/email-verification", emailedLink)
}

// TestHandleAPIAccountEmailVerificationPost_KeepsTheIssuedAt is the verify's half of the resend
// cooldown's bound: a verified code is spent, and its issued-at stays for the cooldown to read,
// so verifying an address the caller holds does not let the next send, to whatever address they
// change to, go out at once (#404).
func TestHandleAPIAccountEmailVerificationPost_KeepsTheIssuedAt(t *testing.T) {
	env := newVerificationEnv(t)
	issuedAt := env.user.EmailVerificationCodeIssuedAt

	require.Equal(t, http.StatusOK, env.post(t, verificationCode).Code)

	assert.True(t, env.user.EmailVerified)
	assert.Nil(t, env.user.EmailVerificationCodeEncrypted, "the verified code is spent")
	assert.Equal(t, issuedAt, env.user.EmailVerificationCodeIssuedAt, "the issued-at stays for the resend cooldown")
}

// TestHandleAPIAccountEmailVerificationSendPost_TheCooldownIsTheAccounts is the resend
// cooldown's bound (#404): one code per five minutes, the code's own lifetime, read from when a
// code was last issued whether or not that code is still pending. An email change and a verification both clear the code and keep the issued-at,
// so neither reopens a send; before, either cleared both, and setting an address, changing away
// and back again had a code mailed to it on every cycle, to any address the caller named.
func TestHandleAPIAccountEmailVerificationSendPost_TheCooldownIsTheAccounts(t *testing.T) {
	pending, err := testDataCipher.Encrypt(verificationCode)
	require.NoError(t, err)

	send := func(t *testing.T, user *models.User, pageRenderer *mocks_handlers.PageRenderer,
		emailSender *mocks_accounthandlers.EmailSender, auditLogger *mocks_handlers.AuditLogger) api.AccountEmailVerificationSendResponse {
		t.Helper()
		database := mocks_data.NewDatabase(t)
		database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), verificationSubject).Return(user, nil)
		database.On("UpdateUser", mock.Anything, (*sql.Tx)(nil), user).Return(nil).Maybe()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/account/email/verification/send", nil)
		req = setTokenContextWithClaims(req, map[string]interface{}{"sub": verificationSubject})
		req = req.WithContext(reqctx.WithSettings(req.Context(), &models.Settings{SMTPEnabled: true, SMTPHost: "smtp.example.com"}))
		rr := httptest.NewRecorder()
		HandleAPIAccountEmailVerificationSendPost(pageRenderer, database, emailSender, auditLogger,
			testDataCipher, testAdminConsoleBaseURL).ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		var resp api.AccountEmailVerificationSendResponse
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
		return resp
	}

	for _, tc := range []struct {
		name string
		code []byte
	}{
		{"a code still pending", pending},
		{"no code pending, as an email change or a verification leaves it", nil},
	} {
		t.Run("a code issued four minutes ago refuses the send, with "+tc.name, func(t *testing.T) {
			// Past the minute the cooldown used to be, so this is the five minutes refusing.
			user := &models.User{Id: 7, Subject: verificationSubject, Email: "anyone@example.com",
				EmailVerificationCodeEncrypted: tc.code,
				EmailVerificationCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC().Add(-4 * time.Minute), Valid: true}}

			// The renderer, the sender and the logger expect nothing, so a send fails the case.
			resp := send(t, user, mocks_handlers.NewPageRenderer(t), mocks_accounthandlers.NewEmailSender(t),
				mocks_handlers.NewAuditLogger(t))

			assert.True(t, resp.TooManyRequests)
			assert.InDelta(t, 60, resp.WaitInSeconds, 2, "the wait is what is left of the five minutes")
			assert.False(t, resp.EmailVerificationSent)
		})
	}

	t.Run("a code issued over five minutes ago, none pending, lets the send through", func(t *testing.T) {
		user := &models.User{Id: 7, Subject: verificationSubject, Email: "anyone@example.com",
			EmailVerificationCodeIssuedAt: sql.NullTime{Time: time.Now().UTC().Add(-5*time.Minute - time.Second), Valid: true}}
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		emailSender := mocks_accounthandlers.NewEmailSender(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)
		pageRenderer.On("RenderTemplateToBuffer", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(&bytes.Buffer{}, nil).Once()
		emailSender.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		auditLogger.On("Log", mock.Anything, audit.AuditSentEmailVerificationMessage, mock.Anything).Return().Once()

		resp := send(t, user, pageRenderer, emailSender, auditLogger)

		assert.True(t, resp.EmailVerificationSent)
		assert.False(t, resp.TooManyRequests)
	})
}
