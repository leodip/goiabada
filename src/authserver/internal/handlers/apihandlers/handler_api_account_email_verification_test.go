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
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/record"
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
	database *datamocks.Database
	user     *record.User
}

const (
	verificationSubject = "33333333-3333-3333-3333-333333333333"
	verificationCode    = "ABCD1234"
)

// newVerificationEnv builds the handler behind a live, enabled middleware.RateLimiter.
//
// Through the middleware rather than called directly, and that is the point of this seam:
// the reservation the handler converts is placed by the limiter and lives in the request
// context, so a handler invoked on a bare request has nothing to convert and
// RecordCredentialFailure is a no-op. A case written that way passes while proving nothing
// (#219).
func newVerificationEnv(t *testing.T) *verificationEnv {
	t.Helper()

	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	encrypted, err := testDataCipher.Encrypt(verificationCode)
	require.NoError(t, err)

	user := &record.User{
		Id:                             7,
		Enabled:                        true,
		Email:                          "someone@example.com",
		EmailVerificationCodeEncrypted: encrypted,
		EmailVerificationCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}

	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), verificationSubject).Return(user, nil).Maybe()
	database.On("TryVerifyUserEmail", mock.Anything, (*sql.Tx)(nil), int64(7), "someone@example.com", mock.Anything).
		Return(true, nil).Maybe()
	auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Return().Maybe()

	rateLimiter := middleware.NewRateLimiter(nil, unusedRenderer{t}, nil, nil, true)
	handler := HandleAccountEmailVerificationPost(database, auditLogger, rateLimiter, testDataCipher)

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
	// assertion without it, and middleware.Settings puts it there in production.
	ctx := reqctx.WithSettings(req.Context(), &record.Settings{SMTPEnabled: true})
	req = setTokenContextWithClaims(req.WithContext(ctx),
		map[string]interface{}{"sub": verificationSubject})

	rr := httptest.NewRecorder()
	e.handler.ServeHTTP(rr, req)
	return rr
}

// TestHandleAccountEmailVerificationPost_SpendsTheLimiterBudgetOnFailuresOnly is seam 2
// for the email verification check. The budget itself is pinned at seam 1 in authserver/internal/middleware;
// what is new here is the wiring, that a wrong code reaches the counter at all and that a
// right one does not.
func TestHandleAccountEmailVerificationPost_SpendsTheLimiterBudgetOnFailuresOnly(t *testing.T) {
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

// TestHandleAccountEmailVerificationPost_CodeComparison pins what the move from
// strings.EqualFold to subtle.ConstantTimeCompare kept and what it narrowed.
//
// Kept: a code submitted in the wrong case still verifies, which the single-case alphabet
// relies on. Narrowed: an empty submission no longer verifies against a stored code that
// failed to decrypt, which EqualFold("", "") accepted (#219).
func TestHandleAccountEmailVerificationPost_CodeComparison(t *testing.T) {
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
func TestHandleAccountEmailVerificationSendPost_LinksToTheAdminConsoleItWasHanded(t *testing.T) {
	pageRenderer := handlersmocks.NewPageRenderer(t)
	database := datamocks.NewDatabase(t)
	emailSender := accounthandlersmocks.NewEmailSender(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleAccountEmailVerificationSendPost(pageRenderer, database, emailSender, auditLogger,
		testDataCipher, testAdminConsoleBaseURL)

	user := &record.User{Id: 7, Subject: verificationSubject, Email: "someone@example.com"}
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), verificationSubject).Return(user, nil)
	database.On("TryStoreEmailVerificationCode", mock.Anything, (*sql.Tx)(nil), int64(7), "someone@example.com",
		mock.Anything, mock.Anything, mock.Anything).Return(true, nil)
	var emailedLink string
	pageRenderer.On("RenderTemplateToBuffer", mock.Anything, "/layouts/email_layout.html",
		"/emails/email_verification.html", mock.Anything).
		Run(func(args mock.Arguments) {
			emailedLink, _ = args.Get(3).(map[string]interface{})["link"].(string)
		}).Return(&bytes.Buffer{}, nil)
	emailSender.On("SendEmail", mock.Anything, emaildelivery.SMTPConfig{Host: "smtp.example.com"}, mock.Anything).Return(nil)
	auditLogger.On("Log", mock.Anything, audit.EventSentEmailVerificationMessage, mock.Anything).Return()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/account/email/verification/send", nil)
	req = setTokenContextWithClaims(req, map[string]interface{}{"sub": verificationSubject})
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{SMTPEnabled: true, SMTPHost: "smtp.example.com"}))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, "https://admin.test/account/email-verification", emailedLink)
}

// TestHandleAccountEmailVerificationPost_KeepsTheIssuedAt is the verify's half of the resend
// cooldown's bound: a verified code is spent, and its issued-at stays for the cooldown to read,
// so verifying an address the caller holds does not let the next send, to whatever address they
// change to, go out at once (#404).
func TestHandleAccountEmailVerificationPost_KeepsTheIssuedAt(t *testing.T) {
	env := newVerificationEnv(t)
	issuedAt := env.user.EmailVerificationCodeIssuedAt

	require.Equal(t, http.StatusOK, env.post(t, verificationCode).Code)

	assert.True(t, env.user.EmailVerified)
	assert.Nil(t, env.user.EmailVerificationCodeEncrypted, "the verified code is spent")
	assert.Equal(t, issuedAt, env.user.EmailVerificationCodeIssuedAt, "the issued-at stays for the resend cooldown")
}

// TestHandleAccountEmailVerificationSendPost_TheCooldownIsTheAccounts is the resend
// cooldown's bound (#404): one code per five minutes, the code's own lifetime, read from when a
// code was last issued whether or not that code is still pending. An email change and a verification both clear the code and keep the issued-at,
// so neither reopens a send; before, either cleared both, and setting an address, changing away
// and back again had a code mailed to it on every cycle, to any address the caller named.
func TestHandleAccountEmailVerificationSendPost_TheCooldownIsTheAccounts(t *testing.T) {
	pending, err := testDataCipher.Encrypt(verificationCode)
	require.NoError(t, err)

	send := func(t *testing.T, user *record.User, database *datamocks.Database, pageRenderer *handlersmocks.PageRenderer,
		emailSender *accounthandlersmocks.EmailSender, auditLogger *handlersmocks.AuditLogger) api.AccountEmailVerificationSendResponse {
		t.Helper()
		database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), verificationSubject).Return(user, nil)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/account/email/verification/send", nil)
		req = setTokenContextWithClaims(req, map[string]interface{}{"sub": verificationSubject})
		req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{SMTPEnabled: true, SMTPHost: "smtp.example.com"}))
		rr := httptest.NewRecorder()
		HandleAccountEmailVerificationSendPost(pageRenderer, database, emailSender, auditLogger,
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
			user := &record.User{Id: 7, Subject: verificationSubject, Email: "anyone@example.com",
				EmailVerificationCodeEncrypted: tc.code,
				EmailVerificationCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC().Add(-4 * time.Minute), Valid: true}}

			// The renderer, the sender and the logger expect nothing, so a send fails the case.
			database := datamocks.NewDatabase(t)
			resp := send(t, user, database, handlersmocks.NewPageRenderer(t), accounthandlersmocks.NewEmailSender(t),
				handlersmocks.NewAuditLogger(t))
			database.AssertNotCalled(t, "TryStoreEmailVerificationCode", mock.Anything, mock.Anything, mock.Anything,
				mock.Anything, mock.Anything, mock.Anything, mock.Anything)

			assert.True(t, resp.TooManyRequests)
			assert.InDelta(t, 60, resp.WaitInSeconds, 2, "the wait is what is left of the five minutes")
			assert.False(t, resp.EmailVerificationSent)
		})
	}

	t.Run("a code issued over five minutes ago, none pending, lets the send through", func(t *testing.T) {
		user := &record.User{Id: 7, Subject: verificationSubject, Email: "anyone@example.com",
			EmailVerificationCodeIssuedAt: sql.NullTime{Time: time.Now().UTC().Add(-5*time.Minute - time.Second), Valid: true}}
		pageRenderer := handlersmocks.NewPageRenderer(t)
		emailSender := accounthandlersmocks.NewEmailSender(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		pageRenderer.On("RenderTemplateToBuffer", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(&bytes.Buffer{}, nil).Once()
		emailSender.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		auditLogger.On("Log", mock.Anything, audit.EventSentEmailVerificationMessage, mock.Anything).Return().Once()
		database := datamocks.NewDatabase(t)
		database.On("TryStoreEmailVerificationCode", mock.Anything, (*sql.Tx)(nil), int64(7), "anyone@example.com",
			mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Once()

		resp := send(t, user, database, pageRenderer, emailSender, auditLogger)

		assert.True(t, resp.EmailVerificationSent)
		assert.False(t, resp.TooManyRequests)
	})
}

// sendVerification drives one send through the handler on database and returns the response.
func sendVerification(t *testing.T, database *datamocks.Database, pageRenderer *handlersmocks.PageRenderer,
	emailSender *accounthandlersmocks.EmailSender, auditLogger *handlersmocks.AuditLogger) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/account/email/verification/send", nil)
	req = setTokenContextWithClaims(req, map[string]interface{}{"sub": verificationSubject})
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{SMTPEnabled: true, SMTPHost: "smtp.example.com"}))
	rr := httptest.NewRecorder()
	HandleAccountEmailVerificationSendPost(pageRenderer, database, emailSender, auditLogger,
		testDataCipher, testAdminConsoleBaseURL).ServeHTTP(rr, req)
	return rr
}

// TestHandleAccountEmailVerificationSendPost_ClaimsTheCodeInOneConditionalWrite is the
// cooldown under concurrency (#404). The check the handler reads first cannot bound concurrent
// sends, which all read the same old issued-at; the write decides. It is keyed on the address
// the mail goes to, its cutoff is exactly one code lifetime before the issued-at it stores, and
// what it stores is the code the mail carries, encrypted.
func TestHandleAccountEmailVerificationSendPost_ClaimsTheCodeInOneConditionalWrite(t *testing.T) {
	database := datamocks.NewDatabase(t)
	pageRenderer := handlersmocks.NewPageRenderer(t)
	emailSender := accounthandlersmocks.NewEmailSender(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	user := &record.User{Id: 7, Subject: verificationSubject, Email: "anyone@example.com"}
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), verificationSubject).Return(user, nil).Once()
	var stored []byte
	var issuedAt, issuedNotAfter time.Time
	database.On("TryStoreEmailVerificationCode", mock.Anything, (*sql.Tx)(nil), int64(7), "anyone@example.com",
		mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			stored = args.Get(4).([]byte)
			issuedAt = args.Get(5).(time.Time)
			issuedNotAfter = args.Get(6).(time.Time)
		}).Return(true, nil).Once()
	var mailedCode string
	pageRenderer.On("RenderTemplateToBuffer", mock.Anything, mock.Anything, "/emails/email_verification.html", mock.Anything).
		Run(func(args mock.Arguments) {
			mailedCode, _ = args.Get(3).(map[string]interface{})["verificationCode"].(string)
		}).Return(&bytes.Buffer{}, nil).Once()
	emailSender.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventSentEmailVerificationMessage, mock.Anything).Return().Once()

	rr := sendVerification(t, database, pageRenderer, emailSender, auditLogger)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.WithinDuration(t, time.Now().UTC(), issuedAt, 5*time.Second)
	assert.Equal(t, issuedAt.Add(-5*time.Minute), issuedNotAfter, "the cutoff is one code lifetime before the issue")
	decrypted, err := testDataCipher.Decrypt(stored)
	require.NoError(t, err)
	require.NotEmpty(t, mailedCode)
	assert.Equal(t, mailedCode, decrypted, "the code stored is the code mailed")
}

// TestHandleAccountEmailVerificationSendPost_ALostClaimSendsNothing is the other side of
// the claim: a send whose write matched no row mails nothing and answers what the row says now,
// read again. A concurrent send that claimed the code leaves a cooldown, a verification leaves
// the address verified, and an email change leaves neither, which is a 409 (#404).
func TestHandleAccountEmailVerificationSendPost_ALostClaimSendsNothing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reread *record.User
		check  func(t *testing.T, rr *httptest.ResponseRecorder)
	}{
		{
			name: "a concurrent send claimed the code",
			reread: &record.User{Id: 7, Subject: verificationSubject, Email: "anyone@example.com",
				EmailVerificationCodeIssuedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true}},
			check: func(t *testing.T, rr *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
				var resp api.AccountEmailVerificationSendResponse
				require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
				assert.True(t, resp.TooManyRequests)
				assert.InDelta(t, 300, resp.WaitInSeconds, 2)
				assert.False(t, resp.EmailVerificationSent)
			},
		},
		{
			name:   "a concurrent verification verified the address",
			reread: &record.User{Id: 7, Subject: verificationSubject, Email: "anyone@example.com", EmailVerified: true},
			check: func(t *testing.T, rr *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
				var resp api.AccountEmailVerificationSendResponse
				require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
				assert.True(t, resp.EmailVerified)
				assert.False(t, resp.EmailVerificationSent)
			},
		},
		{
			name:   "a concurrent email change moved the address",
			reread: &record.User{Id: 7, Subject: verificationSubject, Email: "elsewhere@example.com"},
			check: func(t *testing.T, rr *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusConflict, rr.Code, rr.Body.String())
				var body map[string]string
				require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
				assert.Equal(t, "CONCURRENT_UPDATE", body["error_code"])
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			first := &record.User{Id: 7, Subject: verificationSubject, Email: "anyone@example.com"}
			database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), verificationSubject).Return(first, nil).Once()
			database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), verificationSubject).Return(tc.reread, nil).Once()
			database.On("TryStoreEmailVerificationCode", mock.Anything, (*sql.Tx)(nil), int64(7), "anyone@example.com",
				mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Once()

			// The renderer, the sender and the logger expect nothing, so a mail or an audit entry
			// fails the case.
			rr := sendVerification(t, database, handlersmocks.NewPageRenderer(t), accounthandlersmocks.NewEmailSender(t),
				handlersmocks.NewAuditLogger(t))

			tc.check(t, rr)
		})
	}
}

// verifyDirect submits a code to the verification handler with no limiter in front, so the
// recorder counts what the handler itself charges.
func verifyDirect(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
	credentials CredentialFailureRecorder, submitted string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(api.VerifyAccountEmailRequest{VerificationCode: submitted})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/account/email/verification", bytes.NewReader(body))
	ctx := reqctx.WithSettings(req.Context(), &record.Settings{SMTPEnabled: true})
	req = setTokenContextWithClaims(req.WithContext(ctx), map[string]interface{}{"sub": verificationSubject})
	rr := httptest.NewRecorder()
	HandleAccountEmailVerificationPost(database, auditLogger, credentials, testDataCipher).ServeHTTP(rr, req)
	return rr
}

// pendingCodeUser is an account holding someone@example.com, unverified, with verificationCode
// pending and issued a moment ago.
func pendingCodeUser(t *testing.T) *record.User {
	t.Helper()
	encrypted, err := testDataCipher.Encrypt(verificationCode)
	require.NoError(t, err)
	return &record.User{Id: 7, Subject: verificationSubject, Enabled: true, Email: "someone@example.com",
		EmailVerificationCodeEncrypted: encrypted,
		EmailVerificationCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC(), Valid: true}}
}

// TestHandleAccountEmailVerificationPost_VerifiesThroughTheConditionalWrite is the verify's
// write (#404): conditional on the address read and on the exact ciphertext the handler
// decrypted and compared, so the code that was checked is the code spent, and narrow, so
// nothing else of the row the request loaded is written back.
func TestHandleAccountEmailVerificationPost_VerifiesThroughTheConditionalWrite(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	user := pendingCodeUser(t)
	compared := user.EmailVerificationCodeEncrypted
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), verificationSubject).Return(user, nil).Once()
	database.On("TryVerifyUserEmail", mock.Anything, (*sql.Tx)(nil), int64(7), "someone@example.com", compared).
		Return(true, nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventVerifiedEmail, mock.Anything).Return().Once()
	credentials := &countingCredentials{}

	rr := verifyDirect(t, database, auditLogger, credentials, verificationCode)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var resp api.UpdateUserResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.True(t, resp.User.EmailVerified)
	assert.Equal(t, 0, credentials.failures)
	database.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything, mock.Anything)
}

// TestHandleAccountEmailVerificationPost_ALostWriteIsNotAGuess covers the verify whose
// conditional write matched no row after the code compared right (#404). A twin submission that
// verified first is answered as that one was; a code a new send or an email change replaced is
// invalid. Neither was a guess, so neither spends the failure budget, and neither writes an
// audit entry: the twin already wrote the verification's.
func TestHandleAccountEmailVerificationPost_ALostWriteIsNotAGuess(t *testing.T) {
	for _, tc := range []struct {
		name       string
		reread     func(user *record.User) *record.User
		wantStatus int
	}{
		{
			name: "a twin submission verified the address first",
			reread: func(user *record.User) *record.User {
				return &record.User{Id: 7, Subject: verificationSubject, Email: user.Email, EmailVerified: true}
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "a new send replaced the code",
			reread: func(user *record.User) *record.User {
				replaced := *user
				replaced.EmailVerificationCodeEncrypted = []byte("another code's ciphertext")
				return &replaced
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "an email change moved the address, verified meanwhile",
			reread: func(user *record.User) *record.User {
				return &record.User{Id: 7, Subject: verificationSubject, Email: "elsewhere@example.com", EmailVerified: true}
			},
			wantStatus: http.StatusBadRequest,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			user := pendingCodeUser(t)
			reread := tc.reread(user)
			database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), verificationSubject).Return(user, nil).Once()
			database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), verificationSubject).Return(reread, nil).Once()
			database.On("TryVerifyUserEmail", mock.Anything, (*sql.Tx)(nil), int64(7), "someone@example.com", mock.Anything).
				Return(false, nil).Once()
			credentials := &countingCredentials{}

			// The logger expects nothing, so an audit entry of either kind fails the case.
			rr := verifyDirect(t, database, handlersmocks.NewAuditLogger(t), credentials, verificationCode)

			require.Equal(t, tc.wantStatus, rr.Code, rr.Body.String())
			if tc.wantStatus == http.StatusOK {
				var resp api.UpdateUserResponse
				require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
				assert.True(t, resp.User.EmailVerified)
			} else {
				var body map[string]string
				require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
				assert.Equal(t, "INVALID_OR_EXPIRED_VERIFICATION_CODE", body["error_code"])
			}
			assert.Equal(t, 0, credentials.failures, "a right code that lost the row is not a guess")
		})
	}
}
