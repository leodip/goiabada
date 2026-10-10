package accounthandlers

import (
	"bytes"
	"context"
	"database/sql"
	"github.com/leodip/goiabada/authserver/internal/afterresponse"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/logging/logtest"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/emaillinks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestHandleForgotPasswordGet(t *testing.T) {
	t.Run("Successful render", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)

		handler := HandleForgotPasswordGet(pageRenderer)

		req, err := http.NewRequest("GET", "/forgot-password", nil)
		require.NoError(t, err)
		req = withEmailOn(req)

		rr := httptest.NewRecorder()

		pageRenderer.On("RenderTemplate",
			rr,
			req,
			"/layouts/auth_layout.html",
			"/forgot_password.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				_, hasError := data["error"]
				return hasError
			}),
		).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		pageRenderer.AssertExpectations(t)
	})

	t.Run("RenderTemplate error", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)

		handler := HandleForgotPasswordGet(pageRenderer)

		req, err := http.NewRequest("GET", "/forgot-password", nil)
		require.NoError(t, err)
		req = withEmailOn(req)

		rr := httptest.NewRecorder()

		expectedError := assert.AnError
		pageRenderer.On("RenderTemplate",
			rr,
			req,
			"/layouts/auth_layout.html",
			"/forgot_password.html",
			mock.Anything,
		).Return(expectedError)

		pageRenderer.On("InternalServerError",
			rr,
			req,
			expectedError,
		).Return()

		handler.ServeHTTP(rr, req)

		pageRenderer.AssertExpectations(t)
	})
}

// heldJobs is the after-response runner as these tests drive it: it holds every job handed to it
// rather than starting it, so a test asserts what the request did before its response, and then
// runs the jobs to completion and asserts what they did (#404 decision 8). Each job runs under the
// context the handler handed over, which is the request's.
type heldJobs struct {
	ctxs    []context.Context
	classes []afterresponse.Class
	jobs    []func(ctx context.Context)
}

func (h *heldJobs) Go(ctx context.Context, class afterresponse.Class, job func(ctx context.Context)) {
	h.ctxs = append(h.ctxs, ctx)
	h.classes = append(h.classes, class)
	h.jobs = append(h.jobs, job)
}

// runAll runs every job held, in the order handed over, and requires exactly one, admitted against
// class: a forgot-password request or a registration hands off one job or none, forgot-password's
// against ClassRecovery and registration's against ClassRegistration, each a budget of its own
// (#394 review).
func (h *heldJobs) runAll(t *testing.T, class afterresponse.Class) {
	t.Helper()
	require.Len(t, h.jobs, 1, "a well-formed request hands exactly one job to run after its response")
	for i, job := range h.jobs {
		assert.Equal(t, class, h.classes[i], "the job is admitted against the budget of its own kind of work")
		job(h.ctxs[i])
	}
}

// forgotPasswordRequestId is the request id forgotPasswordRequest carries, as chi's RequestID
// middleware puts one on every request.
const forgotPasswordRequestId = "req-forgot-0001"

// forgotPasswordRequest is a submission of the forgot-password form for an address, carrying
// the settings middleware.Settings puts on every request of the application branch and a request id.
func forgotPasswordRequest(email string) *http.Request {
	form := url.Values{}
	form.Add("email", email)
	req := httptest.NewRequest("POST", "/forgot-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := context.WithValue(req.Context(), chimiddleware.RequestIDKey, forgotPasswordRequestId)
	return req.WithContext(reqctx.WithSettings(ctx, &record.Settings{
		AppName:       "TestApp",
		SMTPEnabled:   true,
		SMTPHost:      "smtp.example.com",
		SMTPPort:      587,
		SMTPFromEmail: "noreply@example.com",
	}))
}

// expectLinkSentPage expects the one page every well-formed request is answered with, and hands
// back what it was bound with.
func expectLinkSentPage(pageRenderer *handlersmocks.PageRenderer, rr *httptest.ResponseRecorder, req *http.Request) *map[string]interface{} {
	bound := map[string]interface{}{}
	pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/forgot_password.html", mock.Anything).
		Run(func(args mock.Arguments) {
			bound = args.Get(4).(map[string]interface{})
		}).Return(nil).Once()
	return &bound
}

func TestHandleForgotPasswordPost(t *testing.T) {
	t.Run("Email not given", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		emailSender := accounthandlersmocks.NewEmailSender(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		jobs := &heldJobs{}

		handler := HandleForgotPasswordPost(pageRenderer, database, emailSender, auditLogger, jobs, testDataCipher, testBaseURL)

		req := withEmailOn(httptest.NewRequest("POST", "/forgot-password", strings.NewReader("")))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rr := httptest.NewRecorder()

		pageRenderer.On("RenderTemplate",
			rr,
			req,
			"/layouts/auth_layout.html",
			"/forgot_password.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				errorMsg, ok := data["error"].(string)
				return ok && errorMsg == "Please enter a valid email address."
			}),
		).Return(nil)
		details := captureRequestedPasswordReset(auditLogger)

		handler.ServeHTTP(rr, req)

		// The error page is visibly different anyway, so its record is written with it rather than
		// after it, and nothing is left to run.
		assert.Equal(t, map[string]interface{}{
			"ip":           testClientIP,
			"email_digest": emptyAddressDigest,
			"outcome":      "invalid_address",
		}, *details, "a malformed address is audited too, and no account is named")
		assert.Empty(t, jobs.jobs, "a malformed address leaves no work for after the response")

		assert.Equal(t, http.StatusOK, rr.Code)

		pageRenderer.AssertExpectations(t)
		database.AssertExpectations(t)
		emailSender.AssertExpectations(t)
	})

	t.Run("User not found", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		emailSender := accounthandlersmocks.NewEmailSender(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		jobs := &heldJobs{}

		handler := HandleForgotPasswordPost(pageRenderer, database, emailSender, auditLogger, jobs, testDataCipher, testBaseURL)
		req := forgotPasswordRequest("nonexistent@example.com")
		rr := httptest.NewRecorder()

		database.On("GetUserByEmail", mock.Anything, mock.Anything, "nonexistent@example.com").Return(nil, nil)
		bound := expectLinkSentPage(pageRenderer, rr, req)

		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, map[string]interface{}{"linkSent": true}, *bound)
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)

		auditLogger.On("Log", mock.Anything, audit.EventRequestedPasswordReset, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["outcome"] == "unknown_address"
		})).Return().Once()
		jobs.runAll(t, afterresponse.ClassRecovery)

		pageRenderer.AssertExpectations(t)
		database.AssertExpectations(t)
		emailSender.AssertExpectations(t)
	})

	t.Run("Success path, email is sent", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		emailSender := accounthandlersmocks.NewEmailSender(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		jobs := &heldJobs{}

		handler := HandleForgotPasswordPost(pageRenderer, database, emailSender, auditLogger, jobs, testDataCipher, testBaseURL)
		req := forgotPasswordRequest("existing@example.com")
		rr := httptest.NewRecorder()

		user := &record.User{
			Id:            1,
			Enabled:       true,
			Email:         "existing@example.com",
			EmailVerified: true,
		}
		database.On("GetUserByEmail", mock.Anything, mock.Anything, "existing@example.com").Return(user, nil)
		bound := expectLinkSentPage(pageRenderer, rr, req)

		before := time.Now().UTC()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, map[string]interface{}{"linkSent": true}, *bound)

		// The code is stored by the narrow conditional write, predicated on the address the
		// lookup found, and never by writing the loaded row back (#404 decision 2).
		var storedEncrypted []byte
		var storedHash string
		var storedIssuedAt time.Time
		database.On("TryStoreForgotPasswordCode", mock.Anything, (*sql.Tx)(nil), int64(1), "existing@example.com",
			mock.Anything, mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) {
				storedEncrypted = args.Get(4).([]byte)
				storedHash = args.Get(5).(string)
				storedIssuedAt = args.Get(6).(time.Time)
			}).Return(true, nil).Once()

		// The job renders the mail in the recipient's locale (i18n.WithLocale), so the request
		// it renders with is not the handler's. mock.Anything keeps the expectation focused on
		// the layout / template / bind args.
		var emailedLink string
		pageRenderer.On("RenderTemplateToBuffer", mock.Anything, "/layouts/email_layout.html", "/emails/email_forgot_password.html", mock.Anything).
			Run(func(args mock.Arguments) {
				emailedLink, _ = args.Get(3).(map[string]interface{})["link"].(string)
			}).Return(&bytes.Buffer{}, nil)

		// The relay is the request's settings, which is the whole of what the handler now reads
		// for the send (#433).
		emailSender.On("SendEmail", mock.Anything,
			emaildelivery.SMTPConfig{Host: "smtp.example.com", Port: 587, FromEmail: "noreply@example.com"},
			mock.MatchedBy(func(input *emaildelivery.SendEmailInput) bool {
				return input.To == "existing@example.com" && input.Subject == "Password reset"
			})).Return(nil)

		auditLogger.On("Log", mock.Anything, audit.EventRequestedPasswordReset, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["outcome"] == "code_issued" && details["user_id"] == int64(1)
		})).Return().Once()

		jobs.runAll(t, afterresponse.ClassRecovery)

		// The hash stored beside the encrypted code is the only thing that will find this
		// row when the link comes back, since the link carries the code and no address
		// (#112). Derived from the code the handler actually issued, decrypted out of the
		// value it wrote, rather than from a value the test chose: a hash of anything
		// else would leave the user unable to reset at all.
		issuedCode, err := testDataCipher.Decrypt(storedEncrypted)
		require.NoError(t, err)
		expectedHash := hashutil.HashString(issuedCode)
		assert.Equal(t, expectedHash, storedHash,
			"the stored hash must be the hash of the code that was issued")
		assert.False(t, storedIssuedAt.Before(before.Add(-time.Second)), "the code must be stamped as issued now")
		assert.Equal(t, time.UTC, storedIssuedAt.Location(), "the issued-at must be UTC, as every other stamp")

		// This site's only job is to hand the issued code to the shared builder; the link's
		// shape and the absence of an address in it belong to emaillinks.ResetPasswordLink's own tests
		// (#112 decision 5). Asserting the exact string here would pin the shape in a
		// second place and let the two disagree.
		assert.Equal(t, emaillinks.ResetPasswordLink(testBaseURL, issuedCode), emailedLink,
			"the emailed link must be the shared builder's output for the code that was issued")

		pageRenderer.AssertExpectations(t)
		database.AssertExpectations(t)
		emailSender.AssertExpectations(t)
		database.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything, mock.Anything)
	})

	// The lookup is the one database read every well-formed request makes before its response, so
	// its failure is the server's and is answered as one, whatever address was asked about.
	t.Run("The lookup fails", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		emailSender := accounthandlersmocks.NewEmailSender(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		jobs := &heldJobs{}

		handler := HandleForgotPasswordPost(pageRenderer, database, emailSender, auditLogger, jobs, testDataCipher, testBaseURL)
		req := forgotPasswordRequest("existing@example.com")
		rr := httptest.NewRecorder()

		database.On("GetUserByEmail", mock.Anything, mock.Anything, "existing@example.com").Return(nil, assert.AnError).Once()
		pageRenderer.On("InternalServerError", rr, req, assert.AnError).Return().Once()
		details := captureRequestedPasswordReset(auditLogger)

		handler.ServeHTTP(rr, req)

		pageRenderer.AssertExpectations(t)
		assert.Empty(t, jobs.jobs, "a request whose lookup failed decided nothing to finish later")
		// The request still leaves its one record, and names no account, since none was found
		// (#404 decision 6).
		assert.Equal(t, map[string]interface{}{
			"ip":           testClientIP,
			"email_digest": existingDigest,
			"outcome":      "server_error",
		}, *details)
	})

	// The job's faults before a code is issued are the server's too, and leave the one record the
	// request owes beside the Error line that says why (#404 decision 6).
	t.Run("Encrypting the code fails", func(t *testing.T) {
		capture := logtest.CaptureSlog(t)
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		emailSender := accounthandlersmocks.NewEmailSender(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		jobs := &heldJobs{}

		// A nil cipher refuses every encryption, which is the one way to make the real one fail.
		handler := HandleForgotPasswordPost(pageRenderer, database, emailSender, auditLogger, jobs, nil, testBaseURL)
		req := forgotPasswordRequest("existing@example.com")
		rr := httptest.NewRecorder()

		database.On("GetUserByEmail", mock.Anything, mock.Anything, "existing@example.com").
			Return(&record.User{Id: 1, Enabled: true, Email: "existing@example.com", EmailVerified: true}, nil)
		expectLinkSentPage(pageRenderer, rr, req)
		details := captureRequestedPasswordReset(auditLogger)

		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code, "the response has gone before the code is encrypted")
		jobs.runAll(t, afterresponse.ClassRecovery)

		assert.Equal(t, map[string]interface{}{
			"ip":           testClientIP,
			"email_digest": existingDigest,
			"user_id":      int64(1),
			"outcome":      "server_error",
		}, *details)
		database.AssertNotCalled(t, "TryStoreForgotPasswordCode", mock.Anything, mock.Anything, mock.Anything,
			mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		emailSender.AssertNotCalled(t, "SendEmail", mock.Anything, mock.Anything, mock.Anything)
		assertOneErrorRecordOnTheRequest(t, capture)
	})

	t.Run("Storing the code fails", func(t *testing.T) {
		capture := logtest.CaptureSlog(t)
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		emailSender := accounthandlersmocks.NewEmailSender(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		jobs := &heldJobs{}

		handler := HandleForgotPasswordPost(pageRenderer, database, emailSender, auditLogger, jobs, testDataCipher, testBaseURL)
		req := forgotPasswordRequest("existing@example.com")
		rr := httptest.NewRecorder()

		database.On("GetUserByEmail", mock.Anything, mock.Anything, "existing@example.com").
			Return(&record.User{Id: 1, Enabled: true, Email: "existing@example.com", EmailVerified: true}, nil)
		expectLinkSentPage(pageRenderer, rr, req)

		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code, "the response has gone before the store is attempted")

		database.On("TryStoreForgotPasswordCode", mock.Anything, (*sql.Tx)(nil), int64(1), "existing@example.com",
			mock.Anything, mock.Anything, mock.Anything).Return(false, assert.AnError).Once()
		details := captureRequestedPasswordReset(auditLogger)
		jobs.runAll(t, afterresponse.ClassRecovery)

		pageRenderer.AssertExpectations(t)
		database.AssertExpectations(t)
		pageRenderer.AssertNotCalled(t, "InternalServerError", mock.Anything, mock.Anything, mock.Anything)
		emailSender.AssertNotCalled(t, "SendEmail", mock.Anything, mock.Anything, mock.Anything)
		// The store failed, which is the server's fault: the Error line says why, and the one
		// record keeps the request in the catalog with its digest and account.
		assert.Equal(t, map[string]interface{}{
			"ip":           testClientIP,
			"email_digest": existingDigest,
			"user_id":      int64(1),
			"outcome":      "server_error",
		}, *details)
		assertOneErrorRecordOnTheRequest(t, capture)
	})
}

// assertOneErrorRecordOnTheRequest requires that the job wrote exactly one record, at Error, carrying
// the id of the request that started it: with the response gone, that line is the only trace of a
// failure after it (#404 decision 8).
func assertOneErrorRecordOnTheRequest(t *testing.T, capture *logtest.SlogCapture) {
	t.Helper()
	records := capture.Records()
	require.Len(t, records, 1, capture.Text())
	assert.Equal(t, slog.LevelError, records[0].Level)
	assert.Equal(t, forgotPasswordRequestId, records[0].Attrs["request_id"])
	assert.NotNil(t, records[0].Attrs["error"])
}

// Recovery goes only to a verified address on an enabled account. Every other account is
// answered exactly as an address with no account is: the same "link sent" page at the same
// status, no code stored and no mail rendered or sent (#404 decisions 1 and 2). The unknown
// address is in the table so the comparison is with what that request actually gets.
func TestHandleForgotPasswordPost_SendsNothingUnlessTheAccountIsVerifiedAndEnabled(t *testing.T) {
	const email = "someone@example.com"

	testCases := []struct {
		name string
		user *record.User
		// storeRefused is the conditional store declining: the account was disabled,
		// unverified or re-addressed between the lookup and the write.
		storeRefused bool
		// wantAudit is the one requested_password_reset record the request must leave, which
		// is the only place these cases differ (#404 decision 6).
		wantAudit map[string]interface{}
	}{
		{
			name: "an address with no account", user: nil,
			wantAudit: map[string]interface{}{"ip": testClientIP, "email_digest": someoneDigest, "outcome": "unknown_address"},
		},
		{
			name: "an unverified address", user: &record.User{Id: 7, Enabled: true, Email: email, EmailVerified: false},
			wantAudit: map[string]interface{}{"ip": testClientIP, "email_digest": someoneDigest, "user_id": int64(7),
				"outcome": "unverified_address"},
		},
		{
			name: "a disabled account", user: &record.User{Id: 7, Enabled: false, Email: email, EmailVerified: true},
			wantAudit: map[string]interface{}{"ip": testClientIP, "email_digest": someoneDigest, "user_id": int64(7),
				"outcome": "account_disabled"},
		},
		{
			// Disabled is what an administrator did, and the reason re-verifying would not help.
			name: "a disabled account with an unverified address", user: &record.User{Id: 7, Enabled: false, Email: email},
			wantAudit: map[string]interface{}{"ip": testClientIP, "email_digest": someoneDigest, "user_id": int64(7),
				"outcome": "account_disabled"},
		},
		{
			name:         "an account changed between the lookup and the store",
			user:         &record.User{Id: 7, Enabled: true, Email: email, EmailVerified: true},
			storeRefused: true,
			wantAudit: map[string]interface{}{"ip": testClientIP, "email_digest": someoneDigest, "user_id": int64(7),
				"outcome": "account_changed"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			database := datamocks.NewDatabase(t)
			emailSender := accounthandlersmocks.NewEmailSender(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			jobs := &heldJobs{}

			handler := HandleForgotPasswordPost(pageRenderer, database, emailSender, auditLogger, jobs, testDataCipher, testBaseURL)
			req := forgotPasswordRequest(email)
			rr := httptest.NewRecorder()

			database.On("GetUserByEmail", mock.Anything, mock.Anything, email).Return(tc.user, nil).Once()
			if tc.storeRefused {
				database.On("TryStoreForgotPasswordCode", mock.Anything, (*sql.Tx)(nil), int64(7), email,
					mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Once()
			}
			bound := expectLinkSentPage(pageRenderer, rr, req)
			details := captureRequestedPasswordReset(auditLogger)

			handler.ServeHTTP(rr, req)
			jobs.runAll(t, afterresponse.ClassRecovery)

			assert.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, map[string]interface{}{"linkSent": true}, *bound,
				"the page must be exactly the one an address with no account gets")
			assert.Equal(t, tc.wantAudit, *details)

			pageRenderer.AssertExpectations(t)
			database.AssertExpectations(t)
			if !tc.storeRefused {
				database.AssertNotCalled(t, "TryStoreForgotPasswordCode", mock.Anything, mock.Anything, mock.Anything,
					mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			}
			database.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything, mock.Anything)
			pageRenderer.AssertNotCalled(t, "RenderTemplateToBuffer", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			emailSender.AssertNotCalled(t, "SendEmail", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// Every well-formed request is answered after the format check and the lookup alone, whatever
// the lookup found: the code store, the audit record, the render and the send all wait for the
// job, so a live account costs the response no more than an address with no account does (#404
// decisions 7 and 8). The job is held here and never run, so anything the handler did before
// answering is exactly what these mocks recorded.
func TestHandleForgotPasswordPost_AnswersAfterTheLookupAlone(t *testing.T) {
	const email = "someone@example.com"

	for _, tc := range []struct {
		name string
		user *record.User
	}{
		{name: "an address with no account", user: nil},
		{name: "an unverified address", user: &record.User{Id: 7, Enabled: true, Email: email}},
		{name: "a disabled account", user: &record.User{Id: 7, Enabled: false, Email: email, EmailVerified: true}},
		{name: "a verified, enabled account", user: &record.User{Id: 7, Enabled: true, Email: email, EmailVerified: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			database := datamocks.NewDatabase(t)
			emailSender := accounthandlersmocks.NewEmailSender(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			jobs := &heldJobs{}

			handler := HandleForgotPasswordPost(pageRenderer, database, emailSender, auditLogger, jobs, testDataCipher, testBaseURL)
			req := forgotPasswordRequest(email)
			rr := httptest.NewRecorder()

			database.On("GetUserByEmail", mock.Anything, mock.Anything, email).Return(tc.user, nil).Once()
			bound := expectLinkSentPage(pageRenderer, rr, req)

			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, map[string]interface{}{"linkSent": true}, *bound)
			pageRenderer.AssertExpectations(t)
			database.AssertExpectations(t)

			database.AssertNotCalled(t, "TryStoreForgotPasswordCode", mock.Anything, mock.Anything, mock.Anything,
				mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
			pageRenderer.AssertNotCalled(t, "RenderTemplateToBuffer", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			emailSender.AssertNotCalled(t, "SendEmail", mock.Anything, mock.Anything, mock.Anything)

			require.Len(t, jobs.jobs, 1, "the rest is handed to one job")
			assert.Equal(t, forgotPasswordRequestId, jobs.ctxs[0].Value(chimiddleware.RequestIDKey),
				"the job is handed the request's context, so what it records joins the request")
		})
	}
}

// The SHA-256 hex digests of the addresses these tests submit, computed outside the code under
// test (sha256sum), so a digest of anything else, or of the address before normalization,
// fails rather than agreeing with itself.
const (
	// someoneDigest is the digest of "someone@example.com".
	someoneDigest = "72497f475e4f76d0b28f57c73a084ece576d170874eba3ee2609d9afe4b71aab"
	// notAnAddressDigest is the digest of "not-an-address".
	notAnAddressDigest = "e50f7840fcd02669893cddaf76a8d16e2908150aedda106664e92ec2422f56eb"
	// existingDigest is the digest of "existing@example.com".
	existingDigest = "376ff10ae1de82646eb0a5a13b45d31cb1d1ac92981936929855fb5405cfe804"
	// emptyAddressDigest is the digest of "".
	emptyAddressDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// captureRequestedPasswordReset requires exactly one requested_password_reset record and hands
// back its payload once the handler has run, so a test compares the whole map: a key present
// that should not be, an address in plain text or a userId naming no account, fails as surely as
// a wrong value.
func captureRequestedPasswordReset(auditLogger *handlersmocks.AuditLogger) *map[string]interface{} {
	details := map[string]interface{}{}
	auditLogger.On("Log", mock.Anything, audit.EventRequestedPasswordReset, mock.Anything).
		Run(func(args mock.Arguments) {
			details = args.Get(2).(map[string]interface{})
		}).Return().Once()
	return &details
}

// Every forgot-password request leaves exactly one requested_password_reset record saying what
// became of it, with the address digested rather than recorded (#404 decision 6). The cases the
// conditional store and the eligibility check decide are in
// TestHandleForgotPasswordPost_SendsNothingUnlessTheAccountIsVerifiedAndEnabled; these are the
// two ends of the handler, the format check and the code issued.
func TestHandleForgotPasswordPost_AuditsEveryRequestOnce(t *testing.T) {
	t.Run("a malformed address is recorded as invalid_address, digested as submitted", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		emailSender := accounthandlersmocks.NewEmailSender(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		jobs := &heldJobs{}

		handler := HandleForgotPasswordPost(pageRenderer, database, emailSender, auditLogger, jobs, testDataCipher, testBaseURL)
		req := forgotPasswordRequest("Not-An-Address")
		rr := httptest.NewRecorder()

		pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/forgot_password.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				_, hasError := data["error"]
				return hasError
			})).Return(nil).Once()
		details := captureRequestedPasswordReset(auditLogger)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, map[string]interface{}{
			"ip":           testClientIP,
			"email_digest": notAnAddressDigest,
			"outcome":      "invalid_address",
		}, *details, "lowercased as every other submission is, and no account looked up")
		database.AssertNotCalled(t, "GetUserByEmail", mock.Anything, mock.Anything, mock.Anything)
		assert.Empty(t, jobs.jobs)
	})

	t.Run("a code issued is recorded once, digesting the address as looked up, before the mail is sent", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		emailSender := accounthandlersmocks.NewEmailSender(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		jobs := &heldJobs{}

		handler := HandleForgotPasswordPost(pageRenderer, database, emailSender, auditLogger, jobs, testDataCipher, testBaseURL)
		req := forgotPasswordRequest("SomeOne@Example.COM")
		rr := httptest.NewRecorder()

		var order []string
		database.On("GetUserByEmail", mock.Anything, mock.Anything, "someone@example.com").
			Return(&record.User{Id: 7, Enabled: true, Email: "someone@example.com", EmailVerified: true}, nil).Once()
		database.On("TryStoreForgotPasswordCode", mock.Anything, (*sql.Tx)(nil), int64(7), "someone@example.com",
			mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Once()
		pageRenderer.On("RenderTemplateToBuffer", mock.Anything, "/layouts/email_layout.html",
			"/emails/email_forgot_password.html", mock.Anything).Return(&bytes.Buffer{}, nil).Once()
		emailSender.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).
			Run(func(mock.Arguments) { order = append(order, "send") }).Return(nil).Once()
		expectLinkSentPage(pageRenderer, rr, req)
		var details map[string]interface{}
		var auditCtx context.Context
		auditLogger.On("Log", mock.Anything, audit.EventRequestedPasswordReset, mock.Anything).
			Run(func(args mock.Arguments) {
				order = append(order, "audit")
				auditCtx = args.Get(0).(context.Context)
				details = args.Get(2).(map[string]interface{})
			}).Return().Once()

		handler.ServeHTTP(rr, req)
		jobs.runAll(t, afterresponse.ClassRecovery)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, map[string]interface{}{
			"ip":           testClientIP,
			"email_digest": someoneDigest,
			"user_id":      int64(7),
			"outcome":      "code_issued",
		}, details)
		assert.Equal(t, []string{"audit", "send"}, order,
			"the record is written once the code is stored and before the mail is sent")
		assert.Equal(t, forgotPasswordRequestId, auditCtx.Value(chimiddleware.RequestIDKey),
			"the record is written under the job's context, which carries the request's id")
	})

	// The record cannot know whether the mail went out, so a send failure leaves the one record
	// already written and an Error line on the same request id, and the requester, already
	// answered, is told nothing different (#404 decisions 7 and 8).
	t.Run("a mail that fails to send leaves the one code_issued record and an Error line", func(t *testing.T) {
		capture := logtest.CaptureSlog(t)
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		emailSender := accounthandlersmocks.NewEmailSender(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		jobs := &heldJobs{}

		handler := HandleForgotPasswordPost(pageRenderer, database, emailSender, auditLogger, jobs, testDataCipher, testBaseURL)
		req := forgotPasswordRequest("someone@example.com")
		rr := httptest.NewRecorder()

		database.On("GetUserByEmail", mock.Anything, mock.Anything, "someone@example.com").
			Return(&record.User{Id: 7, Enabled: true, Email: "someone@example.com", EmailVerified: true}, nil).Once()
		database.On("TryStoreForgotPasswordCode", mock.Anything, (*sql.Tx)(nil), int64(7), "someone@example.com",
			mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Once()
		pageRenderer.On("RenderTemplateToBuffer", mock.Anything, "/layouts/email_layout.html",
			"/emails/email_forgot_password.html", mock.Anything).Return(&bytes.Buffer{}, nil).Once()
		emailSender.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).Return(assert.AnError).Once()
		bound := expectLinkSentPage(pageRenderer, rr, req)
		details := captureRequestedPasswordReset(auditLogger)

		handler.ServeHTTP(rr, req)
		jobs.runAll(t, afterresponse.ClassRecovery)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, map[string]interface{}{"linkSent": true}, *bound, "the requester is told a link was sent")
		assert.Equal(t, "code_issued", (*details)["outcome"])
		pageRenderer.AssertNotCalled(t, "InternalServerError", mock.Anything, mock.Anything, mock.Anything)
		assertOneErrorRecordOnTheRequest(t, capture)
	})
}

// withEmailOn puts the settings of a deployment with email set up on req, which both forgot-password
// handlers require.
func withEmailOn(req *http.Request) *http.Request {
	return req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{AppName: "TestApp", SMTPEnabled: true}))
}

// With email off no link can reach anyone, so the form isn't there: both handlers answer 404 with a
// Warn record, issue no code, look nobody up, audit nothing and hand off no mail (#542).
func TestHandleForgotPassword_WithEmailOffThePageIsNotThere(t *testing.T) {
	off := func(req *http.Request) *http.Request {
		return req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{AppName: "TestApp", SMTPEnabled: false}))
	}

	t.Run("GET", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		req := off(httptest.NewRequest(http.MethodGet, "/forgot-password", nil))
		rr := httptest.NewRecorder()
		pageRenderer.On("NotFound", rr, req).Return().Once()

		HandleForgotPasswordGet(pageRenderer).ServeHTTP(rr, req)

		pageRenderer.AssertExpectations(t)
	})

	t.Run("POST", func(t *testing.T) {
		logs := logtest.CaptureSlog(t)
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		emailSender := accounthandlersmocks.NewEmailSender(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		jobs := &heldJobs{}
		form := url.Values{"email": {"someone@example.com"}}
		req := off(httptest.NewRequest(http.MethodPost, "/forgot-password", strings.NewReader(form.Encode())))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		pageRenderer.On("NotFound", rr, req).Return().Once()

		HandleForgotPasswordPost(pageRenderer, database, emailSender, auditLogger, jobs, testDataCipher, testBaseURL).ServeHTTP(rr, req)

		pageRenderer.AssertExpectations(t)
		database.AssertNotCalled(t, "GetUserByEmail", mock.Anything, mock.Anything, mock.Anything)
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		assert.Empty(t, jobs.jobs, "no mail is handed off")
		records := logs.Records()
		require.Len(t, records, 1)
		assert.Equal(t, slog.LevelWarn, records[0].Level)
		assert.Equal(t, "forgot-password request refused because email is not set up", records[0].Message)
	})
}
