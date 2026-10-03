package accounthandlers

import (
	"bytes"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_accounthandlers "github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	mocks_handlers "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/reqctx"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/emaillinks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandleForgotPasswordGet(t *testing.T) {
	t.Run("Successful render", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)

		handler := HandleForgotPasswordGet(pageRenderer)

		req, err := http.NewRequest("GET", "/forgot-password", nil)
		assert.NoError(t, err)

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
		pageRenderer := mocks_handlers.NewPageRenderer(t)

		handler := HandleForgotPasswordGet(pageRenderer)

		req, err := http.NewRequest("GET", "/forgot-password", nil)
		assert.NoError(t, err)

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

func TestHandleForgotPasswordPost(t *testing.T) {
	t.Run("Email not given", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		database := mocks_data.NewDatabase(t)
		emailSender := mocks_accounthandlers.NewEmailSender(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleForgotPasswordPost(pageRenderer, database, emailSender, auditLogger, testDataCipher, testBaseURL)

		req := httptest.NewRequest("POST", "/forgot-password", strings.NewReader(""))
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

		assert.Equal(t, map[string]interface{}{
			"ip":          testClientIP,
			"emailDigest": emptyAddressDigest,
			"outcome":     "invalid_address",
		}, *details, "a malformed address is audited too, and no account is named")

		assert.Equal(t, http.StatusOK, rr.Code)

		pageRenderer.AssertExpectations(t)
		database.AssertExpectations(t)
		emailSender.AssertExpectations(t)
	})

	t.Run("User not found", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		database := mocks_data.NewDatabase(t)
		emailSender := mocks_accounthandlers.NewEmailSender(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleForgotPasswordPost(pageRenderer, database, emailSender, auditLogger, testDataCipher, testBaseURL)

		form := url.Values{}
		form.Add("email", "nonexistent@example.com")
		req, err := http.NewRequest("POST", "/forgot-password", strings.NewReader(form.Encode()))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		settings := &models.Settings{}
		ctx := req.Context()
		ctx = reqctx.WithSettings(ctx, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		database.On("GetUserByEmail", mock.Anything, mock.Anything, "nonexistent@example.com").Return(nil, nil)
		auditLogger.On("Log", mock.Anything, audit.AuditRequestedPasswordReset, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["outcome"] == "unknown_address"
		})).Return().Once()

		pageRenderer.On("RenderTemplate",
			rr,
			req,
			"/layouts/auth_layout.html",
			"/forgot_password.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				linkSent, ok := data["linkSent"].(bool)
				return ok && linkSent
			}),
		).Return(nil)

		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)

		pageRenderer.AssertExpectations(t)
		database.AssertExpectations(t)
		emailSender.AssertExpectations(t)
	})

	t.Run("Success path, email is sent", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		database := mocks_data.NewDatabase(t)
		emailSender := mocks_accounthandlers.NewEmailSender(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleForgotPasswordPost(pageRenderer, database, emailSender, auditLogger, testDataCipher, testBaseURL)

		form := url.Values{}
		form.Add("email", "existing@example.com")
		req, err := http.NewRequest("POST", "/forgot-password", strings.NewReader(form.Encode()))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		settings := &models.Settings{
			AppName:       "TestApp",
			SMTPHost:      "smtp.example.com",
			SMTPPort:      587,
			SMTPFromEmail: "noreply@example.com",
		}
		ctx := req.Context()
		ctx = reqctx.WithSettings(ctx, settings)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()

		user := &models.User{
			Id:            1,
			Enabled:       true,
			Email:         "existing@example.com",
			EmailVerified: true,
		}
		database.On("GetUserByEmail", mock.Anything, mock.Anything, "existing@example.com").Return(user, nil)

		// The code is stored by the narrow conditional write, predicated on the address the
		// lookup found, and never by writing the loaded row back (#404 decision 2).
		var storedEncrypted []byte
		var storedHash string
		var storedIssuedAt time.Time
		before := time.Now().UTC()
		database.On("TryStoreForgotPasswordCode", mock.Anything, (*sql.Tx)(nil), int64(1), "existing@example.com",
			mock.Anything, mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) {
				storedEncrypted = args.Get(4).([]byte)
				storedHash = args.Get(5).(string)
				storedIssuedAt = args.Get(6).(time.Time)
			}).Return(true, nil).Once()

		// The handler now wraps the request with a recipient-locale context
		// (i18n.WithLocale) before rendering the email body, so the request
		// pointer differs from the original. mock.Anything keeps the
		// expectation focused on the layout / template / bind args.
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

		pageRenderer.On("RenderTemplate",
			rr,
			req,
			"/layouts/auth_layout.html",
			"/forgot_password.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				linkSent, ok := data["linkSent"].(bool)
				return ok && linkSent
			}),
		).Return(nil)

		auditLogger.On("Log", mock.Anything, audit.AuditRequestedPasswordReset, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["outcome"] == "code_issued" && details["userId"] == int64(1)
		})).Return().Once()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		// The hash stored beside the encrypted code is the only thing that will find this
		// row when the link comes back, since the link carries the code and no address
		// (#112). Derived from the code the handler actually issued, decrypted out of the
		// value it wrote, rather than from a value the test chose: a hash of anything
		// else would leave the user unable to reset at all.
		issuedCode, err := testDataCipher.Decrypt(storedEncrypted)
		assert.NoError(t, err)
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

	t.Run("Storing the code fails", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		database := mocks_data.NewDatabase(t)
		emailSender := mocks_accounthandlers.NewEmailSender(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleForgotPasswordPost(pageRenderer, database, emailSender, auditLogger, testDataCipher, testBaseURL)
		req := forgotPasswordRequest("existing@example.com")
		rr := httptest.NewRecorder()

		database.On("GetUserByEmail", mock.Anything, mock.Anything, "existing@example.com").
			Return(&models.User{Id: 1, Enabled: true, Email: "existing@example.com", EmailVerified: true}, nil)
		database.On("TryStoreForgotPasswordCode", mock.Anything, (*sql.Tx)(nil), int64(1), "existing@example.com",
			mock.Anything, mock.Anything, mock.Anything).Return(false, assert.AnError).Once()
		pageRenderer.On("InternalServerError", rr, req, assert.AnError).Return().Once()

		handler.ServeHTTP(rr, req)

		pageRenderer.AssertExpectations(t)
		database.AssertExpectations(t)
		emailSender.AssertNotCalled(t, "SendEmail", mock.Anything, mock.Anything, mock.Anything)
		// No outcome was decided: the store failed, which is the server's fault and the 500's
		// Error line, not something an administrator reads off the request.
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	})
}

// forgotPasswordRequest is a submission of the forgot-password form for an address, carrying
// the settings MiddlewareSettings puts on every request of the application branch.
func forgotPasswordRequest(email string) *http.Request {
	form := url.Values{}
	form.Add("email", email)
	req := httptest.NewRequest("POST", "/forgot-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req.WithContext(reqctx.WithSettings(req.Context(), &models.Settings{
		AppName:       "TestApp",
		SMTPHost:      "smtp.example.com",
		SMTPPort:      587,
		SMTPFromEmail: "noreply@example.com",
	}))
}

// Recovery goes only to a verified address on an enabled account. Every other account is
// answered exactly as an address with no account is: the same "link sent" page at the same
// status, no code stored and no mail rendered or sent (#404 decisions 1 and 2). The unknown
// address is in the table so the comparison is with what that request actually gets.
func TestHandleForgotPasswordPost_SendsNothingUnlessTheAccountIsVerifiedAndEnabled(t *testing.T) {
	const email = "someone@example.com"

	testCases := []struct {
		name string
		user *models.User
		// storeRefused is the conditional store declining: the account was disabled,
		// unverified or re-addressed between the lookup and the write.
		storeRefused bool
		// wantAudit is the one requested_password_reset record the request must leave, which
		// is the only place these cases differ (#404 decision 6).
		wantAudit map[string]interface{}
	}{
		{
			name: "an address with no account", user: nil,
			wantAudit: map[string]interface{}{"ip": testClientIP, "emailDigest": someoneDigest, "outcome": "unknown_address"},
		},
		{
			name: "an unverified address", user: &models.User{Id: 7, Enabled: true, Email: email, EmailVerified: false},
			wantAudit: map[string]interface{}{"ip": testClientIP, "emailDigest": someoneDigest, "userId": int64(7),
				"outcome": "unverified_address"},
		},
		{
			name: "a disabled account", user: &models.User{Id: 7, Enabled: false, Email: email, EmailVerified: true},
			wantAudit: map[string]interface{}{"ip": testClientIP, "emailDigest": someoneDigest, "userId": int64(7),
				"outcome": "account_disabled"},
		},
		{
			// Disabled is what an administrator did, and the reason re-verifying would not help.
			name: "a disabled account with an unverified address", user: &models.User{Id: 7, Enabled: false, Email: email},
			wantAudit: map[string]interface{}{"ip": testClientIP, "emailDigest": someoneDigest, "userId": int64(7),
				"outcome": "account_disabled"},
		},
		{
			name:         "an account changed between the lookup and the store",
			user:         &models.User{Id: 7, Enabled: true, Email: email, EmailVerified: true},
			storeRefused: true,
			wantAudit: map[string]interface{}{"ip": testClientIP, "emailDigest": someoneDigest, "userId": int64(7),
				"outcome": "account_changed"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := mocks_handlers.NewPageRenderer(t)
			database := mocks_data.NewDatabase(t)
			emailSender := mocks_accounthandlers.NewEmailSender(t)
			auditLogger := mocks_handlers.NewAuditLogger(t)

			handler := HandleForgotPasswordPost(pageRenderer, database, emailSender, auditLogger, testDataCipher, testBaseURL)
			req := forgotPasswordRequest(email)
			rr := httptest.NewRecorder()

			database.On("GetUserByEmail", mock.Anything, mock.Anything, email).Return(tc.user, nil).Once()
			if tc.storeRefused {
				database.On("TryStoreForgotPasswordCode", mock.Anything, (*sql.Tx)(nil), int64(7), email,
					mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Once()
			}

			var bound map[string]interface{}
			pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/forgot_password.html", mock.Anything).
				Run(func(args mock.Arguments) {
					bound = args.Get(4).(map[string]interface{})
				}).Return(nil).Once()
			details := captureRequestedPasswordReset(auditLogger)

			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, map[string]interface{}{"linkSent": true}, bound,
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

// The SHA-256 hex digests of the addresses these tests submit, computed outside the code under
// test (sha256sum), so a digest of anything else, or of the address before normalization,
// fails rather than agreeing with itself.
const (
	// someoneDigest is the digest of "someone@example.com".
	someoneDigest = "72497f475e4f76d0b28f57c73a084ece576d170874eba3ee2609d9afe4b71aab"
	// notAnAddressDigest is the digest of "not-an-address".
	notAnAddressDigest = "e50f7840fcd02669893cddaf76a8d16e2908150aedda106664e92ec2422f56eb"
	// emptyAddressDigest is the digest of "".
	emptyAddressDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// captureRequestedPasswordReset requires exactly one requested_password_reset record and hands
// back its payload once the handler has run, so a test compares the whole map: a key present
// that should not be, an address in plain text or a userId naming no account, fails as surely as
// a wrong value.
func captureRequestedPasswordReset(auditLogger *mocks_handlers.AuditLogger) *map[string]interface{} {
	details := map[string]interface{}{}
	auditLogger.On("Log", mock.Anything, audit.AuditRequestedPasswordReset, mock.Anything).
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
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		database := mocks_data.NewDatabase(t)
		emailSender := mocks_accounthandlers.NewEmailSender(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleForgotPasswordPost(pageRenderer, database, emailSender, auditLogger, testDataCipher, testBaseURL)
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
			"ip":          testClientIP,
			"emailDigest": notAnAddressDigest,
			"outcome":     "invalid_address",
		}, *details, "lowercased as every other submission is, and no account looked up")
		database.AssertNotCalled(t, "GetUserByEmail", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("a code issued is recorded once, digesting the address as looked up, before the mail is sent", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		database := mocks_data.NewDatabase(t)
		emailSender := mocks_accounthandlers.NewEmailSender(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleForgotPasswordPost(pageRenderer, database, emailSender, auditLogger, testDataCipher, testBaseURL)
		req := forgotPasswordRequest("SomeOne@Example.COM")
		rr := httptest.NewRecorder()

		var order []string
		database.On("GetUserByEmail", mock.Anything, mock.Anything, "someone@example.com").
			Return(&models.User{Id: 7, Enabled: true, Email: "someone@example.com", EmailVerified: true}, nil).Once()
		database.On("TryStoreForgotPasswordCode", mock.Anything, (*sql.Tx)(nil), int64(7), "someone@example.com",
			mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Once()
		pageRenderer.On("RenderTemplateToBuffer", mock.Anything, "/layouts/email_layout.html",
			"/emails/email_forgot_password.html", mock.Anything).Return(&bytes.Buffer{}, nil).Once()
		emailSender.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).
			Run(func(mock.Arguments) { order = append(order, "send") }).Return(nil).Once()
		pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/forgot_password.html", mock.Anything).
			Return(nil).Once()
		var details map[string]interface{}
		auditLogger.On("Log", mock.Anything, audit.AuditRequestedPasswordReset, mock.Anything).
			Run(func(args mock.Arguments) {
				order = append(order, "audit")
				details = args.Get(2).(map[string]interface{})
			}).Return().Once()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, map[string]interface{}{
			"ip":          testClientIP,
			"emailDigest": someoneDigest,
			"userId":      int64(7),
			"outcome":     "code_issued",
		}, details)
		assert.Equal(t, []string{"audit", "send"}, order,
			"the record is written once the code is stored and before the mail is sent")
	})

	// The record cannot know whether the mail went out, so a send failure leaves the one record
	// already written and nothing more.
	t.Run("a mail that fails to send leaves the one code_issued record", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		database := mocks_data.NewDatabase(t)
		emailSender := mocks_accounthandlers.NewEmailSender(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleForgotPasswordPost(pageRenderer, database, emailSender, auditLogger, testDataCipher, testBaseURL)
		req := forgotPasswordRequest("someone@example.com")
		rr := httptest.NewRecorder()

		database.On("GetUserByEmail", mock.Anything, mock.Anything, "someone@example.com").
			Return(&models.User{Id: 7, Enabled: true, Email: "someone@example.com", EmailVerified: true}, nil).Once()
		database.On("TryStoreForgotPasswordCode", mock.Anything, (*sql.Tx)(nil), int64(7), "someone@example.com",
			mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Once()
		pageRenderer.On("RenderTemplateToBuffer", mock.Anything, "/layouts/email_layout.html",
			"/emails/email_forgot_password.html", mock.Anything).Return(&bytes.Buffer{}, nil).Once()
		emailSender.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).Return(assert.AnError).Once()
		pageRenderer.On("InternalServerError", rr, req, assert.AnError).Return().Once()
		details := captureRequestedPasswordReset(auditLogger)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, "code_issued", (*details)["outcome"])
	})
}
