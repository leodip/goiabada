package handlers

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/core/constants"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/encryption"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/models"
	mocks_validators "github.com/leodip/goiabada/core/validators/mocks"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// expectRenderedCodeInvalid matches the one response that every link-attributable
// failure must produce: the reset form in its invalid-or-expired state, with a
// 400. Using a single matcher everywhere is deliberate — if any of these paths
// starts answering differently, it becomes an oracle for whether an email address
// has an account, and these tests fail.
// wantStatus is the expected _httpStatus; pass 0 to require that no status is set,
// which is how the GET keeps its long-standing implicit 200.
func expectRenderedCodeInvalid(httpHelper *mocks_handlerhelpers.HttpHelper, wantStatus int) {
	httpHelper.On("RenderTemplate",
		mock.Anything,
		mock.Anything,
		"/layouts/auth_layout.html",
		"/reset_password.html",
		mock.MatchedBy(func(data map[string]interface{}) bool {
			flag, ok := data["codeInvalidOrExpired"].(bool)
			if !ok || !flag {
				return false
			}
			status, present := data["_httpStatus"]
			if wantStatus == 0 {
				return !present
			}
			return present && status == wantStatus
		}),
	).Return(nil).Once()
}

// expectAuditFailedCode requires exactly one audit entry for a refused submission,
// carrying the given reason. The reason is the only place the cause is recorded,
// since every refusal returns the same response.
func expectAuditFailedCode(auditLogger *mocks_audit.AuditLogger, wantReason string) {
	auditLogger.On("Log", constants.AuditFailedResetPasswordCode,
		mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["reason"] == wantReason
		}),
	).Return().Once()
}

func TestHandleResetPasswordGet(t *testing.T) {
	t.Run("No code provided", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleResetPasswordGet(httpHelper, database)

		req, _ := http.NewRequest("GET", "/reset-password", nil)
		rr := httptest.NewRecorder()

		expectRenderedCodeInvalid(httpHelper, 0)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
	})

	t.Run("No email provided", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleResetPasswordGet(httpHelper, database)

		req, _ := http.NewRequest("GET", "/reset-password?code=123", nil)
		rr := httptest.NewRecorder()

		expectRenderedCodeInvalid(httpHelper, 0)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
	})

	t.Run("User not found", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleResetPasswordGet(httpHelper, database)

		req, _ := http.NewRequest("GET", "/reset-password?code=123456&email=test@example.com", nil)
		rr := httptest.NewRecorder()

		database.On("GetUserByEmail", (*sql.Tx)(nil), "test@example.com").Return(nil, nil)
		expectRenderedCodeInvalid(httpHelper, 0)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
	})

	t.Run("DecryptText error", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleResetPasswordGet(httpHelper, database)

		req, _ := http.NewRequest("GET", "/reset-password?code=123456&email=test@example.com", nil)
		rr := httptest.NewRecorder()

		user := &models.User{
			Id:                          1,
			Email:                       "test@example.com",
			ForgotPasswordCodeEncrypted: []byte("encrypted_code"),
			ForgotPasswordCodeIssuedAt:  sql.NullTime{Time: time.Now(), Valid: true},
		}

		database.On("GetUserByEmail", (*sql.Tx)(nil), "test@example.com").Return(user, nil)

		httpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool {
				return strings.Contains(err.Error(), "unable to decrypt forgot password code")
			}),
		).Return().Once()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Forgot password code doesn't match", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleResetPasswordGet(httpHelper, database)

		// The code in the request
		requestCode := "123456"
		req, _ := http.NewRequest("GET", "/reset-password?code="+requestCode+"&email=test@example.com", nil)
		rr := httptest.NewRecorder()

		// The actual forgot password code (different from the request)
		actualCode := "654321"

		// Encrypt the actual code
		encryptedCode, err := encryption.EncryptData(actualCode)
		assert.NoError(t, err)

		user := &models.User{
			Id:                          1,
			Email:                       "test@example.com",
			ForgotPasswordCodeEncrypted: encryptedCode,
			ForgotPasswordCodeIssuedAt:  sql.NullTime{Time: time.Now(), Valid: true},
		}

		database.On("GetUserByEmail", (*sql.Tx)(nil), "test@example.com").Return(user, nil)

		expectRenderedCodeInvalid(httpHelper, 0)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Forgot password code is expired", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleResetPasswordGet(httpHelper, database)

		// The code in the request
		requestCode := "123456"
		req, _ := http.NewRequest("GET", "/reset-password?code="+requestCode+"&email=test@example.com", nil)
		rr := httptest.NewRecorder()

		// Encrypt the request code
		encryptedCode, err := encryption.EncryptData(requestCode)
		assert.NoError(t, err)

		// Set the issued time to 6 minutes ago (exceeding the 5-minute expiration)
		issuedTime := time.Now().Add(-6 * time.Minute)

		user := &models.User{
			Id:                          1,
			Email:                       "test@example.com",
			ForgotPasswordCodeEncrypted: encryptedCode,
			ForgotPasswordCodeIssuedAt:  sql.NullTime{Time: issuedTime, Valid: true},
		}

		database.On("GetUserByEmail", (*sql.Tx)(nil), "test@example.com").Return(user, nil)

		expectRenderedCodeInvalid(httpHelper, 0)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Happy path - valid code and not expired", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleResetPasswordGet(httpHelper, database)

		// The code in the request
		requestCode := "123456"
		req, _ := http.NewRequest("GET", "/reset-password?code="+requestCode+"&email=test@example.com", nil)
		rr := httptest.NewRecorder()

		// Encrypt the request code
		encryptedCode, err := encryption.EncryptData(requestCode)
		assert.NoError(t, err)

		// Set the issued time to 4 minutes ago (within the 5-minute expiration)
		issuedTime := time.Now().Add(-4 * time.Minute)

		user := &models.User{
			Id:                          1,
			Email:                       "test@example.com",
			ForgotPasswordCodeEncrypted: encryptedCode,
			ForgotPasswordCodeIssuedAt:  sql.NullTime{Time: issuedTime, Valid: true},
		}

		database.On("GetUserByEmail", (*sql.Tx)(nil), "test@example.com").Return(user, nil)

		httpHelper.On("RenderTemplate",
			mock.Anything,
			mock.Anything,
			"/layouts/auth_layout.html",
			"/reset_password.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				// Ensure that codeInvalidOrExpired is not set or is false
				codeInvalidOrExpired, ok := data["codeInvalidOrExpired"].(bool)
				return !ok || !codeInvalidOrExpired
			}),
		).Return(nil).Once()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})
}

// =============================================================================
// Tests for HandleResetPasswordPost
//
// This is the handler that actually changes the password, and it had no tests.
// The cases below cover the rejection paths first, because each one is what
// stands between a stale or forged reset link and an account takeover. The
// expiry case in particular is the regression guard for the lifetime check:
// enforcing it only in the GET handler (which merely renders a warning flag)
// left a leaked link usable forever.
// =============================================================================

// postResetRequest builds a form POST carrying the password fields, with the code
// and email in the query string where the handler reads them from.
func postResetRequest(code, email, password, passwordConfirmation string) *http.Request {
	form := url.Values{}
	form.Set("password", password)
	form.Set("passwordConfirmation", passwordConfirmation)

	target := "/reset-password"
	query := url.Values{}
	if code != "" {
		query.Set("code", code)
	}
	if email != "" {
		query.Set("email", email)
	}
	if len(query) > 0 {
		target += "?" + query.Encode()
	}

	req, _ := http.NewRequest("POST", target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// expectRenderedFormError matches a re-render of the form carrying a non-empty
// error message, without coupling the test to the localized text.
func expectRenderedFormError(httpHelper *mocks_handlerhelpers.HttpHelper) {
	httpHelper.On("RenderTemplate",
		mock.Anything,
		mock.Anything,
		"/layouts/auth_layout.html",
		"/reset_password.html",
		mock.MatchedBy(func(data map[string]interface{}) bool {
			msg, ok := data["error"].(string)
			return ok && msg != ""
		}),
	).Return(nil).Once()
}

func TestHandleResetPasswordPost_PasswordFieldRejections(t *testing.T) {
	// None of these reach the database, which NewDatabase(t) enforces.
	t.Run("empty password", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		passwordValidator := mocks_validators.NewPasswordValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleResetPasswordPost(httpHelper, database, passwordValidator, auditLogger)
		expectRenderedFormError(httpHelper)

		handler.ServeHTTP(httptest.NewRecorder(),
			postResetRequest("123456", "test@example.com", "", ""))

		httpHelper.AssertExpectations(t)
	})

	t.Run("confirmation does not match", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		passwordValidator := mocks_validators.NewPasswordValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleResetPasswordPost(httpHelper, database, passwordValidator, auditLogger)
		expectRenderedFormError(httpHelper)

		handler.ServeHTTP(httptest.NewRecorder(),
			postResetRequest("123456", "test@example.com", "Str0ngP4ss!", "Different1!"))

		httpHelper.AssertExpectations(t)
	})

	t.Run("password rejected by the policy", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		passwordValidator := mocks_validators.NewPasswordValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		passwordValidator.On("ValidatePassword", mock.Anything, "weak").
			Return(errors.New("password is too weak")).Once()

		handler := HandleResetPasswordPost(httpHelper, database, passwordValidator, auditLogger)
		expectRenderedFormError(httpHelper)

		handler.ServeHTTP(httptest.NewRecorder(),
			postResetRequest("123456", "test@example.com", "weak", "weak"))

		httpHelper.AssertExpectations(t)
		passwordValidator.AssertExpectations(t)
	})

	t.Run("password rejected with a localized error", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		passwordValidator := mocks_validators.NewPasswordValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		passwordValidator.On("ValidatePassword", mock.Anything, "weak").
			Return(i18n.NewLocalizedError(i18n.ErrCodePasswordTooShort, map[string]any{"min": 8})).Once()

		handler := HandleResetPasswordPost(httpHelper, database, passwordValidator, auditLogger)
		expectRenderedFormError(httpHelper)

		handler.ServeHTTP(httptest.NewRecorder(),
			postResetRequest("123456", "test@example.com", "weak", "weak"))

		httpHelper.AssertExpectations(t)
		passwordValidator.AssertExpectations(t)
	})
}

func TestHandleResetPasswordPost_MissingCodeOrEmail(t *testing.T) {
	testCases := []struct {
		name  string
		code  string
		email string
	}{
		{name: "no code", email: "test@example.com"},
		{name: "no email", code: "123456"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			database := mocks_data.NewDatabase(t)
			passwordValidator := mocks_validators.NewPasswordValidator(t)
			auditLogger := mocks_audit.NewAuditLogger(t)

			passwordValidator.On("ValidatePassword", mock.Anything, "Str0ngP4ss!").Return(nil).Once()
			expectAuditFailedCode(auditLogger, "missing_code_or_email")
			expectRenderedCodeInvalid(httpHelper, http.StatusBadRequest)

			handler := HandleResetPasswordPost(httpHelper, database, passwordValidator, auditLogger)
			handler.ServeHTTP(httptest.NewRecorder(),
				postResetRequest(tc.code, tc.email, "Str0ngP4ss!", "Str0ngP4ss!"))

			httpHelper.AssertExpectations(t)
		})
	}
}

// Every rejection below must leave the password untouched. NewDatabase(t) fails
// the test on an unexpected call, so the absence of an UpdateUser expectation is
// the assertion that nothing was written.
func TestHandleResetPasswordPost_CodeRejectionsDoNotChangeThePassword(t *testing.T) {
	validCode := "123456"

	encryptedValidCode, err := encryption.EncryptData(validCode)
	assert.NoError(t, err)

	newUser := func(encrypted []byte, issuedAt sql.NullTime) *models.User {
		return &models.User{
			Id:                          1,
			Email:                       "test@example.com",
			ForgotPasswordCodeEncrypted: encrypted,
			ForgotPasswordCodeIssuedAt:  issuedAt,
		}
	}

	testCases := []struct {
		name string
		user *models.User
		// reqCode is the code supplied on the request.
		reqCode string
		// wantReason is the cause recorded in the audit entry. The response is the
		// same either way, so this is the only place the difference shows.
		wantReason string
	}{
		{
			name:       "code does not match",
			user:       newUser(encryptedValidCode, sql.NullTime{Time: time.Now().UTC(), Valid: true}),
			reqCode:    "999999",
			wantReason: "code_mismatch",
		},
		{
			name: "code is expired",
			// Issued six minutes ago, past the five minute lifetime.
			user:       newUser(encryptedValidCode, sql.NullTime{Time: time.Now().UTC().Add(-6 * time.Minute), Valid: true}),
			reqCode:    validCode,
			wantReason: "code_expired",
		},
		{
			name: "issued timestamp missing",
			// A stored code with no issue time reads as expired, which fails closed.
			user:       newUser(encryptedValidCode, sql.NullTime{Valid: false}),
			reqCode:    validCode,
			wantReason: "code_expired",
		},
		{
			name:       "code is long expired",
			user:       newUser(encryptedValidCode, sql.NullTime{Time: time.Now().UTC().Add(-30 * 24 * time.Hour), Valid: true}),
			reqCode:    validCode,
			wantReason: "code_expired",
		},
		{
			name:       "no code was ever issued",
			user:       newUser(nil, sql.NullTime{Valid: false}),
			reqCode:    validCode,
			wantReason: "no_code_issued",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			database := mocks_data.NewDatabase(t)
			passwordValidator := mocks_validators.NewPasswordValidator(t)
			auditLogger := mocks_audit.NewAuditLogger(t)

			passwordValidator.On("ValidatePassword", mock.Anything, "Str0ngP4ss!").Return(nil).Once()
			database.On("GetUserByEmail", (*sql.Tx)(nil), "test@example.com").Return(tc.user, nil).Once()
			expectAuditFailedCode(auditLogger, tc.wantReason)
			expectRenderedCodeInvalid(httpHelper, http.StatusBadRequest)

			handler := HandleResetPasswordPost(httpHelper, database, passwordValidator, auditLogger)
			handler.ServeHTTP(httptest.NewRecorder(),
				postResetRequest(tc.reqCode, "test@example.com", "Str0ngP4ss!", "Str0ngP4ss!"))

			httpHelper.AssertExpectations(t)
			database.AssertExpectations(t)
			auditLogger.AssertExpectations(t)
		})
	}
}

func TestHandleResetPasswordPost_UserLookupFailures(t *testing.T) {
	t.Run("user does not exist", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		passwordValidator := mocks_validators.NewPasswordValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		passwordValidator.On("ValidatePassword", mock.Anything, "Str0ngP4ss!").Return(nil).Once()
		database.On("GetUserByEmail", (*sql.Tx)(nil), "ghost@example.com").Return(nil, nil).Once()
		expectAuditFailedCode(auditLogger, "unknown_email")
		expectRenderedCodeInvalid(httpHelper, http.StatusBadRequest)

		handler := HandleResetPasswordPost(httpHelper, database, passwordValidator, auditLogger)
		handler.ServeHTTP(httptest.NewRecorder(),
			postResetRequest("123456", "ghost@example.com", "Str0ngP4ss!", "Str0ngP4ss!"))

		httpHelper.AssertExpectations(t)
	})

	t.Run("database error", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		passwordValidator := mocks_validators.NewPasswordValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		passwordValidator.On("ValidatePassword", mock.Anything, "Str0ngP4ss!").Return(nil).Once()
		database.On("GetUserByEmail", (*sql.Tx)(nil), "test@example.com").
			Return(nil, errors.New("database is down")).Once()
		httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Return().Once()

		handler := HandleResetPasswordPost(httpHelper, database, passwordValidator, auditLogger)
		handler.ServeHTTP(httptest.NewRecorder(),
			postResetRequest("123456", "test@example.com", "Str0ngP4ss!", "Str0ngP4ss!"))

		httpHelper.AssertExpectations(t)
	})

	t.Run("stored code cannot be decrypted", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		passwordValidator := mocks_validators.NewPasswordValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		user := &models.User{
			Id:                          1,
			Email:                       "test@example.com",
			ForgotPasswordCodeEncrypted: []byte("not-valid-ciphertext"),
			ForgotPasswordCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC(), Valid: true},
		}

		passwordValidator.On("ValidatePassword", mock.Anything, "Str0ngP4ss!").Return(nil).Once()
		database.On("GetUserByEmail", (*sql.Tx)(nil), "test@example.com").Return(user, nil).Once()
		httpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool {
				return strings.Contains(err.Error(), "unable to decrypt forgot password code")
			}),
		).Return().Once()

		handler := HandleResetPasswordPost(httpHelper, database, passwordValidator, auditLogger)
		handler.ServeHTTP(httptest.NewRecorder(),
			postResetRequest("123456", "test@example.com", "Str0ngP4ss!", "Str0ngP4ss!"))

		httpHelper.AssertExpectations(t)
	})
}

func TestHandleResetPasswordPost_HappyPath(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)
	passwordValidator := mocks_validators.NewPasswordValidator(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	const code = "123456"
	const newPassword = "Str0ngP4ss!"

	encryptedCode, err := encryption.EncryptData(code)
	assert.NoError(t, err)

	user := &models.User{
		Id:                          1,
		Email:                       "test@example.com",
		PasswordHash:                "the-previous-hash",
		ForgotPasswordCodeEncrypted: encryptedCode,
		// Issued four minutes ago, inside the five minute lifetime.
		ForgotPasswordCodeIssuedAt: sql.NullTime{Time: time.Now().UTC().Add(-4 * time.Minute), Valid: true},
	}

	passwordValidator.On("ValidatePassword", mock.Anything, newPassword).Return(nil).Once()
	database.On("GetUserByEmail", (*sql.Tx)(nil), "test@example.com").Return(user, nil).Once()

	var saved *models.User
	database.On("UpdateUser", (*sql.Tx)(nil), mock.Anything).Run(func(args mock.Arguments) {
		saved = args.Get(1).(*models.User)
	}).Return(nil).Once()

	httpHelper.On("RenderTemplate",
		mock.Anything,
		mock.Anything,
		"/layouts/auth_layout.html",
		"/reset_password.html",
		mock.MatchedBy(func(data map[string]interface{}) bool {
			done, ok := data["passwordReset"].(bool)
			return ok && done
		}),
	).Return(nil).Once()

	handler := HandleResetPasswordPost(httpHelper, database, passwordValidator, auditLogger)
	handler.ServeHTTP(httptest.NewRecorder(),
		postResetRequest(code, "test@example.com", newPassword, newPassword))

	httpHelper.AssertExpectations(t)
	database.AssertExpectations(t)

	assert.NotNil(t, saved)
	assert.NotEqual(t, "the-previous-hash", saved.PasswordHash, "the password hash must be replaced")
	assert.True(t, hashutil.VerifyPasswordHash(saved.PasswordHash, newPassword),
		"the stored hash must verify against the new password")

	// The code is single use: both halves are cleared so it cannot be replayed.
	assert.Nil(t, saved.ForgotPasswordCodeEncrypted, "the reset code must be cleared")
	assert.False(t, saved.ForgotPasswordCodeIssuedAt.Valid, "the issued timestamp must be cleared")
}

// The lifetime boundary: just inside is accepted, just outside is refused.
func TestHandleResetPasswordPost_LifetimeBoundary(t *testing.T) {
	const code = "123456"
	const newPassword = "Str0ngP4ss!"

	encryptedCode, err := encryption.EncryptData(code)
	assert.NoError(t, err)

	newUser := func(age time.Duration) *models.User {
		return &models.User{
			Id:                          1,
			Email:                       "test@example.com",
			ForgotPasswordCodeEncrypted: encryptedCode,
			ForgotPasswordCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC().Add(-age), Valid: true},
		}
	}

	t.Run("just inside the lifetime is accepted", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		passwordValidator := mocks_validators.NewPasswordValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		passwordValidator.On("ValidatePassword", mock.Anything, newPassword).Return(nil).Once()
		database.On("GetUserByEmail", (*sql.Tx)(nil), "test@example.com").
			Return(newUser(forgotPasswordCodeLifetime-30*time.Second), nil).Once()
		database.On("UpdateUser", (*sql.Tx)(nil), mock.Anything).Return(nil).Once()
		httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, mock.Anything, mock.Anything,
			mock.Anything).Return(nil).Once()

		handler := HandleResetPasswordPost(httpHelper, database, passwordValidator, auditLogger)
		handler.ServeHTTP(httptest.NewRecorder(),
			postResetRequest(code, "test@example.com", newPassword, newPassword))

		database.AssertExpectations(t)
	})

	t.Run("just outside the lifetime is refused", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		passwordValidator := mocks_validators.NewPasswordValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		passwordValidator.On("ValidatePassword", mock.Anything, newPassword).Return(nil).Once()
		database.On("GetUserByEmail", (*sql.Tx)(nil), "test@example.com").
			Return(newUser(forgotPasswordCodeLifetime+30*time.Second), nil).Once()
		expectAuditFailedCode(auditLogger, "code_expired")
		expectRenderedCodeInvalid(httpHelper, http.StatusBadRequest)

		handler := HandleResetPasswordPost(httpHelper, database, passwordValidator, auditLogger)
		handler.ServeHTTP(httptest.NewRecorder(),
			postResetRequest(code, "test@example.com", newPassword, newPassword))

		httpHelper.AssertExpectations(t)
	})
}

func TestHandleResetPasswordPost_UpdateUserFails(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)
	passwordValidator := mocks_validators.NewPasswordValidator(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	const code = "123456"
	encryptedCode, err := encryption.EncryptData(code)
	assert.NoError(t, err)

	user := &models.User{
		Id:                          1,
		Email:                       "test@example.com",
		ForgotPasswordCodeEncrypted: encryptedCode,
		ForgotPasswordCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}

	passwordValidator.On("ValidatePassword", mock.Anything, "Str0ngP4ss!").Return(nil).Once()
	database.On("GetUserByEmail", (*sql.Tx)(nil), "test@example.com").Return(user, nil).Once()
	database.On("UpdateUser", (*sql.Tx)(nil), mock.Anything).Return(errors.New("update failed")).Once()
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Return().Once()

	handler := HandleResetPasswordPost(httpHelper, database, passwordValidator, auditLogger)
	handler.ServeHTTP(httptest.NewRecorder(),
		postResetRequest(code, "test@example.com", "Str0ngP4ss!", "Str0ngP4ss!"))

	httpHelper.AssertExpectations(t)
}

// isForgotPasswordCodeExpired is the single rule both handlers consult, so it is
// worth pinning directly as well as through them.
func TestIsForgotPasswordCodeExpired(t *testing.T) {
	testCases := []struct {
		name      string
		issuedAt  sql.NullTime
		wantExpir bool
	}{
		{"just issued", sql.NullTime{Time: time.Now().UTC(), Valid: true}, false},
		{"one minute old", sql.NullTime{Time: time.Now().UTC().Add(-time.Minute), Valid: true}, false},
		{"just inside the lifetime", sql.NullTime{Time: time.Now().UTC().Add(-forgotPasswordCodeLifetime + 30*time.Second), Valid: true}, false},
		{"just outside the lifetime", sql.NullTime{Time: time.Now().UTC().Add(-forgotPasswordCodeLifetime - time.Second), Valid: true}, true},
		{"an hour old", sql.NullTime{Time: time.Now().UTC().Add(-time.Hour), Valid: true}, true},
		{"never issued", sql.NullTime{Valid: false}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			user := &models.User{ForgotPasswordCodeIssuedAt: tc.issuedAt}

			assert.Equal(t, tc.wantExpir, isForgotPasswordCodeExpired(user))
		})
	}
}

// =============================================================================
// Response indistinguishability
//
// The reset endpoints must not reveal whether an email address has an account.
// An attacker can trigger POST /forgot-password for a target address (which
// correctly reveals nothing) and then probe /reset-password with a guessed code:
// if a known address answered differently from an unknown one, that difference is
// an account-existence oracle. Previously it was, because an unknown address and
// a user with no pending code both produced a 500 error page while a known
// address with a pending code produced the form.
//
// These tests capture the response for each condition and assert they are the
// same, so the oracle cannot reappear.
// =============================================================================

// captureResetRender records the bind map passed to RenderTemplate, along with
// which template was used.
func captureResetRender(t *testing.T, httpHelper *mocks_handlerhelpers.HttpHelper) *map[string]interface{} {
	t.Helper()
	captured := new(map[string]interface{})
	httpHelper.On("RenderTemplate",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Run(func(args mock.Arguments) {
		*captured = args.Get(4).(map[string]interface{})
	}).Return(nil).Once()
	return captured
}

// comparableBind strips the per-request CSRF token, which necessarily differs
// between requests and so cannot serve as an oracle.
func comparableBind(bind map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	for k, v := range bind {
		if k == "csrfField" {
			continue
		}
		out[k] = v
	}
	return out
}

func TestResetPassword_LinkFailuresAreIndistinguishable(t *testing.T) {
	const requestCode = "123456"

	encryptedOtherCode, err := encryption.EncryptData("999999")
	assert.NoError(t, err)

	// Every scenario below is a condition attributable to the link, across both
	// handlers. All must yield byte-identical responses.
	scenarios := []struct {
		name string
		// handler groups the scenario, because the two handlers deliberately use
		// different statuses: what must match is every branch WITHIN a handler.
		handler    string
		wantStatus interface{} // nil when no _httpStatus is set
		setup      func(t *testing.T) (*map[string]interface{}, func())
	}{
		{
			name:    "GET, unknown email",
			handler: "GET",
			setup: func(t *testing.T) (*map[string]interface{}, func()) {
				httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
				database := mocks_data.NewDatabase(t)
				database.On("GetUserByEmail", (*sql.Tx)(nil), "ghost@example.com").Return(nil, nil).Once()
				bind := captureResetRender(t, httpHelper)
				handler := HandleResetPasswordGet(httpHelper, database)
				req, _ := http.NewRequest("GET", "/reset-password?code="+requestCode+"&email=ghost@example.com", nil)
				return bind, func() { handler.ServeHTTP(httptest.NewRecorder(), req) }
			},
		},
		{
			name:    "GET, known email with no pending code",
			handler: "GET",
			setup: func(t *testing.T) (*map[string]interface{}, func()) {
				httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
				database := mocks_data.NewDatabase(t)
				user := &models.User{Id: 1, Email: "test@example.com"} // no code issued
				database.On("GetUserByEmail", (*sql.Tx)(nil), "test@example.com").Return(user, nil).Once()
				bind := captureResetRender(t, httpHelper)
				handler := HandleResetPasswordGet(httpHelper, database)
				req, _ := http.NewRequest("GET", "/reset-password?code="+requestCode+"&email=test@example.com", nil)
				return bind, func() { handler.ServeHTTP(httptest.NewRecorder(), req) }
			},
		},
		{
			name:    "GET, known email with a wrong code",
			handler: "GET",
			setup: func(t *testing.T) (*map[string]interface{}, func()) {
				httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
				database := mocks_data.NewDatabase(t)
				user := &models.User{
					Id: 1, Email: "test@example.com",
					ForgotPasswordCodeEncrypted: encryptedOtherCode,
					ForgotPasswordCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC(), Valid: true},
				}
				database.On("GetUserByEmail", (*sql.Tx)(nil), "test@example.com").Return(user, nil).Once()
				bind := captureResetRender(t, httpHelper)
				handler := HandleResetPasswordGet(httpHelper, database)
				req, _ := http.NewRequest("GET", "/reset-password?code="+requestCode+"&email=test@example.com", nil)
				return bind, func() { handler.ServeHTTP(httptest.NewRecorder(), req) }
			},
		},
		{
			name:    "GET, known email with an expired code",
			handler: "GET",
			setup: func(t *testing.T) (*map[string]interface{}, func()) {
				httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
				database := mocks_data.NewDatabase(t)
				matching, encErr := encryption.EncryptData(requestCode)
				assert.NoError(t, encErr)
				user := &models.User{
					Id: 1, Email: "test@example.com",
					ForgotPasswordCodeEncrypted: matching,
					ForgotPasswordCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC().Add(-time.Hour), Valid: true},
				}
				database.On("GetUserByEmail", (*sql.Tx)(nil), "test@example.com").Return(user, nil).Once()
				bind := captureResetRender(t, httpHelper)
				handler := HandleResetPasswordGet(httpHelper, database)
				req, _ := http.NewRequest("GET", "/reset-password?code="+requestCode+"&email=test@example.com", nil)
				return bind, func() { handler.ServeHTTP(httptest.NewRecorder(), req) }
			},
		},
		{
			name:       "POST, unknown email",
			handler:    "POST",
			wantStatus: http.StatusBadRequest,
			setup: func(t *testing.T) (*map[string]interface{}, func()) {
				httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
				database := mocks_data.NewDatabase(t)
				passwordValidator := mocks_validators.NewPasswordValidator(t)
				auditLogger := mocks_audit.NewAuditLogger(t)
				passwordValidator.On("ValidatePassword", mock.Anything, "Str0ngP4ss!").Return(nil).Once()
				database.On("GetUserByEmail", (*sql.Tx)(nil), "ghost@example.com").Return(nil, nil).Once()
				expectAuditFailedCode(auditLogger, "unknown_email")
				bind := captureResetRender(t, httpHelper)
				handler := HandleResetPasswordPost(httpHelper, database, passwordValidator, auditLogger)
				req := postResetRequest(requestCode, "ghost@example.com", "Str0ngP4ss!", "Str0ngP4ss!")
				return bind, func() { handler.ServeHTTP(httptest.NewRecorder(), req) }
			},
		},
		{
			name:       "POST, known email with a wrong code",
			handler:    "POST",
			wantStatus: http.StatusBadRequest,
			setup: func(t *testing.T) (*map[string]interface{}, func()) {
				httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
				database := mocks_data.NewDatabase(t)
				passwordValidator := mocks_validators.NewPasswordValidator(t)
				auditLogger := mocks_audit.NewAuditLogger(t)
				user := &models.User{
					Id: 1, Email: "test@example.com",
					ForgotPasswordCodeEncrypted: encryptedOtherCode,
					ForgotPasswordCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC(), Valid: true},
				}
				passwordValidator.On("ValidatePassword", mock.Anything, "Str0ngP4ss!").Return(nil).Once()
				database.On("GetUserByEmail", (*sql.Tx)(nil), "test@example.com").Return(user, nil).Once()
				expectAuditFailedCode(auditLogger, "code_mismatch")
				bind := captureResetRender(t, httpHelper)
				handler := HandleResetPasswordPost(httpHelper, database, passwordValidator, auditLogger)
				req := postResetRequest(requestCode, "test@example.com", "Str0ngP4ss!", "Str0ngP4ss!")
				return bind, func() { handler.ServeHTTP(httptest.NewRecorder(), req) }
			},
		},
	}

	reference := map[string]map[string]interface{}{}
	referenceName := map[string]string{}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			bind, run := sc.setup(t)
			run()

			got := comparableBind(*bind)
			assert.Equal(t, true, got["codeInvalidOrExpired"])
			assert.Equal(t, sc.wantStatus, got["_httpStatus"])

			if _, seen := reference[sc.handler]; !seen {
				reference[sc.handler], referenceName[sc.handler] = got, sc.name
				return
			}
			assert.Equal(t, reference[sc.handler], got,
				"%q must be indistinguishable from %q, otherwise it reveals whether the address has an account",
				sc.name, referenceName[sc.handler])
		})
	}
}

// A genuine server fault must stay a 500 with its stack trace, so real problems
// keep alerting instead of being hidden behind the friendly page.
func TestResetPassword_GenuineFaultsStayInternalServerErrors(t *testing.T) {
	t.Run("GET, stored code will not decrypt", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)

		user := &models.User{
			Id: 1, Email: "test@example.com",
			ForgotPasswordCodeEncrypted: []byte("not-valid-ciphertext"),
			ForgotPasswordCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC(), Valid: true},
		}
		database.On("GetUserByEmail", (*sql.Tx)(nil), "test@example.com").Return(user, nil).Once()
		httpHelper.On("InternalServerError", mock.Anything, mock.Anything,
			mock.MatchedBy(func(err error) bool {
				return strings.Contains(err.Error(), "unable to decrypt forgot password code")
			}),
		).Return().Once()

		handler := HandleResetPasswordGet(httpHelper, database)
		req, _ := http.NewRequest("GET", "/reset-password?code=123456&email=test@example.com", nil)
		handler.ServeHTTP(httptest.NewRecorder(), req)

		httpHelper.AssertExpectations(t)
	})

	t.Run("GET, database failure", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)

		database.On("GetUserByEmail", (*sql.Tx)(nil), "test@example.com").
			Return(nil, errors.New("database is down")).Once()
		httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Return().Once()

		handler := HandleResetPasswordGet(httpHelper, database)
		req, _ := http.NewRequest("GET", "/reset-password?code=123456&email=test@example.com", nil)
		handler.ServeHTTP(httptest.NewRecorder(), req)

		httpHelper.AssertExpectations(t)
	})
}

// If rendering the invalid-or-expired page itself fails, that is a real fault and
// must surface as a 500 rather than a blank response.
func TestRenderResetPasswordCodeInvalid_RenderFailureFallsBackToInternalServerError(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)

	database.On("GetUserByEmail", (*sql.Tx)(nil), "ghost@example.com").Return(nil, nil).Once()
	httpHelper.On("RenderTemplate",
		mock.Anything, mock.Anything,
		"/layouts/auth_layout.html", "/reset_password.html", mock.Anything,
	).Return(errors.New("template blew up")).Once()
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything,
		mock.MatchedBy(func(err error) bool { return err.Error() == "template blew up" }),
	).Return().Once()

	handler := HandleResetPasswordGet(httpHelper, database)
	req, _ := http.NewRequest("GET", "/reset-password?code=123456&email=ghost@example.com", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	httpHelper.AssertExpectations(t)
}

// forgotPasswordCodeMatches is the single comparison both handlers use, so it is
// pinned directly as well as through them. The point of the constant-time
// comparison is not observable from the outside, so what these cases guard is
// that the matching semantics stayed correct when it was introduced.
func TestForgotPasswordCodeMatches(t *testing.T) {
	testCases := []struct {
		name     string
		stored   string
		supplied string
		want     bool
	}{
		{"identical codes match", "abc123", "abc123", true},
		{"long identical codes match", strings.Repeat("a1B2", 8), strings.Repeat("a1B2", 8), true},
		{"different codes do not match", "abc123", "abc124", false},
		{"differing only in the last byte", "abc123", "abc12X", false},
		{"differing only in the first byte", "abc123", "Xbc123", false},
		{"a prefix does not match", "abc123", "abc", false},
		{"a longer supplied code does not match", "abc123", "abc1234", false},
		{"case matters", "abc123", "ABC123", false},
		{"empty supplied code does not match a stored one", "abc123", "", false},
		{"empty stored code does not match a supplied one", "", "abc123", false},
		{"two empty strings match", "", "", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, forgotPasswordCodeMatches(tc.stored, tc.supplied))
		})
	}
}
