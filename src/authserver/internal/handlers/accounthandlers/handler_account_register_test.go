package accounthandlers

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_accounthandlers "github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	mocks_handlers "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/usercreation"

	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/i18n"

	"github.com/leodip/goiabada/core/logging/logtest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// assertSelfRegistrationDisabledLogged holds a refusal while self-registration is off to its one
// record: a refused request is Warn, not the error-level record the 500 page used to write
// (#425 decision 5).
func assertSelfRegistrationDisabledLogged(t *testing.T, logs *logtest.SlogCapture) {
	t.Helper()

	records := logs.Records()
	require.Len(t, records, 1, "a refusal writes exactly one record: %s", logs.Text())
	assert.Equal(t, slog.LevelWarn, records[0].Level)
	assert.Equal(t, "self-registration request refused because self-registration is disabled", records[0].Message)
}

func TestHandleAccountRegisterGet(t *testing.T) {
	t.Run("Self registration enabled", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		handler := HandleAccountRegisterGet(pageRenderer)

		req, _ := http.NewRequest("GET", "/account/register", nil)
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			SelfRegistrationEnabled: true,
		}
		ctx := req.Context()
		ctx = reqctx.WithSettings(ctx, settings)
		req = req.WithContext(ctx)

		pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		pageRenderer.AssertExpectations(t)
	})

	t.Run("Self registration disabled", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		handler := HandleAccountRegisterGet(pageRenderer)

		req, _ := http.NewRequest("GET", "/account/register", nil)
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			SelfRegistrationEnabled: false,
		}
		ctx := req.Context()
		ctx = reqctx.WithSettings(ctx, settings)
		req = req.WithContext(ctx)

		pageRenderer.On("NotFound", rr, req).Return().Once()
		logs := logtest.CaptureSlog(t)

		handler.ServeHTTP(rr, req)

		assertSelfRegistrationDisabledLogged(t, logs)
		pageRenderer.AssertExpectations(t)
	})
}

func TestHandleAccountRegisterPost(t *testing.T) {
	t.Run("No email and email is required", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_accounthandlers.NewUserCreator(t)
		emailValidator := mocks_accounthandlers.NewEmailValidator(t)
		passwordValidator := mocks_accounthandlers.NewPasswordValidator(t)
		emailSender := mocks_accounthandlers.NewEmailSender(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleAccountRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		req, _ := http.NewRequest("POST", "/register", nil)
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			SelfRegistrationEnabled: true,
		}
		ctx := req.Context()
		ctx = reqctx.WithSettings(ctx, settings)
		req = req.WithContext(ctx)

		pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		pageRenderer.AssertCalled(t, "RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Email is required."
		}))
	})

	t.Run("Invalid email given", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_accounthandlers.NewUserCreator(t)
		emailValidator := mocks_accounthandlers.NewEmailValidator(t)
		passwordValidator := mocks_accounthandlers.NewPasswordValidator(t)
		emailSender := mocks_accounthandlers.NewEmailSender(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleAccountRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		form := url.Values{}
		form.Add("email", "invalid-email")
		req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			SelfRegistrationEnabled: true,
		}
		ctx := req.Context()
		ctx = reqctx.WithSettings(ctx, settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "invalid-email").Return(customerrors.NewErrorDetail("", "Please enter a valid email address."))
		pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		pageRenderer.AssertCalled(t, "RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Please enter a valid email address."
		}))
	})

	t.Run("Email is already registered", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_accounthandlers.NewUserCreator(t)
		emailValidator := mocks_accounthandlers.NewEmailValidator(t)
		passwordValidator := mocks_accounthandlers.NewPasswordValidator(t)
		emailSender := mocks_accounthandlers.NewEmailSender(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleAccountRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		form := url.Values{}
		form.Add("email", "existing@example.com")
		req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			SelfRegistrationEnabled: true,
		}
		ctx := req.Context()
		ctx = reqctx.WithSettings(ctx, settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "existing@example.com").Return(nil)
		database.On("GetUserByEmail", mock.Anything, mock.Anything, "existing@example.com").Return(&models.User{}, nil)
		pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		pageRenderer.AssertCalled(t, "RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Apologies, but this email address is already registered."
		}))
	})

	t.Run("Pre registration already exists", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_accounthandlers.NewUserCreator(t)
		emailValidator := mocks_accounthandlers.NewEmailValidator(t)
		passwordValidator := mocks_accounthandlers.NewPasswordValidator(t)
		emailSender := mocks_accounthandlers.NewEmailSender(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleAccountRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		form := url.Values{}
		form.Add("email", "preregistered@example.com")
		req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			SelfRegistrationEnabled: true,
		}
		ctx := req.Context()
		ctx = reqctx.WithSettings(ctx, settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "preregistered@example.com").Return(nil)
		database.On("GetUserByEmail", mock.Anything, mock.Anything, "preregistered@example.com").Return(nil, nil)
		database.On("GetPreRegistrationByEmail", mock.Anything, mock.Anything, "preregistered@example.com").Return(&models.PreRegistration{}, nil)
		pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		pageRenderer.AssertCalled(t, "RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Apologies, but this email address is already registered."
		}))
	})

	t.Run("Password not given", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_accounthandlers.NewUserCreator(t)
		emailValidator := mocks_accounthandlers.NewEmailValidator(t)
		passwordValidator := mocks_accounthandlers.NewPasswordValidator(t)
		emailSender := mocks_accounthandlers.NewEmailSender(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleAccountRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		form := url.Values{}
		form.Add("email", "valid@example.com")
		req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			SelfRegistrationEnabled: true,
		}
		ctx := req.Context()
		ctx = reqctx.WithSettings(ctx, settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "valid@example.com").Return(nil)
		database.On("GetUserByEmail", mock.Anything, mock.Anything, "valid@example.com").Return(nil, nil)
		database.On("GetPreRegistrationByEmail", mock.Anything, mock.Anything, "valid@example.com").Return(nil, nil)
		pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		pageRenderer.AssertCalled(t, "RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Password is required."
		}))
	})

	// The same answer "Password not given" gets, for a submission that does carry a password
	// and a matching confirmation, in the request target rather than the body. r.FormValue
	// merges the query behind the body, so it would register the account on a password taken
	// from a URL, where it reaches the browser's history, the Referer of anything the page
	// loads, and the access log of every proxy in front of the deployment. passwordValidator
	// and userCreator are given no expectations, so reaching either fails the test on an
	// unexpected call (#202).
	t.Run("Password in the query alone", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_accounthandlers.NewUserCreator(t)
		emailValidator := mocks_accounthandlers.NewEmailValidator(t)
		passwordValidator := mocks_accounthandlers.NewPasswordValidator(t)
		emailSender := mocks_accounthandlers.NewEmailSender(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleAccountRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		// The email stays in the body, so the handler reaches the credential read the same
		// way the neighbouring case does.
		form := url.Values{}
		form.Add("email", "valid@example.com")
		target := "/register?" + url.Values{
			"password":             {"Str0ngP4ss!"},
			"passwordConfirmation": {"Str0ngP4ss!"},
		}.Encode()
		req, _ := http.NewRequest("POST", target, strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			SelfRegistrationEnabled: true,
		}
		ctx := req.Context()
		ctx = reqctx.WithSettings(ctx, settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "valid@example.com").Return(nil)
		database.On("GetUserByEmail", mock.Anything, mock.Anything, "valid@example.com").Return(nil, nil)
		database.On("GetPreRegistrationByEmail", mock.Anything, mock.Anything, "valid@example.com").Return(nil, nil)
		pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		pageRenderer.AssertCalled(t, "RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Password is required."
		}))
		passwordValidator.AssertNotCalled(t, "ValidatePassword", mock.Anything, mock.Anything)
		userCreator.AssertExpectations(t)
		emailSender.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	// The confirmation alone in the query, matching the password in the body. This is the
	// only input that reaches the confirmation read: the case above returns at the password
	// check, so it says nothing about how the second field is read. Body-only the
	// confirmation is absent and the handler asks for it; merged, the two would agree and
	// the account would be created. passwordValidator and userCreator are given no
	// expectations, so reaching either fails the test on an unexpected call (#202).
	t.Run("Password confirmation in the query alone", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_accounthandlers.NewUserCreator(t)
		emailValidator := mocks_accounthandlers.NewEmailValidator(t)
		passwordValidator := mocks_accounthandlers.NewPasswordValidator(t)
		emailSender := mocks_accounthandlers.NewEmailSender(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleAccountRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		form := url.Values{}
		form.Add("email", "valid@example.com")
		form.Add("password", "Str0ngP4ss!")
		target := "/register?" + url.Values{
			"passwordConfirmation": {"Str0ngP4ss!"},
		}.Encode()
		req, _ := http.NewRequest("POST", target, strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			SelfRegistrationEnabled: true,
		}
		ctx := req.Context()
		ctx = reqctx.WithSettings(ctx, settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "valid@example.com").Return(nil)
		database.On("GetUserByEmail", mock.Anything, mock.Anything, "valid@example.com").Return(nil, nil)
		database.On("GetPreRegistrationByEmail", mock.Anything, mock.Anything, "valid@example.com").Return(nil, nil)
		pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		pageRenderer.AssertCalled(t, "RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Password confirmation is required."
		}))
		passwordValidator.AssertNotCalled(t, "ValidatePassword", mock.Anything, mock.Anything)
		userCreator.AssertExpectations(t)
		emailSender.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Password confirmation is required", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_accounthandlers.NewUserCreator(t)
		emailValidator := mocks_accounthandlers.NewEmailValidator(t)
		passwordValidator := mocks_accounthandlers.NewPasswordValidator(t)
		emailSender := mocks_accounthandlers.NewEmailSender(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleAccountRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		form := url.Values{}
		form.Add("email", "valid@example.com")
		form.Add("password", "password123")
		req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			SelfRegistrationEnabled: true,
		}
		ctx := req.Context()
		ctx = reqctx.WithSettings(ctx, settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "valid@example.com").Return(nil)
		database.On("GetUserByEmail", mock.Anything, mock.Anything, "valid@example.com").Return(nil, nil)
		database.On("GetPreRegistrationByEmail", mock.Anything, mock.Anything, "valid@example.com").Return(nil, nil)
		pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		pageRenderer.AssertCalled(t, "RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Password confirmation is required."
		}))
	})

	t.Run("Password confirmation does not match", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_accounthandlers.NewUserCreator(t)
		emailValidator := mocks_accounthandlers.NewEmailValidator(t)
		passwordValidator := mocks_accounthandlers.NewPasswordValidator(t)
		emailSender := mocks_accounthandlers.NewEmailSender(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleAccountRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		form := url.Values{}
		form.Add("email", "valid@example.com")
		form.Add("password", "password123")
		form.Add("passwordConfirmation", "password456")
		req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			SelfRegistrationEnabled: true,
		}
		ctx := req.Context()
		ctx = reqctx.WithSettings(ctx, settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "valid@example.com").Return(nil)
		database.On("GetUserByEmail", mock.Anything, mock.Anything, "valid@example.com").Return(nil, nil)
		database.On("GetPreRegistrationByEmail", mock.Anything, mock.Anything, "valid@example.com").Return(nil, nil)
		pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		pageRenderer.AssertCalled(t, "RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "The password confirmation does not match the password."
		}))
	})

	t.Run("ValidatePassword fails", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_accounthandlers.NewUserCreator(t)
		emailValidator := mocks_accounthandlers.NewEmailValidator(t)
		passwordValidator := mocks_accounthandlers.NewPasswordValidator(t)
		emailSender := mocks_accounthandlers.NewEmailSender(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleAccountRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		form := url.Values{}
		form.Add("email", "valid@example.com")
		form.Add("password", "short")
		form.Add("passwordConfirmation", "short")
		req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			SelfRegistrationEnabled: true,
		}
		ctx := req.Context()
		ctx = reqctx.WithSettings(ctx, settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "valid@example.com").Return(nil)
		database.On("GetUserByEmail", mock.Anything, mock.Anything, "valid@example.com").Return(nil, nil)
		database.On("GetPreRegistrationByEmail", mock.Anything, mock.Anything, "valid@example.com").Return(nil, nil)
		passwordValidator.On("ValidatePassword", mock.Anything, "short").Return(customerrors.NewErrorDetail("", "The minimum length for the password is 8 characters"))
		pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		pageRenderer.AssertCalled(t, "RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "The minimum length for the password is 8 characters"
		}))
	})

	t.Run("Self registration is disabled", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_accounthandlers.NewUserCreator(t)
		emailValidator := mocks_accounthandlers.NewEmailValidator(t)
		passwordValidator := mocks_accounthandlers.NewPasswordValidator(t)
		emailSender := mocks_accounthandlers.NewEmailSender(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleAccountRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		form := url.Values{}
		form.Add("email", "valid@example.com")
		form.Add("password", "password123")
		form.Add("passwordConfirmation", "password123")
		req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			SelfRegistrationEnabled: false,
		}
		ctx := req.Context()
		ctx = reqctx.WithSettings(ctx, settings)
		req = req.WithContext(ctx)

		// The not-found page, RFC 9110 section 15.5.5, rather than the 500 page it used to be.
		pageRenderer.On("NotFound", rr, req).Run(func(args mock.Arguments) {
			w := args.Get(0).(http.ResponseWriter)
			w.WriteHeader(http.StatusNotFound)
		}).Return().Once()
		logs := logtest.CaptureSlog(t)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
		assertSelfRegistrationDisabledLogged(t, logs)
		pageRenderer.AssertExpectations(t)

		// Ensure that no other mock methods were called
		emailValidator.AssertNotCalled(t, "ValidateEmailAddress", mock.Anything)
		database.AssertNotCalled(t, "GetUserByEmail", mock.Anything, mock.Anything, mock.Anything)
		database.AssertNotCalled(t, "GetPreRegistrationByEmail", mock.Anything, mock.Anything, mock.Anything)
		passwordValidator.AssertNotCalled(t, "ValidatePassword", mock.Anything, mock.Anything)
	})

	t.Run("SMTP enabled and requires email verification", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_accounthandlers.NewUserCreator(t)
		emailValidator := mocks_accounthandlers.NewEmailValidator(t)
		passwordValidator := mocks_accounthandlers.NewPasswordValidator(t)
		emailSender := mocks_accounthandlers.NewEmailSender(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleAccountRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		form := url.Values{}
		form.Add("email", "test@example.com")
		form.Add("password", "password123")
		form.Add("passwordConfirmation", "password123")
		req, err := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		assert.NoError(t, err)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			SelfRegistrationEnabled: true,
			SMTPEnabled:             true,
			SMTPHost:                "smtp.example.com",
			SelfRegistrationRequiresEmailVerification: true,
		}
		ctx := reqctx.WithSettings(req.Context(), settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "test@example.com").Return(nil)
		database.On("GetUserByEmail", mock.Anything, mock.Anything, "test@example.com").Return(nil, nil)
		database.On("GetPreRegistrationByEmail", mock.Anything, mock.Anything, "test@example.com").Return(nil, nil)
		passwordValidator.On("ValidatePassword", mock.Anything, "password123").Return(nil)

		var capturedVerificationCode string
		database.On("CreatePreRegistration", mock.Anything, mock.Anything, mock.AnythingOfType("*models.PreRegistration")).Return(nil).Run(func(args mock.Arguments) {
			preReg := args.Get(2).(*models.PreRegistration)
			assert.Equal(t, "test@example.com", preReg.Email)
			assert.NotEmpty(t, preReg.PasswordHash)
			assert.NotEmpty(t, preReg.VerificationCodeEncrypted)
			assert.True(t, preReg.VerificationCodeIssuedAt.Valid)

			// Capture the verification code for later use
			decryptedCode, err := testDataCipher.Decrypt(preReg.VerificationCodeEncrypted)
			assert.NoError(t, err)
			capturedVerificationCode = decryptedCode

			// The hash stored beside the encrypted code is the only thing that will find
			// this row when the link comes back, since the link carries the code and no
			// address (#112). Derived from the code the handler actually issued rather
			// than from a value the test chose: a hash of anything else would leave the
			// registration unactivatable.
			expectedHash := hashutil.HashString(decryptedCode)
			assert.Equal(t, expectedHash, preReg.VerificationCodeHash,
				"the stored hash must be the hash of the code that was issued")
		})

		auditLogger.On("Log", mock.Anything, audit.AuditCreatedPreRegistration, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["email"] == "test@example.com"
		})).Return()

		pageRenderer.On("RenderTemplateToBuffer", mock.Anything, "/layouts/email_layout.html", "/emails/email_register_activate.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			link, ok := data["link"].(string)
			if !ok {
				return false
			}
			// The code and nothing else. The address used to be in here, which is what
			// #112 reports: form-urlencoded query parsing turns a '+' into a space, so a
			// '+' address could never be activated. Asserted at seam 1 as well, which
			// owns the shape; this is the build site agreeing with it.
			expectedLink := fmt.Sprintf("%s/account/activate?code=%s", testBaseURL, capturedVerificationCode)
			return link == expectedLink
		})).Return(bytes.NewBuffer([]byte("email content")), nil)

		emailSender.On("SendEmail", mock.Anything, emaildelivery.SMTPConfig{Host: "smtp.example.com"},
			mock.MatchedBy(func(input *emaildelivery.SendEmailInput) bool {
				return input.To == "test@example.com" && input.Subject == "Activate your account"
			})).Return(nil)

		pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register_activation.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		database.AssertExpectations(t)
		emailValidator.AssertExpectations(t)
		passwordValidator.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		emailSender.AssertExpectations(t)
		pageRenderer.AssertExpectations(t)
	})

	t.Run("Direct registration without email verification", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_accounthandlers.NewUserCreator(t)
		emailValidator := mocks_accounthandlers.NewEmailValidator(t)
		passwordValidator := mocks_accounthandlers.NewPasswordValidator(t)
		emailSender := mocks_accounthandlers.NewEmailSender(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleAccountRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		form := url.Values{}
		form.Add("email", "test@example.com")
		form.Add("password", "password123")
		form.Add("passwordConfirmation", "password123")
		req, err := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		assert.NoError(t, err)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			SelfRegistrationEnabled: true,
			SMTPEnabled:             false, // SMTP is disabled
		}
		ctx := reqctx.WithSettings(req.Context(), settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "test@example.com").Return(nil)
		database.On("GetUserByEmail", mock.Anything, mock.Anything, "test@example.com").Return(nil, nil)
		database.On("GetPreRegistrationByEmail", mock.Anything, mock.Anything, "test@example.com").Return(nil, nil)
		passwordValidator.On("ValidatePassword", mock.Anything, "password123").Return(nil)

		userCreator.On("CreateUser", mock.Anything, mock.MatchedBy(func(input *usercreation.CreateUserInput) bool {
			return input.Email == "test@example.com" && !input.EmailVerified
		})).Return(&models.User{}, nil)

		auditLogger.On("Log", mock.Anything, audit.AuditCreatedUser, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["email"] == "test@example.com"
		})).Return()

		pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register_success.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			adminConsoleBaseUrl, ok := data["adminConsoleBaseUrl"].(string)
			return ok && adminConsoleBaseUrl == testAdminConsoleBaseURL
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		database.AssertExpectations(t)
		emailValidator.AssertExpectations(t)
		passwordValidator.AssertExpectations(t)
		userCreator.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		pageRenderer.AssertExpectations(t)

		// Ensure that these methods were not called
		emailSender.AssertNotCalled(t, "SendEmail", mock.Anything, mock.Anything, mock.Anything)
		database.AssertNotCalled(t, "CreatePreRegistration", mock.Anything, mock.Anything, mock.Anything)
		pageRenderer.AssertNotCalled(t, "RenderTemplateToBuffer",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("SMTP enabled but does not require email verification", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_accounthandlers.NewUserCreator(t)
		emailValidator := mocks_accounthandlers.NewEmailValidator(t)
		passwordValidator := mocks_accounthandlers.NewPasswordValidator(t)
		emailSender := mocks_accounthandlers.NewEmailSender(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleAccountRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		form := url.Values{}
		form.Add("email", "test@example.com")
		form.Add("password", "password123")
		form.Add("passwordConfirmation", "password123")
		req, err := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		assert.NoError(t, err)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			SelfRegistrationEnabled: true,
			SMTPEnabled:             true,
			SMTPHost:                "smtp.example.com",
			SMTPPort:                2525,
			PasswordPolicy:          models.PasswordPolicyHigh,
			SelfRegistrationRequiresEmailVerification: false,
		}
		ctx := reqctx.WithSettings(req.Context(), settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "test@example.com").Return(nil)
		database.On("GetUserByEmail", mock.Anything, mock.Anything, "test@example.com").Return(nil, nil)
		database.On("GetPreRegistrationByEmail", mock.Anything, mock.Anything, "test@example.com").Return(nil, nil)
		// The policy is the request's settings', passed by the handler (#433).
		passwordValidator.On("ValidatePassword", models.PasswordPolicyHigh, "password123").Return(nil)

		userCreator.On("CreateUser", mock.Anything, mock.MatchedBy(func(input *usercreation.CreateUserInput) bool {
			return input.Email == "test@example.com" && !input.EmailVerified
		})).Return(&models.User{}, nil)

		auditLogger.On("Log", mock.Anything, audit.AuditCreatedUser, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["email"] == "test@example.com"
		})).Return()

		pageRenderer.On("RenderTemplateToBuffer", mock.Anything, "/layouts/email_layout.html", "/emails/email_register_confirmation.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			link, ok := data["link"].(string)
			return ok && link == testAdminConsoleBaseURL+"/account/profile"
		})).Return(bytes.NewBuffer([]byte("email content")), nil)

		emailSender.On("SendEmail", mock.Anything, emaildelivery.SMTPConfig{Host: "smtp.example.com", Port: 2525},
			mock.MatchedBy(func(input *emaildelivery.SendEmailInput) bool {
				return input.To == "test@example.com" && input.Subject == "Welcome!"
			})).Return(nil)

		pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register_success.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			adminConsoleBaseUrl, ok := data["adminConsoleBaseUrl"].(string)
			return ok && adminConsoleBaseUrl == testAdminConsoleBaseURL
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		database.AssertExpectations(t)
		emailValidator.AssertExpectations(t)
		passwordValidator.AssertExpectations(t)
		userCreator.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		emailSender.AssertExpectations(t)
		pageRenderer.AssertExpectations(t)

		// Ensure no pre-registration is created on the no-verification path
		database.AssertNotCalled(t, "CreatePreRegistration", mock.Anything, mock.Anything, mock.Anything)
	})
}

// Decision 6: a wire-meaning error is matched with errors.As, never a bare assertion. A type
// switch is a bare assertion in different syntax -- both read the dynamic type, and both fall to
// the default arm on a wrapped value. This handler used one, so a wrap anywhere between the
// validator and here turned "please enter a valid email address" into a 500 page with the
// administrator's reason in the log. Nothing wraps it today, which is exactly why a test has to
// hold it: the old shape was correct only while that stayed true.
func TestHandleAccountRegisterPost_AWrappedRefusalStillRedrawsTheForm(t *testing.T) {
	testCases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "a wrapped ErrorDetail",
			err: errs.Wrap(customerrors.NewErrorDetail("", "Please enter a valid email address."),
				"validating the email address"),
			want: "Please enter a valid email address.",
		},
		{
			name: "a wrapped LocalizedError",
			err: errs.Wrap(i18n.NewLocalizedError(i18n.ErrCodeHandlerEmailRequired, nil),
				"validating the email address"),
			want: i18n.NewLocalizedError(i18n.ErrCodeHandlerEmailRequired, nil).Localize(context.Background()),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			pageRenderer := mocks_handlers.NewPageRenderer(t)
			database := mocks_data.NewDatabase(t)
			userCreator := mocks_accounthandlers.NewUserCreator(t)
			emailValidator := mocks_accounthandlers.NewEmailValidator(t)
			passwordValidator := mocks_accounthandlers.NewPasswordValidator(t)
			emailSender := mocks_accounthandlers.NewEmailSender(t)
			auditLogger := mocks_handlers.NewAuditLogger(t)

			handler := HandleAccountRegisterPost(pageRenderer, database, userCreator, emailValidator,
				passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

			form := url.Values{}
			form.Add("email", "invalid-email")
			req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()

			ctx := reqctx.WithSettings(req.Context(), &models.Settings{SelfRegistrationEnabled: true})
			req = req.WithContext(ctx)

			emailValidator.On("ValidateEmailAddress", "invalid-email").Return(testCase.err)
			pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html",
				"/account_register.html", mock.Anything).Return(nil)

			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code)
			pageRenderer.AssertCalled(t, "RenderTemplate", rr, req, "/layouts/auth_layout.html",
				"/account_register.html", mock.MatchedBy(func(data map[string]interface{}) bool {
					return data["error"] == testCase.want
				}))
		})
	}
}
