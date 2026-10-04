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
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/usercreation"

	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/oauth"

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

// TestHandleRegisterGet_TheFormAsksForThePasswordOnlyWithoutVerification pins what the page is
// bound with: with verification required (SMTP on and the setting on) the form takes the address
// alone and the password is chosen from the emailed link; in every other mode it is unchanged
// (#207 decision 1).
func TestHandleRegisterGet_TheFormAsksForThePasswordOnlyWithoutVerification(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		smtpEnabled              bool
		requiresVerification     bool
		wantRequiresVerification bool
	}{
		{"SMTP on and verification required", true, true, true},
		{"SMTP on and verification not required", true, false, false},
		{"SMTP off and verification required", false, true, false},
		{"SMTP off and verification not required", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			req := httptest.NewRequest("GET", "/account/register", nil)
			req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{
				SelfRegistrationEnabled: true,
				SMTPEnabled:             tc.smtpEnabled,
				SelfRegistrationRequiresEmailVerification: tc.requiresVerification,
			}))

			var rendered map[string]interface{}
			pageRenderer.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).
				Run(func(args mock.Arguments) { rendered = args.Get(4).(map[string]interface{}) }).
				Return(nil).Once()

			HandleRegisterGet(pageRenderer).ServeHTTP(httptest.NewRecorder(), req)

			require.NotNil(t, rendered)
			assert.Equal(t, tc.wantRequiresVerification, rendered["requiresEmailVerification"])
		})
	}
}

// A redrawn form keeps the shape the mode gives it: with verification, still the address alone.
func TestHandleRegisterPost_TheRedrawnFormKeepsItsMode(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		settings                 *record.Settings
		wantRequiresVerification bool
	}{
		{"with verification", &record.Settings{SelfRegistrationEnabled: true, SMTPEnabled: true,
			SelfRegistrationRequiresEmailVerification: true}, true},
		{"without verification", &record.Settings{SelfRegistrationEnabled: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			database := datamocks.NewDatabase(t)
			userCreator := accounthandlersmocks.NewUserCreator(t)
			emailValidator := accounthandlersmocks.NewEmailValidator(t)
			passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
			emailSender := accounthandlersmocks.NewEmailSender(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator,
				passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

			req := httptest.NewRequest("POST", "/account/register", strings.NewReader(url.Values{"email": {""}}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req = req.WithContext(reqctx.WithSettings(req.Context(), tc.settings))

			var rendered map[string]interface{}
			pageRenderer.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).
				Run(func(args mock.Arguments) { rendered = args.Get(4).(map[string]interface{}) }).
				Return(nil).Once()

			handler.ServeHTTP(httptest.NewRecorder(), req)

			require.NotNil(t, rendered)
			assert.Equal(t, "Email is required.", rendered["error"])
			assert.Equal(t, tc.wantRequiresVerification, rendered["requiresEmailVerification"])
		})
	}
}

func TestHandleRegisterGet(t *testing.T) {
	t.Run("Self registration enabled", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		handler := HandleRegisterGet(pageRenderer)

		req, _ := http.NewRequest("GET", "/account/register", nil)
		rr := httptest.NewRecorder()

		settings := &record.Settings{
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
		pageRenderer := handlersmocks.NewPageRenderer(t)
		handler := HandleRegisterGet(pageRenderer)

		req, _ := http.NewRequest("GET", "/account/register", nil)
		rr := httptest.NewRecorder()

		settings := &record.Settings{
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

func TestHandleRegisterPost(t *testing.T) {
	t.Run("No email and email is required", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		userCreator := accounthandlersmocks.NewUserCreator(t)
		emailValidator := accounthandlersmocks.NewEmailValidator(t)
		passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
		emailSender := accounthandlersmocks.NewEmailSender(t)
		auditLogger := handlersmocks.NewAuditLogger(t)

		handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		req, _ := http.NewRequest("POST", "/register", nil)
		rr := httptest.NewRecorder()

		settings := &record.Settings{
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
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		userCreator := accounthandlersmocks.NewUserCreator(t)
		emailValidator := accounthandlersmocks.NewEmailValidator(t)
		passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
		emailSender := accounthandlersmocks.NewEmailSender(t)
		auditLogger := handlersmocks.NewAuditLogger(t)

		handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		form := url.Values{}
		form.Add("email", "invalid-email")
		req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &record.Settings{
			SelfRegistrationEnabled: true,
		}
		ctx := req.Context()
		ctx = reqctx.WithSettings(ctx, settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "invalid-email").Return(oauth.NewErrorDetail("", "Please enter a valid email address."))
		pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		pageRenderer.AssertCalled(t, "RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Please enter a valid email address."
		}))
	})

	t.Run("Email is already registered", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		userCreator := accounthandlersmocks.NewUserCreator(t)
		emailValidator := accounthandlersmocks.NewEmailValidator(t)
		passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
		emailSender := accounthandlersmocks.NewEmailSender(t)
		auditLogger := handlersmocks.NewAuditLogger(t)

		handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		form := url.Values{}
		form.Add("email", "existing@example.com")
		req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &record.Settings{
			SelfRegistrationEnabled: true,
		}
		ctx := req.Context()
		ctx = reqctx.WithSettings(ctx, settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "existing@example.com").Return(nil)
		database.On("GetUserByEmail", mock.Anything, mock.Anything, "existing@example.com").Return(&record.User{}, nil)
		pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		pageRenderer.AssertCalled(t, "RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Apologies, but this email address is already registered."
		}))
	})

	t.Run("Pre registration already exists", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		userCreator := accounthandlersmocks.NewUserCreator(t)
		emailValidator := accounthandlersmocks.NewEmailValidator(t)
		passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
		emailSender := accounthandlersmocks.NewEmailSender(t)
		auditLogger := handlersmocks.NewAuditLogger(t)

		handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		form := url.Values{}
		form.Add("email", "preregistered@example.com")
		req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &record.Settings{
			SelfRegistrationEnabled: true,
		}
		ctx := req.Context()
		ctx = reqctx.WithSettings(ctx, settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "preregistered@example.com").Return(nil)
		database.On("GetUserByEmail", mock.Anything, mock.Anything, "preregistered@example.com").Return(nil, nil)
		database.On("GetPreRegistrationByEmail", mock.Anything, mock.Anything, "preregistered@example.com").Return(&record.PreRegistration{}, nil)
		pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		pageRenderer.AssertCalled(t, "RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Apologies, but this email address is already registered."
		}))
	})

	t.Run("Password not given", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		userCreator := accounthandlersmocks.NewUserCreator(t)
		emailValidator := accounthandlersmocks.NewEmailValidator(t)
		passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
		emailSender := accounthandlersmocks.NewEmailSender(t)
		auditLogger := handlersmocks.NewAuditLogger(t)

		handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		form := url.Values{}
		form.Add("email", "valid@example.com")
		req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &record.Settings{
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
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		userCreator := accounthandlersmocks.NewUserCreator(t)
		emailValidator := accounthandlersmocks.NewEmailValidator(t)
		passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
		emailSender := accounthandlersmocks.NewEmailSender(t)
		auditLogger := handlersmocks.NewAuditLogger(t)

		handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

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

		settings := &record.Settings{
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
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		userCreator := accounthandlersmocks.NewUserCreator(t)
		emailValidator := accounthandlersmocks.NewEmailValidator(t)
		passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
		emailSender := accounthandlersmocks.NewEmailSender(t)
		auditLogger := handlersmocks.NewAuditLogger(t)

		handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		form := url.Values{}
		form.Add("email", "valid@example.com")
		form.Add("password", "Str0ngP4ss!")
		target := "/register?" + url.Values{
			"passwordConfirmation": {"Str0ngP4ss!"},
		}.Encode()
		req, _ := http.NewRequest("POST", target, strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &record.Settings{
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
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		userCreator := accounthandlersmocks.NewUserCreator(t)
		emailValidator := accounthandlersmocks.NewEmailValidator(t)
		passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
		emailSender := accounthandlersmocks.NewEmailSender(t)
		auditLogger := handlersmocks.NewAuditLogger(t)

		handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		form := url.Values{}
		form.Add("email", "valid@example.com")
		form.Add("password", "password123")
		req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &record.Settings{
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
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		userCreator := accounthandlersmocks.NewUserCreator(t)
		emailValidator := accounthandlersmocks.NewEmailValidator(t)
		passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
		emailSender := accounthandlersmocks.NewEmailSender(t)
		auditLogger := handlersmocks.NewAuditLogger(t)

		handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		form := url.Values{}
		form.Add("email", "valid@example.com")
		form.Add("password", "password123")
		form.Add("passwordConfirmation", "password456")
		req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &record.Settings{
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
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		userCreator := accounthandlersmocks.NewUserCreator(t)
		emailValidator := accounthandlersmocks.NewEmailValidator(t)
		passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
		emailSender := accounthandlersmocks.NewEmailSender(t)
		auditLogger := handlersmocks.NewAuditLogger(t)

		handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		form := url.Values{}
		form.Add("email", "valid@example.com")
		form.Add("password", "short")
		form.Add("passwordConfirmation", "short")
		req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &record.Settings{
			SelfRegistrationEnabled: true,
		}
		ctx := req.Context()
		ctx = reqctx.WithSettings(ctx, settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "valid@example.com").Return(nil)
		database.On("GetUserByEmail", mock.Anything, mock.Anything, "valid@example.com").Return(nil, nil)
		database.On("GetPreRegistrationByEmail", mock.Anything, mock.Anything, "valid@example.com").Return(nil, nil)
		passwordValidator.On("ValidatePassword", mock.Anything, "short").Return(oauth.NewErrorDetail("", "The minimum length for the password is 8 characters"))
		pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		pageRenderer.AssertCalled(t, "RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "The minimum length for the password is 8 characters"
		}))
	})

	t.Run("Self registration is disabled", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		userCreator := accounthandlersmocks.NewUserCreator(t)
		emailValidator := accounthandlersmocks.NewEmailValidator(t)
		passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
		emailSender := accounthandlersmocks.NewEmailSender(t)
		auditLogger := handlersmocks.NewAuditLogger(t)

		handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		form := url.Values{}
		form.Add("email", "valid@example.com")
		form.Add("password", "password123")
		form.Add("passwordConfirmation", "password123")
		req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &record.Settings{
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
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		userCreator := accounthandlersmocks.NewUserCreator(t)
		emailValidator := accounthandlersmocks.NewEmailValidator(t)
		passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
		emailSender := accounthandlersmocks.NewEmailSender(t)
		auditLogger := handlersmocks.NewAuditLogger(t)

		handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		// The form with verification has the address alone. A password submitted anyway is
		// ignored: the person who follows the emailed link chooses it (#207 decision 1), so the
		// validator is never asked and nothing derived from it is stored.
		form := url.Values{}
		form.Add("email", "test@example.com")
		form.Add("password", "password123")
		form.Add("passwordConfirmation", "password123")
		req, err := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		assert.NoError(t, err)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &record.Settings{
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

		var capturedVerificationCode string
		database.On("CreatePreRegistration", mock.Anything, mock.Anything, mock.AnythingOfType("*record.PreRegistration")).Return(nil).Run(func(args mock.Arguments) {
			preReg := args.Get(2).(*record.PreRegistration)
			assert.Equal(t, "test@example.com", preReg.Email)
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

		auditLogger.On("Log", mock.Anything, audit.EventCreatedPreRegistration, mock.MatchedBy(func(details map[string]interface{}) bool {
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
		passwordValidator.AssertNotCalled(t, "ValidatePassword", mock.Anything, mock.Anything)
		userCreator.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
		auditLogger.AssertExpectations(t)
		emailSender.AssertExpectations(t)
		pageRenderer.AssertExpectations(t)
	})

	t.Run("Direct registration without email verification", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		userCreator := accounthandlersmocks.NewUserCreator(t)
		emailValidator := accounthandlersmocks.NewEmailValidator(t)
		passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
		emailSender := accounthandlersmocks.NewEmailSender(t)
		auditLogger := handlersmocks.NewAuditLogger(t)

		handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		form := url.Values{}
		form.Add("email", "test@example.com")
		form.Add("password", "password123")
		form.Add("passwordConfirmation", "password123")
		req, err := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		assert.NoError(t, err)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &record.Settings{
			SelfRegistrationEnabled: true,
			SMTPEnabled:             false, // SMTP is disabled
		}
		ctx := reqctx.WithSettings(req.Context(), settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "test@example.com").Return(nil)
		database.On("GetUserByEmail", mock.Anything, mock.Anything, "test@example.com").Return(nil, nil)
		database.On("GetPreRegistrationByEmail", mock.Anything, mock.Anything, "test@example.com").Return(nil, nil)
		passwordValidator.On("ValidatePassword", mock.Anything, "password123").Return(nil)

		userCreator.On("CreateUser", mock.Anything, mock.MatchedBy(func(input *usercreation.Input) bool {
			return input.Email == "test@example.com" && !input.EmailVerified
		})).Return(&record.User{}, nil)

		auditLogger.On("Log", mock.Anything, audit.EventCreatedUser, mock.MatchedBy(func(details map[string]interface{}) bool {
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
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		userCreator := accounthandlersmocks.NewUserCreator(t)
		emailValidator := accounthandlersmocks.NewEmailValidator(t)
		passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
		emailSender := accounthandlersmocks.NewEmailSender(t)
		auditLogger := handlersmocks.NewAuditLogger(t)

		handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		form := url.Values{}
		form.Add("email", "test@example.com")
		form.Add("password", "password123")
		form.Add("passwordConfirmation", "password123")
		req, err := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		assert.NoError(t, err)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &record.Settings{
			SelfRegistrationEnabled: true,
			SMTPEnabled:             true,
			SMTPHost:                "smtp.example.com",
			SMTPPort:                2525,
			PasswordPolicy:          record.PasswordPolicyHigh,
			SelfRegistrationRequiresEmailVerification: false,
		}
		ctx := reqctx.WithSettings(req.Context(), settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "test@example.com").Return(nil)
		database.On("GetUserByEmail", mock.Anything, mock.Anything, "test@example.com").Return(nil, nil)
		database.On("GetPreRegistrationByEmail", mock.Anything, mock.Anything, "test@example.com").Return(nil, nil)
		// The policy is the request's settings', passed by the handler (#433).
		passwordValidator.On("ValidatePassword", record.PasswordPolicyHigh, "password123").Return(nil)

		userCreator.On("CreateUser", mock.Anything, mock.MatchedBy(func(input *usercreation.Input) bool {
			return input.Email == "test@example.com" && !input.EmailVerified
		})).Return(&record.User{}, nil)

		auditLogger.On("Log", mock.Anything, audit.EventCreatedUser, mock.MatchedBy(func(details map[string]interface{}) bool {
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
func TestHandleRegisterPost_AWrappedRefusalStillRedrawsTheForm(t *testing.T) {
	testCases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "a wrapped ErrorDetail",
			err: errs.Wrap(oauth.NewErrorDetail("", "Please enter a valid email address."),
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
			pageRenderer := handlersmocks.NewPageRenderer(t)
			database := datamocks.NewDatabase(t)
			userCreator := accounthandlersmocks.NewUserCreator(t)
			emailValidator := accounthandlersmocks.NewEmailValidator(t)
			passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
			emailSender := accounthandlersmocks.NewEmailSender(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator,
				passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

			form := url.Values{}
			form.Add("email", "invalid-email")
			req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()

			ctx := reqctx.WithSettings(req.Context(), &record.Settings{SelfRegistrationEnabled: true})
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

// TestHandleRegisterPost_RefusesAnAddressOverSixtyCharacters holds registration to the limit the
// administrator's and the self-service email change already apply: an address over 60
// characters redraws the form with the "too long" message, in both modes, before either lookup,
// so the database is never asked about it (#207 decision 11). The addresses are well formed, so
// it is the length and nothing else that refuses them.
func TestHandleRegisterPost_RefusesAnAddressOverSixtyCharacters(t *testing.T) {
	// 49 + len("@example.com") = 61 characters.
	const tooLong = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@example.com"
	require.Len(t, tooLong, 61)

	modes := []struct {
		name     string
		settings *record.Settings
	}{
		{
			name: "with email verification",
			settings: &record.Settings{
				SelfRegistrationEnabled: true,
				SMTPEnabled:             true,
				SelfRegistrationRequiresEmailVerification: true,
			},
		},
		{
			name:     "without email verification",
			settings: &record.Settings{SelfRegistrationEnabled: true},
		},
	}

	for _, mode := range modes {
		t.Run(mode.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			database := datamocks.NewDatabase(t)
			userCreator := accounthandlersmocks.NewUserCreator(t)
			emailValidator := accounthandlersmocks.NewEmailValidator(t)
			passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
			emailSender := accounthandlersmocks.NewEmailSender(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator,
				passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

			form := url.Values{}
			form.Add("email", tooLong)
			form.Add("password", "Str0ngP4ss!")
			form.Add("passwordConfirmation", "Str0ngP4ss!")
			req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()
			req = req.WithContext(reqctx.WithSettings(req.Context(), mode.settings))

			emailValidator.On("ValidateEmailAddress", tooLong).Return(nil).Maybe()
			pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html",
				"/account_register.html", mock.Anything).Return(nil)

			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code)
			pageRenderer.AssertCalled(t, "RenderTemplate", rr, req, "/layouts/auth_layout.html",
				"/account_register.html", mock.MatchedBy(func(data map[string]interface{}) bool {
					return data["error"] == "The email address cannot exceed a maximum length of 60 characters." &&
						data["email"] == tooLong
				}))
			database.AssertNotCalled(t, "GetUserByEmail", mock.Anything, mock.Anything, mock.Anything)
			database.AssertNotCalled(t, "GetPreRegistrationByEmail", mock.Anything, mock.Anything, mock.Anything)
			database.AssertNotCalled(t, "CreatePreRegistration", mock.Anything, mock.Anything, mock.Anything)
			userCreator.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
			emailSender.AssertNotCalled(t, "SendEmail", mock.Anything, mock.Anything, mock.Anything)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// TestHandleRegisterPost_AcceptsAnAddressOfExactlySixtyCharacters is the boundary beside it: 60
// characters is within the limit, so the address goes on to the lookup, here finding an account
// and answering as an address already registered does in this mode.
func TestHandleRegisterPost_AcceptsAnAddressOfExactlySixtyCharacters(t *testing.T) {
	// 48 + len("@example.com") = 60 characters.
	const atTheLimit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@example.com"
	require.Len(t, atTheLimit, 60)

	pageRenderer := handlersmocks.NewPageRenderer(t)
	database := datamocks.NewDatabase(t)
	userCreator := accounthandlersmocks.NewUserCreator(t)
	emailValidator := accounthandlersmocks.NewEmailValidator(t)
	passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
	emailSender := accounthandlersmocks.NewEmailSender(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator,
		passwordValidator, emailSender, auditLogger, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

	form := url.Values{}
	form.Add("email", atTheLimit)
	req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{SelfRegistrationEnabled: true}))

	emailValidator.On("ValidateEmailAddress", atTheLimit).Return(nil)
	database.On("GetUserByEmail", mock.Anything, mock.Anything, atTheLimit).Return(&record.User{}, nil).Once()
	pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html",
		"/account_register.html", mock.Anything).Return(nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	pageRenderer.AssertCalled(t, "RenderTemplate", rr, req, "/layouts/auth_layout.html",
		"/account_register.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Apologies, but this email address is already registered."
		}))
}
