package accounthandlers

import (
	"bytes"
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/usercreation"

	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
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
// bound with: with verification required the form takes the address alone and the password is
// chosen from the emailed link; without it the form asks for the password (#207 decision 1).
// Verification required with SMTP off is no mode at all: the page is refused (#526 decision 2),
// which TestHandleRegister_RefusedWhileItRequiresVerificationAndEmailIsOff pins.
func TestHandleRegisterGet_TheFormAsksForThePasswordOnlyWithoutVerification(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		smtpEnabled              bool
		requiresVerification     bool
		wantRequiresVerification bool
	}{
		{"SMTP on and verification required", true, true, true},
		{"SMTP on and verification not required", true, false, false},
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
				passwordValidator, emailSender, auditLogger, &heldJobs{}, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

			req := httptest.NewRequest("POST", "/account/register", strings.NewReader(url.Values{"email": {""}}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req = req.WithContext(reqctx.WithSettings(req.Context(), tc.settings))

			var rendered map[string]interface{}
			pageRenderer.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).
				Run(func(args mock.Arguments) { rendered = args.Get(4).(map[string]interface{}) }).
				Return(nil).Once()
			// With verification the refusal is recorded too; what it records is pinned in
			// TestHandleRegisterPost_WithVerificationAnInvalidAddressIsRecordedAndRedrawn.
			auditLogger.On("Log", mock.Anything, audit.EventRequestedRegistration, mock.Anything).Return().Maybe()

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
		handler := RefuseUnavailableRegistration(pageRenderer)(HandleRegisterGet(pageRenderer))

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

// assertRegistrationWithoutEmailLogged holds a refusal while registration requires verification and
// email is off to its one record, distinct from the record for self-registration being off, as
// forgot-password's refusal without email has its own (#526 decision 2).
func assertRegistrationWithoutEmailLogged(t *testing.T, logs *logtest.SlogCapture) {
	t.Helper()

	records := logs.Records()
	require.Len(t, records, 1, "a refusal writes exactly one record: %s", logs.Text())
	assert.Equal(t, slog.LevelWarn, records[0].Level)
	assert.Equal(t, "self-registration request refused because email is not set up", records[0].Message)
}

// TestHandleRegister_RefusedWhileItRequiresVerificationAndEmailIsOff: with verification required
// and email off no activation link can reach anyone, so the page and its submission answer the
// not-found page, with one Warn record and no audit entry, as forgot-password answers without
// email. They used to fall back to creating an unverified account and answering "already
// registered" for a taken address, the opposite of what the setting asks for (#526 decision 2).
// The two modes beside it are served as before: verification off, with or without email, and
// verification on with email on.
func TestHandleRegister_RefusedWhileItRequiresVerificationAndEmailIsOff(t *testing.T) {
	refused := &record.Settings{SelfRegistrationEnabled: true, SelfRegistrationRequiresEmailVerification: true}

	newPost := func(pageRenderer *handlersmocks.PageRenderer, database *datamocks.Database,
		auditLogger *handlersmocks.AuditLogger) http.Handler {
		return RefuseUnavailableRegistration(pageRenderer)(HandleRegisterPost(pageRenderer, database,
			accounthandlersmocks.NewUserCreator(t), accounthandlersmocks.NewEmailValidator(t),
			accounthandlersmocks.NewPasswordValidator(t), accounthandlersmocks.NewEmailSender(t), auditLogger,
			&heldJobs{}, testDataCipher, testBaseURL, testAdminConsoleBaseURL))
	}
	postRequest := func(settings *record.Settings, email string) *http.Request {
		form := url.Values{"email": {email}, "password": {"password123"}, "passwordConfirmation": {"password123"}}
		req := httptest.NewRequest("POST", "/account/register", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req.WithContext(reqctx.WithSettings(req.Context(), settings))
	}

	t.Run("the page is refused", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		req := httptest.NewRequest("GET", "/account/register", nil)
		req = req.WithContext(reqctx.WithSettings(req.Context(), refused))
		rr := httptest.NewRecorder()
		pageRenderer.On("NotFound", rr, req).Return().Once()
		logs := logtest.CaptureSlog(t)

		RefuseUnavailableRegistration(pageRenderer)(HandleRegisterGet(pageRenderer)).ServeHTTP(rr, req)

		pageRenderer.AssertExpectations(t)
		assertRegistrationWithoutEmailLogged(t, logs)
	})

	t.Run("the submission is refused and touches nothing", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		// No expectations: an audit entry, or any lookup, fails the test.
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		req := postRequest(refused, "taken@example.com")
		rr := httptest.NewRecorder()
		pageRenderer.On("NotFound", rr, req).Return().Once()
		logs := logtest.CaptureSlog(t)

		newPost(pageRenderer, database, auditLogger).ServeHTTP(rr, req)

		pageRenderer.AssertExpectations(t)
		assertRegistrationWithoutEmailLogged(t, logs)
	})

	for _, tc := range []struct {
		name                     string
		settings                 *record.Settings
		wantRequiresVerification bool
	}{
		{"verification off and email off", &record.Settings{SelfRegistrationEnabled: true}, false},
		{"verification on and email on", &record.Settings{SelfRegistrationEnabled: true,
			SelfRegistrationRequiresEmailVerification: true, SMTPEnabled: true}, true},
	} {
		t.Run("the page is served, "+tc.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			req := httptest.NewRequest("GET", "/account/register", nil)
			req = req.WithContext(reqctx.WithSettings(req.Context(), tc.settings))

			var rendered map[string]interface{}
			pageRenderer.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).
				Run(func(args mock.Arguments) { rendered = args.Get(4).(map[string]interface{}) }).
				Return(nil).Once()

			RefuseUnavailableRegistration(pageRenderer)(HandleRegisterGet(pageRenderer)).ServeHTTP(httptest.NewRecorder(), req)

			require.NotNil(t, rendered)
			assert.Equal(t, tc.wantRequiresVerification, rendered["requiresEmailVerification"])
		})

		// An empty address is the cheapest submission that shows the form got past the refusal:
		// it is redrawn. What each mode then does with a real address is pinned by
		// TestHandleRegisterPost's "Direct registration without email verification" and the
		// TestHandleRegisterPost_WithVerification tests.
		t.Run("the submission is served, "+tc.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			auditLogger.On("Log", mock.Anything, audit.EventRequestedRegistration, mock.Anything).Return().Maybe()

			var rendered map[string]interface{}
			pageRenderer.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).
				Run(func(args mock.Arguments) { rendered = args.Get(4).(map[string]interface{}) }).
				Return(nil).Once()

			newPost(pageRenderer, datamocks.NewDatabase(t), auditLogger).ServeHTTP(httptest.NewRecorder(),
				postRequest(tc.settings, ""))

			require.NotNil(t, rendered)
			assert.Equal(t, "Email is required.", rendered["error"])
			assert.Equal(t, tc.wantRequiresVerification, rendered["requiresEmailVerification"])
		})
	}
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

		handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, &heldJobs{}, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

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

		handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, &heldJobs{}, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

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

		handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, &heldJobs{}, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

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

		handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, &heldJobs{}, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

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
		database.On("GetPreRegistrationByEmail", mock.Anything, mock.Anything, "preregistered@example.com").Return(&record.PreRegistration{
			VerificationCodeIssuedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
		}, nil)
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

		handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, &heldJobs{}, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

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

		handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, &heldJobs{}, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

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
		passwordValidator.AssertNotCalled(t, "ValidatePassword", mock.Anything, mock.Anything, mock.Anything)
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

		handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, &heldJobs{}, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

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
			return data["error"] == "Confirm your password."
		}))
		passwordValidator.AssertNotCalled(t, "ValidatePassword", mock.Anything, mock.Anything, mock.Anything)
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

		handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, &heldJobs{}, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

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
			return data["error"] == "Confirm your password."
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

		handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, &heldJobs{}, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

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
			return data["error"] == "The passwords don't match."
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

		handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, &heldJobs{}, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

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
		passwordValidator.On("ValidatePassword", mock.Anything, "short", mock.Anything).Return(oauth.NewErrorDetail("", "The minimum length for the password is 8 characters"))
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

		handler := RefuseUnavailableRegistration(pageRenderer)(HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, &heldJobs{}, testDataCipher, testBaseURL, testAdminConsoleBaseURL))

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
		passwordValidator.AssertNotCalled(t, "ValidatePassword", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("Direct registration without email verification", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		database := datamocks.NewDatabase(t)
		userCreator := accounthandlersmocks.NewUserCreator(t)
		emailValidator := accounthandlersmocks.NewEmailValidator(t)
		passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
		emailSender := accounthandlersmocks.NewEmailSender(t)
		auditLogger := handlersmocks.NewAuditLogger(t)

		handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, &heldJobs{}, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		form := url.Values{}
		form.Add("email", "test@example.com")
		form.Add("password", "password123")
		form.Add("passwordConfirmation", "password123")
		req, err := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		require.NoError(t, err)
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
		passwordValidator.On("ValidatePassword", mock.Anything, "password123", mock.Anything).Return(nil)

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

		handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger, &heldJobs{}, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

		form := url.Values{}
		form.Add("email", "test@example.com")
		form.Add("password", "password123")
		form.Add("passwordConfirmation", "password123")
		req, err := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		require.NoError(t, err)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &record.Settings{
			SelfRegistrationEnabled: true,
			SMTPEnabled:             true,
			SMTPHost:                "smtp.example.com",
			SMTPPort:                2525,
			PasswordPolicy:          record.PasswordPolicyHigh,
			AppName:                 "Goiabada",
			SelfRegistrationRequiresEmailVerification: false,
		}
		ctx := reqctx.WithSettings(req.Context(), settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "test@example.com").Return(nil)
		database.On("GetUserByEmail", mock.Anything, mock.Anything, "test@example.com").Return(nil, nil)
		database.On("GetPreRegistrationByEmail", mock.Anything, mock.Anything, "test@example.com").Return(nil, nil)
		// The policy is the request's settings', passed by the handler (#433), and the words
		// beside it the address typed and the app name; a registering account has no username
		// (#550 decision 6).
		passwordValidator.On("ValidatePassword", record.PasswordPolicyHigh, "password123",
			accountvalidation.AccountWords{Email: "test@example.com", AppName: "Goiabada"}).Return(nil)

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

// The welcome mail takes the language the registration page was matched to, as the activation
// mail does: the page's matcher answers pt-BR for "fr-CA,fr;q=0.9,pt-BR;q=0.8", and the first
// Accept-Language tag alone sent the mail in English (#607). The rows are the activation mail's:
// a cross-language guess and a ui_locales the sign-in page carried follow the page too. The locale
// is attached the way the request chain attaches it, so the page's matcher is the production one.
func TestHandleRegisterPost_TheWelcomeMailTakesThePageLanguage(t *testing.T) {
	for _, tc := range []struct {
		name        string
		accept      string
		uiLocales   string
		spanish     bool
		wantTag     string
		wantSubject string
	}{
		{name: "the page's matched language, not the first Accept-Language tag alone",
			accept: "fr-CA,fr;q=0.9,pt-BR;q=0.8", wantTag: "pt-BR", wantSubject: "Bem-vindo(a)!"},
		{name: "a cross-language guess gets its subject and body in the same language",
			accept: "gl", spanish: true, wantTag: "es", wantSubject: spanishConfirmationSubject},
		{name: "ui_locales, the ceremony's explicit intent, also follows the page",
			uiLocales: "fr pt-BR", wantTag: "pt-BR", wantSubject: "Bem-vindo(a)!"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.spanish {
				installSpanishOverrideCatalog(t)
			}
			pageRenderer := handlersmocks.NewPageRenderer(t)
			database := datamocks.NewDatabase(t)
			userCreator := accounthandlersmocks.NewUserCreator(t)
			emailValidator := accounthandlersmocks.NewEmailValidator(t)
			passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
			emailSender := accounthandlersmocks.NewEmailSender(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator, passwordValidator,
				emailSender, auditLogger, &heldJobs{}, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

			form := url.Values{}
			form.Add("email", "test@example.com")
			form.Add("password", "password123")
			form.Add("passwordConfirmation", "password123")
			target := "/register"
			if tc.uiLocales != "" {
				target += "?" + url.Values{"ui_locales": {tc.uiLocales}}.Encode()
			}
			req, err := http.NewRequest("POST", target, strings.NewReader(form.Encode()))
			require.NoError(t, err)
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			if tc.accept != "" {
				req.Header.Set("Accept-Language", tc.accept)
			}
			rr := httptest.NewRecorder()

			settings := &record.Settings{
				SelfRegistrationEnabled: true,
				SMTPEnabled:             true,
				SMTPHost:                "smtp.example.com",
				SMTPPort:                2525,
				PasswordPolicy:          record.PasswordPolicyHigh,
				SelfRegistrationRequiresEmailVerification: false,
			}
			req = req.WithContext(i18n.ResolveRequestLocale(reqctx.WithSettings(req.Context(), settings), req))
			require.Equal(t, tc.wantTag, i18n.CatalogTag(req.Context()), "the page's catalog")

			emailValidator.On("ValidateEmailAddress", "test@example.com").Return(nil)
			database.On("GetUserByEmail", mock.Anything, mock.Anything, "test@example.com").Return(nil, nil)
			database.On("GetPreRegistrationByEmail", mock.Anything, mock.Anything, "test@example.com").Return(nil, nil)
			passwordValidator.On("ValidatePassword", record.PasswordPolicyHigh, "password123", mock.Anything).Return(nil)
			userCreator.On("CreateUser", mock.Anything, mock.MatchedBy(func(input *usercreation.Input) bool {
				return input.Email == "test@example.com" && !input.EmailVerified
			})).Return(&record.User{}, nil)
			auditLogger.On("Log", mock.Anything, audit.EventCreatedUser, mock.Anything).Return()

			var mailReq *http.Request
			pageRenderer.On("RenderTemplateToBuffer", mock.Anything, "/layouts/email_layout.html",
				"/emails/email_register_confirmation.html", mock.Anything).
				Run(func(args mock.Arguments) { mailReq = args.Get(0).(*http.Request) }).
				Return(bytes.NewBufferString("email content"), nil)
			var sent *emaildelivery.SendEmailInput
			emailSender.On("SendEmail", mock.Anything, emaildelivery.SMTPConfig{Host: "smtp.example.com", Port: 2525},
				mock.Anything).
				Run(func(args mock.Arguments) { sent = args.Get(2).(*emaildelivery.SendEmailInput) }).
				Return(nil)
			pageRenderer.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register_success.html",
				mock.Anything).Return(nil)

			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code)
			require.NotNil(t, mailReq)
			assert.Equal(t, tc.wantTag, i18n.LocaleTag(mailReq.Context()),
				"the mail is rendered in the page's language, which is also what picks its body copy")
			require.NotNil(t, sent)
			assert.Equal(t, tc.wantSubject, sent.Subject)
		})
	}
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
				passwordValidator, emailSender, auditLogger, &heldJobs{}, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

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

// registerAddressOfLength is a well-formed address of exactly n characters, n at least 70: a local
// part of 64, the most RFC 5321 allows, and a domain of labels of 61 characters or fewer.
func registerAddressOfLength(n int) string {
	remaining := n - 64 - len("@.com")
	var labels []string
	for remaining > 63 {
		labels = append(labels, strings.Repeat("d", 61))
		remaining -= 62
	}
	labels = append(labels, strings.Repeat("d", remaining), "com")
	return strings.Repeat("a", 64) + "@" + strings.Join(labels, ".")
}

// TestHandleRegisterPost_RefusesAnAddressOverTheLimit holds registration to the limit the
// administrator's and the self-service email change already apply: an address over 254
// characters, the longest SMTP carries, redraws the form with the "too long" message, in both
// modes, before either lookup, so the database is never asked about it (#207 decision 11, #632).
// The addresses are well formed, so it is the length and nothing else that refuses them.
func TestHandleRegisterPost_RefusesAnAddressOverTheLimit(t *testing.T) {
	tooLong := registerAddressOfLength(255)
	require.Len(t, tooLong, 255)

	modes := []struct {
		name     string
		settings *record.Settings
		// audited is whether the refusal is recorded: with verification every request is, as
		// invalid_address (#207 decision 8), and without it none is.
		audited bool
	}{
		{
			name: "with email verification",
			settings: &record.Settings{
				SelfRegistrationEnabled: true,
				SMTPEnabled:             true,
				SelfRegistrationRequiresEmailVerification: true,
			},
			audited: true,
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
				passwordValidator, emailSender, auditLogger, &heldJobs{}, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

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
			if mode.audited {
				auditLogger.On("Log", mock.Anything, audit.EventRequestedRegistration, mock.MatchedBy(
					func(details map[string]interface{}) bool { return details["outcome"] == "invalid_address" })).
					Return().Once()
			}

			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code)
			pageRenderer.AssertCalled(t, "RenderTemplate", rr, req, "/layouts/auth_layout.html",
				"/account_register.html", mock.MatchedBy(func(data map[string]interface{}) bool {
					return data["error"] == "The email address cannot exceed a maximum length of 254 characters." &&
						data["email"] == tooLong
				}))
			database.AssertNotCalled(t, "GetUserByEmail", mock.Anything, mock.Anything, mock.Anything)
			database.AssertNotCalled(t, "GetPreRegistrationByEmail", mock.Anything, mock.Anything, mock.Anything)
			database.AssertNotCalled(t, "CreatePreRegistration", mock.Anything, mock.Anything, mock.Anything)
			userCreator.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
			emailSender.AssertNotCalled(t, "SendEmail", mock.Anything, mock.Anything, mock.Anything)
			if !mode.audited {
				auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
			}
		})
	}
}

// TestHandleRegisterPost_AcceptsAnAddressAtTheLimit is the boundary beside it: 254 characters is
// within the limit, so the address goes on to the lookup, here finding an account and answering as
// an address already registered does in this mode.
func TestHandleRegisterPost_AcceptsAnAddressAtTheLimit(t *testing.T) {
	atTheLimit := registerAddressOfLength(254)
	require.Len(t, atTheLimit, 254)

	pageRenderer := handlersmocks.NewPageRenderer(t)
	database := datamocks.NewDatabase(t)
	userCreator := accounthandlersmocks.NewUserCreator(t)
	emailValidator := accounthandlersmocks.NewEmailValidator(t)
	passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
	emailSender := accounthandlersmocks.NewEmailSender(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleRegisterPost(pageRenderer, database, userCreator, emailValidator,
		passwordValidator, emailSender, auditLogger, &heldJobs{}, testDataCipher, testBaseURL, testAdminConsoleBaseURL)

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

// RefuseUnavailableRegistration passes an available registration through untouched, refuses an
// unavailable one without reaching what is behind it, which on the submission route is the limiter
// (#526 decision 2), and answers a request reaching it with no settings as the handlers do.
func TestRefuseUnavailableRegistration(t *testing.T) {
	reached := func(n *int) http.Handler {
		return http.HandlerFunc(func(http.ResponseWriter, *http.Request) { *n++ })
	}

	for _, tc := range []struct {
		name      string
		settings  *record.Settings
		wantReach bool
	}{
		{"self-registration off", &record.Settings{SelfRegistrationRequiresEmailVerification: true, SMTPEnabled: true}, false},
		{"verification on and email off", &record.Settings{SelfRegistrationEnabled: true, SelfRegistrationRequiresEmailVerification: true}, false},
		{"verification off and email off", &record.Settings{SelfRegistrationEnabled: true}, true},
		{"verification on and email on", &record.Settings{SelfRegistrationEnabled: true, SelfRegistrationRequiresEmailVerification: true, SMTPEnabled: true}, true},
	} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			t.Run(tc.name+", "+method, func(t *testing.T) {
				pageRenderer := handlersmocks.NewPageRenderer(t)
				req := httptest.NewRequest(method, "/account/register", nil)
				req = req.WithContext(reqctx.WithSettings(req.Context(), tc.settings))
				rr := httptest.NewRecorder()
				if !tc.wantReach {
					pageRenderer.On("NotFound", rr, req).Return().Once()
				}
				calls := 0

				RefuseUnavailableRegistration(pageRenderer)(reached(&calls)).ServeHTTP(rr, req)

				if tc.wantReach {
					assert.Equal(t, 1, calls)
				} else {
					assert.Zero(t, calls, "nothing behind it is reached")
				}
				pageRenderer.AssertExpectations(t)
			})
		}
	}

	t.Run("no settings", func(t *testing.T) {
		pageRenderer := handlersmocks.NewPageRenderer(t)
		req := httptest.NewRequest(http.MethodPost, "/account/register", nil)
		rr := httptest.NewRecorder()
		pageRenderer.On("InternalServerError", rr, req, reqctx.ErrNoSettings).Return().Once()
		calls := 0

		RefuseUnavailableRegistration(pageRenderer)(reached(&calls)).ServeHTTP(rr, req)

		assert.Zero(t, calls)
		pageRenderer.AssertExpectations(t)
	})
}
