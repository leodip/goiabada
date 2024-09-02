package accounthandlers

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_communication "github.com/leodip/goiabada/core/communication/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_users "github.com/leodip/goiabada/core/users/mocks"
	mocks_validators "github.com/leodip/goiabada/core/validators/mocks"

	"github.com/leodip/goiabada/core/communication"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/users"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestMain(m *testing.M) {
	config.Init("AuthServer")
	code := m.Run()
	os.Exit(code)
}

func TestHandleAccountRegisterGet(t *testing.T) {
	t.Run("self registration enabled", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		handler := HandleAccountRegisterGet(httpHelper)

		req, _ := http.NewRequest("GET", "/account/register", nil)
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			SelfRegistrationEnabled: true,
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertExpectations(t)
	})

	t.Run("self registration disabled", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		handler := HandleAccountRegisterGet(httpHelper)

		req, _ := http.NewRequest("GET", "/account/register", nil)
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			SelfRegistrationEnabled: false,
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		httpHelper.On("InternalServerError", rr, req, mock.Anything).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
	})
}

func TestHandleAccountRegisterPost(t *testing.T) {
	t.Run("No email and email is required", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_users.NewUserCreator(t)
		emailValidator := mocks_validators.NewEmailValidator(t)
		passwordValidator := mocks_validators.NewPasswordValidator(t)
		emailSender := mocks_communication.NewEmailSender(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountRegisterPost(httpHelper, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger)

		req, _ := http.NewRequest("POST", "/register", nil)
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			SelfRegistrationEnabled: true,
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertCalled(t, "RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Email is required."
		}))
	})

	t.Run("Invalid email given", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_users.NewUserCreator(t)
		emailValidator := mocks_validators.NewEmailValidator(t)
		passwordValidator := mocks_validators.NewPasswordValidator(t)
		emailSender := mocks_communication.NewEmailSender(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountRegisterPost(httpHelper, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger)

		form := url.Values{}
		form.Add("email", "invalid-email")
		req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			SelfRegistrationEnabled: true,
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "invalid-email").Return(customerrors.NewErrorDetail("", "Please enter a valid email address."))
		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertCalled(t, "RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Please enter a valid email address."
		}))
	})

	t.Run("Email is already registered", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_users.NewUserCreator(t)
		emailValidator := mocks_validators.NewEmailValidator(t)
		passwordValidator := mocks_validators.NewPasswordValidator(t)
		emailSender := mocks_communication.NewEmailSender(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountRegisterPost(httpHelper, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger)

		form := url.Values{}
		form.Add("email", "existing@example.com")
		req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			SelfRegistrationEnabled: true,
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "existing@example.com").Return(nil)
		database.On("GetUserByEmail", mock.Anything, "existing@example.com").Return(&models.User{}, nil)
		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertCalled(t, "RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Apologies, but this email address is already registered."
		}))
	})

	t.Run("Pre registration already exists", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_users.NewUserCreator(t)
		emailValidator := mocks_validators.NewEmailValidator(t)
		passwordValidator := mocks_validators.NewPasswordValidator(t)
		emailSender := mocks_communication.NewEmailSender(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountRegisterPost(httpHelper, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger)

		form := url.Values{}
		form.Add("email", "preregistered@example.com")
		req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			SelfRegistrationEnabled: true,
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "preregistered@example.com").Return(nil)
		database.On("GetUserByEmail", mock.Anything, "preregistered@example.com").Return(nil, nil)
		database.On("GetPreRegistrationByEmail", mock.Anything, "preregistered@example.com").Return(&models.PreRegistration{}, nil)
		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertCalled(t, "RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Apologies, but this email address is already registered."
		}))
	})

	t.Run("Password not given", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_users.NewUserCreator(t)
		emailValidator := mocks_validators.NewEmailValidator(t)
		passwordValidator := mocks_validators.NewPasswordValidator(t)
		emailSender := mocks_communication.NewEmailSender(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountRegisterPost(httpHelper, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger)

		form := url.Values{}
		form.Add("email", "valid@example.com")
		req, _ := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			SelfRegistrationEnabled: true,
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "valid@example.com").Return(nil)
		database.On("GetUserByEmail", mock.Anything, "valid@example.com").Return(nil, nil)
		database.On("GetPreRegistrationByEmail", mock.Anything, "valid@example.com").Return(nil, nil)
		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertCalled(t, "RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Password is required."
		}))
	})

	t.Run("Password confirmation is required", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_users.NewUserCreator(t)
		emailValidator := mocks_validators.NewEmailValidator(t)
		passwordValidator := mocks_validators.NewPasswordValidator(t)
		emailSender := mocks_communication.NewEmailSender(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountRegisterPost(httpHelper, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger)

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
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "valid@example.com").Return(nil)
		database.On("GetUserByEmail", mock.Anything, "valid@example.com").Return(nil, nil)
		database.On("GetPreRegistrationByEmail", mock.Anything, "valid@example.com").Return(nil, nil)
		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertCalled(t, "RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Password confirmation is required."
		}))
	})

	t.Run("Password confirmation does not match", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_users.NewUserCreator(t)
		emailValidator := mocks_validators.NewEmailValidator(t)
		passwordValidator := mocks_validators.NewPasswordValidator(t)
		emailSender := mocks_communication.NewEmailSender(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountRegisterPost(httpHelper, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger)

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
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "valid@example.com").Return(nil)
		database.On("GetUserByEmail", mock.Anything, "valid@example.com").Return(nil, nil)
		database.On("GetPreRegistrationByEmail", mock.Anything, "valid@example.com").Return(nil, nil)
		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertCalled(t, "RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "The password confirmation does not match the password."
		}))
	})

	t.Run("ValidatePassword fails", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_users.NewUserCreator(t)
		emailValidator := mocks_validators.NewEmailValidator(t)
		passwordValidator := mocks_validators.NewPasswordValidator(t)
		emailSender := mocks_communication.NewEmailSender(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountRegisterPost(httpHelper, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger)

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
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "valid@example.com").Return(nil)
		database.On("GetUserByEmail", mock.Anything, "valid@example.com").Return(nil, nil)
		database.On("GetPreRegistrationByEmail", mock.Anything, "valid@example.com").Return(nil, nil)
		passwordValidator.On("ValidatePassword", mock.Anything, "short").Return(customerrors.NewErrorDetail("", "The minimum length for the password is 8 characters"))
		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertCalled(t, "RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "The minimum length for the password is 8 characters"
		}))
	})

	t.Run("Self registration is disabled", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_users.NewUserCreator(t)
		emailValidator := mocks_validators.NewEmailValidator(t)
		passwordValidator := mocks_validators.NewPasswordValidator(t)
		emailSender := mocks_communication.NewEmailSender(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountRegisterPost(httpHelper, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger)

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
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "trying to access self registration page but self registration is not enabled in settings")
		})).Run(func(args mock.Arguments) {
			w := args.Get(0).(http.ResponseWriter)
			w.WriteHeader(http.StatusInternalServerError)
		}).Return()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
		httpHelper.AssertExpectations(t)

		// Ensure that no other mock methods were called
		emailValidator.AssertNotCalled(t, "ValidateEmailAddress")
		database.AssertNotCalled(t, "GetUserByEmail")
		database.AssertNotCalled(t, "GetPreRegistrationByEmail")
		passwordValidator.AssertNotCalled(t, "ValidatePassword")
	})

	t.Run("SMTP enabled and requires email verification", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_users.NewUserCreator(t)
		emailValidator := mocks_validators.NewEmailValidator(t)
		passwordValidator := mocks_validators.NewPasswordValidator(t)
		emailSender := mocks_communication.NewEmailSender(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountRegisterPost(httpHelper, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger)

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
			SelfRegistrationRequiresEmailVerification: true,
			AESEncryptionKey: []byte("some_encryption_key0000000000000"),
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "test@example.com").Return(nil)
		database.On("GetUserByEmail", mock.Anything, "test@example.com").Return(nil, nil)
		database.On("GetPreRegistrationByEmail", mock.Anything, "test@example.com").Return(nil, nil)
		passwordValidator.On("ValidatePassword", mock.Anything, "password123").Return(nil)

		var capturedVerificationCode string
		database.On("CreatePreRegistration", mock.Anything, mock.AnythingOfType("*models.PreRegistration")).Return(nil).Run(func(args mock.Arguments) {
			preReg := args.Get(1).(*models.PreRegistration)
			assert.Equal(t, "test@example.com", preReg.Email)
			assert.NotEmpty(t, preReg.PasswordHash)
			assert.NotEmpty(t, preReg.VerificationCodeEncrypted)
			assert.True(t, preReg.VerificationCodeIssuedAt.Valid)

			// Capture the verification code for later use
			decryptedCode, err := encryption.DecryptText(preReg.VerificationCodeEncrypted, settings.AESEncryptionKey)
			assert.NoError(t, err)
			capturedVerificationCode = decryptedCode
		})

		auditLogger.On("Log", constants.AuditCreatedPreRegistration, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["email"] == "test@example.com"
		})).Return()

		httpHelper.On("RenderTemplateToBuffer", mock.Anything, "/layouts/email_layout.html", "/emails/email_register_activate.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			link, ok := data["link"].(string)
			if !ok {
				return false
			}
			expectedLink := fmt.Sprintf("%s/account/activate?email=test@example.com&code=%s", config.Get().BaseURL, capturedVerificationCode)
			return link == expectedLink
		})).Return(bytes.NewBuffer([]byte("email content")), nil)

		emailSender.On("SendEmail", mock.Anything, mock.MatchedBy(func(input *communication.SendEmailInput) bool {
			return input.To == "test@example.com" && input.Subject == "Activate your account"
		})).Return(nil)

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/account_register_activation.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		database.AssertExpectations(t)
		emailValidator.AssertExpectations(t)
		passwordValidator.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		emailSender.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	t.Run("Direct registration without email verification", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		userCreator := mocks_users.NewUserCreator(t)
		emailValidator := mocks_validators.NewEmailValidator(t)
		passwordValidator := mocks_validators.NewPasswordValidator(t)
		emailSender := mocks_communication.NewEmailSender(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountRegisterPost(httpHelper, database, userCreator, emailValidator, passwordValidator, emailSender, auditLogger)

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
			AESEncryptionKey:        []byte("some_encryption_key0000000000000"),
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		emailValidator.On("ValidateEmailAddress", "test@example.com").Return(nil)
		database.On("GetUserByEmail", mock.Anything, "test@example.com").Return(nil, nil)
		database.On("GetPreRegistrationByEmail", mock.Anything, "test@example.com").Return(nil, nil)
		passwordValidator.On("ValidatePassword", mock.Anything, "password123").Return(nil)

		userCreator.On("CreateUser", mock.MatchedBy(func(input *users.CreateUserInput) bool {
			return input.Email == "test@example.com" && !input.EmailVerified
		})).Return(&models.User{}, nil)

		auditLogger.On("Log", constants.AuditCreatedUser, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["email"] == "test@example.com"
		})).Return()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.Get().BaseURL+"/auth/pwd", rr.Header().Get("Location"))

		database.AssertExpectations(t)
		emailValidator.AssertExpectations(t)
		passwordValidator.AssertExpectations(t)
		userCreator.AssertExpectations(t)
		auditLogger.AssertExpectations(t)

		// Ensure that these methods were not called
		emailSender.AssertNotCalled(t, "SendEmail")
		database.AssertNotCalled(t, "CreatePreRegistration")
		httpHelper.AssertNotCalled(t, "RenderTemplateToBuffer")
	})
}
