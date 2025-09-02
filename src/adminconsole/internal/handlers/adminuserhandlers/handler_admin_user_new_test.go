package adminuserhandlers

// COMMENTED OUT - Tests need to be rewritten to use API client instead of database
/*

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/communication"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_communication "github.com/leodip/goiabada/core/communication/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_inputsanitizer "github.com/leodip/goiabada/core/inputsanitizer/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
	mocks_user "github.com/leodip/goiabada/core/user/mocks"
	mocks_validators "github.com/leodip/goiabada/core/validators/mocks"
)

func TestHandleAdminUserNewGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)

	handler := HandleAdminUserNewGet(mockHttpHelper)

	req, err := http.NewRequest("GET", "/admin/users/new", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()

	settings := &models.Settings{SMTPEnabled: true}
	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_users_new.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["smtpEnabled"] == true && data["setPasswordType"] == "now"
	})).Return(nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockHttpHelper.AssertExpectations(t)
}

func TestHandleAdminUserNewPost(t *testing.T) {
	t.Run("Valid input", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockUserCreator := mocks_user.NewUserCreator(t)
		mockProfileValidator := mocks_validators.NewProfileValidator(t)
		mockEmailValidator := mocks_validators.NewEmailValidator(t)
		mockPasswordValidator := mocks_validators.NewPasswordValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockEmailSender := mocks_communication.NewEmailSender(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserNewPost(
			mockHttpHelper,
			mockSessionStore,
			mockAuthHelper,
			mockDB,
			mockUserCreator,
			mockProfileValidator,
			mockEmailValidator,
			mockPasswordValidator,
			mockInputSanitizer,
			mockEmailSender,
			mockAuditLogger,
		)

		form := url.Values{}
		form.Add("email", "test@example.com")
		form.Add("password", "validPassword123!")
		form.Add("givenName", "John")
		form.Add("familyName", "Doe")
		form.Add("setPasswordType", "now")

		req, _ := http.NewRequest("POST", "/admin/users/new", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rr := httptest.NewRecorder()

		settings := &models.Settings{SMTPEnabled: true}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		mockEmailValidator.On("ValidateEmailAddress", "test@example.com").Return(nil)
		mockDB.On("GetUserByEmail", mock.Anything, "test@example.com").Return(nil, nil)
		mockProfileValidator.On("ValidateName", "John", "given name").Return(nil)
		mockProfileValidator.On("ValidateName", "", "middle name").Return(nil)
		mockProfileValidator.On("ValidateName", "Doe", "family name").Return(nil)
		mockPasswordValidator.On("ValidatePassword", mock.Anything, "validPassword123!").Return(nil)
		mockInputSanitizer.On("Sanitize", "John").Return("John")
		mockInputSanitizer.On("Sanitize", "").Return("")
		mockInputSanitizer.On("Sanitize", "Doe").Return("Doe")

		newUser := &models.User{Id: 1, Email: "test@example.com"}
		mockUserCreator.On("CreateUser", mock.MatchedBy(func(input *user.CreateUserInput) bool {
			return input.Email == "test@example.com" &&
				input.EmailVerified == false &&
				input.PasswordHash != "" && // We can't check the exact hash, but we can ensure it's not empty
				input.GivenName == "John" &&
				input.MiddleName == "" &&
				input.FamilyName == "Doe"
		})).Return(newUser, nil)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
		mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin")
		mockAuditLogger.On("Log", constants.AuditCreatedUser, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["email"] == "test@example.com" && details["loggedInUser"] == "admin"
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Contains(t, rr.Header().Get("Location"), "/admin/users/1/details")

		mockEmailValidator.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockProfileValidator.AssertExpectations(t)
		mockPasswordValidator.AssertExpectations(t)
		mockInputSanitizer.AssertExpectations(t)
		mockUserCreator.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockAuditLogger.AssertExpectations(t)
	})

	t.Run("Invalid email", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockUserCreator := mocks_user.NewUserCreator(t)
		mockProfileValidator := mocks_validators.NewProfileValidator(t)
		mockEmailValidator := mocks_validators.NewEmailValidator(t)
		mockPasswordValidator := mocks_validators.NewPasswordValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockEmailSender := mocks_communication.NewEmailSender(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserNewPost(
			mockHttpHelper,
			mockSessionStore,
			mockAuthHelper,
			mockDB,
			mockUserCreator,
			mockProfileValidator,
			mockEmailValidator,
			mockPasswordValidator,
			mockInputSanitizer,
			mockEmailSender,
			mockAuditLogger,
		)

		form := url.Values{}
		form.Add("email", "invalid-email")

		req, _ := http.NewRequest("POST", "/admin/users/new", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rr := httptest.NewRecorder()

		settings := &models.Settings{SMTPEnabled: true}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		mockEmailValidator.On("ValidateEmailAddress", "invalid-email").Return(errors.New("Invalid email"))

		mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_users_new.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Invalid email"
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		mockEmailValidator.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Email already in use", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockUserCreator := mocks_user.NewUserCreator(t)
		mockProfileValidator := mocks_validators.NewProfileValidator(t)
		mockEmailValidator := mocks_validators.NewEmailValidator(t)
		mockPasswordValidator := mocks_validators.NewPasswordValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockEmailSender := mocks_communication.NewEmailSender(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserNewPost(
			mockHttpHelper,
			mockSessionStore,
			mockAuthHelper,
			mockDB,
			mockUserCreator,
			mockProfileValidator,
			mockEmailValidator,
			mockPasswordValidator,
			mockInputSanitizer,
			mockEmailSender,
			mockAuditLogger,
		)

		form := url.Values{}
		form.Add("email", "existing@example.com")

		req, _ := http.NewRequest("POST", "/admin/users/new", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rr := httptest.NewRecorder()

		settings := &models.Settings{SMTPEnabled: true}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		mockEmailValidator.On("ValidateEmailAddress", "existing@example.com").Return(nil)
		mockDB.On("GetUserByEmail", mock.Anything, "existing@example.com").Return(&models.User{}, nil)

		mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_users_new.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "The email address is already in use."
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		mockEmailValidator.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Invalid name", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockUserCreator := mocks_user.NewUserCreator(t)
		mockProfileValidator := mocks_validators.NewProfileValidator(t)
		mockEmailValidator := mocks_validators.NewEmailValidator(t)
		mockPasswordValidator := mocks_validators.NewPasswordValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockEmailSender := mocks_communication.NewEmailSender(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserNewPost(
			mockHttpHelper,
			mockSessionStore,
			mockAuthHelper,
			mockDB,
			mockUserCreator,
			mockProfileValidator,
			mockEmailValidator,
			mockPasswordValidator,
			mockInputSanitizer,
			mockEmailSender,
			mockAuditLogger,
		)

		form := url.Values{}
		form.Add("email", "test@example.com")
		form.Add("givenName", "Invalid123")

		req, _ := http.NewRequest("POST", "/admin/users/new", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rr := httptest.NewRecorder()

		settings := &models.Settings{SMTPEnabled: true}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		mockEmailValidator.On("ValidateEmailAddress", "test@example.com").Return(nil)
		mockDB.On("GetUserByEmail", mock.Anything, "test@example.com").Return(nil, nil)
		mockProfileValidator.On("ValidateName", "Invalid123", "given name").Return(customerrors.NewErrorDetail("", "Invalid given name"))

		mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_users_new.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Invalid given name"
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		mockEmailValidator.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockProfileValidator.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Invalid password", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockUserCreator := mocks_user.NewUserCreator(t)
		mockProfileValidator := mocks_validators.NewProfileValidator(t)
		mockEmailValidator := mocks_validators.NewEmailValidator(t)
		mockPasswordValidator := mocks_validators.NewPasswordValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockEmailSender := mocks_communication.NewEmailSender(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserNewPost(
			mockHttpHelper,
			mockSessionStore,
			mockAuthHelper,
			mockDB,
			mockUserCreator,
			mockProfileValidator,
			mockEmailValidator,
			mockPasswordValidator,
			mockInputSanitizer,
			mockEmailSender,
			mockAuditLogger,
		)

		form := url.Values{}
		form.Add("email", "test@example.com")
		form.Add("password", "weak")
		form.Add("givenName", "John")
		form.Add("familyName", "Doe")
		form.Add("setPasswordType", "now")

		req, _ := http.NewRequest("POST", "/admin/users/new", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rr := httptest.NewRecorder()

		settings := &models.Settings{SMTPEnabled: true}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		mockEmailValidator.On("ValidateEmailAddress", "test@example.com").Return(nil)
		mockDB.On("GetUserByEmail", mock.Anything, "test@example.com").Return(nil, nil)
		mockProfileValidator.On("ValidateName", "John", "given name").Return(nil)
		mockProfileValidator.On("ValidateName", "", "middle name").Return(nil)
		mockProfileValidator.On("ValidateName", "Doe", "family name").Return(nil)
		mockPasswordValidator.On("ValidatePassword", mock.Anything, "weak").Return(errors.New("Password is too weak"))

		mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_users_new.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Password is too weak"
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		mockEmailValidator.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockProfileValidator.AssertExpectations(t)
		mockPasswordValidator.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("User creation error", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockUserCreator := mocks_user.NewUserCreator(t)
		mockProfileValidator := mocks_validators.NewProfileValidator(t)
		mockEmailValidator := mocks_validators.NewEmailValidator(t)
		mockPasswordValidator := mocks_validators.NewPasswordValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockEmailSender := mocks_communication.NewEmailSender(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserNewPost(
			mockHttpHelper,
			mockSessionStore,
			mockAuthHelper,
			mockDB,
			mockUserCreator,
			mockProfileValidator,
			mockEmailValidator,
			mockPasswordValidator,
			mockInputSanitizer,
			mockEmailSender,
			mockAuditLogger,
		)

		form := url.Values{}
		form.Add("email", "test@example.com")
		form.Add("password", "validPassword123!")
		form.Add("givenName", "John")
		form.Add("familyName", "Doe")
		form.Add("setPasswordType", "now")

		req, _ := http.NewRequest("POST", "/admin/users/new", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rr := httptest.NewRecorder()

		settings := &models.Settings{SMTPEnabled: true}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		mockEmailValidator.On("ValidateEmailAddress", "test@example.com").Return(nil)
		mockDB.On("GetUserByEmail", mock.Anything, "test@example.com").Return(nil, nil)
		mockProfileValidator.On("ValidateName", "John", "given name").Return(nil)
		mockProfileValidator.On("ValidateName", "", "middle name").Return(nil)
		mockProfileValidator.On("ValidateName", "Doe", "family name").Return(nil)
		mockPasswordValidator.On("ValidatePassword", mock.Anything, "validPassword123!").Return(nil)
		mockInputSanitizer.On("Sanitize", "John").Return("John")
		mockInputSanitizer.On("Sanitize", "").Return("")
		mockInputSanitizer.On("Sanitize", "Doe").Return("Doe")

		mockUserCreator.On("CreateUser", mock.AnythingOfType("*user.CreateUserInput")).Return(nil, errors.New("User creation failed"))

		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "User creation failed"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockEmailValidator.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockProfileValidator.AssertExpectations(t)
		mockPasswordValidator.AssertExpectations(t)
		mockInputSanitizer.AssertExpectations(t)
		mockUserCreator.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Email sending (SMTP enabled)", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockUserCreator := mocks_user.NewUserCreator(t)
		mockProfileValidator := mocks_validators.NewProfileValidator(t)
		mockEmailValidator := mocks_validators.NewEmailValidator(t)
		mockPasswordValidator := mocks_validators.NewPasswordValidator(t)
		mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
		mockEmailSender := mocks_communication.NewEmailSender(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserNewPost(
			mockHttpHelper,
			mockSessionStore,
			mockAuthHelper,
			mockDB,
			mockUserCreator,
			mockProfileValidator,
			mockEmailValidator,
			mockPasswordValidator,
			mockInputSanitizer,
			mockEmailSender,
			mockAuditLogger,
		)

		form := url.Values{}
		form.Add("email", "test@example.com")
		form.Add("givenName", "John")
		form.Add("familyName", "Doe")
		form.Add("setPasswordType", "email")

		req, _ := http.NewRequest("POST", "/admin/users/new", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rr := httptest.NewRecorder()

		aesEncryptionKey := "12345678901234567890123456789012"
		settings := &models.Settings{SMTPEnabled: true, AppName: "TestApp", AESEncryptionKey: []byte(aesEncryptionKey)}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		mockEmailValidator.On("ValidateEmailAddress", "test@example.com").Return(nil)
		mockDB.On("GetUserByEmail", mock.Anything, "test@example.com").Return(nil, nil)
		mockProfileValidator.On("ValidateName", "John", "given name").Return(nil)
		mockProfileValidator.On("ValidateName", "", "middle name").Return(nil)
		mockProfileValidator.On("ValidateName", "Doe", "family name").Return(nil)
		mockInputSanitizer.On("Sanitize", "John").Return("John")
		mockInputSanitizer.On("Sanitize", "").Return("")
		mockInputSanitizer.On("Sanitize", "Doe").Return("Doe")

		newUser := &models.User{Id: 1, Email: "test@example.com"}
		mockUserCreator.On("CreateUser", mock.AnythingOfType("*user.CreateUserInput")).Return(newUser, nil)

		mockDB.On("UpdateUser", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil)

		mockHttpHelper.On("RenderTemplateToBuffer", req, "/layouts/email_layout.html", "/emails/email_newuser_set_password.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			nameOk := data["name"] == "test@example.com"
			linkOk := strings.HasPrefix(data["link"].(string), config.GetAdminConsole().BaseURL+"/reset-password?email=test@example.com&code=")
			return nameOk && linkOk
		})).Return(bytes.NewBufferString("Email content"), nil)

		mockEmailSender.On("SendEmail", mock.Anything, mock.MatchedBy(func(input interface{}) bool {
			emailInput, ok := input.(*communication.SendEmailInput)
			return ok && emailInput.To == "test@example.com" && emailInput.Subject == "TestApp - create a password for your new account"
		})).Return(nil)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
		mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin")
		mockAuditLogger.On("Log", constants.AuditCreatedUser, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["email"] == "test@example.com" && details["loggedInUser"] == "admin"
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Contains(t, rr.Header().Get("Location"), "/admin/users/1/details")

		mockEmailValidator.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockProfileValidator.AssertExpectations(t)
		mockInputSanitizer.AssertExpectations(t)
		mockUserCreator.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
		mockEmailSender.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockAuditLogger.AssertExpectations(t)
	})
}
*/
