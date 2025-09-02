package accounthandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_validator "github.com/leodip/goiabada/core/validators/mocks"
)

func TestHandleAccountChangePasswordGet_SuccessfulRender(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(uuid.New().String())

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/account_change_password.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		_, csrfFieldExists := data["csrfField"]
		return csrfFieldExists
	})).Return(nil)

	handler := HandleAccountChangePasswordGet(mockHttpHelper, mockAuthHelper)

	req, _ := http.NewRequest("GET", "/account/change-password", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockHttpHelper.AssertExpectations(t)
}

func TestHandleAccountChangePasswordGet_RenderTemplateError(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(uuid.New().String())
	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/account_change_password.html", mock.Anything).Return(assert.AnError)
	mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, assert.AnError).Once()

	handler := HandleAccountChangePasswordGet(mockHttpHelper, mockAuthHelper)

	req, _ := http.NewRequest("GET", "/account/change-password", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
}

func TestHandleAccountChangePasswordPost_PasswordRequired(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDb := mocks_data.NewDatabase(t)
	mockPasswordValidator := mocks_validator.NewPasswordValidator(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(uuid.New().String())
	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/account_change_password.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "Current password is required."
	})).Return(nil)

	handler := HandleAccountChangePasswordPost(mockHttpHelper, mockAuthHelper, mockDb, mockPasswordValidator, mockAuditLogger)

	form := url.Values{}
	req, _ := http.NewRequest("POST", "/account/change-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
		IdToken: &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"sub": uuid.New(),
			},
		},
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockHttpHelper.AssertExpectations(t)
}

func TestHandleAccountChangePasswordPost_AuthenticationFailed(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDb := mocks_data.NewDatabase(t)
	mockPasswordValidator := mocks_validator.NewPasswordValidator(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	user := &models.User{
		Id:           1,
		Subject:      uuid.New(),
		PasswordHash: "$2a$10$invalid_hash",
	}

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDb.On("GetUserBySubject", mock.Anything, mock.Anything).Return(user, nil)
	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/account_change_password.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "Authentication failed. Check your current password and try again."
	})).Return(nil)

	handler := HandleAccountChangePasswordPost(mockHttpHelper, mockAuthHelper, mockDb, mockPasswordValidator, mockAuditLogger)

	form := url.Values{}
	form.Add("currentPassword", "oldpassword")
	form.Add("newPassword", "newpassword")
	form.Add("newPasswordConfirmation", "newpassword")

	req, _ := http.NewRequest("POST", "/account/change-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
		IdToken: &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"sub": user.Subject.String(),
			},
		},
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockHttpHelper.AssertExpectations(t)
	mockDb.AssertExpectations(t)
}

func TestHandleAccountChangePasswordPost_NewPasswordRequired(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDb := mocks_data.NewDatabase(t)
	mockPasswordValidator := mocks_validator.NewPasswordValidator(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	password := "$2a$10$asdasd"
	passwordHash, err := hashutil.HashPassword(password)
	assert.Nil(t, err)

	user := &models.User{
		Id:           1,
		Subject:      uuid.New(),
		PasswordHash: passwordHash,
	}
	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDb.On("GetUserBySubject", mock.Anything, mock.Anything).Return(user, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/account_change_password.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "New password is required."
	})).Return(nil)

	handler := HandleAccountChangePasswordPost(mockHttpHelper, mockAuthHelper, mockDb, mockPasswordValidator, mockAuditLogger)

	form := url.Values{}
	form.Add("currentPassword", password)
	form.Add("newPassword", "")
	form.Add("newPasswordConfirmation", "")

	req, _ := http.NewRequest("POST", "/account/change-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
		IdToken: &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"sub": user.Subject.String(),
			},
		},
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockHttpHelper.AssertExpectations(t)
	mockDb.AssertExpectations(t)
}

func TestHandleAccountChangePasswordPost_PasswordConfirmationDoesNotMatch(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDb := mocks_data.NewDatabase(t)
	mockPasswordValidator := mocks_validator.NewPasswordValidator(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	password := "$2a$10$asdasd"
	passwordHash, err := hashutil.HashPassword(password)
	assert.Nil(t, err)

	user := &models.User{
		Id:           1,
		Subject:      uuid.New(),
		PasswordHash: passwordHash,
	}
	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDb.On("GetUserBySubject", mock.Anything, mock.Anything).Return(user, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/account_change_password.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "The new password confirmation does not match the password."
	})).Return(nil)

	handler := HandleAccountChangePasswordPost(mockHttpHelper, mockAuthHelper, mockDb, mockPasswordValidator, mockAuditLogger)

	form := url.Values{}
	form.Add("currentPassword", password)
	form.Add("newPassword", "abcd1234")
	form.Add("newPasswordConfirmation", "different")

	req, _ := http.NewRequest("POST", "/account/change-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
		IdToken: &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"sub": user.Subject.String(),
			},
		},
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockHttpHelper.AssertExpectations(t)
	mockDb.AssertExpectations(t)
}

func TestHandleAccountChangePasswordPost_PasswordValidationError(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDb := mocks_data.NewDatabase(t)
	mockPasswordValidator := mocks_validator.NewPasswordValidator(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	password := "$2a$10$asdasd"
	passwordHash, err := hashutil.HashPassword(password)
	assert.Nil(t, err)

	user := &models.User{
		Id:           1,
		Subject:      uuid.New(),
		PasswordHash: passwordHash,
	}
	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDb.On("GetUserBySubject", mock.Anything, mock.Anything).Return(user, nil)

	validationError := customerrors.NewErrorDetail("validation_error", "Password does not meet requirements")
	mockPasswordValidator.On("ValidatePassword", mock.Anything, mock.AnythingOfType("string")).Return(validationError)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/account_change_password.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "Password does not meet requirements"
	})).Return(nil)

	handler := HandleAccountChangePasswordPost(mockHttpHelper, mockAuthHelper, mockDb, mockPasswordValidator, mockAuditLogger)

	form := url.Values{}
	form.Add("currentPassword", password)
	form.Add("newPassword", "newpassword")
	form.Add("newPasswordConfirmation", "newpassword")

	req, _ := http.NewRequest("POST", "/account/change-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
		IdToken: &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"sub": user.Subject.String(),
			},
		},
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockHttpHelper.AssertExpectations(t)
	mockDb.AssertExpectations(t)
	mockPasswordValidator.AssertExpectations(t)
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAccountChangePasswordPost_HappyPath(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDb := mocks_data.NewDatabase(t)
	mockPasswordValidator := mocks_validator.NewPasswordValidator(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	password := "oldPassword123"
	newPassword := "newPassword456"
	passwordHash, err := hashutil.HashPassword(password)
	assert.Nil(t, err)

	user := &models.User{
		Id:           1,
		Subject:      uuid.New(),
		PasswordHash: passwordHash,
	}

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDb.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)
	mockPasswordValidator.On("ValidatePassword", mock.Anything, newPassword).Return(nil)
	mockDb.On("UpdateUser", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil)
	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockAuditLogger.On("Log", constants.AuditChangedPassword, mock.MatchedBy(func(m map[string]interface{}) bool {
		return m["userId"] == int64(1) && m["loggedInUser"] == user.Subject.String()
	})).Return(nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/account_change_password.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["savedSuccessfully"] == true
	})).Return(nil)

	handler := HandleAccountChangePasswordPost(mockHttpHelper, mockAuthHelper, mockDb, mockPasswordValidator, mockAuditLogger)

	form := url.Values{}
	form.Add("currentPassword", password)
	form.Add("newPassword", newPassword)
	form.Add("newPasswordConfirmation", newPassword)

	req, _ := http.NewRequest("POST", "/account/change-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
		IdToken: &oauth.JwtToken{
			Claims: jwt.MapClaims{
				"sub": user.Subject.String(),
			},
		},
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockHttpHelper.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDb.AssertExpectations(t)
	mockPasswordValidator.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
}

func TestHandleAccountChangePasswordGet_Unauthenticated(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("")

	handler := HandleAccountChangePasswordGet(mockHttpHelper, mockAuthHelper)

	req, _ := http.NewRequest("GET", "/account/change-password", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.GetAdminConsole().BaseURL+"/unauthorized", rr.Header().Get("Location"))

	mockAuthHelper.AssertExpectations(t)
	mockHttpHelper.AssertNotCalled(t, "RenderTemplate")
}

func TestHandleAccountChangePasswordPost_Unauthenticated(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDb := mocks_data.NewDatabase(t)
	mockPasswordValidator := mocks_validator.NewPasswordValidator(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("")

	handler := HandleAccountChangePasswordPost(mockHttpHelper, mockAuthHelper, mockDb, mockPasswordValidator, mockAuditLogger)

	form := "currentPassword=oldpass&newPassword=newpass&newPasswordConfirmation=newpass"
	req, _ := http.NewRequest("POST", "/account/change-password", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.GetAdminConsole().BaseURL+"/unauthorized", rr.Header().Get("Location"))

	mockAuthHelper.AssertExpectations(t)
	mockHttpHelper.AssertNotCalled(t, "RenderTemplate")
	mockDb.AssertNotCalled(t, "GetUserBySubject")
	mockPasswordValidator.AssertNotCalled(t, "ValidatePassword")
	mockAuditLogger.AssertNotCalled(t, "Log")
}
