package accounthandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_otp "github.com/leodip/goiabada/core/otp/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
)

func TestHandleAccountOtpGet_OTPDisabled(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockOtpSecretGenerator := mocks_otp.NewOtpSecretGenerator(t)

	user := &models.User{
		Id:      1,
		Subject: uuid.New(),
		Email:   "test@example.com",
	}

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)
	mockOtpSecretGenerator.On("GenerateOTPSecret", user.Email, mock.Anything).Return("base64image", "secretkey", nil)

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/account_otp.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["otpEnabled"] == false &&
			data["base64Image"] == "base64image" &&
			data["secretKey"] == "secretkey"
	})).Return(nil)

	handler := HandleAccountOtpGet(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockOtpSecretGenerator)

	req, _ := http.NewRequest("GET", "/account/otp", nil)
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{
		AppName: "TestApp",
	}))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockOtpSecretGenerator.AssertExpectations(t)
}

func TestHandleAccountOtpGet_OTPEnabled(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockOtpSecretGenerator := mocks_otp.NewOtpSecretGenerator(t)

	user := &models.User{
		Id:         1,
		Subject:    uuid.New(),
		Email:      "test@example.com",
		OTPEnabled: true,
	}

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/account_otp.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["otpEnabled"] == true
	})).Return(nil)

	handler := HandleAccountOtpGet(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockOtpSecretGenerator)

	req, _ := http.NewRequest("GET", "/account/otp", nil)
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{
		AppName: "TestApp",
	}))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockOtpSecretGenerator.AssertExpectations(t)
}

func TestHandleAccountOtpGet_NotAuthorized(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockOtpSecretGenerator := mocks_otp.NewOtpSecretGenerator(t)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("")

	handler := HandleAccountOtpGet(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockOtpSecretGenerator)

	req, err := http.NewRequest("GET", "/account/otp", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)

	expectedURL := config.Get().BaseURL + "/unauthorized"
	assert.Equal(t, expectedURL, rr.Header().Get("Location"))

	mockAuthHelper.AssertExpectations(t)

	mockHttpHelper.AssertNotCalled(t, "RenderTemplate")
	mockDB.AssertNotCalled(t, "GetUserBySubject")
	mockSessionStore.AssertNotCalled(t, "Get")
	mockOtpSecretGenerator.AssertNotCalled(t, "GenerateOTPSecret")
}

func TestHandleAccountOtpPost_NotAuthorized(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("")

	handler := HandleAccountOtpPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockSessionStore, mockAuditLogger)

	req, _ := http.NewRequest("POST", "/account/otp", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.Get().BaseURL+"/unauthorized", rr.Header().Get("Location"))

	mockAuthHelper.AssertExpectations(t)
	mockHttpHelper.AssertNotCalled(t, "RenderTemplate")
	mockDB.AssertNotCalled(t, "GetUserBySubject")
	mockSessionStore.AssertNotCalled(t, "Get")
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAccountOtpPost_OtpIsEnabledAndVerifyPasswordHashFails(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	user := &models.User{
		Id:           1,
		Subject:      uuid.New(),
		OTPEnabled:   true,
		PasswordHash: "$2a$10$invalid_hash",
	}

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/account_otp.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "Authentication failed. Check your password and try again." &&
			data["otpEnabled"] == true
	})).Return(nil)

	handler := HandleAccountOtpPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockSessionStore, mockAuditLogger)

	form := url.Values{}
	form.Add("password", "wrongpassword")
	req, _ := http.NewRequest("POST", "/account/otp", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, jwt.MapClaims{
		"sub": user.Subject.String(),
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockSessionStore.AssertNotCalled(t, "Get")
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAccountOtpPost_OtpIsEnabledAndVerifyPasswordHashSucceeds(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	password := "correctpassword"
	passwordHash, err := hashutil.HashPassword(password)
	assert.NoError(t, err)

	user := &models.User{
		Id:           1,
		Subject:      uuid.New(),
		OTPEnabled:   true,
		PasswordHash: passwordHash,
	}

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)
	mockDB.On("UpdateUser", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
		return u.Id == user.Id && !u.OTPEnabled && u.OTPSecret == ""
	})).Return(nil)

	mockAuditLogger.On("Log", constants.AuditDisabledOTP, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["userId"] == user.Id
	})).Return(nil)

	mockSession := &sessions.Session{
		Values: make(map[interface{}]interface{}),
	}
	mockSession.Values[constants.SessionKeySessionIdentifier] = "session_identifier"
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

	mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "session_identifier").Return(&models.UserSession{}, nil)
	mockDB.On("UpdateUserSession", mock.Anything, mock.MatchedBy(func(us *models.UserSession) bool {
		return us.Level2AuthConfigHasChanged == true
	})).Return(nil)

	handler := HandleAccountOtpPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockSessionStore, mockAuditLogger)

	form := url.Values{}
	form.Add("password", "correctpassword")
	req, _ := http.NewRequest("POST", "/account/otp", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, jwt.MapClaims{
		"sub": user.Subject.String(),
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.Get().BaseURL+"/account/otp", rr.Header().Get("Location"))

	mockHttpHelper.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
}

func TestHandleAccountOtpPost_OtpIsNotEnabledAndPasswordIsInvalid(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	user := &models.User{
		Id:           1,
		Subject:      uuid.New(),
		OTPEnabled:   false,
		PasswordHash: "$2a$10$valid_hash",
	}

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)

	mockSession := &sessions.Session{
		Values: make(map[interface{}]interface{}),
	}
	mockSession.Values[constants.SessionKeyOTPSecret] = "test_secret"
	mockSession.Values[constants.SessionKeyOTPImage] = "test_image"
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/account_otp.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "Authentication failed. Check your password and try again." &&
			data["otpEnabled"] == false &&
			data["base64Image"] == "test_image" &&
			data["secretKey"] == "test_secret"
	})).Return(nil)

	handler := HandleAccountOtpPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockSessionStore, mockAuditLogger)

	form := url.Values{}
	form.Add("password", "correctpassword")
	form.Add("otp", "invalid_otp")
	req, _ := http.NewRequest("POST", "/account/otp", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, jwt.MapClaims{
		"sub": user.Subject.String(),
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAccountOtpPost_OtpIsNotEnabledAndOtpCodeIsInvalid(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	password := "correctpassword"
	passwordHash, err := hashutil.HashPassword(password)
	assert.NoError(t, err)

	user := &models.User{
		Id:           1,
		Subject:      uuid.New(),
		OTPEnabled:   false,
		PasswordHash: passwordHash,
	}

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)

	mockSession := &sessions.Session{
		Values: make(map[interface{}]interface{}),
	}
	mockSession.Values[constants.SessionKeyOTPSecret] = "test_secret"
	mockSession.Values[constants.SessionKeyOTPImage] = "test_image"
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/account_otp.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "Incorrect OTP Code. OTP codes are time-sensitive and change every 30 seconds. Make sure you're using the most recent code generated by your authenticator app." &&
			data["otpEnabled"] == false &&
			data["base64Image"] == "test_image" &&
			data["secretKey"] == "test_secret"
	})).Return(nil)

	handler := HandleAccountOtpPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockSessionStore, mockAuditLogger)

	form := url.Values{}
	form.Add("password", "correctpassword")
	form.Add("otp", "invalid_otp")
	req, _ := http.NewRequest("POST", "/account/otp", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, jwt.MapClaims{
		"sub": user.Subject.String(),
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAccountOtpPost_OtpIsNotEnabledAndOtpCodeIsValid(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	password := "correctpassword"
	passwordHash, err := hashutil.HashPassword(password)
	assert.NoError(t, err)

	user := &models.User{
		Id:           1,
		Subject:      uuid.New(),
		OTPEnabled:   false,
		PasswordHash: passwordHash,
	}

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
	mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Goiabada",
		AccountName: user.Subject.String(),
	})
	assert.NoError(t, err)
	otpSecret := key.Secret()

	mockSession := &sessions.Session{
		Values: make(map[interface{}]interface{}),
	}
	mockSession.Values[constants.SessionKeyOTPSecret] = otpSecret
	mockSession.Values[constants.SessionKeyOTPImage] = "test_image"
	mockSession.Values[constants.SessionKeySessionIdentifier] = "session_identifier"
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

	mockDB.On("UpdateUser", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
		return u.Id == user.Id && u.OTPEnabled && u.OTPSecret == otpSecret
	})).Return(nil)

	mockAuditLogger.On("Log", constants.AuditEnabledOTP, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["userId"] == user.Id
	})).Return(nil)

	mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "session_identifier").Return(&models.UserSession{}, nil)
	mockDB.On("UpdateUserSession", mock.Anything, mock.MatchedBy(func(us *models.UserSession) bool {
		return us.Level2AuthConfigHasChanged == true
	})).Return(nil)

	handler := HandleAccountOtpPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockSessionStore, mockAuditLogger)

	otp, err := totp.GenerateCode(otpSecret, time.Now())
	assert.NoError(t, err)

	form := url.Values{}
	form.Add("password", "correctpassword")
	form.Add("otp", otp)
	req, _ := http.NewRequest("POST", "/account/otp", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, jwt.MapClaims{
		"sub": user.Subject.String(),
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.Get().BaseURL+"/account/otp", rr.Header().Get("Location"))

	mockHttpHelper.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
}
