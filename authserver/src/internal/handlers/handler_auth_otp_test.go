package handlers

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/enums"
	"github.com/leodip/goiabada/authserver/internal/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oauth"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandleAuthOtpGet(t *testing.T) {
	t.Run("Cannot get a session", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		httpSession := mocks.NewStore(t)
		authHelper := mocks.NewAuthHelper(t)
		database := mocks.NewDatabase(t)
		otpSecretGenerator := mocks.NewOtpSecretGenerator(t)

		handler := HandleAuthOtpGet(httpHelper, httpSession, authHelper, database, otpSecretGenerator)

		req, _ := http.NewRequest("GET", "/auth/otp", nil)
		rr := httptest.NewRecorder()

		httpSession.On("Get", mock.Anything, constants.SessionName).Return(nil, errors.New("session error"))

		httpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool { return err.Error() == "session error" }),
		).Return()

		handler.ServeHTTP(rr, req)

		httpSession.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	t.Run("Cannot get auth context", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		httpSession := mocks.NewStore(t)
		authHelper := mocks.NewAuthHelper(t)
		database := mocks.NewDatabase(t)
		otpSecretGenerator := mocks.NewOtpSecretGenerator(t)

		handler := HandleAuthOtpGet(httpHelper, httpSession, authHelper, database, otpSecretGenerator)

		req, _ := http.NewRequest("GET", "/auth/otp", nil)
		rr := httptest.NewRecorder()

		mockSession := &sessions.Session{}
		httpSession.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		authHelper.On("GetAuthContext", req).Return(nil, errors.New("auth context error"))

		httpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool { return err.Error() == "auth context error" }),
		).Return()

		handler.ServeHTTP(rr, req)

		httpSession.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	t.Run("Get User is nil", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		httpSession := mocks.NewStore(t)
		authHelper := mocks.NewAuthHelper(t)
		database := mocks.NewDatabase(t)
		otpSecretGenerator := mocks.NewOtpSecretGenerator(t)

		handler := HandleAuthOtpGet(httpHelper, httpSession, authHelper, database, otpSecretGenerator)

		req, _ := http.NewRequest("GET", "/auth/otp", nil)
		rr := httptest.NewRecorder()

		mockSession := &sessions.Session{}
		httpSession.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		authContext := &oauth.AuthContext{UserId: 1}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		database.On("GetUserById", mock.Anything, int64(1)).Return(nil, nil)

		httpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool { return err.Error() == "user not found" }),
		).Return()

		handler.ServeHTTP(rr, req)

		httpSession.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	t.Run("Get User errors", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		httpSession := mocks.NewStore(t)
		authHelper := mocks.NewAuthHelper(t)
		database := mocks.NewDatabase(t)
		otpSecretGenerator := mocks.NewOtpSecretGenerator(t)

		handler := HandleAuthOtpGet(httpHelper, httpSession, authHelper, database, otpSecretGenerator)

		req, _ := http.NewRequest("GET", "/auth/otp", nil)
		rr := httptest.NewRecorder()

		mockSession := &sessions.Session{}
		httpSession.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		authContext := &oauth.AuthContext{UserId: 1}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		database.On("GetUserById", mock.Anything, int64(1)).Return(nil, errors.New("database error"))

		httpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool { return err.Error() == "database error" }),
		).Return()

		handler.ServeHTTP(rr, req)

		httpSession.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	t.Run("Cant generate otp", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		httpSession := mocks.NewStore(t)
		authHelper := mocks.NewAuthHelper(t)
		database := mocks.NewDatabase(t)
		otpSecretGenerator := mocks.NewOtpSecretGenerator(t)

		handler := HandleAuthOtpGet(httpHelper, httpSession, authHelper, database, otpSecretGenerator)

		req, _ := http.NewRequest("GET", "/auth/otp", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			UserId: 123,
		}

		mockSession := &sessions.Session{
			Values: make(map[interface{}]interface{}),
		}

		user := &models.User{
			Id:         123,
			Email:      "test@example.com",
			OTPEnabled: false,
		}

		settings := &models.Settings{
			AppName: "TestApp",
		}

		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", req).Return(authContext, nil)
		httpSession.On("Get", req, constants.SessionName).Return(mockSession, nil)
		database.On("GetUserById", (*sql.Tx)(nil), int64(123)).Return(user, nil)
		otpSecretGenerator.On("GenerateOTPSecret", "test@example.com", "TestApp").Return("", "", errors.New("otp generation error"))

		httpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool { return err.Error() == "otp generation error" }),
		).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		httpSession.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		otpSecretGenerator.AssertExpectations(t)
	})

	t.Run("Session can't be saved", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		httpSession := mocks.NewStore(t)
		authHelper := mocks.NewAuthHelper(t)
		database := mocks.NewDatabase(t)
		otpSecretGenerator := mocks.NewOtpSecretGenerator(t)

		handler := HandleAuthOtpGet(httpHelper, httpSession, authHelper, database, otpSecretGenerator)

		req, _ := http.NewRequest("GET", "/auth/otp", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			UserId: 123,
		}

		mockSession := &sessions.Session{
			Values: make(map[interface{}]interface{}),
		}

		user := &models.User{
			Id:         123,
			Email:      "test@example.com",
			OTPEnabled: false,
		}

		settings := &models.Settings{
			AppName: "TestApp",
		}

		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", req).Return(authContext, nil)
		httpSession.On("Get", req, constants.SessionName).Return(mockSession, nil)
		database.On("GetUserById", (*sql.Tx)(nil), int64(123)).Return(user, nil)
		otpSecretGenerator.On("GenerateOTPSecret", "test@example.com", "TestApp").Return("base64image", "secretkey", nil)

		httpSession.On("Save", req, rr, mock.MatchedBy(func(s *sessions.Session) bool {
			return s.Values[constants.SessionKeyOTPImage] == "base64image" &&
				s.Values[constants.SessionKeyOTPSecret] == "secretkey"
		})).Return(errors.New("session save error"))

		httpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool { return err.Error() == "session save error" }),
		).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		httpSession.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		otpSecretGenerator.AssertExpectations(t)
	})

	t.Run("Must enroll first", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		httpSession := mocks.NewStore(t)
		authHelper := mocks.NewAuthHelper(t)
		database := mocks.NewDatabase(t)
		otpSecretGenerator := mocks.NewOtpSecretGenerator(t)

		handler := HandleAuthOtpGet(httpHelper, httpSession, authHelper, database, otpSecretGenerator)

		req, _ := http.NewRequest("GET", "/auth/otp", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			UserId: 123,
		}

		mockSession := &sessions.Session{
			Values: make(map[interface{}]interface{}),
		}

		user := &models.User{
			Id:         123,
			Email:      "test@example.com",
			OTPEnabled: false,
		}

		settings := &models.Settings{
			AppName: "TestApp",
		}

		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", req).Return(authContext, nil)
		httpSession.On("Get", req, constants.SessionName).Return(mockSession, nil)
		database.On("GetUserById", (*sql.Tx)(nil), int64(123)).Return(user, nil)
		otpSecretGenerator.On("GenerateOTPSecret", "test@example.com", "TestApp").Return("base64image", "secretkey", nil)
		httpSession.On("Save", req, rr, mockSession).Return(nil)

		// Validate the 'bind' parameter passed to RenderTemplate
		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp_enrollment.html",
			mock.MatchedBy(func(bind map[string]interface{}) bool {
				baseImage, hasBaseImage := bind["base64Image"]
				secretKey, hasSecretKey := bind["secretKey"]
				return hasBaseImage && hasSecretKey &&
					baseImage == "base64image" && secretKey == "secretkey"
			})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, "base64image", mockSession.Values[constants.SessionKeyOTPImage])
		assert.Equal(t, "secretkey", mockSession.Values[constants.SessionKeyOTPSecret])

		httpHelper.AssertExpectations(t)
		httpSession.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		otpSecretGenerator.AssertExpectations(t)
	})

	t.Run("OTP is enabled for the user", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		httpSession := mocks.NewStore(t)
		authHelper := mocks.NewAuthHelper(t)
		database := mocks.NewDatabase(t)
		otpSecretGenerator := mocks.NewOtpSecretGenerator(t)

		handler := HandleAuthOtpGet(httpHelper, httpSession, authHelper, database, otpSecretGenerator)

		req, err := http.NewRequest("GET", "/auth/otp", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			UserId: 123,
		}

		user := &models.User{
			Id:         123,
			OTPEnabled: true,
		}

		// Set up mock expectations
		mockSession := &sessions.Session{
			Values: make(map[interface{}]interface{}),
		}

		// Add OTP-related values to the session
		mockSession.Values[constants.SessionKeyOTPImage] = "some-image-data"
		mockSession.Values[constants.SessionKeyOTPSecret] = "some-secret-data"

		httpSession.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
		authHelper.On("GetAuthContext", req).Return(authContext, nil)
		database.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)
		httpSession.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

		httpHelper.On("RenderTemplate",
			mock.Anything,
			mock.Anything,
			"/layouts/auth_layout.html",
			"/auth_otp.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				_, hasError := data["error"]
				_, hasCsrfField := data["csrfField"]
				return hasError && hasCsrfField
			}),
		).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertExpectations(t)
		httpSession.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		otpSecretGenerator.AssertExpectations(t)

		// Assert that OTP-related session values are deleted
		assert.NotContains(t, mockSession.Values, constants.SessionKeyOTPImage)
		assert.NotContains(t, mockSession.Values, constants.SessionKeyOTPSecret)
	})
}

func TestHandleAuthOtpPost(t *testing.T) {
	t.Run("Unable to get auth context", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		httpSession := mocks.NewStore(t)
		authHelper := mocks.NewAuthHelper(t)
		userSessionManager := mocks.NewUserSessionManager(t)
		database := mocks.NewDatabase(t)
		auditLogger := mocks.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, userSessionManager, database, auditLogger)

		req, _ := http.NewRequest("POST", "/auth/otp", nil)
		rr := httptest.NewRecorder()

		authHelper.On("GetAuthContext", req).Return(nil, errors.New("auth context error"))

		httpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool { return err.Error() == "auth context error" }),
		).Return()

		handler.ServeHTTP(rr, req)

		authHelper.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	t.Run("Unable to get a session", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		httpSession := mocks.NewStore(t)
		authHelper := mocks.NewAuthHelper(t)
		userSessionManager := mocks.NewUserSessionManager(t)
		database := mocks.NewDatabase(t)
		auditLogger := mocks.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, userSessionManager, database, auditLogger)

		req, _ := http.NewRequest("POST", "/auth/otp", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{UserId: 1}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		httpSession.On("Get", mock.Anything, constants.SessionName).Return(nil, errors.New("session error"))

		httpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool { return err.Error() == "session error" }),
		).Return()

		handler.ServeHTTP(rr, req)

		authHelper.AssertExpectations(t)
		httpSession.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	t.Run("Get user gives error", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		httpSession := mocks.NewStore(t)
		authHelper := mocks.NewAuthHelper(t)
		userSessionManager := mocks.NewUserSessionManager(t)
		database := mocks.NewDatabase(t)
		auditLogger := mocks.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, userSessionManager, database, auditLogger)

		req, _ := http.NewRequest("POST", "/auth/otp", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{UserId: 1}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		mockSession := &sessions.Session{}
		httpSession.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		database.On("GetUserById", mock.Anything, int64(1)).Return(nil, errors.New("database error"))

		httpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool { return err.Error() == "database error" }),
		).Return()

		handler.ServeHTTP(rr, req)

		authHelper.AssertExpectations(t)
		httpSession.AssertExpectations(t)
		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	t.Run("Get user returns nil", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		httpSession := mocks.NewStore(t)
		authHelper := mocks.NewAuthHelper(t)
		userSessionManager := mocks.NewUserSessionManager(t)
		database := mocks.NewDatabase(t)
		auditLogger := mocks.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, userSessionManager, database, auditLogger)

		req, _ := http.NewRequest("POST", "/auth/otp", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{UserId: 1}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		mockSession := &sessions.Session{}
		httpSession.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		database.On("GetUserById", mock.Anything, int64(1)).Return(nil, nil)

		httpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool { return err.Error() == "user not found" }),
		).Return()

		handler.ServeHTTP(rr, req)

		authHelper.AssertExpectations(t)
		httpSession.AssertExpectations(t)
		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	t.Run("User account is disabled", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		httpSession := mocks.NewStore(t)
		authHelper := mocks.NewAuthHelper(t)
		userSessionManager := mocks.NewUserSessionManager(t)
		database := mocks.NewDatabase(t)
		auditLogger := mocks.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, userSessionManager, database, auditLogger)

		form := url.Values{}
		form.Add("otp", "123456")
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{UserId: 1}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		mockSession := &sessions.Session{}
		httpSession.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		disabledUser := &models.User{Id: 1, Email: "test@example.com", OTPEnabled: true, Enabled: false}
		database.On("GetUserById", mock.Anything, int64(1)).Return(disabledUser, nil)

		auditLogger.On("Log", constants.AuditUserDisabled, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(1)
		})).Return()

		expectedErrorMessage := "Your account is disabled."

		httpHelper.On("RenderTemplate",
			mock.Anything,
			mock.Anything,
			"/layouts/auth_layout.html",
			"/auth_otp.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				return data["error"] == expectedErrorMessage
			}),
		).Return(nil)

		handler.ServeHTTP(rr, req)

		authHelper.AssertExpectations(t)
		httpSession.AssertExpectations(t)
		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
		auditLogger.AssertExpectations(t)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("OTP code was not given", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		httpSession := mocks.NewStore(t)
		authHelper := mocks.NewAuthHelper(t)
		userSessionManager := mocks.NewUserSessionManager(t)
		database := mocks.NewDatabase(t)
		auditLogger := mocks.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, userSessionManager, database, auditLogger)

		form := url.Values{}
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{UserId: 1}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		mockSession := &sessions.Session{}
		httpSession.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		user := &models.User{Id: 1, Email: "test@example.com", OTPEnabled: true, Enabled: true}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		httpHelper.On("RenderTemplate",
			mock.Anything,
			mock.Anything,
			"/layouts/auth_layout.html",
			"/auth_otp.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				return data["error"] == "OTP code is required."
			}),
		).Return(nil)

		handler.ServeHTTP(rr, req)

		authHelper.AssertExpectations(t)
		httpSession.AssertExpectations(t)
		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	t.Run("OTP enabled but invalid code", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		httpSession := mocks.NewStore(t)
		authHelper := mocks.NewAuthHelper(t)
		userSessionManager := mocks.NewUserSessionManager(t)
		database := mocks.NewDatabase(t)
		auditLogger := mocks.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, userSessionManager, database, auditLogger)

		// Generate a valid OTP secret
		secret, _ := totp.Generate(totp.GenerateOpts{
			Issuer:      "Test",
			AccountName: "test@example.com",
		})

		// Use an invalid OTP code (not generated from the secret)
		invalidOTP := "123456"

		form := url.Values{}
		form.Add("otp", invalidOTP)
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{UserId: 1}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		mockSession := &sessions.Session{}
		httpSession.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		user := &models.User{Id: 1, Email: "test@example.com", Enabled: true, OTPEnabled: true, OTPSecret: secret.Secret()}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		expectedErrorMessage := "Incorrect OTP Code. OTP codes are time-sensitive and change every 30 seconds. Make sure you're using the most recent code generated by your authenticator app."

		httpHelper.On("RenderTemplate",
			mock.Anything,
			mock.Anything,
			"/layouts/auth_layout.html",
			"/auth_otp.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				return data["error"] == expectedErrorMessage
			}),
		).Return(nil)

		auditLogger.On("Log", constants.AuditAuthFailedOtp, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(1)
		})).Return()

		handler.ServeHTTP(rr, req)

		authHelper.AssertExpectations(t)
		httpSession.AssertExpectations(t)
		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
		auditLogger.AssertExpectations(t)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("OTP not enabled and invalid code during enrollment", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		httpSession := mocks.NewStore(t)
		authHelper := mocks.NewAuthHelper(t)
		userSessionManager := mocks.NewUserSessionManager(t)
		database := mocks.NewDatabase(t)
		auditLogger := mocks.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, userSessionManager, database, auditLogger)

		// Generate a valid OTP secret
		secret, _ := totp.Generate(totp.GenerateOpts{
			Issuer:      "Test",
			AccountName: "test@example.com",
		})

		// Use an invalid OTP code (not generated from the secret)
		invalidOTP := "123456"

		form := url.Values{}
		form.Add("otp", invalidOTP)
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{UserId: 1}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		mockSession := &sessions.Session{
			Values: make(map[interface{}]interface{}),
		}
		mockSession.Values[constants.SessionKeyOTPSecret] = secret.Secret()
		mockSession.Values[constants.SessionKeyOTPImage] = "test_image_data"
		httpSession.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		user := &models.User{Id: 1, Email: "test@example.com", Enabled: true, OTPEnabled: false}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		expectedErrorMessage := "Incorrect OTP Code. OTP codes are time-sensitive and change every 30 seconds. Make sure you're using the most recent code generated by your authenticator app."

		httpHelper.On("RenderTemplate",
			mock.Anything,
			mock.Anything,
			"/layouts/auth_layout.html",
			"/auth_otp_enrollment.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				return data["error"] == expectedErrorMessage &&
					data["base64Image"] == "test_image_data" &&
					data["secretKey"] == secret.Secret()
			}),
		).Return(nil)

		auditLogger.On("Log", constants.AuditAuthFailedOtp, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(1)
		})).Return()

		handler.ServeHTTP(rr, req)

		authHelper.AssertExpectations(t)
		httpSession.AssertExpectations(t)
		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
		auditLogger.AssertExpectations(t)

		assert.Equal(t, http.StatusOK, rr.Code)

		// Verify that the user's OTPEnabled status hasn't changed
		assert.False(t, user.OTPEnabled)
	})

	t.Run("OTP not enabled, valid code, get client errors", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		httpSession := mocks.NewStore(t)
		authHelper := mocks.NewAuthHelper(t)
		userSessionManager := mocks.NewUserSessionManager(t)
		database := mocks.NewDatabase(t)
		auditLogger := mocks.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, userSessionManager, database, auditLogger)

		// Generate a valid OTP secret
		key, _ := totp.Generate(totp.GenerateOpts{
			Issuer:      "Test",
			AccountName: "test@example.com",
		})
		secret := key.Secret()

		// Generate a valid OTP code
		validOTP, _ := totp.GenerateCode(secret, time.Now())

		form := url.Values{}
		form.Add("otp", validOTP)
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{UserId: 1, ClientId: "test-client"}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		mockSession := &sessions.Session{
			Values: make(map[interface{}]interface{}),
		}
		mockSession.Values[constants.SessionKeyOTPSecret] = secret
		mockSession.Values[constants.SessionKeyOTPImage] = "test_image_data"
		httpSession.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		user := &models.User{Id: 1, Email: "test@example.com", OTPEnabled: false, Enabled: true}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		// Mock updating the user
		database.On("UpdateUser", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
			return u.Id == 1 && u.OTPEnabled && u.OTPSecret == secret
		})).Return(nil)

		// Mock the client lookup to return an error
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(nil, errors.New("client lookup failed"))

		// Expect an internal server error
		httpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool {
				return err.Error() == "client lookup failed"
			}),
		).Return()

		auditLogger.On("Log", constants.AuditAuthSuccessOtp, mock.Anything).Return()

		handler.ServeHTTP(rr, req)

		authHelper.AssertExpectations(t)
		httpSession.AssertExpectations(t)
		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
		auditLogger.AssertExpectations(t)

		// Verify that the user's OTPEnabled status has changed
		assert.True(t, user.OTPEnabled)
		assert.Equal(t, secret, user.OTPSecret)
	})

	t.Run("OTP not enabled, valid code, client not found", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		httpSession := mocks.NewStore(t)
		authHelper := mocks.NewAuthHelper(t)
		userSessionManager := mocks.NewUserSessionManager(t)
		database := mocks.NewDatabase(t)
		auditLogger := mocks.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, userSessionManager, database, auditLogger)

		// Generate a valid OTP secret
		key, _ := totp.Generate(totp.GenerateOpts{
			Issuer:      "Test",
			AccountName: "test@example.com",
		})
		secret := key.Secret()

		// Generate a valid OTP code
		validOTP, _ := totp.GenerateCode(secret, time.Now())

		form := url.Values{}
		form.Add("otp", validOTP)
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{UserId: 1, ClientId: "test-client"}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		mockSession := &sessions.Session{
			Values: make(map[interface{}]interface{}),
		}
		mockSession.Values[constants.SessionKeyOTPSecret] = secret
		mockSession.Values[constants.SessionKeyOTPImage] = "test_image_data"
		httpSession.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		user := &models.User{Id: 1, Email: "test@example.com", OTPEnabled: false, Enabled: true}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		// Mock updating the user
		database.On("UpdateUser", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
			return u.Id == 1 && u.OTPEnabled && u.OTPSecret == secret
		})).Return(nil)

		// Mock the client lookup to return nil (client not found)
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(nil, nil)

		// Expect an internal server error
		httpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool {
				return err.Error() == "client test-client not found"
			}),
		).Return()

		auditLogger.On("Log", constants.AuditAuthSuccessOtp, mock.Anything).Return()

		handler.ServeHTTP(rr, req)

		authHelper.AssertExpectations(t)
		httpSession.AssertExpectations(t)
		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
		auditLogger.AssertExpectations(t)

		// Verify that the user's OTPEnabled status has changed
		assert.True(t, user.OTPEnabled)
		assert.Equal(t, secret, user.OTPSecret)
	})

	t.Run("Error when starting new user session", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		httpSession := mocks.NewStore(t)
		authHelper := mocks.NewAuthHelper(t)
		userSessionManager := mocks.NewUserSessionManager(t)
		database := mocks.NewDatabase(t)
		auditLogger := mocks.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, userSessionManager, database, auditLogger)

		// Generate a valid OTP secret
		key, _ := totp.Generate(totp.GenerateOpts{
			Issuer:      "Test",
			AccountName: "test@example.com",
		})
		secret := key.Secret()

		// Generate a valid OTP code
		validOTP, _ := totp.GenerateCode(secret, time.Now())

		form := url.Values{}
		form.Add("otp", validOTP)
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			UserId:             1,
			ClientId:           "test-client",
			RequestedAcrValues: enums.AcrLevel2.String(),
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		mockSession := &sessions.Session{
			Values: make(map[interface{}]interface{}),
		}
		mockSession.Values[constants.SessionKeyOTPSecret] = secret
		mockSession.Values[constants.SessionKeyOTPImage] = "test_image_data"
		httpSession.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		user := &models.User{Id: 1, Email: "test@example.com", OTPEnabled: true, Enabled: true, OTPSecret: secret}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{Id: 1, ClientIdentifier: "test-client", DefaultAcrLevel: enums.AcrLevel1}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		// Mock session creation to return an error
		sessionError := errors.New("failed to create user session")
		userSessionManager.On("StartNewUserSession",
			mock.Anything,
			mock.Anything,
			int64(1),
			int64(1),
			"pwd otp",
			enums.AcrLevel2.String(),
		).Return(nil, sessionError)

		// Expect an internal server error
		httpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool {
				return err.Error() == "failed to create user session"
			}),
		).Return()

		auditLogger.On("Log", constants.AuditAuthSuccessOtp, mock.Anything).Return()

		handler.ServeHTTP(rr, req)

		authHelper.AssertExpectations(t)
		httpSession.AssertExpectations(t)
		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
	})

	t.Run("Success redirects to consent", func(t *testing.T) {
		httpHelper := mocks.NewHttpHelper(t)
		httpSession := mocks.NewStore(t)
		authHelper := mocks.NewAuthHelper(t)
		userSessionManager := mocks.NewUserSessionManager(t)
		database := mocks.NewDatabase(t)
		auditLogger := mocks.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, userSessionManager, database, auditLogger)

		// Generate a valid OTP secret
		key, _ := totp.Generate(totp.GenerateOpts{
			Issuer:      "Test",
			AccountName: "test@example.com",
		})
		secret := key.Secret()

		// Generate a valid OTP code
		validOTP, _ := totp.GenerateCode(secret, time.Now())

		form := url.Values{}
		form.Add("otp", validOTP)
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			UserId:             1,
			ClientId:           "test-client",
			RequestedAcrValues: enums.AcrLevel2.String(),
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		mockSession := &sessions.Session{
			Values: make(map[interface{}]interface{}),
		}
		mockSession.Values[constants.SessionKeyOTPSecret] = secret
		mockSession.Values[constants.SessionKeyOTPImage] = "test_image_data"
		httpSession.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		user := &models.User{Id: 1, Email: "test@example.com", OTPEnabled: true, Enabled: true, OTPSecret: secret}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{Id: 1, ClientIdentifier: "test-client", DefaultAcrLevel: enums.AcrLevel1}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		userSessionManager.On("StartNewUserSession",
			mock.Anything,
			mock.Anything,
			int64(1),
			int64(1),
			"pwd otp",
			enums.AcrLevel2.String(),
		).Return(&models.UserSession{}, nil)

		auditLogger.On("Log", constants.AuditAuthSuccessOtp, mock.Anything).Return()
		auditLogger.On("Log", constants.AuditStartedNewUserSesson, mock.Anything).Return()

		authHelper.On("SaveAuthContext", mock.Anything, mock.Anything, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthCompleted && ac.AcrLevel == enums.AcrLevel2.String() && ac.AuthMethods == "pwd otp"
		})).Return(nil)

		// Set up the config package
		config.AuthServerBaseUrl = "http://localhost:8080"

		handler.ServeHTTP(rr, req)

		authHelper.AssertExpectations(t)
		httpSession.AssertExpectations(t)
		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)

		// Check that we got a redirect to the consent page
		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, "http://localhost:8080/auth/consent", rr.Header().Get("Location"))
	})
}
