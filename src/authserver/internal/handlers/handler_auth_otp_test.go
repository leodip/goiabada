package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_otp "github.com/leodip/goiabada/core/otp/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
)

func TestHandleAuthOtpGet(t *testing.T) {
	t.Run("Error when getting GetAuthContext", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		otpSecretGenerator := mocks_otp.NewOtpSecretGenerator(t)

		handler := HandleAuthOtpGet(httpHelper, httpSession, authHelper, database, otpSecretGenerator)

		req, _ := http.NewRequest("GET", "/auth/otp", nil)
		rr := httptest.NewRecorder()

		expectedError := &customerrors.ErrorDetail{}
		authHelper.On("GetAuthContext", mock.Anything).Return(nil, expectedError)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err == expectedError
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Unexpected AuthState", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		otpSecretGenerator := mocks_otp.NewOtpSecretGenerator(t)

		handler := HandleAuthOtpGet(httpHelper, httpSession, authHelper, database, otpSecretGenerator)

		req, _ := http.NewRequest("GET", "/auth/otp", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateInitial,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "authContext.AuthState is not level2_otp"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("OTP enabled user", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		otpSecretGenerator := mocks_otp.NewOtpSecretGenerator(t)

		handler := HandleAuthOtpGet(httpHelper, httpSession, authHelper, database, otpSecretGenerator)

		req, _ := http.NewRequest("GET", "/auth/otp", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel2OTP,
			UserId:    1,
			ClientId:  "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		session := sessions.NewSession(httpSession, constants.AuthServerSessionName)
		httpSession.On("Get", req, constants.AuthServerSessionName).Return(session, nil)
		httpSession.On("Save", req, rr, session).Return(nil)

		user := &models.User{
			Id:         1,
			OTPEnabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		httpHelper.On("RenderTemplate",
			mock.Anything,
			mock.Anything,
			"/layouts/auth_layout.html",
			"/auth_otp.html",
			mock.MatchedBy(func(bind map[string]interface{}) bool {
				if len(bind) != 8 {
					return false
				}
				if _, ok := bind["csrfField"]; !ok {
					return false
				}
				if err, ok := bind["error"]; !ok || err != nil {
					return false
				}
				if _, ok := bind["layoutShowClientSection"]; !ok {
					return false
				}
				if _, ok := bind["layoutClientName"]; !ok {
					return false
				}
				if _, ok := bind["layoutHasClientLogo"]; !ok {
					return false
				}
				if _, ok := bind["layoutClientLogoUrl"]; !ok {
					return false
				}
				if _, ok := bind["layoutClientDescription"]; !ok {
					return false
				}
				if _, ok := bind["layoutClientWebsiteUrl"]; !ok {
					return false
				}
				return true
			}),
		).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		httpSession.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("OTP not enabled user", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		otpSecretGenerator := mocks_otp.NewOtpSecretGenerator(t)

		handler := HandleAuthOtpGet(httpHelper, httpSession, authHelper, database, otpSecretGenerator)

		req, _ := http.NewRequest("GET", "/auth/otp", nil)
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			AppName: "TestApp",
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel2OTP,
			UserId:    1,
			ClientId:  "test-client",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		session := sessions.NewSession(httpSession, constants.AuthServerSessionName)
		httpSession.On("Get", mock.MatchedBy(func(r *http.Request) bool {
			return r.Context().Value(constants.ContextKeySettings) == settings
		}), constants.AuthServerSessionName).Return(session, nil)
		httpSession.On("Save", req, rr, session).Return(nil)

		user := &models.User{
			Id:         1,
			OTPEnabled: false,
			Email:      "test@example.com",
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		otpSecretGenerator.On("GenerateOTPSecret", "test@example.com", "TestApp").Return("base64Image", "secretKey", nil)

		httpHelper.On("RenderTemplate",
			mock.Anything,
			mock.Anything,
			"/layouts/auth_layout.html",
			"/auth_otp_enrollment.html",
			mock.MatchedBy(func(bind map[string]interface{}) bool {
				if len(bind) != 10 {
					return false
				}
				if _, ok := bind["csrfField"]; !ok {
					return false
				}
				if err, ok := bind["error"]; !ok || err != nil {
					return false
				}
				if base64Image, ok := bind["base64Image"]; !ok || base64Image != "base64Image" {
					return false
				}
				if secretKey, ok := bind["secretKey"]; !ok || secretKey != "secretKey" {
					return false
				}
				if _, ok := bind["layoutShowClientSection"]; !ok {
					return false
				}
				if _, ok := bind["layoutClientName"]; !ok {
					return false
				}
				if _, ok := bind["layoutHasClientLogo"]; !ok {
					return false
				}
				if _, ok := bind["layoutClientLogoUrl"]; !ok {
					return false
				}
				if _, ok := bind["layoutClientDescription"]; !ok {
					return false
				}
				if _, ok := bind["layoutClientWebsiteUrl"]; !ok {
					return false
				}
				return true
			}),
		).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		httpSession.AssertExpectations(t)
		database.AssertExpectations(t)
		otpSecretGenerator.AssertExpectations(t)

		assert.Equal(t, "secretKey", session.Values[constants.SessionKeyOTPSecret])
		assert.Equal(t, "base64Image", session.Values[constants.SessionKeyOTPImage])
	})
}

func TestHandleAuthOtpPost(t *testing.T) {
	t.Run("Error when getting AuthContext", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger)

		req, _ := http.NewRequest("POST", "/auth/otp", nil)
		rr := httptest.NewRecorder()

		expectedError := errors.New("auth context error")
		authHelper.On("GetAuthContext", mock.Anything).Return(nil, expectedError)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == expectedError.Error()
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Unexpected AuthState", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger)

		req, _ := http.NewRequest("POST", "/auth/otp", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateInitial,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "authContext.AuthState is not level2_otp"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("User not found", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger)

		req, _ := http.NewRequest("POST", "/auth/otp", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel2OTP,
			UserId:    1,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		session := sessions.NewSession(httpSession, constants.AuthServerSessionName)
		httpSession.On("Get", req, constants.AuthServerSessionName).Return(session, nil)

		database.On("GetUserById", mock.Anything, int64(1)).Return(nil, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "user not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("User disabled", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger)

		req, _ := http.NewRequest("POST", "/auth/otp", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel2OTP,
			UserId:    1,
			ClientId:  "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		session := sessions.NewSession(httpSession, constants.AuthServerSessionName)
		httpSession.On("Get", req, constants.AuthServerSessionName).Return(session, nil)

		user := &models.User{
			Id:      1,
			Enabled: false,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		auditLogger.On("Log", constants.AuditUserDisabled, mock.Anything).Return()

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Empty OTP code", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger)

		req, _ := http.NewRequest("POST", "/auth/otp", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel2OTP,
			UserId:    1,
			ClientId:  "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		session := sessions.NewSession(httpSession, constants.AuthServerSessionName)
		httpSession.On("Get", req, constants.AuthServerSessionName).Return(session, nil)

		user := &models.User{
			Id:      1,
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Invalid OTP code for enabled OTP", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger)

		form := url.Values{}
		form.Add("otp", "123456")
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel2OTP,
			UserId:    1,
			ClientId:  "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		session := sessions.NewSession(httpSession, constants.AuthServerSessionName)
		httpSession.On("Get", req, constants.AuthServerSessionName).Return(session, nil)

		user := &models.User{
			Id:         1,
			Enabled:    true,
			OTPEnabled: true,
			OTPSecret:  "test-secret",
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		auditLogger.On("Log", constants.AuditAuthFailedOtp, mock.Anything).Return()

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Invalid OTP code for disabled OTP", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger)

		form := url.Values{}
		form.Add("otp", "123456")
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel2OTP,
			UserId:    1,
			ClientId:  "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		session := sessions.NewSession(httpSession, constants.AuthServerSessionName)
		session.Values[constants.SessionKeyOTPSecret] = "test-secret"
		httpSession.On("Get", req, constants.AuthServerSessionName).Return(session, nil)

		user := &models.User{
			Id:         1,
			Enabled:    true,
			OTPEnabled: false,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		auditLogger.On("Log", constants.AuditAuthFailedOtp, mock.Anything).Return()

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Successful OTP validation for enabled OTP", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger)

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "TestApp",
			AccountName: "test@test.com",
		})
		assert.Nil(t, err)

		otpCode, err := totp.GenerateCode(key.Secret(), time.Now())
		assert.Nil(t, err)

		form := url.Values{}
		form.Add("otp", otpCode)
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel2OTP,
			UserId:    1,
			ClientId:  "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		session := sessions.NewSession(httpSession, constants.AuthServerSessionName)
		httpSession.On("Get", req, constants.AuthServerSessionName).Return(session, nil)

		otpSecret := key.Secret()
		user := &models.User{
			Id:         1,
			Enabled:    true,
			OTPEnabled: true,
			OTPSecret:  otpSecret,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		auditLogger.On("Log", constants.AuditAuthSuccessOtp, mock.Anything).Return()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateAuthenticationCompleted &&
				ac.AuthMethods == enums.AuthMethodOTP.String() &&
				ac.AuthenticatedAt != nil && !ac.AuthenticatedAt.IsZero()
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/completed", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Successful OTP validation for disabled OTP (enrollment)", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger)

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "TestApp",
			AccountName: "test@test.com",
		})
		assert.Nil(t, err)

		otpCode, err := totp.GenerateCode(key.Secret(), time.Now())
		assert.Nil(t, err)

		form := url.Values{}
		form.Add("otp", otpCode)
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel2OTP,
			UserId:    1,
			ClientId:  "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		session := sessions.NewSession(httpSession, constants.AuthServerSessionName)
		otpSecret := key.Secret()
		session.Values[constants.SessionKeyOTPSecret] = otpSecret
		httpSession.On("Get", req, constants.AuthServerSessionName).Return(session, nil)

		user := &models.User{
			Id:         1,
			Enabled:    true,
			OTPEnabled: false,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		updatedUser := &models.User{
			Id:         1,
			Enabled:    true,
			OTPEnabled: true,
			OTPSecret:  otpSecret,
		}
		database.On("UpdateUser", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
			return u.Id == updatedUser.Id && u.OTPEnabled == updatedUser.OTPEnabled && u.OTPSecret == updatedUser.OTPSecret
		})).Return(nil)

		auditLogger.On("Log", constants.AuditEnabledOTP, mock.Anything).Return()
		auditLogger.On("Log", constants.AuditAuthSuccessOtp, mock.Anything).Return()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateAuthenticationCompleted &&
				ac.AuthMethods == enums.AuthMethodOTP.String() &&
				ac.AuthenticatedAt != nil && !ac.AuthenticatedAt.IsZero()
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/completed", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Error updating user during OTP enrollment", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger)

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "TestApp",
			AccountName: "test@test.com",
		})
		assert.Nil(t, err)

		otpCode, err := totp.GenerateCode(key.Secret(), time.Now())
		assert.Nil(t, err)

		form := url.Values{}
		form.Add("otp", otpCode)
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel2OTP,
			UserId:    1,
			ClientId:  "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		session := sessions.NewSession(httpSession, constants.AuthServerSessionName)
		otpSecret := key.Secret()
		session.Values[constants.SessionKeyOTPSecret] = otpSecret
		httpSession.On("Get", req, constants.AuthServerSessionName).Return(session, nil)

		user := &models.User{
			Id:         1,
			Enabled:    true,
			OTPEnabled: false,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		updateError := errors.New("failed to update user")
		database.On("UpdateUser", mock.Anything, mock.Anything).Return(updateError)

		httpHelper.On("InternalServerError", rr, req, updateError).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("User account is disabled", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger)

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "TestApp",
			AccountName: "test@test.com",
		})
		assert.Nil(t, err)

		otpCode, err := totp.GenerateCode(key.Secret(), time.Now())
		assert.Nil(t, err)

		form := url.Values{}
		form.Add("otp", otpCode)
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel2OTP,
			UserId:    1,
			ClientId:  "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		session := sessions.NewSession(httpSession, constants.AuthServerSessionName)
		httpSession.On("Get", req, constants.AuthServerSessionName).Return(session, nil)

		user := &models.User{
			Id:         1,
			Enabled:    false,
			OTPEnabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		auditLogger.On("Log", constants.AuditUserDisabled, mock.Anything).Return()

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})
}
