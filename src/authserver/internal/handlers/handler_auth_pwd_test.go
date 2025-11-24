package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
)

func TestHandleAuthPwdGet(t *testing.T) {
	t.Run("Error when getting GetAuthContext", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthPwdGet(httpHelper, authHelper, database)

		req, err := http.NewRequest("GET", "/auth/pwd", nil)
		assert.NoError(t, err)

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
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthPwdGet(httpHelper, authHelper, database)

		req, err := http.NewRequest("GET", "/auth/pwd", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateInitial,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "authContext.AuthState is not level1_password"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Successful rendering with email from user session", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthPwdGet(httpHelper, authHelper, database)

		req, err := http.NewRequest("GET", "/auth/pwd", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel1Password,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		sessionIdentifier := "test-session"
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		userSession := &models.UserSession{
			Id: 1,
			User: models.User{
				Email: "test@example.com",
			},
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)

		settings := &models.Settings{
			SMTPEnabled: true,
		}
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_pwd.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["email"] == "test@example.com" && data["smtpEnabled"] == true
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Successful rendering without email", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthPwdGet(httpHelper, authHelper, database)

		req, err := http.NewRequest("GET", "/auth/pwd", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel1Password,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		settings := &models.Settings{
			SMTPEnabled: false,
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_pwd.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			_, hasEmail := data["email"]
			return !hasEmail && data["smtpEnabled"] == false
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})
}

func TestHandleAuthPwdPost(t *testing.T) {
	t.Run("Error when getting AuthContext", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthPwdPost(httpHelper, authHelper, database, auditLogger)

		req, _ := http.NewRequest("POST", "/auth/pwd", nil)
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
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthPwdPost(httpHelper, authHelper, database, auditLogger)

		req, _ := http.NewRequest("POST", "/auth/pwd", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateInitial,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "authContext.AuthState is not level1_password"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Missing email", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthPwdPost(httpHelper, authHelper, database, auditLogger)

		form := url.Values{}
		form.Add("password", "testpassword")
		req, _ := http.NewRequest("POST", "/auth/pwd", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel1Password,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		settings := &models.Settings{
			SMTPEnabled: true,
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_pwd.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Email is required."
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Missing password", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthPwdPost(httpHelper, authHelper, database, auditLogger)

		form := url.Values{}
		form.Add("email", "test@example.com")
		req, _ := http.NewRequest("POST", "/auth/pwd", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel1Password,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		settings := &models.Settings{
			SMTPEnabled: true,
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_pwd.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Password is required."
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("User not found", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthPwdPost(httpHelper, authHelper, database, auditLogger)

		form := url.Values{}
		form.Add("email", "test@example.com")
		form.Add("password", "testpassword")
		req, _ := http.NewRequest("POST", "/auth/pwd", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel1Password,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		settings := &models.Settings{
			SMTPEnabled: true,
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		database.On("GetUserByEmail", mock.Anything, "test@example.com").Return(nil, nil)

		auditLogger.On("Log", constants.AuditAuthFailedPwd, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["email"] == "test@example.com"
		})).Return()

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_pwd.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Authentication failed."
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Successful authentication", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthPwdPost(httpHelper, authHelper, database, auditLogger)

		password := "testpassword"
		passwordHash, err := hashutil.HashPassword(password)
		assert.NoError(t, err)

		form := url.Values{}
		form.Add("email", "test@example.com")
		form.Add("password", password)
		req, _ := http.NewRequest("POST", "/auth/pwd", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel1Password,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		settings := &models.Settings{
			SMTPEnabled: true,
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		user := &models.User{
			Id:           1,
			Email:        "test@example.com",
			PasswordHash: passwordHash,
			Enabled:      true,
		}
		database.On("GetUserByEmail", mock.Anything, "test@example.com").Return(user, nil)

		auditLogger.On("Log", constants.AuditAuthSuccessPwd, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(1)
		})).Return()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.UserId == 1 &&
				ac.AuthState == oauth.AuthStateLevel1PasswordCompleted &&
				ac.AuthMethods == enums.AuthMethodPassword.String()
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/level1completed", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Disabled user account", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthPwdPost(httpHelper, authHelper, database, auditLogger)

		password := "testpassword"
		passwordHash, err := hashutil.HashPassword(password)
		assert.NoError(t, err)

		form := url.Values{}
		form.Add("email", "disabled@example.com")
		form.Add("password", password)
		req, _ := http.NewRequest("POST", "/auth/pwd", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel1Password,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		settings := &models.Settings{
			SMTPEnabled: true,
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		disabledUser := &models.User{
			Id:           2,
			Email:        "disabled@example.com",
			PasswordHash: passwordHash,
			Enabled:      false,
		}
		database.On("GetUserByEmail", mock.Anything, "disabled@example.com").Return(disabledUser, nil)

		auditLogger.On("Log", constants.AuditUserDisabled, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(2)
		})).Return()

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_pwd.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Your user account is disabled."
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})
}
