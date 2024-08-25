package handlers

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/authserver/internal/handlers/handlerhelpers/mocks"
	mocks_users "github.com/leodip/goiabada/authserver/internal/users/mocks"

	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/customerrors"
	"github.com/leodip/goiabada/authserver/internal/enums"
	"github.com/leodip/goiabada/authserver/internal/hashutil"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oauth"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandleAuthPwdGet(t *testing.T) {
	t.Run("Unable to get auth context 1", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthPwdGet(httpHelper, authHelper, database)

		req, _ := http.NewRequest("GET", "/auth/pwd", nil)
		rr := httptest.NewRecorder()

		authHelper.On("GetAuthContext", req).Return(nil, customerrors.NewErrorDetail("no_auth_context", "no auth context"))

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, "/account/profile", rr.Header().Get("Location"))

		httpHelper.AssertNotCalled(t, "InternalServerError")
		authHelper.AssertExpectations(t)
	})

	t.Run("Unable to get auth context 2", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthPwdGet(httpHelper, authHelper, database)

		req, _ := http.NewRequest("GET", "/auth/pwd", nil)
		rr := httptest.NewRecorder()

		authHelper.On("GetAuthContext", req).Return(nil, errors.New("internal error"))
		httpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool { return err.Error() == "internal error" }),
		).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Found email in session, renders page with email", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthPwdGet(httpHelper, authHelper, database)

		req, _ := http.NewRequest("GET", "/auth/pwd", nil)
		rr := httptest.NewRecorder()

		sessionIdentifier := "test_session"
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, sessionIdentifier)
		settings := &models.Settings{SMTPEnabled: true}
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", req).Return(&oauth.AuthContext{}, nil)

		userSession := &models.UserSession{User: models.User{Email: "test@example.com"}}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_pwd.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["email"] == "test@example.com" && data["smtpEnabled"] == true
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Did not find email in session, renders page without email", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthPwdGet(httpHelper, authHelper, database)

		req, _ := http.NewRequest("GET", "/auth/pwd", nil)
		rr := httptest.NewRecorder()

		sessionIdentifier := "test_session"
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, sessionIdentifier)
		settings := &models.Settings{SMTPEnabled: false}
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", req).Return(&oauth.AuthContext{}, nil)
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(nil, nil)

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
	t.Run("Unable to get auth context", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthPwdPost(httpHelper, authHelper, userSessionManager, database, auditLogger)

		req, _ := http.NewRequest("POST", "/auth/pwd", nil)
		rr := httptest.NewRecorder()

		authHelper.On("GetAuthContext", req).Return(nil, errors.New("unable to get auth context"))
		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "unable to get auth context"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Email is required", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthPwdPost(httpHelper, authHelper, userSessionManager, database, auditLogger)

		req, _ := http.NewRequest("POST", "/auth/pwd", strings.NewReader("password=testpassword"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &models.Settings{SMTPEnabled: true}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.MatchedBy(func(r *http.Request) bool {
			// Check if the request has the expected context value
			settingsFromCtx, ok := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
			return ok && settingsFromCtx.SMTPEnabled == true
		})).Return(&oauth.AuthContext{}, nil)

		httpHelper.On("RenderTemplate", rr, mock.AnythingOfType("*http.Request"), "/layouts/auth_layout.html", "/auth_pwd.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Email is required." && data["smtpEnabled"] == true
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Password is required", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthPwdPost(httpHelper, authHelper, userSessionManager, database, auditLogger)

		req, _ := http.NewRequest("POST", "/auth/pwd", strings.NewReader("email=test@example.com"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authHelper.On("GetAuthContext", mock.MatchedBy(func(r *http.Request) bool {
			// Check if the request has the expected context value
			settingsFromCtx, ok := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
			return ok && settingsFromCtx.SMTPEnabled == true
		})).Return(&oauth.AuthContext{}, nil)

		settings := &models.Settings{SMTPEnabled: true}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_pwd.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Password is required." && data["smtpEnabled"] == true && data["email"] == "test@example.com"
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("GetUserByEmail gives error", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthPwdPost(httpHelper, authHelper, userSessionManager, database, auditLogger)

		req, _ := http.NewRequest("POST", "/auth/pwd", strings.NewReader("email=test@example.com&password=testpassword"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &models.Settings{SMTPEnabled: true}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.MatchedBy(func(r *http.Request) bool {
			settingsFromCtx, ok := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
			return ok && settingsFromCtx.SMTPEnabled == true
		})).Return(&oauth.AuthContext{}, nil)

		database.On("GetUserByEmail", mock.Anything, "test@example.com").Return(nil, errors.New("database error"))

		httpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool { return err.Error() == "database error" }),
		).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("GetUserByEmail returns nil", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthPwdPost(httpHelper, authHelper, userSessionManager, database, auditLogger)

		req, _ := http.NewRequest("POST", "/auth/pwd", strings.NewReader("email=test@example.com&password=testpassword"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authHelper.On("GetAuthContext", mock.MatchedBy(func(r *http.Request) bool {
			settingsFromCtx, ok := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
			return ok && settingsFromCtx.SMTPEnabled == true
		})).Return(&oauth.AuthContext{}, nil)

		database.On("GetUserByEmail", (*sql.Tx)(nil), "test@example.com").Return(nil, nil)
		auditLogger.On("Log", constants.AuditAuthFailedPwd, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["email"] == "test@example.com"
		}))

		settings := &models.Settings{SMTPEnabled: true}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_pwd.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Authentication failed." && data["smtpEnabled"] == true && data["email"] == "test@example.com"
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("VerifyPasswordHash fails", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthPwdPost(httpHelper, authHelper, userSessionManager, database, auditLogger)

		req, _ := http.NewRequest("POST", "/auth/pwd", strings.NewReader("email=test@example.com&password=wrongpassword"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &models.Settings{SMTPEnabled: true}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.Anything).Return(&oauth.AuthContext{}, nil)
		database.On("GetUserByEmail", mock.Anything, "test@example.com").Return(&models.User{
			Id:           1,
			Email:        "test@example.com",
			PasswordHash: "correcthash",
		}, nil)
		auditLogger.On("Log", constants.AuditAuthFailedPwd, mock.Anything)

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_pwd.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Authentication failed." && data["smtpEnabled"] == true && data["email"] == "test@example.com"
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("User is not enabled", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthPwdPost(httpHelper, authHelper, userSessionManager, database, auditLogger)

		password := "correctpassword"
		hashedPassword, err := hashutil.HashPassword(password)
		assert.NoError(t, err)

		req, _ := http.NewRequest("POST", "/auth/pwd", strings.NewReader("email=test@example.com&password="+password))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &models.Settings{SMTPEnabled: true}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.Anything).Return(&oauth.AuthContext{}, nil)
		database.On("GetUserByEmail", mock.Anything, "test@example.com").Return(&models.User{
			Id:           1,
			Email:        "test@example.com",
			PasswordHash: hashedPassword,
			Enabled:      false,
		}, nil)
		auditLogger.On("Log", constants.AuditAuthSuccessPwd, mock.Anything)
		auditLogger.On("Log", constants.AuditUserDisabled, mock.Anything)

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_pwd.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Your account is disabled." && data["smtpEnabled"] == true && data["email"] == "test@example.com"
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("GetClientByClientIdentifier returns nil", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthPwdPost(httpHelper, authHelper, userSessionManager, database, auditLogger)

		password := "password123"
		hashedPassword, _ := hashutil.HashPassword(password)

		req, _ := http.NewRequest("POST", "/auth/pwd", strings.NewReader("email=test@example.com&password="+password))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &models.Settings{SMTPEnabled: true}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, "test-session")
		req = req.WithContext(ctx)

		authHelper.On("GetAuthContext", mock.Anything).Return(&oauth.AuthContext{ClientId: "test-client"}, nil)
		database.On("GetUserByEmail", mock.Anything, "test@example.com").Return(&models.User{
			Id:           1,
			Email:        "test@example.com",
			PasswordHash: hashedPassword,
			Enabled:      true,
		}, nil)
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(nil, nil)
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session").Return(&models.UserSession{}, nil)
		database.On("UserSessionLoadUser", mock.Anything, mock.AnythingOfType("*models.UserSession")).Return(nil)

		auditLogger.On("Log", constants.AuditAuthSuccessPwd, mock.Anything).Return().Once()

		httpHelper.On("InternalServerError", rr, req, mock.AnythingOfType("*errors.withStack")).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("hasValidUserSession and RequiresOTPAuth", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthPwdPost(httpHelper, authHelper, userSessionManager, database, auditLogger)

		password := "password123"
		hashedPassword, _ := hashutil.HashPassword(password)

		req, _ := http.NewRequest("POST", "/auth/pwd", strings.NewReader("email=test@example.com&password="+password))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &models.Settings{SMTPEnabled: true}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, "test-session")
		req = req.WithContext(ctx)

		user := &models.User{
			Id:           1,
			Email:        "test@example.com",
			PasswordHash: hashedPassword,
			Enabled:      true,
		}

		client := &models.Client{
			Id:              1,
			DefaultAcrLevel: enums.AcrLevel1,
		}

		userSession := &models.UserSession{
			User: *user,
		}

		authContext := &oauth.AuthContext{ClientId: "test-client"}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)
		database.On("GetUserByEmail", mock.Anything, "test@example.com").Return(user, nil)
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session").Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, mock.AnythingOfType("*models.UserSession")).Return(nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, mock.AnythingOfType("*models.UserSession"), mock.Anything).Return(true)
		userSessionManager.On("RequiresOTPAuth", mock.Anything, mock.AnythingOfType("*models.Client"), mock.AnythingOfType("*models.UserSession"), mock.Anything).Return(true)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.UserId == user.Id
		})).Return(nil)

		auditLogger.On("Log", constants.AuditAuthSuccessPwd, mock.Anything).Return().Once()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.True(t, strings.HasSuffix(rr.Header().Get("Location"), "/auth/otp"))
	})

	t.Run("targetAcrLevel AcrLevel3 is different from AcrLevel1", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthPwdPost(httpHelper, authHelper, userSessionManager, database, auditLogger)

		password := "password123"
		hashedPassword, _ := hashutil.HashPassword(password)

		req, _ := http.NewRequest("POST", "/auth/pwd", strings.NewReader("email=test@example.com&password="+password))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &models.Settings{SMTPEnabled: true}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, "test-session")
		req = req.WithContext(ctx)

		user := &models.User{
			Id:           1,
			Email:        "test@example.com",
			PasswordHash: hashedPassword,
			Enabled:      true,
			OTPEnabled:   true,
		}

		client := &models.Client{
			Id:              1,
			DefaultAcrLevel: enums.AcrLevel3,
		}

		userSession := &models.UserSession{
			User: *user,
		}

		authContext := &oauth.AuthContext{
			ClientId:           "test-client",
			RequestedAcrValues: enums.AcrLevel3.String(),
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)
		database.On("GetUserByEmail", mock.Anything, "test@example.com").Return(user, nil)
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session").Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, mock.AnythingOfType("*models.UserSession")).Return(nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, mock.AnythingOfType("*models.UserSession"), mock.Anything).Return(false)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.UserId == user.Id
		})).Return(nil)

		auditLogger.On("Log", constants.AuditAuthSuccessPwd, mock.Anything).Return().Once()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.True(t, strings.HasSuffix(rr.Header().Get("Location"), "/auth/otp"))
	})

	t.Run("No OTP required, start new session and redirect to consent", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthPwdPost(httpHelper, authHelper, userSessionManager, database, auditLogger)

		password := "password123"
		hashedPassword, _ := hashutil.HashPassword(password)

		req, _ := http.NewRequest("POST", "/auth/pwd", strings.NewReader("email=test@example.com&password="+password))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		settings := &models.Settings{SMTPEnabled: true}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, "test-session")
		req = req.WithContext(ctx)

		user := &models.User{
			Id:           1,
			Email:        "test@example.com",
			PasswordHash: hashedPassword,
			Enabled:      true,
		}

		client := &models.Client{
			Id:              1,
			DefaultAcrLevel: enums.AcrLevel1,
		}

		userSession := &models.UserSession{
			User:     *user,
			AcrLevel: enums.AcrLevel1.String(),
		}

		authContext := &oauth.AuthContext{
			ClientId:           "test-client",
			RequestedAcrValues: "",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)
		database.On("GetUserByEmail", mock.Anything, "test@example.com").Return(user, nil)
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session").Return(userSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, mock.AnythingOfType("*models.UserSession")).Return(nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, mock.AnythingOfType("*models.UserSession"), mock.Anything).Return(false)
		userSessionManager.On("StartNewUserSession", mock.Anything, mock.Anything, user.Id, client.Id, enums.AuthMethodPassword.String(), enums.AcrLevel1.String()).Return(userSession, nil)

		authHelper.On("SaveAuthContext", mock.Anything, mock.Anything, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.UserId == user.Id &&
				ac.AuthMethods == enums.AuthMethodPassword.String() &&
				ac.AuthCompleted == true &&
				ac.AcrLevel == enums.AcrLevel1.String() &&
				ac.AuthTime.After(time.Now().Add(-time.Minute))
		})).Return(nil)

		auditLogger.On("Log", constants.AuditAuthSuccessPwd, mock.Anything).Return().Once()
		auditLogger.On("Log", constants.AuditStartedNewUserSesson, mock.Anything).Return().Once()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.True(t, strings.HasSuffix(rr.Header().Get("Location"), "/auth/consent"))
	})
}
