package adminuserhandlers

// TODO: This test file has been temporarily commented out during API migration.
// Tests need to be updated to work with API client instead of direct database access.

/*

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
	mocks_validators "github.com/leodip/goiabada/core/validators/mocks"
)

func TestHandleAdminUserAuthenticationGet(t *testing.T) {
	t.Run("Valid user", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		handler := HandleAdminUserAuthenticationGet(mockHttpHelper, mockSessionStore, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/123/authentication", nil)
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com", OTPEnabled: true}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_users_authentication.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["user"] == user && data["otpEnabled"] == true
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockDB.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Invalid user ID", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		handler := HandleAdminUserAuthenticationGet(mockHttpHelper, mockSessionStore, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/invalid/authentication", nil)
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "invalid")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		mockHttpHelper.On("InternalServerError", rr, req, mock.AnythingOfType("*strconv.NumError")).Return()

		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("User not found", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)

		handler := HandleAdminUserAuthenticationGet(mockHttpHelper, mockSessionStore, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/123/authentication", nil)
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(nil, nil)
		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "user not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})
}

func TestHandleAdminUserAuthenticationPost(t *testing.T) {
	t.Run("Valid input - update password", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockPasswordValidator := mocks_validators.NewPasswordValidator(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserAuthenticationPost(
			mockHttpHelper,
			mockSessionStore,
			mockAuthHelper,
			mockDB,
			mockPasswordValidator,
			mockSessionStore,
			mockAuditLogger,
		)

		form := url.Values{}
		form.Add("newPassword", "newValidPassword123!")

		req, _ := http.NewRequest("POST", "/admin/users/123/authentication", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com", OTPEnabled: true}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		mockPasswordValidator.On("ValidatePassword", mock.Anything, "newValidPassword123!").Return(nil)

		// Check parameters passed to UpdateUser
		mockDB.On("UpdateUser", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
			return u.Id == 123 && u.PasswordHash != "" && !u.OTPEnabled && u.OTPSecret == ""
		})).Return(nil)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSession.Values[constants.SessionKeySessionIdentifier] = "test-session-id"
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
		mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin")

		// Expect AuditDisabledOTP instead of AuditUpdatedUserAuthentication
		mockAuditLogger.On("Log", constants.AuditDisabledOTP, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(123)
		})).Return(nil)

		mockAuditLogger.On("Log", constants.AuditUpdatedUserAuthentication, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(123) && details["loggedInUser"] == "admin"
		})).Return(nil)

		// Expect a call to GetUserSessionBySessionIdentifier and UpdateUserSession
		userSession := &models.UserSession{Id: 1, SessionIdentifier: "test-session-id"}
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session-id").Return(userSession, nil)
		mockDB.On("UpdateUserSession", mock.Anything, mock.MatchedBy(func(us *models.UserSession) bool {
			return us.Id == 1 && us.Level2AuthConfigHasChanged
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		mockDB.AssertExpectations(t)
		mockPasswordValidator.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockAuditLogger.AssertExpectations(t)
	})

	t.Run("Invalid user ID", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockPasswordValidator := mocks_validators.NewPasswordValidator(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserAuthenticationPost(
			mockHttpHelper,
			mockSessionStore,
			mockAuthHelper,
			mockDB,
			mockPasswordValidator,
			mockSessionStore,
			mockAuditLogger,
		)

		req, _ := http.NewRequest("POST", "/admin/users/invalid/authentication", strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "invalid")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		mockHttpHelper.On("InternalServerError", rr, req, mock.AnythingOfType("*strconv.NumError")).Return()

		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("User not found", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockPasswordValidator := mocks_validators.NewPasswordValidator(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserAuthenticationPost(
			mockHttpHelper,
			mockSessionStore,
			mockAuthHelper,
			mockDB,
			mockPasswordValidator,
			mockSessionStore,
			mockAuditLogger,
		)

		req, _ := http.NewRequest("POST", "/admin/users/123/authentication", strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(nil, nil)
		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "user not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Invalid password", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockPasswordValidator := mocks_validators.NewPasswordValidator(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserAuthenticationPost(
			mockHttpHelper,
			mockSessionStore,
			mockAuthHelper,
			mockDB,
			mockPasswordValidator,
			mockSessionStore,
			mockAuditLogger,
		)

		form := url.Values{}
		form.Add("newPassword", "weak")

		req, _ := http.NewRequest("POST", "/admin/users/123/authentication", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com", OTPEnabled: true}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		mockPasswordValidator.On("ValidatePassword", mock.Anything, "weak").Return(errors.New("password too weak"))

		mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_users_authentication.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "password too weak"
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockPasswordValidator.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Database error", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockPasswordValidator := mocks_validators.NewPasswordValidator(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserAuthenticationPost(
			mockHttpHelper,
			mockSessionStore,
			mockAuthHelper,
			mockDB,
			mockPasswordValidator,
			mockSessionStore,
			mockAuditLogger,
		)

		form := url.Values{}
		form.Add("newPassword", "validPassword123!")

		req, _ := http.NewRequest("POST", "/admin/users/123/authentication", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com", OTPEnabled: true}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		mockPasswordValidator.On("ValidatePassword", mock.Anything, "validPassword123!").Return(nil)
		mockDB.On("UpdateUser", mock.Anything, mock.AnythingOfType("*models.User")).Return(errors.New("database error"))

		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "database error"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockPasswordValidator.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Disable OTP", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockPasswordValidator := mocks_validators.NewPasswordValidator(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserAuthenticationPost(
			mockHttpHelper,
			mockSessionStore,
			mockAuthHelper,
			mockDB,
			mockPasswordValidator,
			mockSessionStore,
			mockAuditLogger,
		)

		form := url.Values{}
		form.Add("otpEnabled", "off")

		req, _ := http.NewRequest("POST", "/admin/users/123/authentication", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com", OTPEnabled: true}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		mockDB.On("UpdateUser", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
			return u.Id == 123 && !u.OTPEnabled && u.OTPSecret == ""
		})).Return(nil)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSession.Values[constants.SessionKeySessionIdentifier] = "test-session-id"
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
		mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		mockAuditLogger.On("Log", constants.AuditDisabledOTP, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(123)
		})).Return(nil)

		userSession := &models.UserSession{Id: 1, SessionIdentifier: "test-session-id"}
		mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session-id").Return(userSession, nil)
		mockDB.On("UpdateUserSession", mock.Anything, mock.MatchedBy(func(us *models.UserSession) bool {
			return us.Id == 1 && us.Level2AuthConfigHasChanged
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		mockDB.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockAuditLogger.AssertExpectations(t)
	})

	t.Run("No changes", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockPasswordValidator := mocks_validators.NewPasswordValidator(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserAuthenticationPost(
			mockHttpHelper,
			mockSessionStore,
			mockAuthHelper,
			mockDB,
			mockPasswordValidator,
			mockSessionStore,
			mockAuditLogger,
		)

		form := url.Values{}
		form.Add("otpEnabled", "on") // Same as current state

		req, _ := http.NewRequest("POST", "/admin/users/123/authentication", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com", OTPEnabled: true}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
		mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		mockDB.AssertExpectations(t)
		mockSessionStore.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockAuditLogger.AssertExpectations(t)
	})
}

*/
