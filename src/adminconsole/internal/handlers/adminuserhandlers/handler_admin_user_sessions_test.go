package adminuserhandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
)

func TestHandleAdminUserSessionsGet(t *testing.T) {
	t.Run("Valid user with multiple sessions including an invalid one", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)

		handler := HandleAdminUserSessionsGet(mockHttpHelper, mockDB)

		req, err := http.NewRequest("GET", "/admin/users/123/sessions?page=1&query=test", nil)
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		settings := &models.Settings{
			UserSessionIdleTimeoutInSeconds: 3600,
			UserSessionMaxLifetimeInSeconds: 86400,
		}
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, settings))
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, "session1"))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		now := time.Now()
		userSessions := []models.UserSession{
			{
				Id:                int64(1),
				SessionIdentifier: "session1",
				Started:           now.Add(-30 * time.Minute),
				LastAccessed:      now.Add(-5 * time.Minute),
				AuthMethods:       "password",
				AcrLevel:          "1",
				AuthTime:          now.Add(-30 * time.Minute),
				IpAddress:         "192.168.1.1",
				DeviceName:        "Chrome",
				DeviceType:        "browser",
				DeviceOS:          "Windows",
				UserId:            123,
				Clients:           []models.UserSessionClient{{ClientId: 1}},
			},
			{
				Id:                int64(2),
				SessionIdentifier: "session2",
				Started:           now.Add(-1 * time.Hour),
				LastAccessed:      now.Add(-10 * time.Minute),
				AuthMethods:       "password otp",
				AcrLevel:          "2",
				AuthTime:          now.Add(-1 * time.Hour),
				IpAddress:         "192.168.1.2",
				DeviceName:        "Firefox",
				DeviceType:        "browser",
				DeviceOS:          "MacOS",
				UserId:            123,
				Clients:           []models.UserSessionClient{{ClientId: 2}},
			},
			{
				Id:                int64(3),
				SessionIdentifier: "session3",
				Started:           now.Add(-25 * time.Hour), // This session is more than 24 hours old
				LastAccessed:      now.Add(-4 * time.Hour),  // Last accessed more than 3600 seconds ago
				AuthMethods:       "password",
				AcrLevel:          "1",
				AuthTime:          now.Add(-25 * time.Hour),
				IpAddress:         "192.168.1.3",
				DeviceName:        "Safari",
				DeviceType:        "browser",
				DeviceOS:          "iOS",
				UserId:            123,
				Clients:           []models.UserSessionClient{{ClientId: 3}},
			},
		}
		mockDB.On("GetUserSessionsByUserId", mock.Anything, int64(123)).Return(userSessions, nil)
		mockDB.On("UserSessionsLoadClients", mock.Anything, userSessions).Return(nil)
		mockDB.On("UserSessionClientsLoadClients", mock.Anything, mock.AnythingOfType("[]models.UserSessionClient")).Return(nil)

		mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_users_sessions.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			sessions, ok := data["sessions"].([]SessionInfo)
			if !ok || len(sessions) != 2 { // Only 2 valid sessions should be included
				return false
			}

			// Validate first session
			if sessions[0].UserSessionId != 2 ||
				sessions[0].IpAddress != "192.168.1.2" ||
				sessions[0].DeviceName != "Firefox" ||
				sessions[0].DeviceType != "browser" ||
				sessions[0].DeviceOS != "MacOS" {
				return false
			}

			// Validate second session
			if sessions[1].UserSessionId != 1 ||
				sessions[1].IpAddress != "192.168.1.1" ||
				sessions[1].DeviceName != "Chrome" ||
				sessions[1].DeviceType != "browser" ||
				sessions[1].DeviceOS != "Windows" {
				return false
			}

			// Validate other data
			return data["user"] == user &&
				data["page"] == "1" &&
				data["query"] == "test" &&
				data["csrfField"] != nil
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})
}

func TestHandleAdminUserSessionsPost(t *testing.T) {
	t.Run("Valid session revocation", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserSessionsPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

		reqBody := `{"userSessionId": 1}`
		req, err := http.NewRequest("POST", "/admin/users/123/sessions", strings.NewReader(reqBody))
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		userSessions := []models.UserSession{
			{Id: 1, UserId: 123},
		}
		mockDB.On("GetUserSessionsByUserId", mock.Anything, int64(123)).Return(userSessions, nil)
		mockDB.On("DeleteUserSession", mock.Anything, int64(1)).Return(nil)

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin")
		mockAuditLogger.On("Log", constants.AuditDeletedUserSession, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userSessionId"] == int64(1) && details["loggedInUser"] == "admin"
		})).Return(nil)

		mockHttpHelper.On("EncodeJson", rr, req, mock.MatchedBy(func(result interface{}) bool {
			return result.(struct{ Success bool }).Success == true
		})).Return()

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockAuditLogger.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Invalid user ID", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserSessionsPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

		reqBody := `{"userSessionId": 1}`
		req, err := http.NewRequest("POST", "/admin/users/invalid/sessions", strings.NewReader(reqBody))
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "invalid")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		mockHttpHelper.On("JsonError", rr, req, mock.AnythingOfType("*strconv.NumError")).Return()

		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("User not found", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserSessionsPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

		reqBody := `{"userSessionId": 1}`
		req, err := http.NewRequest("POST", "/admin/users/123/sessions", strings.NewReader(reqBody))
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(nil, nil)
		mockHttpHelper.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "user not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Session not found", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminUserSessionsPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

		reqBody := `{"userSessionId": 2}`
		req, err := http.NewRequest("POST", "/admin/users/123/sessions", strings.NewReader(reqBody))
		assert.NoError(t, err)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("userId", "123")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()

		user := &models.User{Id: 123, Email: "test@example.com"}
		mockDB.On("GetUserById", mock.Anything, int64(123)).Return(user, nil)

		userSessions := []models.UserSession{
			{Id: 1, UserId: 123},
		}
		mockDB.On("GetUserSessionsByUserId", mock.Anything, int64(123)).Return(userSessions, nil)

		// The function should complete without calling EncodeJson or DeleteUserSession
		// because the requested session (ID 2) is not found

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockAuditLogger.AssertExpectations(t)

		// Verify that the response body is empty
		assert.Empty(t, rr.Body.String())
	})
}
