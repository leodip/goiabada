package accounthandlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
)

func TestHandleAccountSessionsGet(t *testing.T) {
	t.Run("Successful retrieval of user sessions", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)

		user := &models.User{
			Id:      1,
			Subject: uuid.New(),
		}

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
		mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)

		now := time.Now().UTC()
		userSessions := []models.UserSession{
			{
				Id:                1,
				SessionIdentifier: "session-identifier1",
				Started:           now.Add(-1 * time.Hour),
				LastAccessed:      now.Add(-30 * time.Minute),
				IpAddress:         "192.168.1.1",
				DeviceName:        "Chrome",
				DeviceType:        "Browser",
				DeviceOS:          "Windows",
				UserId:            user.Id,
			},
			{
				Id:                2, // this one should be filtered out
				SessionIdentifier: "session-identifier2",
				Started:           now.Add(-2 * time.Hour),
				LastAccessed:      now.Add(-1 * time.Hour),
				IpAddress:         "192.168.1.2",
				DeviceName:        "Firefox",
				DeviceType:        "Browser",
				DeviceOS:          "MacOS",
				UserId:            user.Id,
			},
		}

		mockDB.On("GetUserSessionsByUserId", mock.Anything, user.Id).Return(userSessions, nil)
		mockDB.On("UserSessionsLoadClients", mock.Anything, userSessions).Return(nil)
		mockDB.On("UserSessionClientsLoadClients", mock.Anything, mock.AnythingOfType("[]models.UserSessionClient")).Return(nil)

		mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/account_user_sessions.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			sessions, ok := data["sessions"].([]SessionInfo)
			if !ok || len(sessions) != 1 {
				return false
			}

			expectedSession := SessionInfo{
				UserSessionId:             1,
				IsCurrent:                 true,
				StartedAt:                 userSessions[0].Started.Format(time.RFC1123),
				LastAcessedAt:             userSessions[0].LastAccessed.Format(time.RFC1123),
				IpAddress:                 "192.168.1.1",
				DeviceName:                "Chrome",
				DeviceType:                "Browser",
				DeviceOS:                  "Windows",
				DurationSinceStarted:      now.Sub(userSessions[0].Started).Round(time.Second).String(),
				DurationSinceLastAccessed: now.Sub(userSessions[0].LastAccessed).Round(time.Second).String(),
			}

			return sessions[0].UserSessionId == expectedSession.UserSessionId &&
				sessions[0].IsCurrent == expectedSession.IsCurrent &&
				sessions[0].StartedAt == expectedSession.StartedAt &&
				sessions[0].LastAcessedAt == expectedSession.LastAcessedAt &&
				sessions[0].IpAddress == expectedSession.IpAddress &&
				sessions[0].DeviceName == expectedSession.DeviceName &&
				sessions[0].DeviceType == expectedSession.DeviceType &&
				sessions[0].DeviceOS == expectedSession.DeviceOS &&
				sessions[0].DurationSinceStarted == expectedSession.DurationSinceStarted &&
				sessions[0].DurationSinceLastAccessed == expectedSession.DurationSinceLastAccessed &&
				len(sessions[0].Clients) == 0 &&
				data["csrfField"] != nil
		})).Return(nil)

		handler := HandleAccountSessionsGet(mockHttpHelper, mockAuthHelper, mockDB)

		req, _ := http.NewRequest("GET", "/account/sessions", nil)
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
			IdToken: &oauth.JwtToken{
				Claims: jwt.MapClaims{
					"sub": user.Subject.String(),
				},
			},
		}))
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{
			UserSessionIdleTimeoutInSeconds: 3600, // 1 hour
			UserSessionMaxLifetimeInSeconds: 86400,
		}))
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, "session-identifier1"))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		mockHttpHelper.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
	})

	t.Run("Unauthorized access", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("")

		handler := HandleAccountSessionsGet(mockHttpHelper, mockAuthHelper, mockDB)

		req, _ := http.NewRequest("GET", "/account/sessions", nil)
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{}))
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.Get().BaseURL+"/unauthorized", rr.Header().Get("Location"))

		mockAuthHelper.AssertExpectations(t)
		mockHttpHelper.AssertNotCalled(t, "RenderTemplate")
		mockDB.AssertNotCalled(t, "GetUserBySubject")
	})
}

func TestHandleAccountSessionsEndSesssionPost(t *testing.T) {
	t.Run("Could not find user session id to revoke", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		user := &models.User{
			Id:      1,
			Subject: uuid.New(),
		}

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
		mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)

		// Simulating an empty request body
		requestBody := strings.NewReader("{}")

		mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return err.Error() == "could not find user session id to revoke"
		})).Return()

		handler := HandleAccountSessionsEndSesssionPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

		req, _ := http.NewRequest("POST", "/account/sessions/end", requestBody)
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
			IdToken: &oauth.JwtToken{
				Claims: jwt.MapClaims{
					"sub": user.Subject.String(),
				},
			},
		}))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockAuditLogger.AssertNotCalled(t, "Log")
	})

	t.Run("Successfully end user session", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		user := &models.User{
			Id:      1,
			Subject: uuid.New(),
		}

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return(user.Subject.String())
		mockDB.On("GetUserBySubject", mock.Anything, user.Subject.String()).Return(user, nil)

		userSessionId := int64(123)
		userSessions := []models.UserSession{
			{
				Id:     userSessionId,
				UserId: user.Id,
			},
		}

		mockDB.On("GetUserSessionsByUserId", mock.Anything, user.Id).Return(userSessions, nil)
		mockDB.On("DeleteUserSession", mock.Anything, userSessionId).Return(nil)

		mockAuditLogger.On("Log", constants.AuditDeletedUserSession, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userSessionId"] == userSessionId && details["loggedInUser"] == user.Subject.String()
		})).Return(nil)

		requestBody := strings.NewReader(fmt.Sprintf(`{"userSessionId": %d}`, userSessionId))

		mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.MatchedBy(func(v interface{}) bool {
			result, ok := v.(struct{ Success bool })
			return ok && result.Success
		})).Return()

		handler := HandleAccountSessionsEndSesssionPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

		req, _ := http.NewRequest("POST", "/account/sessions/end", requestBody)
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, oauth.JwtInfo{
			IdToken: &oauth.JwtToken{
				Claims: jwt.MapClaims{
					"sub": user.Subject.String(),
				},
			},
		}))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockAuditLogger.AssertExpectations(t)
	})

	t.Run("Unauthorized access", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		// Simulate an unauthorized user by returning an empty string
		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("")

		handler := HandleAccountSessionsEndSesssionPost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

		requestBody := strings.NewReader(`{"userSessionId": 123}`)
		req, _ := http.NewRequest("POST", "/account/sessions/end", requestBody)
		req.Header.Set("Content-Type", "application/json")

		// We don't set the ContextKeyJwtInfo here because the user is unauthorized

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.Get().BaseURL+"/unauthorized", rr.Header().Get("Location"))

		mockAuthHelper.AssertExpectations(t)
		mockHttpHelper.AssertNotCalled(t, "EncodeJson")
		mockHttpHelper.AssertNotCalled(t, "JsonError")
		mockDB.AssertNotCalled(t, "GetUserBySubject")
		mockDB.AssertNotCalled(t, "GetUserSessionsByUserId")
		mockDB.AssertNotCalled(t, "DeleteUserSession")
		mockAuditLogger.AssertNotCalled(t, "Log")
	})
}
