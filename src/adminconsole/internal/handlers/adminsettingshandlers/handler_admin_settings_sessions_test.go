package adminsettingshandlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
)

func TestHandleAdminSettingsSessionsGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)

	handler := HandleAdminSettingsSessionsGet(mockHttpHelper, mockSessionStore)

	settings := &models.Settings{
		UserSessionIdleTimeoutInSeconds: 1800,
		UserSessionMaxLifetimeInSeconds: 3600,
	}

	req, err := http.NewRequest("GET", "/admin/settings/sessions", nil)
	assert.NoError(t, err)

	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_settings_sessions.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		settingsInfo, ok := data["settings"].(SettingsSessionGet)
		return ok &&
			settingsInfo.UserSessionIdleTimeoutInSeconds == settings.UserSessionIdleTimeoutInSeconds &&
			settingsInfo.UserSessionMaxLifetimeInSeconds == settings.UserSessionMaxLifetimeInSeconds
	})).Return(nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
}

func TestHandleAdminSettingsSessionsPost(t *testing.T) {
	tests := []struct {
		name                            string
		userSessionIdleTimeoutInSeconds string
		userSessionMaxLifetimeInSeconds string
		expectedError                   string
		expectedStatus                  int
	}{
		{
			name:                            "Valid input",
			userSessionIdleTimeoutInSeconds: "1800",
			userSessionMaxLifetimeInSeconds: "3600",
			expectedStatus:                  http.StatusFound,
		},
		{
			name:                            "Invalid idle timeout",
			userSessionIdleTimeoutInSeconds: "invalid",
			userSessionMaxLifetimeInSeconds: "3600",
			expectedError:                   "Invalid value for user session - idle timeout in seconds.",
		},
		{
			name:                            "Invalid max lifetime",
			userSessionIdleTimeoutInSeconds: "1800",
			userSessionMaxLifetimeInSeconds: "invalid",
			expectedError:                   "Invalid value for user session - max lifetime in seconds.",
		},
		{
			name:                            "Idle timeout too low",
			userSessionIdleTimeoutInSeconds: "0",
			userSessionMaxLifetimeInSeconds: "3600",
			expectedError:                   "User session - idle timeout in seconds must be greater than zero.",
		},
		{
			name:                            "Max lifetime too low",
			userSessionIdleTimeoutInSeconds: "1800",
			userSessionMaxLifetimeInSeconds: "0",
			expectedError:                   "User session - max lifetime in seconds must be greater than zero.",
		},
		{
			name:                            "Idle timeout too high",
			userSessionIdleTimeoutInSeconds: "160000001",
			userSessionMaxLifetimeInSeconds: "3600",
			expectedError:                   "User session - idle timeout in seconds cannot be greater than 160000000.",
		},
		{
			name:                            "Max lifetime too high",
			userSessionIdleTimeoutInSeconds: "1800",
			userSessionMaxLifetimeInSeconds: "160000001",
			expectedError:                   "User session - max lifetime in seconds cannot be greater than 160000000.",
		},
		{
			name:                            "Idle timeout greater than max lifetime",
			userSessionIdleTimeoutInSeconds: "3600",
			userSessionMaxLifetimeInSeconds: "1800",
			expectedError:                   "User session - the idle timeout cannot be greater than the max lifetime.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			mockSessionStore := mocks_sessionstore.NewStore(t)
			mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
			mockDB := mocks_data.NewDatabase(t)
			mockAuditLogger := mocks_audit.NewAuditLogger(t)

			handler := HandleAdminSettingsSessionsPost(
				mockHttpHelper,
				mockSessionStore,
				mockAuthHelper,
				mockDB,
				mockAuditLogger,
			)

			form := url.Values{}
			form.Add("userSessionIdleTimeoutInSeconds", tt.userSessionIdleTimeoutInSeconds)
			form.Add("userSessionMaxLifetimeInSeconds", tt.userSessionMaxLifetimeInSeconds)

			req, _ := http.NewRequest("POST", "/admin/settings/sessions", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			settings := &models.Settings{
				PasswordPolicy: enums.PasswordPolicyMedium,
			}
			ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()

			if tt.expectedError != "" {
				mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_settings_sessions.html", mock.MatchedBy(func(data map[string]interface{}) bool {
					return data["error"] == tt.expectedError
				})).Return(nil)
			} else {
				mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
				mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
				mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

				mockDB.On("UpdateSettings", mock.Anything, mock.MatchedBy(func(s *models.Settings) bool {
					return s.UserSessionIdleTimeoutInSeconds == 1800 &&
						s.UserSessionMaxLifetimeInSeconds == 3600
				})).Return(nil)

				mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin-user")
				mockAuditLogger.On("Log", constants.AuditUpdatedSessionsSettings, mock.MatchedBy(func(details map[string]interface{}) bool {
					return details["loggedInUser"] == "admin-user"
				})).Return(nil)
			}

			handler.ServeHTTP(rr, req)

			if tt.expectedError != "" {
				assert.Equal(t, http.StatusOK, rr.Code)
			} else {
				assert.Equal(t, http.StatusFound, rr.Code)
				assert.Equal(t, fmt.Sprintf("%v/admin/settings/sessions", config.Get().BaseURL), rr.Header().Get("Location"))
			}

			mockHttpHelper.AssertExpectations(t)
			mockSessionStore.AssertExpectations(t)
			mockAuthHelper.AssertExpectations(t)
			mockDB.AssertExpectations(t)
			mockAuditLogger.AssertExpectations(t)
		})
	}
}
