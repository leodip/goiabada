package adminsettingshandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
)

func TestHandleAdminSettingsTokensGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)

	handler := HandleAdminSettingsTokensGet(mockHttpHelper, mockSessionStore)

	settings := &models.Settings{
		TokenExpirationInSeconds:                3600,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1209600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 2419200,
		IncludeOpenIDConnectClaimsInAccessToken: true,
	}

	req, err := http.NewRequest("GET", "/admin/settings/tokens", nil)
	assert.NoError(t, err)

	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_settings_tokens.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		settingsInfo, ok := data["settings"].(SettingsTokenGet)
		return ok &&
			settingsInfo.TokenExpirationInSeconds == settings.TokenExpirationInSeconds &&
			settingsInfo.RefreshTokenOfflineIdleTimeoutInSeconds == settings.RefreshTokenOfflineIdleTimeoutInSeconds &&
			settingsInfo.RefreshTokenOfflineMaxLifetimeInSeconds == settings.RefreshTokenOfflineMaxLifetimeInSeconds &&
			settingsInfo.IncludeOpenIDConnectClaimsInAccessToken == settings.IncludeOpenIDConnectClaimsInAccessToken
	})).Return(nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
}

func TestHandleAdminSettingsTokensPost(t *testing.T) {
	tests := []struct {
		name                                    string
		tokenExpirationInSeconds                string
		refreshTokenOfflineIdleTimeoutInSeconds string
		refreshTokenOfflineMaxLifetimeInSeconds string
		includeOpenIDConnectClaimsInAccessToken string
		expectedError                           string
		expectedStatus                          int
	}{
		{
			name:                                    "Valid input",
			tokenExpirationInSeconds:                "3600",
			refreshTokenOfflineIdleTimeoutInSeconds: "1209600",
			refreshTokenOfflineMaxLifetimeInSeconds: "2419200",
			includeOpenIDConnectClaimsInAccessToken: "on",
			expectedStatus:                          http.StatusFound,
		},
		{
			name:                                    "Invalid token expiration",
			tokenExpirationInSeconds:                "invalid",
			refreshTokenOfflineIdleTimeoutInSeconds: "1209600",
			refreshTokenOfflineMaxLifetimeInSeconds: "2419200",
			expectedError:                           "Invalid value for token expiration in seconds.",
		},
		{
			name:                                    "Token expiration too low",
			tokenExpirationInSeconds:                "0",
			refreshTokenOfflineIdleTimeoutInSeconds: "1209600",
			refreshTokenOfflineMaxLifetimeInSeconds: "2419200",
			expectedError:                           "Token expiration in seconds must be greater than zero.",
		},
		{
			name:                                    "Token expiration too high",
			tokenExpirationInSeconds:                "160000001",
			refreshTokenOfflineIdleTimeoutInSeconds: "1209600",
			refreshTokenOfflineMaxLifetimeInSeconds: "2419200",
			expectedError:                           "Token expiration in seconds cannot be greater than 160000000.",
		},
		{
			name:                                    "Invalid refresh token idle timeout",
			tokenExpirationInSeconds:                "3600",
			refreshTokenOfflineIdleTimeoutInSeconds: "invalid",
			refreshTokenOfflineMaxLifetimeInSeconds: "2419200",
			expectedError:                           "Invalid value for refresh token offline - idle timeout in seconds.",
		},
		{
			name:                                    "Refresh token idle timeout too low",
			tokenExpirationInSeconds:                "3600",
			refreshTokenOfflineIdleTimeoutInSeconds: "0",
			refreshTokenOfflineMaxLifetimeInSeconds: "2419200",
			expectedError:                           "Refresh token offline - idle timeout in seconds must be greater than zero.",
		},
		{
			name:                                    "Refresh token idle timeout too high",
			tokenExpirationInSeconds:                "3600",
			refreshTokenOfflineIdleTimeoutInSeconds: "160000001",
			refreshTokenOfflineMaxLifetimeInSeconds: "2419200",
			expectedError:                           "Refresh token offline - idle timeout in seconds cannot be greater than 160000000.",
		},
		{
			name:                                    "Invalid refresh token max lifetime",
			tokenExpirationInSeconds:                "3600",
			refreshTokenOfflineIdleTimeoutInSeconds: "1209600",
			refreshTokenOfflineMaxLifetimeInSeconds: "invalid",
			expectedError:                           "Invalid value for refresh token offline - max lifetime in seconds.",
		},
		{
			name:                                    "Refresh token max lifetime too low",
			tokenExpirationInSeconds:                "3600",
			refreshTokenOfflineIdleTimeoutInSeconds: "1209600",
			refreshTokenOfflineMaxLifetimeInSeconds: "0",
			expectedError:                           "Refresh token offline - max lifetime in seconds must be greater than zero.",
		},
		{
			name:                                    "Refresh token max lifetime too high",
			tokenExpirationInSeconds:                "3600",
			refreshTokenOfflineIdleTimeoutInSeconds: "1209600",
			refreshTokenOfflineMaxLifetimeInSeconds: "160000001",
			expectedError:                           "Refresh token offline - max lifetime in seconds cannot be greater than 160000000.",
		},
		{
			name:                                    "Refresh token idle timeout greater than max lifetime",
			tokenExpirationInSeconds:                "3600",
			refreshTokenOfflineIdleTimeoutInSeconds: "2419200",
			refreshTokenOfflineMaxLifetimeInSeconds: "1209600",
			expectedError:                           "Refresh token offline - idle timeout cannot be greater than max lifetime.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			mockSessionStore := mocks_sessionstore.NewStore(t)
			mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
			mockDB := mocks_data.NewDatabase(t)
			mockAuditLogger := mocks_audit.NewAuditLogger(t)

			handler := HandleAdminSettingsTokensPost(
				mockHttpHelper,
				mockSessionStore,
				mockAuthHelper,
				mockDB,
				mockAuditLogger,
			)

			form := url.Values{}
			form.Add("tokenExpirationInSeconds", tt.tokenExpirationInSeconds)
			form.Add("refreshTokenOfflineIdleTimeoutInSeconds", tt.refreshTokenOfflineIdleTimeoutInSeconds)
			form.Add("refreshTokenOfflineMaxLifetimeInSeconds", tt.refreshTokenOfflineMaxLifetimeInSeconds)
			form.Add("includeOpenIDConnectClaimsInAccessToken", tt.includeOpenIDConnectClaimsInAccessToken)

			req, _ := http.NewRequest("POST", "/admin/settings/tokens", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			settings := &models.Settings{}
			ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()

			if tt.expectedError != "" {
				mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_settings_tokens.html", mock.MatchedBy(func(data map[string]interface{}) bool {
					return data["error"] == tt.expectedError
				})).Return(nil)
			} else {
				mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
				mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
				mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

				mockDB.On("UpdateSettings", mock.Anything, mock.MatchedBy(func(s *models.Settings) bool {
					return s.TokenExpirationInSeconds == 3600 &&
						s.RefreshTokenOfflineIdleTimeoutInSeconds == 1209600 &&
						s.RefreshTokenOfflineMaxLifetimeInSeconds == 2419200 &&
						s.IncludeOpenIDConnectClaimsInAccessToken == true
				})).Return(nil)

				mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin-user")
				mockAuditLogger.On("Log", constants.AuditUpdatedTokensSettings, mock.MatchedBy(func(details map[string]interface{}) bool {
					return details["loggedInUser"] == "admin-user"
				})).Return(nil)
			}

			handler.ServeHTTP(rr, req)

			if tt.expectedError != "" {
				assert.Equal(t, http.StatusOK, rr.Code)
			} else {
				assert.Equal(t, http.StatusFound, rr.Code)
				assert.Equal(t, config.GetAdminConsole().BaseURL+"/admin/settings/tokens", rr.Header().Get("Location"))
			}

			mockHttpHelper.AssertExpectations(t)
			mockSessionStore.AssertExpectations(t)
			mockAuthHelper.AssertExpectations(t)
			mockDB.AssertExpectations(t)
			mockAuditLogger.AssertExpectations(t)
		})
	}
}
