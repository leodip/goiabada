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

func TestHandleAdminSettingsUIThemeGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)

	handler := HandleAdminSettingsUIThemeGet(mockHttpHelper, mockSessionStore)

	settings := &models.Settings{
		UITheme: "default",
	}

	req, err := http.NewRequest("GET", "/admin/settings/ui-theme", nil)
	assert.NoError(t, err)

	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_settings_ui_theme.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		settingsInfo, ok := data["settings"].(SettingsUITheme)
		return ok && settingsInfo.UITheme == settings.UITheme
	})).Return(nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
}

func TestHandleAdminSettingsUIThemePost(t *testing.T) {
	tests := []struct {
		name           string
		themeSelection string
		expectedError  string
	}{
		{
			name:           "Valid theme",
			themeSelection: "dark",
			expectedError:  "",
		},
		{
			name:           "Invalid theme",
			themeSelection: "invalid_theme",
			expectedError:  "Invalid theme.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			mockSessionStore := mocks_sessionstore.NewStore(t)
			mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
			mockDB := mocks_data.NewDatabase(t)
			mockAuditLogger := mocks_audit.NewAuditLogger(t)

			handler := HandleAdminSettingsUIThemePost(
				mockHttpHelper,
				mockSessionStore,
				mockAuthHelper,
				mockDB,
				mockAuditLogger,
			)

			form := url.Values{}
			form.Add("themeSelection", tt.themeSelection)

			req, _ := http.NewRequest("POST", "/admin/settings/ui-theme", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			settings := &models.Settings{}
			ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()

			if tt.expectedError != "" {
				mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_settings_ui_theme.html", mock.MatchedBy(func(data map[string]interface{}) bool {
					return data["error"] == tt.expectedError
				})).Return(nil)
			} else {
				mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
				mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
				mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

				mockDB.On("UpdateSettings", mock.Anything, mock.MatchedBy(func(s *models.Settings) bool {
					return s.UITheme == tt.themeSelection
				})).Return(nil)

				mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin-user")
				mockAuditLogger.On("Log", constants.AuditUpdatedUIThemeSettings, mock.MatchedBy(func(details map[string]interface{}) bool {
					return details["loggedInUser"] == "admin-user"
				})).Return(nil)
			}

			handler.ServeHTTP(rr, req)

			if tt.expectedError != "" {
				assert.Equal(t, http.StatusOK, rr.Code)
			} else {
				assert.Equal(t, http.StatusFound, rr.Code)
				assert.Equal(t, config.GetAdminConsole().BaseURL+"/admin/settings/ui-theme", rr.Header().Get("Location"))
			}

			mockHttpHelper.AssertExpectations(t)
			mockSessionStore.AssertExpectations(t)
			mockAuthHelper.AssertExpectations(t)
			mockDB.AssertExpectations(t)
			mockAuditLogger.AssertExpectations(t)
		})
	}
}
