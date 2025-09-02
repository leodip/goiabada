package adminsettingshandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/enums"
	mocks_inputsanitizer "github.com/leodip/goiabada/core/inputsanitizer/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
)

func TestHandleAdminSettingsGeneralGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)

	handler := HandleAdminSettingsGeneralGet(mockHttpHelper, mockSessionStore)

	settings := &models.Settings{
		AppName:                 "Test App",
		Issuer:                  "test-issuer",
		SelfRegistrationEnabled: true,
		SelfRegistrationRequiresEmailVerification: true,
		PasswordPolicy: enums.PasswordPolicyMedium,
	}

	req, err := http.NewRequest("GET", "/admin/settings/general", nil)
	assert.NoError(t, err)

	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_settings_general.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		settingsInfo, ok := data["settings"].(SettingsGeneral)
		return ok &&
			settingsInfo.AppName == settings.AppName &&
			settingsInfo.Issuer == settings.Issuer &&
			settingsInfo.SelfRegistrationEnabled == settings.SelfRegistrationEnabled &&
			settingsInfo.SelfRegistrationRequiresEmailVerification == settings.SelfRegistrationRequiresEmailVerification &&
			settingsInfo.PasswordPolicy == settings.PasswordPolicy.String()
	})).Return(nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
}

func TestHandleAdminSettingsGeneralGetWithSavedSuccessfully(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)

	handler := HandleAdminSettingsGeneralGet(mockHttpHelper, mockSessionStore)

	settings := &models.Settings{
		AppName:                 "Test App",
		Issuer:                  "test-issuer",
		SelfRegistrationEnabled: true,
		SelfRegistrationRequiresEmailVerification: true,
		PasswordPolicy: enums.PasswordPolicyMedium,
	}

	req, err := http.NewRequest("GET", "/admin/settings/general", nil)
	assert.NoError(t, err)

	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSession.AddFlash("true", "savedSuccessfully")
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_settings_general.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		settingsInfo, ok := data["settings"].(SettingsGeneral)
		return ok &&
			settingsInfo.AppName == settings.AppName &&
			settingsInfo.Issuer == settings.Issuer &&
			settingsInfo.SelfRegistrationEnabled == settings.SelfRegistrationEnabled &&
			settingsInfo.SelfRegistrationRequiresEmailVerification == settings.SelfRegistrationRequiresEmailVerification &&
			settingsInfo.PasswordPolicy == settings.PasswordPolicy.String() &&
			data["savedSuccessfully"] == true
	})).Return(nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
}

func TestHandleAdminSettingsGeneralPost(t *testing.T) {
	tests := []struct {
		name           string
		appName        string
		issuer         string
		expectedError  string
		expectedStatus int
	}{
		{
			name:          "App name too long",
			appName:       strings.Repeat("a", 31),
			issuer:        "valid-issuer",
			expectedError: "App name is too long. The maximum length is 30 characters.",
		},
		{
			name:          "Invalid issuer - not a URL",
			appName:       "Valid App",
			issuer:        "http:",
			expectedError: "Invalid issuer. Please enter a valid URI.",
		},
		{
			name:          "Invalid issuer - starts with number",
			appName:       "Valid App",
			issuer:        "1invalid-issuer",
			expectedError: "Invalid issuer. It must start with a letter, can include letters, numbers, dashes, and underscores, but cannot end with a dash or underscore, or have two consecutive dashes or underscores.",
		},
		{
			name:          "Invalid issuer - ends with dash",
			appName:       "Valid App",
			issuer:        "invalid-issuer-",
			expectedError: "Invalid issuer. It must start with a letter, can include letters, numbers, dashes, and underscores, but cannot end with a dash or underscore, or have two consecutive dashes or underscores.",
		},
		{
			name:          "Invalid issuer - contains double dash",
			appName:       "Valid App",
			issuer:        "invalid--issuer",
			expectedError: "Invalid issuer. It must start with a letter, can include letters, numbers, dashes, and underscores, but cannot end with a dash or underscore, or have two consecutive dashes or underscores.",
		},
		{
			name:          "Issuer too short",
			appName:       "Valid App",
			issuer:        "ab",
			expectedError: "Issuer is too short. The minimum length is 3 characters.",
		},
		{
			name:          "Issuer too long",
			appName:       "Valid App",
			issuer:        strings.Repeat("a", 61),
			expectedError: "Issuer is too long. The maximum length is 60 characters.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			mockSessionStore := mocks_sessionstore.NewStore(t)
			mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
			mockDB := mocks_data.NewDatabase(t)
			mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
			mockAuditLogger := mocks_audit.NewAuditLogger(t)

			handler := HandleAdminSettingsGeneralPost(
				mockHttpHelper,
				mockSessionStore,
				mockAuthHelper,
				mockDB,
				mockInputSanitizer,
				mockAuditLogger,
			)

			form := url.Values{}
			form.Add("appName", tt.appName)
			form.Add("issuer", tt.issuer)
			form.Add("passwordPolicy", enums.PasswordPolicyMedium.String())

			req, _ := http.NewRequest("POST", "/admin/settings/general", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			settings := &models.Settings{
				PasswordPolicy: enums.PasswordPolicyMedium,
			}
			ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()

			if tt.expectedError != "" {
				mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_settings_general.html", mock.MatchedBy(func(data map[string]interface{}) bool {
					return data["error"] == tt.expectedError
				})).Return(nil)
			}

			handler.ServeHTTP(rr, req)

			mockHttpHelper.AssertExpectations(t)
			mockSessionStore.AssertExpectations(t)
			mockAuthHelper.AssertExpectations(t)
			mockDB.AssertExpectations(t)
			mockInputSanitizer.AssertExpectations(t)
			mockAuditLogger.AssertExpectations(t)
		})
	}
}

func TestHandleAdminSettingsGeneralPostHappyPath(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAdminSettingsGeneralPost(
		mockHttpHelper,
		mockSessionStore,
		mockAuthHelper,
		mockDB,
		mockInputSanitizer,
		mockAuditLogger,
	)

	form := url.Values{}
	form.Add("appName", "Valid App")
	form.Add("issuer", "valid-issuer")
	form.Add("passwordPolicy", enums.PasswordPolicyMedium.String())
	form.Add("selfRegistrationEnabled", "on")
	form.Add("selfRegistrationRequiresEmailVerification", "on")

	req, _ := http.NewRequest("POST", "/admin/settings/general", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	settings := &models.Settings{
		Issuer:         "original-issuer", // Add the original issuer to test the change
		PasswordPolicy: enums.PasswordPolicyMedium,
	}
	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

	mockInputSanitizer.On("Sanitize", "Valid App").Return("Valid App")
	mockInputSanitizer.On("Sanitize", "valid-issuer").Return("valid-issuer")

	mockDB.On("UpdateSettings", mock.Anything, mock.MatchedBy(func(s *models.Settings) bool {
		return s.AppName == "Valid App" &&
			s.Issuer == "valid-issuer" &&
			s.PasswordPolicy == enums.PasswordPolicyMedium &&
			s.SelfRegistrationEnabled &&
			s.SelfRegistrationRequiresEmailVerification
	})).Return(nil)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin-user")
	mockAuditLogger.On("Log", constants.AuditUpdatedGeneralSettings, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["loggedInUser"] == "admin-user"
	})).Return(nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	// Since we're changing the issuer from "original-issuer" to "valid-issuer",
	// we should expect a redirect to the logout page
	assert.Equal(t, config.GetAdminConsole().BaseURL+"/auth/logout", rr.Header().Get("Location"))

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockInputSanitizer.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
}

func TestHandleAdminSettingsGeneralPostHappyPathNoIssuerChange(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAdminSettingsGeneralPost(
		mockHttpHelper,
		mockSessionStore,
		mockAuthHelper,
		mockDB,
		mockInputSanitizer,
		mockAuditLogger,
	)

	form := url.Values{}
	form.Add("appName", "Valid App")
	form.Add("issuer", "same-issuer") // Using same issuer as in settings
	form.Add("passwordPolicy", enums.PasswordPolicyMedium.String())
	form.Add("selfRegistrationEnabled", "on")
	form.Add("selfRegistrationRequiresEmailVerification", "on")

	req, _ := http.NewRequest("POST", "/admin/settings/general", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	settings := &models.Settings{
		Issuer:         "same-issuer", // Same issuer as in form
		PasswordPolicy: enums.PasswordPolicyMedium,
	}
	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

	mockInputSanitizer.On("Sanitize", "Valid App").Return("Valid App")
	mockInputSanitizer.On("Sanitize", "same-issuer").Return("same-issuer")

	mockDB.On("UpdateSettings", mock.Anything, mock.MatchedBy(func(s *models.Settings) bool {
		return s.AppName == "Valid App" &&
			s.Issuer == "same-issuer" &&
			s.PasswordPolicy == enums.PasswordPolicyMedium &&
			s.SelfRegistrationEnabled &&
			s.SelfRegistrationRequiresEmailVerification
	})).Return(nil)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin-user")
	mockAuditLogger.On("Log", constants.AuditUpdatedGeneralSettings, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["loggedInUser"] == "admin-user"
	})).Return(nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	// Since the issuer hasn't changed, we should redirect back to the settings page
	assert.Equal(t, config.GetAdminConsole().BaseURL+"/admin/settings/general", rr.Header().Get("Location"))

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockInputSanitizer.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
}
