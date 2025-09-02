package adminclienthandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_inputsanitizer "github.com/leodip/goiabada/core/inputsanitizer/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
	mocks_validators "github.com/leodip/goiabada/core/validators/mocks"
)

func TestHandleAdminClientSettingsGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockDB := mocks_data.NewDatabase(t)

	client := &models.Client{
		Id:                       1,
		ClientIdentifier:         "test-client",
		Description:              "Test Client",
		Enabled:                  true,
		ConsentRequired:          true,
		AuthorizationCodeEnabled: true,
		DefaultAcrLevel:          enums.AcrLevel1,
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_clients_settings.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		clientData, ok := data["client"].(struct {
			ClientId                 int64
			ClientIdentifier         string
			Description              string
			Enabled                  bool
			ConsentRequired          bool
			AuthorizationCodeEnabled bool
			DefaultAcrLevel          string
			IsSystemLevelClient      bool
		})
		return ok &&
			clientData.ClientId == 1 &&
			clientData.ClientIdentifier == "test-client" &&
			clientData.Description == "Test Client" &&
			clientData.Enabled &&
			clientData.ConsentRequired &&
			clientData.AuthorizationCodeEnabled &&
			clientData.DefaultAcrLevel == enums.AcrLevel1.String() &&
			!clientData.IsSystemLevelClient
	})).Return(nil)

	handler := HandleAdminClientSettingsGet(mockHttpHelper, mockSessionStore, mockDB)

	req, _ := http.NewRequest("GET", "/admin/clients/1/settings", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("clientId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminClientSettingsPost(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	client := &models.Client{
		Id:                       1,
		ClientIdentifier:         "test-client",
		Description:              "Test Client",
		Enabled:                  true,
		ConsentRequired:          true,
		AuthorizationCodeEnabled: true,
		DefaultAcrLevel:          enums.AcrLevel1,
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)
	mockDB.On("GetClientByClientIdentifier", mock.Anything, "updated-client").Return(nil, nil)
	mockDB.On("UpdateClient", mock.Anything, mock.AnythingOfType("*models.Client")).Return(nil)

	mockIdentifierValidator.On("ValidateIdentifier", "updated-client", true).Return(nil)
	mockInputSanitizer.On("Sanitize", mock.AnythingOfType("string")).Return(func(s string) string { return s })

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("test-subject")

	mockAuditLogger.On("Log", constants.AuditUpdatedClientSettings, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["clientId"] == int64(1) && details["loggedInUser"] == "test-subject"
	})).Return(nil)

	handler := HandleAdminClientSettingsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

	form := url.Values{}
	form.Add("clientIdentifier", "updated-client")
	form.Add("description", "Updated Test Client")
	form.Add("enabled", "on")
	form.Add("consentRequired", "on")
	form.Add("defaultAcrLevel", enums.AcrLevel1.String())

	req, _ := http.NewRequest("POST", "/admin/clients/1/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("clientId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.GetAdminConsole().BaseURL+"/admin/clients/1/settings", rr.Header().Get("Location"))

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockIdentifierValidator.AssertExpectations(t)
	mockInputSanitizer.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
}

func TestHandleAdminClientSettingsPost_SystemLevelClient(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	client := &models.Client{
		Id:               1,
		ClientIdentifier: constants.AdminConsoleClientIdentifier,
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)

	mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		return err.Error() == "trying to edit a system level client"
	}))

	handler := HandleAdminClientSettingsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

	form := url.Values{}
	form.Add("clientIdentifier", "updated-client")
	form.Add("description", "Updated Test Client")
	form.Add("enabled", "on")
	form.Add("consentRequired", "on")
	form.Add("defaultAcrLevel", "1")

	req, _ := http.NewRequest("POST", "/admin/clients/1/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("clientId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAdminClientSettingsPost_InvalidIdentifier(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	client := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)

	mockIdentifierValidator.On("ValidateIdentifier", "invalid client", true).Return(customerrors.NewErrorDetail("", "Invalid identifier"))

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_clients_settings.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "Invalid identifier"
	})).Return(nil)

	handler := HandleAdminClientSettingsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

	form := url.Values{}
	form.Add("clientIdentifier", "invalid client")
	form.Add("description", "Updated Test Client")
	form.Add("enabled", "on")
	form.Add("consentRequired", "on")
	form.Add("defaultAcrLevel", enums.AcrLevel1.String())

	req, _ := http.NewRequest("POST", "/admin/clients/1/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("clientId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockIdentifierValidator.AssertExpectations(t)
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAdminClientSettingsPost_DescriptionTooLong(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	client := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
	}

	mockDB.On("GetClientById", mock.Anything, int64(1)).Return(client, nil)
	mockDB.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

	mockIdentifierValidator.On("ValidateIdentifier", "test-client", true).Return(nil)

	// Create a description that exceeds the maximum length
	longDescription := strings.Repeat("a", 101) // 101 characters

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_clients_settings.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "The description cannot exceed a maximum length of 100 characters."
	})).Return(nil).Once()

	handler := HandleAdminClientSettingsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

	form := url.Values{}
	form.Add("clientIdentifier", "test-client")
	form.Add("description", longDescription)
	form.Add("enabled", "on")
	form.Add("consentRequired", "on")
	form.Add("defaultAcrLevel", enums.AcrLevel1.String())

	req, _ := http.NewRequest("POST", "/admin/clients/1/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("clientId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code) // The handler should render the template with an error, not redirect

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockIdentifierValidator.AssertExpectations(t)
	mockAuditLogger.AssertNotCalled(t, "Log")

	// Ensure that Sanitize was not called
	mockInputSanitizer.AssertNotCalled(t, "Sanitize")
}
