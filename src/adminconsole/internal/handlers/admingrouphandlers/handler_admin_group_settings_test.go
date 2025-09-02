package admingrouphandlers

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

func TestHandleAdminGroupSettingsGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)

	group := &models.Group{
		Id:                   1,
		GroupIdentifier:      "test-group",
		Description:          "Test Group",
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_groups_settings.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["groupId"] == int64(1) &&
			data["groupIdentifier"] == "test-group" &&
			data["description"] == "Test Group" &&
			data["includeInIdToken"] == true &&
			data["includeInAccessToken"] == true &&
			data["savedSuccessfully"] == false
	})).Return(nil)

	handler := HandleAdminGroupSettingsGet(mockHttpHelper, mockSessionStore, mockDB)

	req, _ := http.NewRequest("GET", "/admin/groups/1/settings", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
}

func TestHandleAdminGroupSettingsPost(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	group := &models.Group{
		Id:              1,
		GroupIdentifier: "test-group",
		Description:     "Test Group",
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
	mockIdentifierValidator.On("ValidateIdentifier", "updated-group", true).Return(nil)
	mockDB.On("GetGroupByGroupIdentifier", mock.Anything, "updated-group").Return(nil, nil)
	mockInputSanitizer.On("Sanitize", "updated-group").Return("updated-group")
	mockInputSanitizer.On("Sanitize", "Updated Group Description").Return("Updated Group Description")

	mockDB.On("UpdateGroup", mock.Anything, mock.MatchedBy(func(g *models.Group) bool {
		return g.Id == 1 &&
			g.GroupIdentifier == "updated-group" &&
			g.Description == "Updated Group Description" &&
			g.IncludeInIdToken == true &&
			g.IncludeInAccessToken == true
	})).Return(nil)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("test-subject")

	// Update this mock to validate the log entry
	mockAuditLogger.On("Log", constants.AuditUpdatedGroup, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["groupId"] == int64(1) &&
			details["groupIdentifier"] == "updated-group" &&
			details["loggedInUser"] == "test-subject"
	})).Return(nil)

	mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	handler := HandleAdminGroupSettingsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

	form := url.Values{}
	form.Add("groupIdentifier", "updated-group")
	form.Add("description", "Updated Group Description")
	form.Add("includeInIdToken", "on")
	form.Add("includeInAccessToken", "on")

	req, _ := http.NewRequest("POST", "/admin/groups/1/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.GetAdminConsole().BaseURL+"/admin/groups/1/settings", rr.Header().Get("Location"))

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockIdentifierValidator.AssertExpectations(t)
	mockInputSanitizer.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
}

func TestHandleAdminGroupSettingsPost_InvalidGroupId(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	mockDB.On("GetGroupById", mock.Anything, int64(999)).Return(nil, nil)

	mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		return err.Error() == "group not found"
	}))

	handler := HandleAdminGroupSettingsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

	form := url.Values{}
	form.Add("groupIdentifier", "updated-group")
	form.Add("description", "Updated Group Description")

	req, _ := http.NewRequest("POST", "/admin/groups/999/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "999")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAdminGroupSettingsPost_DescriptionTooLong(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	group := &models.Group{
		Id:              1,
		GroupIdentifier: "test-group",
		Description:     "Test Group",
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
	mockIdentifierValidator.On("ValidateIdentifier", "test-group", true).Return(nil)

	// Add this line to handle the GetGroupByGroupIdentifier call
	mockDB.On("GetGroupByGroupIdentifier", mock.Anything, "test-group").Return(nil, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_groups_settings.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		errorMsg, ok := data["error"].(string)
		return ok && strings.HasPrefix(errorMsg, "The description cannot exceed a maximum length of")
	})).Return(nil)

	handler := HandleAdminGroupSettingsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

	form := url.Values{}
	form.Add("groupIdentifier", "test-group")
	form.Add("description", strings.Repeat("a", 101)) // Description that's too long

	req, _ := http.NewRequest("POST", "/admin/groups/1/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockIdentifierValidator.AssertExpectations(t)

	// Ensure these mocks were not called
	mockInputSanitizer.AssertNotCalled(t, "Sanitize")
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAdminGroupSettingsPost_InvalidIdentifier(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockSessionStore := mocks_sessionstore.NewStore(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockIdentifierValidator := mocks_validators.NewIdentifierValidator(t)
	mockInputSanitizer := mocks_inputsanitizer.NewInputSanitizer(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	group := &models.Group{
		Id:              1,
		GroupIdentifier: "test-group",
		Description:     "Test Group",
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)

	// Mock the identifier validator to return an error
	mockIdentifierValidator.On("ValidateIdentifier", "invalid@identifier", true).Return(customerrors.NewErrorDetail("", "Invalid identifier format"))

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_groups_settings.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		errorMsg, ok := data["error"].(string)
		return ok && errorMsg == "Invalid identifier format"
	})).Return(nil)

	handler := HandleAdminGroupSettingsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

	form := url.Values{}
	form.Add("groupIdentifier", "invalid@identifier")
	form.Add("description", "Updated Group Description")

	req, _ := http.NewRequest("POST", "/admin/groups/1/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockIdentifierValidator.AssertExpectations(t)

	// Ensure these mocks were not called
	mockInputSanitizer.AssertNotCalled(t, "Sanitize")
	mockDB.AssertNotCalled(t, "GetGroupByGroupIdentifier")
	mockDB.AssertNotCalled(t, "UpdateGroup")
	mockAuditLogger.AssertNotCalled(t, "Log")
}
