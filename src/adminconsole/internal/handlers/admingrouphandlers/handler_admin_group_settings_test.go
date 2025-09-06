package admingrouphandlers

// TODO: Update tests after migration to API client pattern

/*
import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandleAdminGroupSettingsGet(t *testing.T) {
	mockHttpHelper := &handlers.HttpHelperMock{}
	mockSessionStore := &MockSessionStore{}
	mockDB := &mocks.Database{}

	group := &models.Group{
		Id:                   1,
		GroupIdentifier:      "test-group",
		Description:          "Test group",
		IncludeInIdToken:     true,
		IncludeInAccessToken: false,
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(&sessions.Session{}, nil)
	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_groups_settings.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["groupId"] == int64(1) && data["groupIdentifier"] == "test-group" && data["description"] == "Test group" && data["includeInIdToken"] == true && data["includeInAccessToken"] == false
	})).Return(nil)

	handler := HandleAdminGroupSettingsGet(mockHttpHelper, mockSessionStore, mockDB)

	req, err := http.NewRequest("GET", "/admin/groups/1/settings", nil)
	assert.NoError(t, err)

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	handler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminGroupSettingsPost(t *testing.T) {
	mockHttpHelper := &handlers.HttpHelperMock{}
	mockSessionStore := &MockSessionStore{}
	mockAuthHelper := &handlers.AuthHelperMock{}
	mockDB := &mocks.Database{}
	mockIdentifierValidator := &handlers.IdentifierValidatorMock{}
	mockInputSanitizer := &handlers.InputSanitizerMock{}
	mockAuditLogger := &handlers.AuditLoggerMock{}

	group := &models.Group{
		Id:                   1,
		GroupIdentifier:      "test-group",
		Description:          "Test group",
		IncludeInIdToken:     true,
		IncludeInAccessToken: false,
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
	mockIdentifierValidator.On("ValidateIdentifier", "updated-group", true).Return(nil)
	mockDB.On("GetGroupByGroupIdentifier", mock.Anything, "updated-group").Return(nil, nil)
	mockInputSanitizer.On("Sanitize", "updated-group").Return("updated-group")
	mockInputSanitizer.On("Sanitize", "Updated description").Return("Updated description")
	mockDB.On("UpdateGroup", mock.Anything, mock.MatchedBy(func(g *models.Group) bool {
		return g.Id == 1 && g.GroupIdentifier == "updated-group" && g.Description == "Updated description" && g.IncludeInIdToken == true && g.IncludeInAccessToken == true
	})).Return(nil)
	mockAuditLogger.On("Log", constants.AuditUpdatedGroup, mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["groupId"] == int64(1) && data["groupIdentifier"] == "updated-group" && data["loggedInUser"] == "test-user"
	})).Return()
	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("test-user")
	mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(&sessions.Session{}, nil)
	mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	handler := HandleAdminGroupSettingsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

	form := url.Values{}
	form.Add("groupIdentifier", "updated-group")
	form.Add("description", "Updated description")
	form.Add("includeInIdToken", "on")
	form.Add("includeInAccessToken", "on")

	req, err := http.NewRequest("POST", "/admin/groups/1/settings", strings.NewReader(form.Encode()))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	handler(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "/admin/groups/1/settings")
	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockIdentifierValidator.AssertExpectations(t)
	mockInputSanitizer.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
}

func TestHandleAdminGroupSettingsPost_InvalidGroupId(t *testing.T) {
	mockHttpHelper := &handlers.HttpHelperMock{}
	mockSessionStore := &MockSessionStore{}
	mockAuthHelper := &handlers.AuthHelperMock{}
	mockDB := &mocks.Database{}
	mockIdentifierValidator := &handlers.IdentifierValidatorMock{}
	mockInputSanitizer := &handlers.InputSanitizerMock{}
	mockAuditLogger := &handlers.AuditLoggerMock{}

	mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		return strings.Contains(err.Error(), "invalid syntax")
	})).Return()

	handler := HandleAdminGroupSettingsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

	req, err := http.NewRequest("POST", "/admin/groups/invalid/settings", nil)
	assert.NoError(t, err)

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "invalid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	handler(w, req)

	mockHttpHelper.AssertExpectations(t)
	mockSessionStore.AssertNotCalled(t, "Get")
	mockAuthHelper.AssertNotCalled(t, "GetLoggedInSubject")
	mockDB.AssertNotCalled(t, "GetGroupById")
	mockIdentifierValidator.AssertNotCalled(t, "ValidateIdentifier")
	mockInputSanitizer.AssertNotCalled(t, "Sanitize")
	mockDB.AssertNotCalled(t, "GetGroupByGroupIdentifier")
	mockDB.AssertNotCalled(t, "UpdateGroup")
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAdminGroupSettingsPost_DescriptionTooLong(t *testing.T) {
	mockHttpHelper := &handlers.HttpHelperMock{}
	mockSessionStore := &MockSessionStore{}
	mockAuthHelper := &handlers.AuthHelperMock{}
	mockDB := &mocks.Database{}
	mockIdentifierValidator := &handlers.IdentifierValidatorMock{}
	mockInputSanitizer := &handlers.InputSanitizerMock{}
	mockAuditLogger := &handlers.AuditLoggerMock{}

	group := &models.Group{
		Id:              1,
		GroupIdentifier: "test-group",
		Description:     "Test group",
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
	mockIdentifierValidator.On("ValidateIdentifier", "test-group", true).Return(nil)
	mockDB.On("GetGroupByGroupIdentifier", mock.Anything, "test-group").Return(nil, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_groups_settings.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		errorMsg, ok := data["error"].(string)
		return ok && strings.HasPrefix(errorMsg, "The description cannot exceed a maximum length of")
	})).Return(nil)

	handler := HandleAdminGroupSettingsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

	form := url.Values{}
	form.Add("groupIdentifier", "test-group")
	form.Add("description", strings.Repeat("a", 101)) // 101 characters, exceeds the 100 limit

	req, err := http.NewRequest("POST", "/admin/groups/1/settings", strings.NewReader(form.Encode()))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	handler(w, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockIdentifierValidator.AssertExpectations(t)
	mockInputSanitizer.AssertNotCalled(t, "Sanitize")
	mockDB.AssertNotCalled(t, "UpdateGroup")
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAdminGroupSettingsPost_InvalidIdentifier(t *testing.T) {
	mockHttpHelper := &handlers.HttpHelperMock{}
	mockSessionStore := &MockSessionStore{}
	mockAuthHelper := &handlers.AuthHelperMock{}
	mockDB := &mocks.Database{}
	mockIdentifierValidator := &handlers.IdentifierValidatorMock{}
	mockInputSanitizer := &handlers.InputSanitizerMock{}
	mockAuditLogger := &handlers.AuditLoggerMock{}

	group := &models.Group{
		Id:              1,
		GroupIdentifier: "test-group",
		Description:     "Test group",
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
	mockIdentifierValidator.On("ValidateIdentifier", "invalid identifier", true).Return(&customerrors.ErrorDetail{
		Code:        "INVALID_IDENTIFIER",
		Description: "Invalid identifier format",
	})

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_groups_settings.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		errorMsg, ok := data["error"].(string)
		return ok && errorMsg == "Invalid identifier format"
	})).Return(nil)

	handler := HandleAdminGroupSettingsPost(mockHttpHelper, mockSessionStore, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

	form := url.Values{}
	form.Add("groupIdentifier", "invalid identifier")
	form.Add("description", "Valid description")

	req, err := http.NewRequest("POST", "/admin/groups/1/settings", strings.NewReader(form.Encode()))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	handler(w, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockIdentifierValidator.AssertExpectations(t)
	mockInputSanitizer.AssertNotCalled(t, "Sanitize")
	mockDB.AssertNotCalled(t, "GetGroupByGroupIdentifier")
	mockDB.AssertNotCalled(t, "UpdateGroup")
	mockAuditLogger.AssertNotCalled(t, "Log")
}
*/