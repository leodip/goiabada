package admingrouphandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_inputsanitizer "github.com/leodip/goiabada/core/inputsanitizer/mocks"
	mocks_validators "github.com/leodip/goiabada/core/validators/mocks"
)

func TestHandleAdminGroupAttributesAddGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	group := &models.Group{
		Id:              1,
		GroupIdentifier: "test-group",
		Description:     "Test Group",
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_groups_attributes_add.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["groupId"] == int64(1) &&
			data["groupIdentifier"] == "test-group" &&
			data["includeInAccessToken"] == true &&
			data["includeInIdToken"] == true &&
			data["description"] == "Test Group"
	})).Return(nil)

	handler := HandleAdminGroupAttributesAddGet(mockHttpHelper, mockDB)

	req, _ := http.NewRequest("GET", "/admin/groups/1/attributes/add", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminGroupAttributesAddPost(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
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
	mockIdentifierValidator.On("ValidateIdentifier", "test-key", false).Return(nil)
	mockInputSanitizer.On("Sanitize", "Test Value").Return("Test Value")
	mockDB.On("CreateGroupAttribute", mock.Anything, mock.AnythingOfType("*models.GroupAttribute")).Return(nil)
	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("test-subject")

	mockAuditLogger.On("Log", constants.AuditAddedGroupAttribute, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["groupId"] == int64(1) &&
			details["groupIdentifier"] == "test-group" &&
			details["loggedInUser"] == "test-subject"
	})).Return(nil)

	handler := HandleAdminGroupAttributesAddPost(mockHttpHelper, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

	form := url.Values{}
	form.Add("attributeKey", "test-key")
	form.Add("attributeValue", "Test Value")
	form.Add("includeInAccessToken", "on")
	form.Add("includeInIdToken", "on")

	req, _ := http.NewRequest("POST", "/admin/groups/1/attributes/add", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, "/admin/groups/1/attributes", rr.Header().Get("Location"))

	mockHttpHelper.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockIdentifierValidator.AssertExpectations(t)
	mockInputSanitizer.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
}

func TestHandleAdminGroupAttributesAddPost_InvalidInput(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
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

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_groups_attributes_add.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "Attribute key is required"
	})).Return(nil)

	handler := HandleAdminGroupAttributesAddPost(mockHttpHelper, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

	form := url.Values{}
	form.Add("attributeKey", "")
	form.Add("attributeValue", "Test Value")

	req, _ := http.NewRequest("POST", "/admin/groups/1/attributes/add", strings.NewReader(form.Encode()))
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
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAdminGroupAttributesAddPost_LongAttributeValue(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
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
	mockIdentifierValidator.On("ValidateIdentifier", "test-key", false).Return(nil)

	longValue := strings.Repeat("a", 251)
	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_groups_attributes_add.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "The attribute value cannot exceed a maximum length of 250 characters. Please make the value shorter."
	})).Return(nil)

	handler := HandleAdminGroupAttributesAddPost(mockHttpHelper, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

	form := url.Values{}
	form.Add("attributeKey", "test-key")
	form.Add("attributeValue", longValue)

	req, _ := http.NewRequest("POST", "/admin/groups/1/attributes/add", strings.NewReader(form.Encode()))
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
	mockAuditLogger.AssertNotCalled(t, "Log")
}
