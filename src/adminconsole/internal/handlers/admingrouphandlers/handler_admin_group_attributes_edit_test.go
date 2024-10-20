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

func TestHandleAdminGroupAttributesEditGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	group := &models.Group{
		Id:              1,
		GroupIdentifier: "test-group",
		Description:     "Test Group",
	}

	attribute := &models.GroupAttribute{
		Id:                   1,
		Key:                  "test-key",
		Value:                "test-value",
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
		GroupId:              1,
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
	mockDB.On("GetGroupAttributeById", mock.Anything, int64(1)).Return(attribute, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_groups_attributes_edit.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["group"] == group && data["attribute"] == attribute
	})).Return(nil)

	handler := HandleAdminGroupAttributesEditGet(mockHttpHelper, mockDB)

	req, _ := http.NewRequest("GET", "/admin/groups/1/attributes/1/edit", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	rctx.URLParams.Add("attributeId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminGroupAttributesEditPost(t *testing.T) {
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

	attribute := &models.GroupAttribute{
		Id:                   1,
		Key:                  "test-key",
		Value:                "test-value",
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
		GroupId:              1,
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
	mockDB.On("GetGroupAttributeById", mock.Anything, int64(1)).Return(attribute, nil)
	mockIdentifierValidator.On("ValidateIdentifier", "updated-key", false).Return(nil)
	mockInputSanitizer.On("Sanitize", "Updated Value").Return("Updated Value")
	mockDB.On("UpdateGroupAttribute", mock.Anything, mock.AnythingOfType("*models.GroupAttribute")).Return(nil)
	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("test-subject")

	mockAuditLogger.On("Log", constants.AuditUpdatedGroupAttribute, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["groupAttributeId"] == int64(1) &&
			details["groupId"] == int64(1) &&
			details["groupIdentifier"] == "test-group" &&
			details["loggedInUser"] == "test-subject"
	})).Return(nil)

	handler := HandleAdminGroupAttributesEditPost(mockHttpHelper, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

	form := url.Values{}
	form.Add("attributeKey", "updated-key")
	form.Add("attributeValue", "Updated Value")
	form.Add("includeInAccessToken", "on")
	form.Add("includeInIdToken", "on")

	req, _ := http.NewRequest("POST", "/admin/groups/1/attributes/1/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	rctx.URLParams.Add("attributeId", "1")
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

func TestHandleAdminGroupAttributesEditPost_InvalidInput(t *testing.T) {
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

	attribute := &models.GroupAttribute{
		Id:                   1,
		Key:                  "test-key",
		Value:                "test-value",
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
		GroupId:              1,
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
	mockDB.On("GetGroupAttributeById", mock.Anything, int64(1)).Return(attribute, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_groups_attributes_edit.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "Attribute key is required"
	})).Return(nil)

	handler := HandleAdminGroupAttributesEditPost(mockHttpHelper, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

	form := url.Values{}
	form.Add("attributeKey", "")
	form.Add("attributeValue", "Updated Value")

	req, _ := http.NewRequest("POST", "/admin/groups/1/attributes/1/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	rctx.URLParams.Add("attributeId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockIdentifierValidator.AssertNotCalled(t, "ValidateIdentifier")
	mockAuditLogger.AssertNotCalled(t, "Log")
}

func TestHandleAdminGroupAttributesEditPost_LongAttributeValue(t *testing.T) {
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

	attribute := &models.GroupAttribute{
		Id:                   1,
		Key:                  "test-key",
		Value:                "test-value",
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
		GroupId:              1,
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
	mockDB.On("GetGroupAttributeById", mock.Anything, int64(1)).Return(attribute, nil)
	mockIdentifierValidator.On("ValidateIdentifier", "test-key", false).Return(nil)

	longValue := strings.Repeat("a", 251)
	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_groups_attributes_edit.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "The attribute value cannot exceed a maximum length of 250 characters. Please make the value shorter."
	})).Return(nil)

	handler := HandleAdminGroupAttributesEditPost(mockHttpHelper, mockAuthHelper, mockDB, mockIdentifierValidator, mockInputSanitizer, mockAuditLogger)

	form := url.Values{}
	form.Add("attributeKey", "test-key")
	form.Add("attributeValue", longValue)

	req, _ := http.NewRequest("POST", "/admin/groups/1/attributes/1/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	rctx.URLParams.Add("attributeId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockIdentifierValidator.AssertExpectations(t)
	mockAuditLogger.AssertNotCalled(t, "Log")
}
