package admingrouphandlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
)

func TestHandleAdminGroupAttributesGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	group := &models.Group{
		Id:              1,
		GroupIdentifier: "test-group",
		Description:     "Test Group",
	}

	attributes := []models.GroupAttribute{
		{Id: 1, Key: "attr1", Value: "value1"},
		{Id: 2, Key: "attr2", Value: "value2"},
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
	mockDB.On("GetGroupAttributesByGroupId", mock.Anything, int64(1)).Return(attributes, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_groups_attributes.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["groupId"] == int64(1) &&
			data["groupIdentifier"] == "test-group" &&
			data["description"] == "Test Group" &&
			len(data["attributes"].([]models.GroupAttribute)) == 2
	})).Return(nil)

	handler := HandleAdminGroupAttributesGet(mockHttpHelper, mockDB)

	req, _ := http.NewRequest("GET", "/admin/groups/1/attributes", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminGroupAttributesRemovePost(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	group := &models.Group{
		Id:              1,
		GroupIdentifier: "test-group",
	}

	attributes := []models.GroupAttribute{
		{Id: 1, Key: "attr1", Value: "value1"},
		{Id: 2, Key: "attr2", Value: "value2"},
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
	mockDB.On("GetGroupAttributesByGroupId", mock.Anything, int64(1)).Return(attributes, nil)
	mockDB.On("DeleteGroupAttribute", mock.Anything, int64(1)).Return(nil)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("test-subject")

	mockAuditLogger.On("Log", constants.AuditDeleteGroupAttribute, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["groupAttributeId"] == int64(1) &&
			details["groupId"] == int64(1) &&
			details["groupIdentifier"] == "test-group" &&
			details["loggedInUser"] == "test-subject"
	})).Return(nil)

	mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.MatchedBy(func(v interface{}) bool {
		result, ok := v.(struct{ Success bool })
		return ok && result.Success
	})).Run(func(args mock.Arguments) {
		w := args.Get(0).(http.ResponseWriter)
		err := json.NewEncoder(w).Encode(struct{ Success bool }{Success: true})
		assert.NoError(t, err)
	}).Return()

	handler := HandleAdminGroupAttributesRemovePost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

	req, _ := http.NewRequest("POST", "/admin/groups/1/attributes/1/remove", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	rctx.URLParams.Add("attributeId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response struct {
		Success bool `json:"success"`
	}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response.Success)

	mockHttpHelper.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
}

func TestHandleAdminGroupAttributesRemovePost_AttributeNotFound(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	group := &models.Group{
		Id:              1,
		GroupIdentifier: "test-group",
	}

	attributes := []models.GroupAttribute{
		{Id: 2, Key: "attr2", Value: "value2"},
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
	mockDB.On("GetGroupAttributesByGroupId", mock.Anything, int64(1)).Return(attributes, nil)

	mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		return err.Error() == "attribute not found"
	}))

	handler := HandleAdminGroupAttributesRemovePost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

	req, _ := http.NewRequest("POST", "/admin/groups/1/attributes/1/remove", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	rctx.URLParams.Add("attributeId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertNotCalled(t, "Log")
}
