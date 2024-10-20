package admingrouphandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
)

func TestHandleAdminGroupDeleteGet(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockDB := mocks_data.NewDatabase(t)

	group := &models.Group{
		Id:              1,
		GroupIdentifier: "test-group",
		Description:     "Test Group",
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
	mockDB.On("CountGroupMembers", mock.Anything, int64(1)).Return(5, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_groups_delete.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["group"] == group && data["countOfUsers"] == 5
	})).Return(nil)

	handler := HandleAdminGroupDeleteGet(mockHttpHelper, mockDB)

	req, _ := http.NewRequest("GET", "/admin/groups/1/delete", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
}

func TestHandleAdminGroupDeletePost(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	group := &models.Group{
		Id:              1,
		GroupIdentifier: "test-group",
		Description:     "Test Group",
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
	mockDB.On("CountGroupMembers", mock.Anything, int64(1)).Return(5, nil)
	mockDB.On("DeleteGroup", mock.Anything, int64(1)).Return(nil)

	mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("test-subject")

	mockAuditLogger.On("Log", constants.AuditDeletedGroup, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["groupId"] == int64(1) &&
			details["groupIdentifier"] == "test-group" &&
			details["loggedInUser"] == "test-subject"
	})).Return(nil)

	handler := HandleAdminGroupDeletePost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

	form := url.Values{}
	form.Add("groupIdentifier", "test-group")

	req, _ := http.NewRequest("POST", "/admin/groups/1/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, config.Get().BaseURL+"/admin/groups", rr.Header().Get("Location"))

	mockHttpHelper.AssertExpectations(t)
	mockAuthHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertExpectations(t)
}

func TestHandleAdminGroupDeletePost_InvalidIdentifier(t *testing.T) {
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockDB := mocks_data.NewDatabase(t)
	mockAuditLogger := mocks_audit.NewAuditLogger(t)

	group := &models.Group{
		Id:              1,
		GroupIdentifier: "test-group",
		Description:     "Test Group",
	}

	mockDB.On("GetGroupById", mock.Anything, int64(1)).Return(group, nil)
	mockDB.On("CountGroupMembers", mock.Anything, int64(1)).Return(5, nil)

	mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_groups_delete.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["error"] == "Group identifier does not match the group being deleted."
	})).Return(nil)

	handler := HandleAdminGroupDeletePost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

	form := url.Values{}
	form.Add("groupIdentifier", "wrong-identifier")

	req, _ := http.NewRequest("POST", "/admin/groups/1/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("groupId", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockHttpHelper.AssertExpectations(t)
	mockDB.AssertExpectations(t)
	mockAuditLogger.AssertNotCalled(t, "Log")
}
