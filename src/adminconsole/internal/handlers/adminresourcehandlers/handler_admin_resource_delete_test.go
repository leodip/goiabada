package adminresourcehandlers

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
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
)

func TestHandleAdminResourceDeleteGet(t *testing.T) {

	t.Run("Valid resource", func(t *testing.T) {

		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)

		resource := &models.Resource{
			Id:                 1,
			ResourceIdentifier: "test-resource",
		}
		permissions := []models.Permission{
			{Id: 1, PermissionIdentifier: "permission1"},
			{Id: 2, PermissionIdentifier: "permission2"},
		}

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return(permissions, nil)

		mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_resources_delete.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["resource"] == resource && len(data["permissions"].([]models.Permission)) == 2
		})).Return(nil)

		handler := HandleAdminResourceDeleteGet(mockHttpHelper, mockDB)

		req, _ := http.NewRequest("GET", "/admin/resources/1/delete", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("resourceId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
	})

	t.Run("Resource not found", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(nil, nil)

		mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return errors.Cause(err).Error() == "resource not found"
		}))

		handler := HandleAdminResourceDeleteGet(mockHttpHelper, mockDB)

		req, _ := http.NewRequest("GET", "/admin/resources/1/delete", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("resourceId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
	})
}

func TestHandleAdminResourceDeletePost(t *testing.T) {

	t.Run("Valid resource deletion", func(t *testing.T) {

		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		resource := &models.Resource{
			Id:                 1,
			ResourceIdentifier: "test-resource",
		}

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return([]models.Permission{}, nil)
		mockDB.On("DeleteResource", mock.Anything, int64(1)).Return(nil)

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin-subject")

		mockAuditLogger.On("Log", constants.AuditDeletedResource, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["resourceId"] == int64(1) &&
				details["resourceIdentifier"] == "test-resource" &&
				details["loggedInUser"] == "admin-subject"
		})).Return(nil)

		handler := HandleAdminResourceDeletePost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

		formData := url.Values{}
		formData.Set("resourceIdentifier", "test-resource")
		req, _ := http.NewRequest("POST", "/admin/resources/1/delete", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("resourceId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAdminConsole().BaseURL+"/admin/resources", rr.Header().Get("Location"))

		mockHttpHelper.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockAuditLogger.AssertExpectations(t)
	})

	t.Run("System level resource deletion attempt", func(t *testing.T) {

		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		resource := &models.Resource{
			Id:                 1,
			ResourceIdentifier: constants.AuthServerResourceIdentifier,
		}

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)

		mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return errors.Cause(err).Error() == "system level resources cannot be deleted"
		}))

		handler := HandleAdminResourceDeletePost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

		req, _ := http.NewRequest("POST", "/admin/resources/1/delete", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("resourceId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		req.PostForm = map[string][]string{"resourceIdentifier": {constants.AuthServerResourceIdentifier}}

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockAuditLogger.AssertNotCalled(t, "Log")
	})

	t.Run("Resource identifier mismatch", func(t *testing.T) {

		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDB := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		resource := &models.Resource{
			Id:                 1,
			ResourceIdentifier: "test-resource",
		}

		mockDB.On("GetResourceById", mock.Anything, int64(1)).Return(resource, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return([]models.Permission{}, nil)

		mockHttpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/menu_layout.html", "/admin_resources_delete.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Resource identifier does not match the resource being deleted."
		})).Return(nil)

		handler := HandleAdminResourceDeletePost(mockHttpHelper, mockAuthHelper, mockDB, mockAuditLogger)

		req, _ := http.NewRequest("POST", "/admin/resources/1/delete", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("resourceId", "1")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		req.PostForm = map[string][]string{"resourceIdentifier": {"wrong-identifier"}}

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockAuditLogger.AssertNotCalled(t, "Log")
	})
}
