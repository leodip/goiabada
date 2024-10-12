package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
)

func TestHandleAdminGetPermissionsGet(t *testing.T) {
	t.Run("Valid request", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)

		handler := HandleAdminGetPermissionsGet(mockHttpHelper, mockDB)

		req, err := http.NewRequest("GET", "/admin/get-permissions?resourceId=1", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		permissions := []models.Permission{
			{Id: 1, PermissionIdentifier: "read", ResourceId: 1},
			{Id: 2, PermissionIdentifier: "write", ResourceId: 1},
		}
		mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return(permissions, nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, permissions).Return(nil)

		mockHttpHelper.On("EncodeJson", rr, req, mock.MatchedBy(func(result interface{}) bool {
			getPermissionsResult, ok := result.(GetPermissionsResult)
			return ok && len(getPermissionsResult.Permissions) == 2
		})).Return()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Invalid resourceId", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)

		handler := HandleAdminGetPermissionsGet(mockHttpHelper, mockDB)

		req, err := http.NewRequest("GET", "/admin/get-permissions?resourceId=invalid", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		mockHttpHelper.On("JsonError", rr, req, mock.AnythingOfType("*strconv.NumError")).Return()

		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Filter out userinfo permission for AuthServer resource", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDB := mocks_data.NewDatabase(t)

		handler := HandleAdminGetPermissionsGet(mockHttpHelper, mockDB)

		req, err := http.NewRequest("GET", "/admin/get-permissions?resourceId=1", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		permissions := []models.Permission{
			{Id: 1, PermissionIdentifier: "read", ResourceId: 1},
			{Id: 2, PermissionIdentifier: constants.UserinfoPermissionIdentifier, ResourceId: 1},
			{Id: 3, PermissionIdentifier: "write", ResourceId: 1},
		}
		mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return(permissions, nil)
		mockDB.On("PermissionsLoadResources", mock.Anything, permissions).Return(nil).Run(func(args mock.Arguments) {
			loadedPermissions := args.Get(1).([]models.Permission)
			for i := range loadedPermissions {
				loadedPermissions[i].Resource = models.Resource{ResourceIdentifier: constants.AuthServerResourceIdentifier}
			}
		})

		mockHttpHelper.On("EncodeJson", rr, req, mock.MatchedBy(func(result interface{}) bool {
			getPermissionsResult, ok := result.(GetPermissionsResult)
			if !ok || len(getPermissionsResult.Permissions) != 2 {
				return false
			}
			for _, perm := range getPermissionsResult.Permissions {
				if perm.PermissionIdentifier == constants.UserinfoPermissionIdentifier {
					return false
				}
			}
			return true
		})).Return()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})
}
