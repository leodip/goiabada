package adminuserhandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/unknwon/paginater"

	mocks_apiclient "github.com/leodip/goiabada/adminconsole/internal/apiclient/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
)

func compareUsers(a, b []models.User) bool {
	return reflect.DeepEqual(a, b)
}

func TestHandleAdminUsersGet(t *testing.T) {
	t.Run("Valid request with results", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockApiClient := mocks_apiclient.NewApiClient(t)

		handler := HandleAdminUsersGet(mockHttpHelper, mockApiClient)

		req, err := http.NewRequest("GET", "/admin/users?page=2&query=test", nil)
		assert.NoError(t, err)

		// Add JWT context
		jwtInfo := oauth.JwtInfo{
			TokenResponse: oauth.TokenResponse{
				AccessToken: "test-access-token",
			},
		}
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, jwtInfo))

		rr := httptest.NewRecorder()

		users := []models.User{
			{Id: 11, Email: "user11@example.com"},
			{Id: 12, Email: "user12@example.com"},
			{Id: 13, Email: "user13@example.com"},
			{Id: 14, Email: "user14@example.com"},
			{Id: 15, Email: "user15@example.com"},
			{Id: 16, Email: "user16@example.com"},
			{Id: 17, Email: "user17@example.com"},
			{Id: 18, Email: "user18@example.com"},
			{Id: 19, Email: "user19@example.com"},
			{Id: 20, Email: "user20@example.com"},
		}
		totalUsers := 25
		mockApiClient.On("SearchUsersPaginated", "test-access-token", "test", 2, 10).Return(users, totalUsers, nil)

		mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_users.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			pageResult, ok := data["pageResult"].(PageResult)
			if !ok {
				return false
			}
			paginator, ok := data["paginator"].(*paginater.Paginater)
			if !ok {
				return false
			}
			return compareUsers(pageResult.Users, users) &&
				pageResult.Total == totalUsers &&
				pageResult.Query == "test" &&
				pageResult.Page == 2 &&
				pageResult.PageSize == 10 &&
				paginator != nil
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockApiClient.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Valid request with no results", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockApiClient := mocks_apiclient.NewApiClient(t)

		handler := HandleAdminUsersGet(mockHttpHelper, mockApiClient)

		req, err := http.NewRequest("GET", "/admin/users", nil)
		assert.NoError(t, err)

		// Add JWT context
		jwtInfo := oauth.JwtInfo{
			TokenResponse: oauth.TokenResponse{
				AccessToken: "test-access-token",
			},
		}
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, jwtInfo))

		rr := httptest.NewRecorder()

		mockApiClient.On("SearchUsersPaginated", "test-access-token", "", 1, 10).Return([]models.User{}, 0, nil)

		mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_users.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			pageResult, ok := data["pageResult"].(PageResult)
			if !ok {
				return false
			}
			paginator, ok := data["paginator"].(*paginater.Paginater)
			if !ok {
				return false
			}
			return len(pageResult.Users) == 0 &&
				pageResult.Total == 0 &&
				pageResult.Query == "" &&
				pageResult.Page == 1 &&
				pageResult.PageSize == 10 &&
				paginator != nil
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockApiClient.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Invalid page number", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockApiClient := mocks_apiclient.NewApiClient(t)

		handler := HandleAdminUsersGet(mockHttpHelper, mockApiClient)

		req, err := http.NewRequest("GET", "/admin/users?page=-1", nil)
		assert.NoError(t, err)

		// Add JWT context
		jwtInfo := oauth.JwtInfo{
			TokenResponse: oauth.TokenResponse{
				AccessToken: "test-access-token",
			},
		}
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo, jwtInfo))

		rr := httptest.NewRecorder()

		mockApiClient.On("SearchUsersPaginated", "test-access-token", "", 1, 10).Return([]models.User{}, 0, nil)

		mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/menu_layout.html", "/admin_users.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			pageResult, ok := data["pageResult"].(PageResult)
			if !ok {
				return false
			}
			return pageResult.Page == 1
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockApiClient.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Missing JWT context", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockApiClient := mocks_apiclient.NewApiClient(t)

		handler := HandleAdminUsersGet(mockHttpHelper, mockApiClient)

		req, err := http.NewRequest("GET", "/admin/users", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "no JWT info found in context"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
	})
}
