package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
)

func TestHandleIndexGet_AuthenticatedUser(t *testing.T) {
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)

	handler := HandleIndexGet(mockAuthHelper, mockHttpHelper)

	req, err := http.NewRequest("GET", "/", nil)
	assert.NoError(t, err)

	jwtInfo := oauth.JwtInfo{
		IdToken: &oauth.JwtToken{
			Claims: map[string]interface{}{
				"email": "test@example.com",
			},
		},
	}
	ctx := context.WithValue(req.Context(), constants.ContextKeyJwtInfo, jwtInfo)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()

	mockAuthHelper.On("IsAuthenticated", jwtInfo).Return(true)

	expectedBindData := map[string]interface{}{
		"AuthServerBaseUrl": config.GetAuthServer().BaseURL,
		"IsAuthenticated":   true,
		"LoggedInUser":      "test@example.com",
		"LogoutLink":        "/auth/logout",
	}

	mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/index.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return assert.Equal(t, expectedBindData, data)
	})).Return(nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockAuthHelper.AssertExpectations(t)
	mockHttpHelper.AssertExpectations(t)
}

func TestHandleIndexGet_UnauthenticatedUser(t *testing.T) {
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)

	handler := HandleIndexGet(mockAuthHelper, mockHttpHelper)

	req, err := http.NewRequest("GET", "/", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()

	expectedBindData := map[string]interface{}{
		"AuthServerBaseUrl": config.GetAuthServer().BaseURL,
		"IsAuthenticated":   false,
		"LoggedInUser":      "",
		"LogoutLink":        "",
	}

	mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/index.html", mock.MatchedBy(func(data map[string]interface{}) bool {
		return assert.Equal(t, expectedBindData, data)
	})).Return(nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	mockAuthHelper.AssertExpectations(t)
	mockHttpHelper.AssertExpectations(t)
}

func TestHandleIndexGet_RenderTemplateError(t *testing.T) {
	mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
	mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)

	handler := HandleIndexGet(mockAuthHelper, mockHttpHelper)

	req, err := http.NewRequest("GET", "/", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()

	mockHttpHelper.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/index.html", mock.Anything).Return(assert.AnError)
	mockHttpHelper.On("InternalServerError", rr, req, assert.AnError).Return()

	handler.ServeHTTP(rr, req)

	mockAuthHelper.AssertExpectations(t)
	mockHttpHelper.AssertExpectations(t)
}
