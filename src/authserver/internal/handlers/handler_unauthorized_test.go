package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"

	"github.com/stretchr/testify/assert"
)

func TestHandleUnauthorizedGet(t *testing.T) {
	t.Run("Successful render", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)

		handler := HandleUnauthorizedGet(httpHelper)

		req, err := http.NewRequest("GET", "/unauthorized", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		expectedBind := map[string]interface{}{
			"_httpStatus": http.StatusUnauthorized,
		}

		httpHelper.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/unauthorized.html", expectedBind).
			Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Render error", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)

		handler := HandleUnauthorizedGet(httpHelper)

		req, err := http.NewRequest("GET", "/unauthorized", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		expectedBind := map[string]interface{}{
			"_httpStatus": http.StatusUnauthorized,
		}

		renderErr := assert.AnError
		httpHelper.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/unauthorized.html", expectedBind).
			Return(renderErr)

		httpHelper.On("InternalServerError", rr, req, renderErr).
			Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
	})
}
