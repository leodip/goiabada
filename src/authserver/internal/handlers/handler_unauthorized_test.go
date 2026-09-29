package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	mocks_handlers "github.com/leodip/goiabada/authserver/internal/handlers/mocks"

	"github.com/stretchr/testify/assert"
)

func TestHandleUnauthorizedGet(t *testing.T) {
	t.Run("Successful render", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)

		handler := HandleUnauthorizedGet(pageRenderer)

		req, err := http.NewRequest("GET", "/unauthorized", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		expectedBind := map[string]interface{}{
			"_httpStatus": http.StatusUnauthorized,
		}

		pageRenderer.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/unauthorized.html", expectedBind).
			Return(nil)

		handler.ServeHTTP(rr, req)

		pageRenderer.AssertExpectations(t)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Render error", func(t *testing.T) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)

		handler := HandleUnauthorizedGet(pageRenderer)

		req, err := http.NewRequest("GET", "/unauthorized", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		expectedBind := map[string]interface{}{
			"_httpStatus": http.StatusUnauthorized,
		}

		renderErr := assert.AnError
		pageRenderer.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/unauthorized.html", expectedBind).
			Return(renderErr)

		pageRenderer.On("InternalServerError", rr, req, renderErr).
			Return()

		handler.ServeHTTP(rr, req)

		pageRenderer.AssertExpectations(t)
	})
}
