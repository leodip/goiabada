package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	mocks_handlers "github.com/leodip/goiabada/authserver/internal/handlers/mocks"

	"github.com/stretchr/testify/assert"
)

// The handler is now a delegate, so this proves the delegation and nothing else: the page, its
// status, its headers and the render-failure fallback are HttpHelper.NotFound's, and they are
// pinned at the HTTP seam in core/handlerhelpers/http_helper_test.go rather than through a mock
// that can only report what it was told to return (#279).
func TestHandleNotFoundGet(t *testing.T) {
	pageRenderer := mocks_handlers.NewPageRenderer(t)

	req := httptest.NewRequest(http.MethodGet, "/non-existent-path", nil)
	rr := httptest.NewRecorder()

	pageRenderer.On("NotFound", rr, req).Once()

	HandleNotFoundGet(pageRenderer).ServeHTTP(rr, req)

	pageRenderer.AssertExpectations(t)
	assert.Equal(t, http.StatusOK, rr.Code, "the mock writes nothing, so the recorder keeps its default")
}
