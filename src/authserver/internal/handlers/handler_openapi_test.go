package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/web"
	"github.com/stretchr/testify/assert"
)

// GET /openapi.yaml serves the embedded spec.
func TestHandleOpenAPIGet(t *testing.T) {
	handler := HandleOpenAPIGet()

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest("GET", "/openapi.yaml", nil))

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "application/yaml", recorder.Header().Get("Content-Type"))
	assert.Equal(t, "public, max-age=3600", recorder.Header().Get("Cache-Control"))

	// The body is the embedded spec, byte for byte.
	assert.Equal(t, web.OpenAPISpec(), recorder.Body.Bytes())
	assert.NotEmpty(t, recorder.Body.Bytes(), "the embedded spec must not be empty")
}
