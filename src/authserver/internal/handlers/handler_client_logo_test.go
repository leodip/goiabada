package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func setChiURLParamForHandlers(req *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

func createTestLogoData(width, height int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{R: 100, G: 150, B: 200, A: 255})
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

func TestHandleClientLogoGet_EmptyIdentifier(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)

	handler := HandleClientLogoGet(httpHelper, database)

	req, _ := http.NewRequest("GET", "/client/logo/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleClientLogoGet_ClientNotFound(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)

	handler := HandleClientLogoGet(httpHelper, database)

	req, _ := http.NewRequest("GET", "/client/logo/unknown-app", nil)
	req = setChiURLParamForHandlers(req, "clientIdentifier", "unknown-app")
	rr := httptest.NewRecorder()

	database.On("GetClientByClientIdentifier", (*sql.Tx)(nil), "unknown-app").Return(nil, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
	database.AssertExpectations(t)
}

func TestHandleClientLogoGet_NoLogo(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)

	handler := HandleClientLogoGet(httpHelper, database)

	client := &models.Client{Id: 123, ClientIdentifier: "my-app"}

	req, _ := http.NewRequest("GET", "/client/logo/my-app", nil)
	req = setChiURLParamForHandlers(req, "clientIdentifier", "my-app")
	rr := httptest.NewRecorder()

	database.On("GetClientByClientIdentifier", (*sql.Tx)(nil), "my-app").Return(client, nil)
	database.On("GetClientLogoByClientId", (*sql.Tx)(nil), int64(123)).Return(nil, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
	database.AssertExpectations(t)
}

func TestHandleClientLogoGet_Success(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)

	handler := HandleClientLogoGet(httpHelper, database)

	logoData := createTestLogoData(100, 100)
	client := &models.Client{Id: 123, ClientIdentifier: "my-app"}
	clientLogo := &models.ClientLogo{
		Id:          1,
		ClientId:    123,
		Logo:        logoData,
		ContentType: "image/png",
	}

	req, _ := http.NewRequest("GET", "/client/logo/my-app", nil)
	req = setChiURLParamForHandlers(req, "clientIdentifier", "my-app")
	rr := httptest.NewRecorder()

	database.On("GetClientByClientIdentifier", (*sql.Tx)(nil), "my-app").Return(client, nil)
	database.On("GetClientLogoByClientId", (*sql.Tx)(nil), int64(123)).Return(clientLogo, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "image/png", rr.Header().Get("Content-Type"))
	assert.NotEmpty(t, rr.Header().Get("ETag"))
	assert.Equal(t, "public, max-age=300, must-revalidate", rr.Header().Get("Cache-Control"))
	assert.Equal(t, fmt.Sprintf("%d", len(logoData)), rr.Header().Get("Content-Length"))
	assert.True(t, bytes.Equal(logoData, rr.Body.Bytes()))

	database.AssertExpectations(t)
}

func TestHandleClientLogoGet_ETagMatch_304(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)

	handler := HandleClientLogoGet(httpHelper, database)

	logoData := createTestLogoData(100, 100)
	client := &models.Client{Id: 123, ClientIdentifier: "my-app"}
	clientLogo := &models.ClientLogo{
		Id:          1,
		ClientId:    123,
		Logo:        logoData,
		ContentType: "image/png",
	}

	// Compute the expected ETag
	hash := sha256.Sum256(logoData)
	expectedETag := fmt.Sprintf("\"%x\"", hash[:8])

	req, _ := http.NewRequest("GET", "/client/logo/my-app", nil)
	req = setChiURLParamForHandlers(req, "clientIdentifier", "my-app")
	req.Header.Set("If-None-Match", expectedETag)
	rr := httptest.NewRecorder()

	database.On("GetClientByClientIdentifier", (*sql.Tx)(nil), "my-app").Return(client, nil)
	database.On("GetClientLogoByClientId", (*sql.Tx)(nil), int64(123)).Return(clientLogo, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotModified, rr.Code)
	assert.Equal(t, expectedETag, rr.Header().Get("ETag"))
	assert.Empty(t, rr.Body.Bytes())

	database.AssertExpectations(t)
}

func TestHandleClientLogoGet_ETagMismatch_200(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)

	handler := HandleClientLogoGet(httpHelper, database)

	logoData := createTestLogoData(100, 100)
	client := &models.Client{Id: 123, ClientIdentifier: "my-app"}
	clientLogo := &models.ClientLogo{
		Id:          1,
		ClientId:    123,
		Logo:        logoData,
		ContentType: "image/png",
	}

	req, _ := http.NewRequest("GET", "/client/logo/my-app", nil)
	req = setChiURLParamForHandlers(req, "clientIdentifier", "my-app")
	req.Header.Set("If-None-Match", "\"stale-etag\"")
	rr := httptest.NewRecorder()

	database.On("GetClientByClientIdentifier", (*sql.Tx)(nil), "my-app").Return(client, nil)
	database.On("GetClientLogoByClientId", (*sql.Tx)(nil), int64(123)).Return(clientLogo, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.True(t, bytes.Equal(logoData, rr.Body.Bytes()))

	database.AssertExpectations(t)
}

func TestHandleClientLogoGet_WeakETagMatch_304(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)

	handler := HandleClientLogoGet(httpHelper, database)

	logoData := createTestLogoData(100, 100)
	client := &models.Client{Id: 123, ClientIdentifier: "my-app"}
	clientLogo := &models.ClientLogo{
		Id:          1,
		ClientId:    123,
		Logo:        logoData,
		ContentType: "image/png",
	}

	// Compute the expected ETag and send as weak tag
	hash := sha256.Sum256(logoData)
	expectedETag := fmt.Sprintf("\"%x\"", hash[:8])
	weakETag := "W/" + expectedETag

	req, _ := http.NewRequest("GET", "/client/logo/my-app", nil)
	req = setChiURLParamForHandlers(req, "clientIdentifier", "my-app")
	req.Header.Set("If-None-Match", weakETag)
	rr := httptest.NewRecorder()

	database.On("GetClientByClientIdentifier", (*sql.Tx)(nil), "my-app").Return(client, nil)
	database.On("GetClientLogoByClientId", (*sql.Tx)(nil), int64(123)).Return(clientLogo, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotModified, rr.Code)

	database.AssertExpectations(t)
}

func TestHandleClientLogoGet_MultipleETags_304(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)

	handler := HandleClientLogoGet(httpHelper, database)

	logoData := createTestLogoData(100, 100)
	client := &models.Client{Id: 123, ClientIdentifier: "my-app"}
	clientLogo := &models.ClientLogo{
		Id:          1,
		ClientId:    123,
		Logo:        logoData,
		ContentType: "image/png",
	}

	// Compute the expected ETag and include it among multiple comma-separated ETags
	hash := sha256.Sum256(logoData)
	expectedETag := fmt.Sprintf("\"%x\"", hash[:8])
	multipleETags := "\"old-etag-1\", " + expectedETag + ", \"old-etag-2\""

	req, _ := http.NewRequest("GET", "/client/logo/my-app", nil)
	req = setChiURLParamForHandlers(req, "clientIdentifier", "my-app")
	req.Header.Set("If-None-Match", multipleETags)
	rr := httptest.NewRecorder()

	database.On("GetClientByClientIdentifier", (*sql.Tx)(nil), "my-app").Return(client, nil)
	database.On("GetClientLogoByClientId", (*sql.Tx)(nil), int64(123)).Return(clientLogo, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotModified, rr.Code)

	database.AssertExpectations(t)
}

func TestHandleClientLogoGet_StarETag_304(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)

	handler := HandleClientLogoGet(httpHelper, database)

	logoData := createTestLogoData(100, 100)
	client := &models.Client{Id: 123, ClientIdentifier: "my-app"}
	clientLogo := &models.ClientLogo{
		Id:          1,
		ClientId:    123,
		Logo:        logoData,
		ContentType: "image/png",
	}

	req, _ := http.NewRequest("GET", "/client/logo/my-app", nil)
	req = setChiURLParamForHandlers(req, "clientIdentifier", "my-app")
	req.Header.Set("If-None-Match", "*")
	rr := httptest.NewRecorder()

	database.On("GetClientByClientIdentifier", (*sql.Tx)(nil), "my-app").Return(client, nil)
	database.On("GetClientLogoByClientId", (*sql.Tx)(nil), int64(123)).Return(clientLogo, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotModified, rr.Code)

	database.AssertExpectations(t)
}

func TestHandleClientLogoGet_DatabaseError(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)

	handler := HandleClientLogoGet(httpHelper, database)

	req, _ := http.NewRequest("GET", "/client/logo/my-app", nil)
	req = setChiURLParamForHandlers(req, "clientIdentifier", "my-app")
	rr := httptest.NewRecorder()

	database.On("GetClientByClientIdentifier", (*sql.Tx)(nil), "my-app").Return(nil, assert.AnError)

	httpHelper.On("InternalServerError",
		mock.AnythingOfType("*httptest.ResponseRecorder"),
		req,
		mock.MatchedBy(func(err error) bool {
			return err != nil
		}),
	)

	handler.ServeHTTP(rr, req)

	database.AssertExpectations(t)
	httpHelper.AssertExpectations(t)
}
