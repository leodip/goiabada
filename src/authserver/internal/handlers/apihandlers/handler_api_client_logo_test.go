package apihandlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// HandleClientLogoGet tests
// =============================================================================

func TestHandleClientLogoGet_NoClientId(t *testing.T) {
	database := datamocks.NewDatabase(t)

	handler := HandleClientLogoGet(database, testBaseURL)

	req, _ := http.NewRequest("GET", "/api/v1/admin/clients//logo", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "VALIDATION_ERROR", response["error_code"])
}

func TestHandleClientLogoGet_InvalidClientId(t *testing.T) {
	database := datamocks.NewDatabase(t)

	handler := HandleClientLogoGet(database, testBaseURL)

	req, _ := http.NewRequest("GET", "/api/v1/admin/clients/invalid/logo", nil)
	req = setChiURLParam(req, "id", "invalid")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "VALIDATION_ERROR", response["error_code"])
}

func TestHandleClientLogoGet_ClientNotFound(t *testing.T) {
	database := datamocks.NewDatabase(t)

	handler := HandleClientLogoGet(database, testBaseURL)

	req, _ := http.NewRequest("GET", "/api/v1/admin/clients/123/logo", nil)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(nil, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "NOT_FOUND", response["error_code"])

	database.AssertExpectations(t)
}

func TestHandleClientLogoGet_HasLogo(t *testing.T) {
	database := datamocks.NewDatabase(t)

	handler := HandleClientLogoGet(database, testBaseURL)

	client := &record.Client{Id: 123, ClientIdentifier: "my-app"}

	req, _ := http.NewRequest("GET", "/api/v1/admin/clients/123/logo", nil)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(client, nil)
	database.On("ClientHasLogo", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(true, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	assert.JSONEq(t, `{"hasLogo":true,"logoUrl":"`+testBaseURL+`/client/logo/my-app"}`, rr.Body.String())

	database.AssertExpectations(t)
}

func TestHandleClientLogoGet_NoLogo(t *testing.T) {
	database := datamocks.NewDatabase(t)

	handler := HandleClientLogoGet(database, testBaseURL)

	client := &record.Client{Id: 123, ClientIdentifier: "my-app"}

	req, _ := http.NewRequest("GET", "/api/v1/admin/clients/123/logo", nil)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(client, nil)
	database.On("ClientHasLogo", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(false, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	assert.JSONEq(t, `{"hasLogo":false}`, rr.Body.String())

	database.AssertExpectations(t)
}

// =============================================================================
// HandleClientLogoPost tests
// =============================================================================

func TestHandleClientLogoPost_NoClientId(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleClientLogoPost(database, auditLogger, testBaseURL, testMaxUploadBytes)

	req, _ := http.NewRequest("POST", "/api/v1/admin/clients//logo", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "VALIDATION_ERROR", response["error_code"])
}

func TestHandleClientLogoPost_InvalidClientId(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleClientLogoPost(database, auditLogger, testBaseURL, testMaxUploadBytes)

	req, _ := http.NewRequest("POST", "/api/v1/admin/clients/invalid/logo", nil)
	req = setChiURLParam(req, "id", "invalid")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "VALIDATION_ERROR", response["error_code"])
}

func TestHandleClientLogoPost_ClientNotFound(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleClientLogoPost(database, auditLogger, testBaseURL, testMaxUploadBytes)

	pictureData := createTestPNG(100, 100)
	req, err := createMultipartRequest("POST", "/api/v1/admin/clients/123/logo", "picture", pictureData)
	require.NoError(t, err)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(nil, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)

	var response map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "NOT_FOUND", response["error_code"])

	database.AssertExpectations(t)
}

func TestHandleClientLogoPost_InvalidImage(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleClientLogoPost(database, auditLogger, testBaseURL, testMaxUploadBytes)

	client := &record.Client{Id: 123, ClientIdentifier: "my-app"}

	invalidImageData := []byte("not a valid image")
	req, err := createMultipartRequest("POST", "/api/v1/admin/clients/123/logo", "picture", invalidImageData)
	require.NoError(t, err)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(client, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)
	// The catalog key and its English sentence, through writeValidationError, as every other
	// validator on this API answers (#435).
	assert.Equal(t, "validator.image.unsupported_type", response["error_code"])
	assert.Equal(t, "The image type is not supported. Allowed types are JPEG, PNG, GIF and WebP.", response["error_description"])
}

// The size cap is the one the handler was handed, not the configured default: an image the
// default accepts is refused under a smaller injected cap, and the refusal names that cap (#434).
func TestHandleClientLogoPost_RefusesAnImageOverTheCapItWasHanded(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleClientLogoPost(database, auditLogger, testBaseURL, 64)

	client := &record.Client{Id: 123, ClientIdentifier: "my-app"}

	pictureData := createTestPNG(100, 100)
	require.Greater(t, len(pictureData), 64)
	req, err := createMultipartRequest("POST", "/api/v1/admin/clients/123/logo", "picture", pictureData)
	require.NoError(t, err)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(client, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
	assert.Equal(t, "validator.image.too_large", response["error_code"])
	assert.Equal(t, "The image can be at most 64 bytes.", response["error_description"])
}

func TestHandleClientLogoPost_CreateNew(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleClientLogoPost(database, auditLogger, testBaseURL, testMaxUploadBytes)

	client := &record.Client{Id: 123, ClientIdentifier: "my-app"}
	adminSub := "admin-user-sub"

	pictureData := createTestPNG(100, 100)
	req, err := createMultipartRequest("POST", "/api/v1/admin/clients/123/logo", "picture", pictureData)
	require.NoError(t, err)
	req = setChiURLParam(req, "id", "123")
	req = setTokenContextWithClaims(req, map[string]interface{}{"scope": "authserver:manage", "sub": adminSub})
	rr := httptest.NewRecorder()

	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(client, nil)
	database.On("GetClientLogoByClientId", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(nil, nil)
	database.On("CreateClientLogo", mock.Anything, (*sql.Tx)(nil), mock.MatchedBy(func(cl *record.ClientLogo) bool {
		return cl.ClientId == int64(123) && cl.ContentType == "image/png"
	})).Return(nil)

	auditLogger.On("Log", mock.Anything, audit.EventUpdatedClientLogo, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["client_id"] == client.Id && details["logged_in_user"] == adminSub
	})).Return()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	assert.JSONEq(t, `{"success":true,"pictureUrl":"`+testBaseURL+`/client/logo/my-app"}`, rr.Body.String())

	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

func TestHandleClientLogoPost_UpdateExisting(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleClientLogoPost(database, auditLogger, testBaseURL, testMaxUploadBytes)

	client := &record.Client{Id: 123, ClientIdentifier: "my-app"}
	existingLogo := &record.ClientLogo{
		Id:          1,
		ClientId:    123,
		Logo:        []byte("old logo data"),
		ContentType: "image/jpeg",
	}
	adminSub := "admin-user-sub"

	pictureData := createTestPNG(100, 100)
	req, err := createMultipartRequest("POST", "/api/v1/admin/clients/123/logo", "picture", pictureData)
	require.NoError(t, err)
	req = setChiURLParam(req, "id", "123")
	req = setTokenContextWithClaims(req, map[string]interface{}{"scope": "authserver:manage", "sub": adminSub})
	rr := httptest.NewRecorder()

	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(client, nil)
	database.On("GetClientLogoByClientId", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(existingLogo, nil)
	database.On("UpdateClientLogo", mock.Anything, (*sql.Tx)(nil), mock.MatchedBy(func(cl *record.ClientLogo) bool {
		return cl.Id == existingLogo.Id && cl.ContentType == "image/png"
	})).Return(nil)

	auditLogger.On("Log", mock.Anything, audit.EventUpdatedClientLogo, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["client_id"] == client.Id && details["logged_in_user"] == adminSub
	})).Return()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	assert.JSONEq(t, `{"success":true,"pictureUrl":"`+testBaseURL+`/client/logo/my-app"}`, rr.Body.String())

	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

// =============================================================================
// HandleClientLogoDelete tests
// =============================================================================

func TestHandleClientLogoDelete_NoClientId(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleClientLogoDelete(database, auditLogger)

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/clients//logo", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "VALIDATION_ERROR", response["error_code"])
}

func TestHandleClientLogoDelete_InvalidClientId(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleClientLogoDelete(database, auditLogger)

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/clients/invalid/logo", nil)
	req = setChiURLParam(req, "id", "invalid")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "VALIDATION_ERROR", response["error_code"])
}

func TestHandleClientLogoDelete_ClientNotFound(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleClientLogoDelete(database, auditLogger)

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/clients/123/logo", nil)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(nil, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "NOT_FOUND", response["error_code"])

	database.AssertExpectations(t)
}

func TestHandleClientLogoDelete_Success(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleClientLogoDelete(database, auditLogger)

	client := &record.Client{Id: 123, ClientIdentifier: "my-app"}
	adminSub := "admin-user-sub"

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/clients/123/logo", nil)
	req = setChiURLParam(req, "id", "123")
	req = setTokenContextWithClaims(req, map[string]interface{}{"scope": "authserver:manage", "sub": adminSub})
	rr := httptest.NewRecorder()

	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(client, nil)
	database.On("DeleteClientLogo", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(nil)

	auditLogger.On("Log", mock.Anything, audit.EventDeletedClientLogo, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["client_id"] == client.Id && details["logged_in_user"] == adminSub
	})).Return()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	assert.JSONEq(t, `{"success":true}`, rr.Body.String())

	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

func TestHandleClientLogoDelete_DatabaseError(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleClientLogoDelete(database, auditLogger)

	client := &record.Client{Id: 123, ClientIdentifier: "my-app"}

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/clients/123/logo", nil)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(client, nil)
	// No token: the target ceiling reads what the client holds, and an ordinary client's write goes on.
	database.On("GetClientPermissionsByClientId", mock.Anything, (*sql.Tx)(nil), int64(123)).Return([]record.ClientPermission{}, nil).Once()
	database.On("DeleteClientLogo", mock.Anything, (*sql.Tx)(nil), int64(123)).Return(assert.AnError)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "INTERNAL_SERVER_ERROR", response["error_code"])

	database.AssertExpectations(t)
}
