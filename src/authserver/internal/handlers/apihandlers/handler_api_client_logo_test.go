package apihandlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/core/constants"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// =============================================================================
// HandleAPIClientLogoGet tests
// =============================================================================

func TestHandleAPIClientLogoGet_NoClientId(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	handler := HandleAPIClientLogoGet(database)

	req, _ := http.NewRequest("GET", "/api/v1/admin/clients//logo", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "CLIENT_ID_REQUIRED", response["error"].(map[string]interface{})["code"])
}

func TestHandleAPIClientLogoGet_InvalidClientId(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	handler := HandleAPIClientLogoGet(database)

	req, _ := http.NewRequest("GET", "/api/v1/admin/clients/invalid/logo", nil)
	req = setChiURLParam(req, "id", "invalid")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "INVALID_CLIENT_ID", response["error"].(map[string]interface{})["code"])
}

func TestHandleAPIClientLogoGet_ClientNotFound(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	handler := HandleAPIClientLogoGet(database)

	req, _ := http.NewRequest("GET", "/api/v1/admin/clients/123/logo", nil)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetClientById", (*sql.Tx)(nil), int64(123)).Return(nil, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "CLIENT_NOT_FOUND", response["error"].(map[string]interface{})["code"])

	database.AssertExpectations(t)
}

func TestHandleAPIClientLogoGet_HasLogo(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	handler := HandleAPIClientLogoGet(database)

	client := &models.Client{Id: 123, ClientIdentifier: "my-app"}

	req, _ := http.NewRequest("GET", "/api/v1/admin/clients/123/logo", nil)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetClientById", (*sql.Tx)(nil), int64(123)).Return(client, nil)
	database.On("ClientHasLogo", (*sql.Tx)(nil), int64(123)).Return(true, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response["hasLogo"].(bool))
	assert.Contains(t, response["logoUrl"].(string), "my-app")

	database.AssertExpectations(t)
}

func TestHandleAPIClientLogoGet_NoLogo(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	handler := HandleAPIClientLogoGet(database)

	client := &models.Client{Id: 123, ClientIdentifier: "my-app"}

	req, _ := http.NewRequest("GET", "/api/v1/admin/clients/123/logo", nil)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetClientById", (*sql.Tx)(nil), int64(123)).Return(client, nil)
	database.On("ClientHasLogo", (*sql.Tx)(nil), int64(123)).Return(false, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.False(t, response["hasLogo"].(bool))
	assert.Nil(t, response["logoUrl"])

	database.AssertExpectations(t)
}

// =============================================================================
// HandleAPIClientLogoPost tests
// =============================================================================

func TestHandleAPIClientLogoPost_NoClientId(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIClientLogoPost(database, auditLogger)

	req, _ := http.NewRequest("POST", "/api/v1/admin/clients//logo", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "CLIENT_ID_REQUIRED", response["error"].(map[string]interface{})["code"])
}

func TestHandleAPIClientLogoPost_InvalidClientId(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIClientLogoPost(database, auditLogger)

	req, _ := http.NewRequest("POST", "/api/v1/admin/clients/invalid/logo", nil)
	req = setChiURLParam(req, "id", "invalid")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "INVALID_CLIENT_ID", response["error"].(map[string]interface{})["code"])
}

func TestHandleAPIClientLogoPost_ClientNotFound(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIClientLogoPost(database, auditLogger)

	pictureData := createTestPNG(100, 100)
	req, err := createMultipartRequest("POST", "/api/v1/admin/clients/123/logo", "picture", pictureData)
	assert.NoError(t, err)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetClientById", (*sql.Tx)(nil), int64(123)).Return(nil, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)

	var response map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "CLIENT_NOT_FOUND", response["error"].(map[string]interface{})["code"])

	database.AssertExpectations(t)
}

func TestHandleAPIClientLogoPost_InvalidImage(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIClientLogoPost(database, auditLogger)

	client := &models.Client{Id: 123, ClientIdentifier: "my-app"}

	invalidImageData := []byte("not a valid image")
	req, err := createMultipartRequest("POST", "/api/v1/admin/clients/123/logo", "picture", invalidImageData)
	assert.NoError(t, err)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetClientById", (*sql.Tx)(nil), int64(123)).Return(client, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "INVALID_IMAGE", response["error"].(map[string]interface{})["code"])
}

func TestHandleAPIClientLogoPost_CreateNew(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIClientLogoPost(database, auditLogger)

	client := &models.Client{Id: 123, ClientIdentifier: "my-app"}
	adminSub := "admin-user-sub"

	pictureData := createTestPNG(100, 100)
	req, err := createMultipartRequest("POST", "/api/v1/admin/clients/123/logo", "picture", pictureData)
	assert.NoError(t, err)
	req = setChiURLParam(req, "id", "123")
	req = setTokenContextWithClaims(req, map[string]interface{}{"sub": adminSub})
	rr := httptest.NewRecorder()

	database.On("GetClientById", (*sql.Tx)(nil), int64(123)).Return(client, nil)
	database.On("GetClientLogoByClientId", (*sql.Tx)(nil), int64(123)).Return(nil, nil)
	database.On("CreateClientLogo", (*sql.Tx)(nil), mock.MatchedBy(func(cl *models.ClientLogo) bool {
		return cl.ClientId == int64(123) && cl.ContentType == "image/png"
	})).Return(nil)

	auditLogger.On("Log", constants.AuditUpdatedClientLogo, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["clientId"] == client.Id && details["loggedInUser"] == adminSub
	})).Return()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response["success"].(bool))
	assert.Contains(t, response["pictureUrl"].(string), "my-app")

	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

func TestHandleAPIClientLogoPost_UpdateExisting(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIClientLogoPost(database, auditLogger)

	client := &models.Client{Id: 123, ClientIdentifier: "my-app"}
	existingLogo := &models.ClientLogo{
		Id:          1,
		ClientId:    123,
		Logo:        []byte("old logo data"),
		ContentType: "image/jpeg",
	}
	adminSub := "admin-user-sub"

	pictureData := createTestPNG(100, 100)
	req, err := createMultipartRequest("POST", "/api/v1/admin/clients/123/logo", "picture", pictureData)
	assert.NoError(t, err)
	req = setChiURLParam(req, "id", "123")
	req = setTokenContextWithClaims(req, map[string]interface{}{"sub": adminSub})
	rr := httptest.NewRecorder()

	database.On("GetClientById", (*sql.Tx)(nil), int64(123)).Return(client, nil)
	database.On("GetClientLogoByClientId", (*sql.Tx)(nil), int64(123)).Return(existingLogo, nil)
	database.On("UpdateClientLogo", (*sql.Tx)(nil), mock.MatchedBy(func(cl *models.ClientLogo) bool {
		return cl.Id == existingLogo.Id && cl.ContentType == "image/png"
	})).Return(nil)

	auditLogger.On("Log", constants.AuditUpdatedClientLogo, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["clientId"] == client.Id && details["loggedInUser"] == adminSub
	})).Return()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response["success"].(bool))

	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

// =============================================================================
// HandleAPIClientLogoDelete tests
// =============================================================================

func TestHandleAPIClientLogoDelete_NoClientId(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIClientLogoDelete(database, auditLogger)

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/clients//logo", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "CLIENT_ID_REQUIRED", response["error"].(map[string]interface{})["code"])
}

func TestHandleAPIClientLogoDelete_InvalidClientId(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIClientLogoDelete(database, auditLogger)

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/clients/invalid/logo", nil)
	req = setChiURLParam(req, "id", "invalid")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "INVALID_CLIENT_ID", response["error"].(map[string]interface{})["code"])
}

func TestHandleAPIClientLogoDelete_ClientNotFound(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIClientLogoDelete(database, auditLogger)

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/clients/123/logo", nil)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetClientById", (*sql.Tx)(nil), int64(123)).Return(nil, nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "CLIENT_NOT_FOUND", response["error"].(map[string]interface{})["code"])

	database.AssertExpectations(t)
}

func TestHandleAPIClientLogoDelete_Success(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIClientLogoDelete(database, auditLogger)

	client := &models.Client{Id: 123, ClientIdentifier: "my-app"}
	adminSub := "admin-user-sub"

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/clients/123/logo", nil)
	req = setChiURLParam(req, "id", "123")
	req = setTokenContextWithClaims(req, map[string]interface{}{"sub": adminSub})
	rr := httptest.NewRecorder()

	database.On("GetClientById", (*sql.Tx)(nil), int64(123)).Return(client, nil)
	database.On("DeleteClientLogo", (*sql.Tx)(nil), int64(123)).Return(nil)

	auditLogger.On("Log", constants.AuditDeletedClientLogo, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["clientId"] == client.Id && details["loggedInUser"] == adminSub
	})).Return()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response["success"].(bool))

	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

func TestHandleAPIClientLogoDelete_DatabaseError(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleAPIClientLogoDelete(database, auditLogger)

	client := &models.Client{Id: 123, ClientIdentifier: "my-app"}

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/clients/123/logo", nil)
	req = setChiURLParam(req, "id", "123")
	rr := httptest.NewRecorder()

	database.On("GetClientById", (*sql.Tx)(nil), int64(123)).Return(client, nil)
	database.On("DeleteClientLogo", (*sql.Tx)(nil), int64(123)).Return(assert.AnError)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "DELETE_ERROR", response["error"].(map[string]interface{})["code"])

	database.AssertExpectations(t)
}
