package apihandlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/core/constants"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// assertJSONInternalServerError holds a response to the admin and account API's one 500 shape
// (#279 decision 7): status 500, a JSON body, error_code INTERNAL_SERVER_ERROR, and no HTML. The
// last assertion is the one that matters here. These branches used to answer through
// httpHelper.InternalServerError, which renders error.html, so a database failure on an API route
// gave the admin console's fetch a page to JSON.parse.
func assertJSONInternalServerError(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Header().Get("Content-Type"), "application/json")

	body := rr.Body.String()
	assert.False(t, strings.Contains(body, "<html"), "a 500 on the API surface must not render a page: %s", body)

	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "INTERNAL_SERVER_ERROR", response["error_code"])
}

func TestHandleAPIUserConsentsGet_Success(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	handler := HandleAPIUserConsentsGet(database)

	user := &models.User{Id: 7}
	consents := []models.UserConsent{{Id: 1, UserId: 7, ClientId: 3, Scope: "openid"}}

	req, _ := http.NewRequest("GET", "/api/v1/admin/users/7/consents", nil)
	req = setChiURLParam(req, "id", "7")
	rr := httptest.NewRecorder()

	database.On("GetUserById", (*sql.Tx)(nil), int64(7)).Return(user, nil)
	database.On("GetConsentsByUserId", (*sql.Tx)(nil), int64(7)).Return(consents, nil)
	database.On("UserConsentsLoadClients", (*sql.Tx)(nil), consents).Return(nil)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var response map[string]interface{}
	assert.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
	assert.Len(t, response["consents"], 1)
	database.AssertExpectations(t)
}

func TestHandleAPIUserConsentsGet_GetUserFails_JSON500(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	handler := HandleAPIUserConsentsGet(database)

	req, _ := http.NewRequest("GET", "/api/v1/admin/users/7/consents", nil)
	req = setChiURLParam(req, "id", "7")
	rr := httptest.NewRecorder()

	database.On("GetUserById", (*sql.Tx)(nil), int64(7)).Return(nil, assert.AnError)

	handler.ServeHTTP(rr, req)

	assertJSONInternalServerError(t, rr)
	database.AssertExpectations(t)
}

func TestHandleAPIUserConsentsGet_GetConsentsFails_JSON500(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	handler := HandleAPIUserConsentsGet(database)

	req, _ := http.NewRequest("GET", "/api/v1/admin/users/7/consents", nil)
	req = setChiURLParam(req, "id", "7")
	rr := httptest.NewRecorder()

	database.On("GetUserById", (*sql.Tx)(nil), int64(7)).Return(&models.User{Id: 7}, nil)
	database.On("GetConsentsByUserId", (*sql.Tx)(nil), int64(7)).Return(nil, assert.AnError)

	handler.ServeHTTP(rr, req)

	assertJSONInternalServerError(t, rr)
	database.AssertExpectations(t)
}

func TestHandleAPIUserConsentsGet_LoadClientsFails_JSON500(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	handler := HandleAPIUserConsentsGet(database)

	consents := []models.UserConsent{{Id: 1, UserId: 7, ClientId: 3}}

	req, _ := http.NewRequest("GET", "/api/v1/admin/users/7/consents", nil)
	req = setChiURLParam(req, "id", "7")
	rr := httptest.NewRecorder()

	database.On("GetUserById", (*sql.Tx)(nil), int64(7)).Return(&models.User{Id: 7}, nil)
	database.On("GetConsentsByUserId", (*sql.Tx)(nil), int64(7)).Return(consents, nil)
	database.On("UserConsentsLoadClients", (*sql.Tx)(nil), consents).Return(assert.AnError)

	handler.ServeHTTP(rr, req)

	assertJSONInternalServerError(t, rr)
	database.AssertExpectations(t)
}

func TestHandleAPIUserConsentDelete_Success(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	handler := HandleAPIUserConsentDelete(database, auditLogger)

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/user-consents/5", nil)
	req = setChiURLParam(req, "id", "5")
	rr := httptest.NewRecorder()

	database.On("GetUserConsentById", (*sql.Tx)(nil), int64(5)).Return(&models.UserConsent{Id: 5, UserId: 7}, nil)
	database.On("DeleteUserConsent", (*sql.Tx)(nil), int64(5)).Return(nil)
	auditLogger.On("Log", mock.Anything, constants.AuditDeletedUserConsent, mock.MatchedBy(func(details map[string]interface{}) bool {
		return details["userId"] == int64(7) && details["consentId"] == int64(5)
	})).Return()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

func TestHandleAPIUserConsentDelete_GetConsentFails_JSON500(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	handler := HandleAPIUserConsentDelete(database, auditLogger)

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/user-consents/5", nil)
	req = setChiURLParam(req, "id", "5")
	rr := httptest.NewRecorder()

	database.On("GetUserConsentById", (*sql.Tx)(nil), int64(5)).Return(nil, assert.AnError)

	handler.ServeHTTP(rr, req)

	assertJSONInternalServerError(t, rr)
	database.AssertExpectations(t)
}

func TestHandleAPIUserConsentDelete_DeleteFails_JSON500(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	handler := HandleAPIUserConsentDelete(database, auditLogger)

	req, _ := http.NewRequest("DELETE", "/api/v1/admin/user-consents/5", nil)
	req = setChiURLParam(req, "id", "5")
	rr := httptest.NewRecorder()

	database.On("GetUserConsentById", (*sql.Tx)(nil), int64(5)).Return(&models.UserConsent{Id: 5, UserId: 7}, nil)
	database.On("DeleteUserConsent", (*sql.Tx)(nil), int64(5)).Return(assert.AnError)

	handler.ServeHTTP(rr, req)

	assertJSONInternalServerError(t, rr)
	database.AssertExpectations(t)
	// Nothing was deleted, so nothing is audited.
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}
