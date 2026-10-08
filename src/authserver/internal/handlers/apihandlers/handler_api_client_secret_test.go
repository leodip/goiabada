package apihandlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// A client's secret is read from GET /clients/{id}/secret alone, and reading it is audited; GET
// /clients/{id} carries no secret, so admin-read, which reaches the detail and not this route,
// receives no credential (#402 decision 8, #403).

// clientSecretRequest is GET /api/v1/admin/clients/{id}/secret with its chi parameter and a manage
// token, which the target ceiling reads nothing for, whose sub is the caller an audit row names.
func clientSecretRequest(id string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/clients/"+id+"/secret", nil)
	r = setTokenContextWithClaims(r, map[string]interface{}{"scope": "authserver:manage", "sub": "the-caller"})
	return setChiURLParam(r, "id", id)
}

func TestHandleClientSecretGet_AnswersTheDecryptedSecretAndRecordsTheRead(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	sealed, err := testDataCipher.Encrypt("the-plaintext-secret")
	require.NoError(t, err)
	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).
		Return(&record.Client{Id: 7, ClientIdentifier: "portal", ClientSecretEncrypted: sealed}, nil).Once()

	var payload map[string]interface{}
	auditLogger.On("Log", mock.Anything, audit.EventViewedClientSecret, mock.Anything).
		Run(func(args mock.Arguments) { payload = args.Get(2).(map[string]interface{}) }).Return().Once()

	rr := httptest.NewRecorder()
	HandleClientSecretGet(database, auditLogger, testDataCipher).ServeHTTP(rr, clientSecretRequest("7"))

	require.Equal(t, http.StatusOK, rr.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, map[string]any{"clientSecret": "the-plaintext-secret"}, body)

	assert.Equal(t, "viewed_client_secret", audit.EventViewedClientSecret, "the stored event name")
	assert.Equal(t, map[string]interface{}{
		"client_id":         int64(7),
		"client_identifier": "portal",
		"logged_in_user":    "the-caller",
	}, payload)
}

// A public client holds no secret: the answer is an empty one, and since nothing was disclosed
// nothing is recorded.
func TestHandleClientSecretGet_AClientWithNoSecretAnswersAnEmptyOneUnrecorded(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).
		Return(&record.Client{Id: 7, ClientIdentifier: "spa", IsPublic: true}, nil).Once()

	rr := httptest.NewRecorder()
	HandleClientSecretGet(database, auditLogger, testDataCipher).ServeHTTP(rr, clientSecretRequest("7"))

	require.Equal(t, http.StatusOK, rr.Code)
	assert.JSONEq(t, `{"clientSecret":""}`, rr.Body.String())
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

func TestHandleClientSecretGet_AnUnknownClientIsNotFoundAndUnrecorded(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(nil, nil).Once()

	rr := httptest.NewRecorder()
	HandleClientSecretGet(database, auditLogger, testDataCipher).ServeHTTP(rr, clientSecretRequest("7"))

	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.Contains(t, rr.Body.String(), `"NOT_FOUND"`)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

func TestHandleClientSecretGet_AMalformedIdReadsNothing(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	rr := httptest.NewRecorder()
	HandleClientSecretGet(database, auditLogger, testDataCipher).ServeHTTP(rr, clientSecretRequest("not-a-number"))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	database.AssertNotCalled(t, "GetClientById", mock.Anything, mock.Anything, mock.Anything)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// A secret this server cannot open is a 500 that discloses nothing, so it records no read.
func TestHandleClientSecretGet_ASecretThatDoesNotDecryptIsAFailureUnrecorded(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	otherCipher, err := encryption.NewDataCipher([]byte("fedcba9876543210fedcba9876543210"))
	require.NoError(t, err)
	sealed, err := otherCipher.Encrypt("sealed-under-another-key")
	require.NoError(t, err)
	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).
		Return(&record.Client{Id: 7, ClientIdentifier: "portal", ClientSecretEncrypted: sealed}, nil).Once()

	rr := httptest.NewRecorder()
	HandleClientSecretGet(database, auditLogger, testDataCipher).ServeHTTP(rr, clientSecretRequest("7"))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.NotContains(t, rr.Body.String(), "sealed-under-another-key")
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// The detail no longer carries the secret at all: not an empty value, no key.
func TestHandleClientGet_CarriesNoClientSecret(t *testing.T) {
	database := datamocks.NewDatabase(t)

	sealed, err := testDataCipher.Encrypt("the-plaintext-secret")
	require.NoError(t, err)
	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).
		Return(&record.Client{Id: 7, ClientIdentifier: "portal", ClientSecretEncrypted: sealed}, nil).Once()
	stubClientResponseLoads(database)

	r := setChiURLParam(httptest.NewRequest(http.MethodGet, "/api/v1/admin/clients/7", nil), "id", "7")
	rr := httptest.NewRecorder()
	HandleClientGet(database).ServeHTTP(rr, r)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.NotContains(t, rr.Body.String(), "the-plaintext-secret")
	var body struct {
		Client map[string]any `json:"client"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "portal", body.Client["clientIdentifier"], "the detail itself is answered")
	assert.NotContains(t, body.Client, "clientSecret")
}
