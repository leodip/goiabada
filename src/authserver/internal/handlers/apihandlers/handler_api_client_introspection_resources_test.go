package apihandlers

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// What the integration tier cannot make a running server do on demand, for the save of a client's
// introspection resources (#676 decision 14): a client made public between the request's read and
// its transaction, a fault inside the transaction, and the record a committed save writes, field
// by field. The caller holds authserver:manage, so the administrative policy reads nothing here.

// introspectionTx is the transaction the stub hands the save's body. Not nil: a write expected on
// it cannot be matched by one made outside the transaction.
var introspectionTx = &sql.Tx{}

const introspectedResourceId = int64(3)

func serveIntrospectionResourcesPut(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, body string) *httptest.ResponseRecorder {
	r := clientRequest(http.MethodPut, "/api/v1/admin/clients/58/introspection-resources", body, "authserver:manage")
	rr := httptest.NewRecorder()
	HandleClientIntrospectionResourcesPut(database, auditLogger).ServeHTTP(rr, r)
	return rr
}

// expectIntrospectionSaveReads registers the reads before the transaction: the client, confidential,
// and the one resource the save names.
func expectIntrospectionSaveReads(database *datamocks.Database) {
	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), targetClientId).
		Return(&record.Client{Id: targetClientId, ClientIdentifier: "an-api-backend"}, nil).Once()
	database.On("GetResourceById", mock.Anything, (*sql.Tx)(nil), introspectedResourceId).
		Return(&record.Resource{Id: introspectedResourceId, ResourceIdentifier: "product-api"}, nil).Once()
}

// A save adding a resource reads the client again under its row, which making it public takes
// first: made public since the request read it, the client is refused as a public client is, and
// nothing is listed.
func TestHandleClientIntrospectionResourcesPut_AClientMadePublicMeanwhileIsRefusedUnderItsRow(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	expectIntrospectionSaveReads(database)
	stub := datamocks.ExpectRunInTransaction(database, introspectionTx)
	database.On("GetClientIntrospectionResourcesByClientId", mock.Anything, introspectionTx, targetClientId).
		Return([]record.ClientIntrospectionResource{}, nil).Once()
	database.On("AcquireClientRow", mock.Anything, introspectionTx, targetClientId).Return(nil).Once()
	database.On("GetClientById", mock.Anything, introspectionTx, targetClientId).
		Return(&record.Client{Id: targetClientId, ClientIdentifier: "an-api-backend", IsPublic: true}, nil).Once()

	rr := serveIntrospectionResourcesPut(database, auditLogger, `{"resourceIds":[3],"expectedResourceIds":[]}`)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	code, description := decodeErrorEnvelope(t, rr)
	assert.Equal(t, "handler.client_introspection_resources.public_client", code)
	assert.Equal(t, "A public client can't introspect tokens, so it can't list introspection resources.", description)
	require.Error(t, stub.BodyErr, "the transaction was rolled back")
	database.AssertExpectations(t)
	assertNotAttemptedOnClientDatabase(t, database, "CreateClientIntrospectionResource", "DeleteClientIntrospectionResource")
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	// The row is taken before the client is read again, or the read could predate the commit that
	// made the client public.
	var underTheRow []string
	for _, call := range database.Calls {
		if len(call.Arguments) > 1 && call.Arguments.Get(1) == introspectionTx {
			underTheRow = append(underTheRow, call.Method)
		}
	}
	assert.Equal(t, []string{"GetClientIntrospectionResourcesByClientId", "AcquireClientRow", "GetClientById"}, underTheRow)
}

// A save that only removes adds nothing a public client could hold, so it takes no row lock.
func TestHandleClientIntrospectionResourcesPut_ASaveAddingNothingTakesNoRow(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), targetClientId).
		Return(&record.Client{Id: targetClientId, ClientIdentifier: "an-api-backend"}, nil).Once()
	datamocks.ExpectRunInTransaction(database, introspectionTx)
	database.On("GetClientIntrospectionResourcesByClientId", mock.Anything, introspectionTx, targetClientId).
		Return([]record.ClientIntrospectionResource{{Id: 90, ClientId: targetClientId, ResourceId: introspectedResourceId}}, nil).Once()
	database.On("DeleteClientIntrospectionResource", mock.Anything, introspectionTx, int64(90)).Return(nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedClientIntrospectionResources, mock.Anything).Return().Once()

	rr := serveIntrospectionResourcesPut(database, auditLogger, `{"resourceIds":[],"expectedResourceIds":[3]}`)

	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	database.AssertExpectations(t)
	assertNotAttemptedOnClientDatabase(t, database, "AcquireClientRow")
}

// The record names what the save committed, field by field, and is written after the commit.
func TestHandleClientIntrospectionResourcesPut_ACommittedSaveRecordsWhatItChanged(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	expectIntrospectionSaveReads(database)
	var order []string
	datamocks.ExpectRunInTransaction(database, introspectionTx, func(step string) { order = append(order, step) })
	database.On("GetClientIntrospectionResourcesByClientId", mock.Anything, introspectionTx, targetClientId).
		Return([]record.ClientIntrospectionResource{{Id: 91, ClientId: targetClientId, ResourceId: 8}}, nil).Once()
	database.On("AcquireClientRow", mock.Anything, introspectionTx, targetClientId).Return(nil).Once()
	database.On("GetClientById", mock.Anything, introspectionTx, targetClientId).
		Return(&record.Client{Id: targetClientId, ClientIdentifier: "an-api-backend"}, nil).Once()
	database.On("DeleteClientIntrospectionResource", mock.Anything, introspectionTx, int64(91)).Return(nil).Once()
	var created *record.ClientIntrospectionResource
	database.On("CreateClientIntrospectionResource", mock.Anything, introspectionTx, mock.Anything).
		Run(func(args mock.Arguments) { created = args.Get(2).(*record.ClientIntrospectionResource) }).Return(nil).Once()
	var payload map[string]interface{}
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedClientIntrospectionResources, mock.Anything).
		Run(func(args mock.Arguments) {
			order = append(order, "audit")
			payload = args.Get(2).(map[string]interface{})
		}).Return().Once()

	rr := serveIntrospectionResourcesPut(database, auditLogger, `{"resourceIds":[3,3],"expectedResourceIds":[8]}`)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.JSONEq(t, `{"success":true}`, rr.Body.String())
	require.NotNil(t, created)
	assert.Equal(t, record.ClientIntrospectionResource{ClientId: targetClientId, ResourceId: introspectedResourceId}, *created)
	assert.Equal(t, map[string]interface{}{
		"client_id":            targetClientId,
		"added_resource_ids":   []int64{3},
		"removed_resource_ids": []int64{8},
		"logged_in_user":       grantCaller,
	}, payload)
	assert.Equal(t, []string{"begin", "commit", "audit"}, order, "recorded once the save has committed")
}

// A fault inside the transaction answers 500, records nothing and claims nothing was saved.
func TestHandleClientIntrospectionResourcesPut_AFaultInTheTransactionIs500AndRecordsNothing(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	expectIntrospectionSaveReads(database)
	datamocks.ExpectRunInTransaction(database, introspectionTx)
	database.On("GetClientIntrospectionResourcesByClientId", mock.Anything, introspectionTx, targetClientId).
		Return([]record.ClientIntrospectionResource{}, nil).Once()
	database.On("AcquireClientRow", mock.Anything, introspectionTx, targetClientId).Return(nil).Once()
	database.On("GetClientById", mock.Anything, introspectionTx, targetClientId).
		Return(&record.Client{Id: targetClientId, ClientIdentifier: "an-api-backend"}, nil).Once()
	database.On("CreateClientIntrospectionResource", mock.Anything, introspectionTx, mock.Anything).
		Return(errors.New("connection reset")).Once()

	rr := serveIntrospectionResourcesPut(database, auditLogger, `{"resourceIds":[3],"expectedResourceIds":[]}`)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// A list for a client the request read as public is refused before the transaction opens, so the
// refusal reads no resource and writes nothing.
func TestHandleClientIntrospectionResourcesPut_APublicClientIsRefusedBeforeTheTransaction(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), targetClientId).
		Return(&record.Client{Id: targetClientId, ClientIdentifier: "a-spa", IsPublic: true}, nil).Once()

	rr := serveIntrospectionResourcesPut(database, auditLogger, `{"resourceIds":[3],"expectedResourceIds":[]}`)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	code, _ := decodeErrorEnvelope(t, rr)
	assert.Equal(t, "handler.client_introspection_resources.public_client", code)
	database.AssertExpectations(t)
	assertNotAttemptedOnClientDatabase(t, database, "GetResourceById", "RunInTransaction")
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// A public client's empty list is its own: saved with no refusal.
func TestHandleClientIntrospectionResourcesPut_APublicClientSavesItsEmptyList(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), targetClientId).
		Return(&record.Client{Id: targetClientId, ClientIdentifier: "a-spa", IsPublic: true}, nil).Once()
	datamocks.ExpectRunInTransaction(database, introspectionTx)
	database.On("GetClientIntrospectionResourcesByClientId", mock.Anything, introspectionTx, targetClientId).
		Return([]record.ClientIntrospectionResource{}, nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedClientIntrospectionResources, mock.Anything).Return().Once()

	rr := serveIntrospectionResourcesPut(database, auditLogger, `{"resourceIds":[],"expectedResourceIds":[]}`)

	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

// Making a client public clears its introspection resources inside the transaction that revokes
// its grants: a failure clearing them undoes the whole save, which revokes nothing and records
// nothing.
func TestHandleClientAuthenticationPut_AFailedClearingOfTheIntrospectionResourcesSavesNothing(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).
		Return(&record.Client{Id: 7, IsPublic: false, ClientSecretEncrypted: []byte("secret")}, nil).Once()
	stub := datamocks.ExpectRunInTransaction(database, clientUpdateTx)
	database.On("SetClientPublic", mock.Anything, clientUpdateTx, int64(7)).Return(true, nil).Once()
	database.On("DeleteClientIntrospectionResourcesByClientId", mock.Anything, clientUpdateTx, int64(7)).
		Return(errors.New("connection reset")).Once()

	rr := httptest.NewRecorder()
	HandleClientAuthenticationPut(database, auditLogger, testDataCipher).
		ServeHTTP(rr, authenticationPutRequest(t, "7", api.UpdateClientAuthenticationRequest{IsPublic: true}))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	require.EqualError(t, stub.BodyErr, "connection reset")
	assertNotAttemptedOnClientDatabase(t, database, "UpdateClient", "RevokeCodesByClientId", "GetRefreshTokensByClientId")
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}
