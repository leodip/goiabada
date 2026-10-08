package apihandlers

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// serveAllowanceSwitch switches client 58's allowance on with an authserver:manage token. Its first
// read answers an ordinary client, registered before afterWrite's steps because testify matches a
// call against the expectations in the order they were registered.
func serveAllowanceSwitch(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
	afterWrite func(database *datamocks.Database)) *httptest.ResponseRecorder {
	t.Helper()
	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), targetClientId).
		Return(&record.Client{Id: targetClientId, ClientIdentifier: "allowance-client"}, nil).Once()
	afterWrite(database)
	rr := httptest.NewRecorder()
	r := clientRequest(http.MethodPut, "/api/v1/admin/clients/58/administrative-scopes", `{"allowed":true}`, "authserver:manage")
	HandleClientAdministrativeScopesPut(database, auditLogger).ServeHTTP(rr, r)
	return rr
}

// The switch writes outside any transaction, so once the write succeeds it has committed, and the
// reads building the answer can no longer undo it. Each of them failing still answers 500, and the
// switch still leaves its one entry (#499 decision 9).
func TestClientAdministrativeScopesPut_ACommittedSwitchIsAuditedWhateverTheAnswerReadsDo(t *testing.T) {
	readFailure := errors.New("the read after the switch failed")
	stored := func() *record.Client {
		return &record.Client{Id: targetClientId, ClientIdentifier: "allowance-client", AdministrativeScopesAllowed: true}
	}
	cases := []struct {
		name       string
		afterWrite func(database *datamocks.Database)
		status     int
	}{
		{
			name: "the answer is built",
			afterWrite: func(database *datamocks.Database) {
				client := stored()
				database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), targetClientId).Return(client, nil).Once()
				database.On("ClientLoadRedirectURIs", mock.Anything, (*sql.Tx)(nil), client).Return(nil).Once()
				database.On("ClientLoadWebOrigins", mock.Anything, (*sql.Tx)(nil), client).Return(nil).Once()
			},
			status: http.StatusOK,
		},
		{
			name: "reading the client back fails",
			afterWrite: func(database *datamocks.Database) {
				database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), targetClientId).Return(nil, readFailure).Once()
			},
			status: http.StatusInternalServerError,
		},
		{
			name: "the client is gone when read back",
			afterWrite: func(database *datamocks.Database) {
				database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), targetClientId).Return(nil, nil).Once()
			},
			status: http.StatusNotFound,
		},
		{
			name: "loading the redirect URIs fails",
			afterWrite: func(database *datamocks.Database) {
				client := stored()
				database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), targetClientId).Return(client, nil).Once()
				database.On("ClientLoadRedirectURIs", mock.Anything, (*sql.Tx)(nil), client).Return(readFailure).Once()
			},
			status: http.StatusInternalServerError,
		},
		{
			name: "loading the web origins fails",
			afterWrite: func(database *datamocks.Database) {
				client := stored()
				database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), targetClientId).Return(client, nil).Once()
				database.On("ClientLoadRedirectURIs", mock.Anything, (*sql.Tx)(nil), client).Return(nil).Once()
				database.On("ClientLoadWebOrigins", mock.Anything, (*sql.Tx)(nil), client).Return(readFailure).Once()
			},
			status: http.StatusInternalServerError,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			records := recordLoggedEvents(auditLogger)
			database.On("SetClientAdministrativeScopesAllowed", mock.Anything, (*sql.Tx)(nil), targetClientId, true).Return(nil).Once()

			rr := serveAllowanceSwitch(t, database, auditLogger, c.afterWrite)

			assert.Equal(t, c.status, rr.Code)
			require.Len(t, *records, 1, "a committed switch leaves exactly one entry")
			assert.Equal(t, audit.EventUpdatedClientAdministrativeScopes, (*records)[0].event)
			assert.Equal(t, map[string]interface{}{
				"client_id":         targetClientId,
				"client_identifier": "allowance-client",
				"allowed":           true,
				"logged_in_user":    grantCaller,
			}, (*records)[0].details)
		})
	}
}

// A write that fails changed nothing, so it leaves no entry.
func TestClientAdministrativeScopesPut_AFailedWriteIsNotAudited(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	database.On("SetClientAdministrativeScopesAllowed", mock.Anything, (*sql.Tx)(nil), targetClientId, true).
		Return(errors.New("the write failed")).Once()

	rr := serveAllowanceSwitch(t, database, auditLogger, func(*datamocks.Database) {})

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}
