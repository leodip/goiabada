package apihandlers

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/inputvalidation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Four client writes answer with the client's redirect URIs and web origins, loaded after the write
// has committed. Either load failing answers 500, but the change has taken effect, so its event is
// recorded before those loads run, as HandleClientAdministrativeScopesPut's is (#499 decision 9).

// committedClientWrite is one of the four writes and what it records.
type committedClientWrite struct {
	name string
	// event is the write's own event, recorded once whatever the loads after it do.
	event string
	// alsoRecorded is an event the write records ahead of its own, once.
	alsoRecorded string
	serve        func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) *httptest.ResponseRecorder
	// expectWrite registers the write, succeeding.
	expectWrite func(database *datamocks.Database)
	// expectFailingWrite registers the write, failing before anything is committed.
	expectFailingWrite func(database *datamocks.Database)
}

// expectUpdateNotOwningAuthenticationMode registers updateClientNotOwningAuthenticationMode's
// transaction, committing.
func expectUpdateNotOwningAuthenticationMode(database *datamocks.Database) {
	datamocks.ExpectRunInTransaction(database, clientUpdateTx)
	database.On("AcquireClientRow", mock.Anything, clientUpdateTx, targetClientId).Return(nil).Once()
	database.On("GetClientById", mock.Anything, clientUpdateTx, targetClientId).
		Return(&record.Client{Id: targetClientId, ClientIdentifier: "target-client"}, nil).Once()
	database.On("UpdateClient", mock.Anything, clientUpdateTx, mock.Anything).Return(nil).Once()
}

var committedClientWrites = []committedClientWrite{
	{
		name:  "PUT /clients/{id}",
		event: audit.EventUpdatedClientSettings,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) *httptest.ResponseRecorder {
			r := clientRequest(http.MethodPut, "/api/v1/admin/clients/58",
				`{"clientIdentifier":"target-client","description":"changed","enabled":true}`, "authserver:manage")
			rr := httptest.NewRecorder()
			HandleClientUpdatePut(database, inputvalidation.NewIdentifierValidator(), auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectWrite:        expectUpdateNotOwningAuthenticationMode,
		expectFailingWrite: failingWrite("RunInTransaction", mock.Anything, mock.Anything),
	},
	{
		name:  "PUT /clients/{id}/authentication rotating the secret",
		event: audit.EventUpdatedClientAuthentication,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) *httptest.ResponseRecorder {
			r := clientRequest(http.MethodPut, "/api/v1/admin/clients/58/authentication",
				`{"isPublic":false,"clientSecret":"`+strings.Repeat("s", 60)+`"}`, "authserver:manage")
			rr := httptest.NewRecorder()
			HandleClientAuthenticationPut(database, auditLogger, testDataCipher).ServeHTTP(rr, r)
			return rr
		},
		expectWrite: func(database *datamocks.Database) {
			database.On("UpdateClient", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(nil).Once()
		},
		expectFailingWrite: failingWrite("UpdateClient", mock.Anything, (*sql.Tx)(nil), mock.Anything),
	},
	{
		name:         "PUT /clients/{id}/authentication making the client public",
		event:        audit.EventUpdatedClientAuthentication,
		alsoRecorded: audit.EventRevokedClientGrants,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) *httptest.ResponseRecorder {
			r := clientRequest(http.MethodPut, "/api/v1/admin/clients/58/authentication", `{"isPublic":true}`, "authserver:manage")
			rr := httptest.NewRecorder()
			HandleClientAuthenticationPut(database, auditLogger, testDataCipher).ServeHTTP(rr, r)
			return rr
		},
		expectWrite: func(database *datamocks.Database) {
			datamocks.ExpectRunInTransaction(database, clientUpdateTx)
			database.On("SetClientPublic", mock.Anything, clientUpdateTx, targetClientId).Return(true, nil).Once()
			database.On("UpdateClient", mock.Anything, clientUpdateTx, mock.Anything).Return(nil).Once()
			database.On("RevokeCodesByClientId", mock.Anything, clientUpdateTx, targetClientId).Return(int64(1), nil).Once()
			database.On("GetRefreshTokensByClientId", mock.Anything, clientUpdateTx, targetClientId).
				Return([]*record.RefreshToken{}, nil).Once()
		},
		expectFailingWrite: failingWrite("RunInTransaction", mock.Anything, mock.Anything),
	},
	{
		name:  "PUT /clients/{id}/oauth2-flows",
		event: audit.EventUpdatedClientOAuth2Flows,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) *httptest.ResponseRecorder {
			r := clientRequest(http.MethodPut, "/api/v1/admin/clients/58/oauth2-flows",
				`{"authorizationCodeEnabled":true,"clientCredentialsEnabled":true}`, "authserver:manage")
			rr := httptest.NewRecorder()
			HandleClientOAuth2FlowsPut(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectWrite:        expectUpdateNotOwningAuthenticationMode,
		expectFailingWrite: failingWrite("RunInTransaction", mock.Anything, mock.Anything),
	},
	{
		name:  "PUT /clients/{id}/tokens",
		event: audit.EventUpdatedClientTokens,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) *httptest.ResponseRecorder {
			r := clientRequest(http.MethodPut, "/api/v1/admin/clients/58/tokens",
				`{"tokenExpirationInSeconds":300,"includeOpenIDConnectClaimsInAccessToken":"default","includeOpenIDConnectClaimsInIdToken":"default"}`,
				"authserver:manage")
			rr := httptest.NewRecorder()
			HandleClientTokensPut(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectWrite:        expectUpdateNotOwningAuthenticationMode,
		expectFailingWrite: failingWrite("RunInTransaction", mock.Anything, mock.Anything),
	},
}

func TestClientWrites_ACommittedWriteIsAuditedWhateverTheAnswerReadsDo(t *testing.T) {
	readFailure := errors.New("the read after the write failed")
	loads := []struct {
		name   string
		expect func(database *datamocks.Database)
		status int
	}{
		{
			name: "the answer is built",
			expect: func(database *datamocks.Database) {
				database.On("ClientLoadRedirectURIs", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(nil).Once()
				database.On("ClientLoadWebOrigins", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(nil).Once()
			},
			status: http.StatusOK,
		},
		{
			name: "loading the redirect URIs fails",
			expect: func(database *datamocks.Database) {
				database.On("ClientLoadRedirectURIs", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(readFailure).Once()
			},
			status: http.StatusInternalServerError,
		},
		{
			name: "loading the web origins fails",
			expect: func(database *datamocks.Database) {
				database.On("ClientLoadRedirectURIs", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(nil).Once()
				database.On("ClientLoadWebOrigins", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(readFailure).Once()
			},
			status: http.StatusInternalServerError,
		},
	}
	for _, write := range committedClientWrites {
		for _, load := range loads {
			t.Run(write.name+", "+load.name, func(t *testing.T) {
				database := datamocks.NewDatabase(t)
				auditLogger := handlersmocks.NewAuditLogger(t)
				records := recordLoggedEvents(auditLogger)
				expectTheTargetClient(targetClient(t, ordinaryClient))(database)
				write.expectWrite(database)
				load.expect(database)

				rr := write.serve(t, database, auditLogger)

				assert.Equal(t, load.status, rr.Code, rr.Body.String())
				want := []string{write.event}
				if write.alsoRecorded != "" {
					want = []string{write.alsoRecorded, write.event}
				}
				events := make([]string, 0, len(*records))
				for _, logged := range *records {
					events = append(events, logged.event)
				}
				require.Equal(t, want, events, "a committed write leaves exactly its entries")
				assert.Equal(t, map[string]interface{}{
					"client_id":      targetClientId,
					"logged_in_user": grantCaller,
				}, (*records)[len(*records)-1].details)
			})
		}
	}
}

// A write that fails changed nothing, so it leaves no entry.
func TestClientWrites_AFailedWriteIsNotAudited(t *testing.T) {
	for _, write := range committedClientWrites {
		t.Run(write.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			expectTheTargetClient(targetClient(t, ordinaryClient))(database)
			write.expectFailingWrite(database)

			rr := write.serve(t, database, auditLogger)

			assert.Equal(t, http.StatusInternalServerError, rr.Code)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}
