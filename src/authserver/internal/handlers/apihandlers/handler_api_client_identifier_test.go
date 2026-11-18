package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/inputvalidation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// A client's identifier has one writer after creation, SetClientIdentifier, and the settings save
// is its one caller (#710 decision 4). The save loads the client at the top of the request and
// writes under the client's row later, and another save can rename the client in between, so which
// identifier checks a save owes is decided against the row as read under that lock: an identifier
// that differs from the row's is never written without passing the format, uniqueness and
// resource-name checks, and one that equals the row's is not checked. These tests give the request's
// copy and the row different identifiers, which nothing reachable over HTTP produces on its own.

// settingsPutRequest is the settings save of client 7 under a manage token.
func settingsPutRequest(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPut, "/api/v1/admin/clients/7", strings.NewReader(body))
	r = setTokenContextWithClaims(r, map[string]interface{}{"scope": "authserver:manage"})
	return withPathValue(r, "id", "7")
}

// expectSettingsSaveRow registers the request's load of client 7 as loaded, and the transaction
// that acquires the row and reads it as row.
func expectSettingsSaveRow(database *datamocks.Database, loaded, row *record.Client) *datamocks.RunInTransactionStub {
	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(loaded, nil).Once()
	stub := datamocks.ExpectRunInTransaction(database, clientUpdateTx)
	database.On("AcquireClientRow", mock.Anything, clientUpdateTx, int64(7)).Return(nil).Once()
	database.On("GetClientById", mock.Anything, clientUpdateTx, int64(7)).Return(row, nil).Once()
	return stub
}

func serveSettingsPut(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, body string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	HandleClientUpdatePut(database, inputvalidation.NewIdentifierValidator(), auditLogger).ServeHTTP(rr, settingsPutRequest(body))
	return rr
}

// TestHandleClientUpdatePut_ARenameIsCheckedThenWrittenByTheNarrowWrite: an identifier other than
// the row's is checked for uniqueness and against the resources on the save's transaction, under
// the row's lock, and written by SetClientIdentifier there, never by the whole-row save. The answer
// carries the new identifier.
func TestHandleClientUpdatePut_ARenameIsCheckedThenWrittenByTheNarrowWrite(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	expectSettingsSaveRow(database,
		&record.Client{Id: 7, ClientIdentifier: "old-name"},
		&record.Client{Id: 7, ClientIdentifier: "old-name"})
	database.On("GetClientByClientIdentifier", mock.Anything, clientUpdateTx, "new-name").Return(nil, nil).Once()
	database.On("GetResourceByResourceIdentifier", mock.Anything, clientUpdateTx, "new-name").Return(nil, nil).Once()
	var written *record.Client
	database.On("UpdateClient", mock.Anything, clientUpdateTx, mock.Anything).
		Run(func(args mock.Arguments) {
			c := *args.Get(2).(*record.Client)
			written = &c
		}).Return(nil).Once()
	database.On("SetClientIdentifier", mock.Anything, clientUpdateTx, int64(7), "new-name").Return(true, nil).Once()
	// The rename revokes the client's grants: here it has none (#710 decision 5).
	database.On("RevokeCodesByClientId", mock.Anything, clientUpdateTx, int64(7)).Return(int64(0), nil).Once()
	database.On("GetRefreshTokensByClientId", mock.Anything, clientUpdateTx, int64(7)).
		Return([]*record.RefreshToken{}, nil).Once()
	stubClientResponseLoads(database)
	auditLogger.On("Log", mock.Anything, audit.EventRevokedClientGrants, mock.Anything).Return().Once()
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedClientSettings, mock.Anything).Return().Once()

	rr := serveSettingsPut(database, auditLogger, `{"clientIdentifier":"new-name","description":"d","enabled":true}`)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var response api.UpdateClientResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
	assert.Equal(t, "new-name", response.Client.ClientIdentifier)

	require.NotNil(t, written)
	assert.Equal(t, "d", written.Description, "the whole-row save still writes the settings")

	// The checks are decided against the row read under its lock, and refuse before anything is
	// written.
	assert.Less(t, callIndex(t, database, "AcquireClientRow"), lastCallIndex(t, database, "GetClientById"))
	assert.Less(t, lastCallIndex(t, database, "GetClientById"), callIndex(t, database, "GetClientByClientIdentifier"))
	assert.Less(t, callIndex(t, database, "GetResourceByResourceIdentifier"), callIndex(t, database, "UpdateClient"))
	assert.Less(t, callIndex(t, database, "GetResourceByResourceIdentifier"), callIndex(t, database, "SetClientIdentifier"))
}

// TestHandleClientUpdatePut_TheRowsIdentifierIsNotChecked: a save whose identifier is the one the
// row holds is not checked, whatever the request's copy said. Here the client was renamed since the
// request loaded it, to an identifier longer than the validator allows today, as a self-registered
// client's 40 characters are: checked against the copy, the save would be refused for a value it
// does not change. The narrow write is still asked, and reports no change.
func TestHandleClientUpdatePut_TheRowsIdentifierIsNotChecked(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	rowIdentifier := "renamed-meanwhile-" + strings.Repeat("x", 22)
	require.Len(t, rowIdentifier, 40)

	expectSettingsSaveRow(database,
		&record.Client{Id: 7, ClientIdentifier: "loaded-name"},
		&record.Client{Id: 7, ClientIdentifier: rowIdentifier})
	database.On("UpdateClient", mock.Anything, clientUpdateTx, mock.Anything).Return(nil).Once()
	database.On("SetClientIdentifier", mock.Anything, clientUpdateTx, int64(7), rowIdentifier).Return(false, nil).Once()
	stubClientResponseLoads(database)
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedClientSettings, mock.Anything).Return().Once()

	rr := serveSettingsPut(database, auditLogger, `{"clientIdentifier":"`+rowIdentifier+`","description":"d","enabled":true}`)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var response api.UpdateClientResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
	assert.Equal(t, rowIdentifier, response.Client.ClientIdentifier)
	assertNotAttemptedOnClientDatabase(t, database, "GetClientByClientIdentifier", "GetResourceByResourceIdentifier")
}

// TestHandleClientUpdatePut_TheLoadedIdentifierIsCheckedWhenTheRowWasRenamed: a save submitting the
// identifier its copy holds, after another save renamed the client, would rename it back, so it is
// checked like any other rename. Each check refuses here, on the save's transaction, with nothing
// written.
func TestHandleClientUpdatePut_TheLoadedIdentifierIsCheckedWhenTheRowWasRenamed(t *testing.T) {
	cases := []struct {
		name string
		// loaded is the identifier the request loaded and submits; the row holds another.
		loaded string
		expect func(database *datamocks.Database, loaded string)
		code   string
	}{
		{
			name:   "taken by another client meanwhile",
			loaded: "loaded-name",
			expect: func(database *datamocks.Database, loaded string) {
				database.On("GetClientByClientIdentifier", mock.Anything, clientUpdateTx, loaded).
					Return(&record.Client{Id: 9, ClientIdentifier: loaded}, nil).Once()
			},
			code: "handler.client.identifier_in_use",
		},
		{
			name:   "naming a resource",
			loaded: "loaded-name",
			expect: func(database *datamocks.Database, loaded string) {
				database.On("GetClientByClientIdentifier", mock.Anything, clientUpdateTx, loaded).Return(nil, nil).Once()
				database.On("GetResourceByResourceIdentifier", mock.Anything, clientUpdateTx, loaded).
					Return(&record.Resource{Id: 4, ResourceIdentifier: loaded}, nil).Once()
			},
			code: "handler.client.identifier_names_resource",
		},
		{
			// An identifier stored before the validator held it to its bounds, which the rename
			// replaced: renaming the client back to it is a rename the validator refuses.
			name:   "of a format the validator refuses",
			loaded: "ab",
			expect: func(*datamocks.Database, string) {},
			code:   "validator.identifier.too_short",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			stub := expectSettingsSaveRow(database,
				&record.Client{Id: 7, ClientIdentifier: tc.loaded},
				&record.Client{Id: 7, ClientIdentifier: "renamed-meanwhile"})
			tc.expect(database, tc.loaded)

			rr := serveSettingsPut(database, auditLogger, `{"clientIdentifier":"`+tc.loaded+`","description":"d","enabled":true}`)

			require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
			assert.Equal(t, tc.code, errorCodeOf(t, rr))
			require.Error(t, stub.BodyErr, "the refusal rolls the transaction back")
			assertNotAttemptedOnClientDatabase(t, database, "UpdateClient", "SetClientIdentifier")
		})
	}
}

// TestHandleClientUpdatePut_AFailedIdentifierLookupIsAFiveHundredAndWritesNothing: a lookup that
// fails under the lock is not read as "no clash".
func TestHandleClientUpdatePut_AFailedIdentifierLookupIsAFiveHundredAndWritesNothing(t *testing.T) {
	for _, lookup := range []string{"GetClientByClientIdentifier", "GetResourceByResourceIdentifier"} {
		t.Run(lookup, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			expectSettingsSaveRow(database,
				&record.Client{Id: 7, ClientIdentifier: "old-name"},
				&record.Client{Id: 7, ClientIdentifier: "old-name"})
			if lookup == "GetClientByClientIdentifier" {
				database.On("GetClientByClientIdentifier", mock.Anything, clientUpdateTx, "new-name").
					Return(nil, errors.New("boom")).Once()
			} else {
				database.On("GetClientByClientIdentifier", mock.Anything, clientUpdateTx, "new-name").Return(nil, nil).Once()
				database.On("GetResourceByResourceIdentifier", mock.Anything, clientUpdateTx, "new-name").
					Return(nil, errors.New("boom")).Once()
			}

			rr := serveSettingsPut(database, auditLogger, `{"clientIdentifier":"new-name","description":"d","enabled":true}`)

			assert.Equal(t, http.StatusInternalServerError, rr.Code, rr.Body.String())
			assertNotAttemptedOnClientDatabase(t, database, "UpdateClient", "SetClientIdentifier")
		})
	}
}

// TestHandleClientUpdatePut_AFailedNarrowWriteIsAFiveHundred: the write's error rolls the save back
// and is not recorded as a settings change.
func TestHandleClientUpdatePut_AFailedNarrowWriteIsAFiveHundred(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	stub := expectSettingsSaveRow(database,
		&record.Client{Id: 7, ClientIdentifier: "same-name"},
		&record.Client{Id: 7, ClientIdentifier: "same-name"})
	database.On("UpdateClient", mock.Anything, clientUpdateTx, mock.Anything).Return(nil).Once()
	database.On("SetClientIdentifier", mock.Anything, clientUpdateTx, int64(7), "same-name").
		Return(false, errors.New("deadlock")).Once()

	rr := serveSettingsPut(database, auditLogger, `{"clientIdentifier":"same-name","description":"d","enabled":true}`)

	assert.Equal(t, http.StatusInternalServerError, rr.Code, rr.Body.String())
	require.Error(t, stub.BodyErr)
}

// TestUpdateClientNotOwningAuthenticationMode_TheOtherSavesNeverWriteTheIdentifier: the OAuth2
// flows and tokens saves go through the same helper with no settings of their own. They never ask
// the identifier's writer, and answer with the identifier the row holds, not the one their copy
// loaded before a rename.
func TestUpdateClientNotOwningAuthenticationMode_TheOtherSavesNeverWriteTheIdentifier(t *testing.T) {
	database := datamocks.NewDatabase(t)

	datamocks.ExpectRunInTransaction(database, clientUpdateTx)
	database.On("AcquireClientRow", mock.Anything, clientUpdateTx, int64(7)).Return(nil).Once()
	database.On("GetClientById", mock.Anything, clientUpdateTx, int64(7)).
		Return(&record.Client{Id: 7, ClientIdentifier: "renamed-meanwhile"}, nil).Once()
	database.On("UpdateClient", mock.Anything, clientUpdateTx, mock.Anything).Return(nil).Once()

	stale := &record.Client{Id: 7, ClientIdentifier: "loaded-name"}
	require.NoError(t, updateClientNotOwningAuthenticationMode(context.Background(), database, stale, nil))

	assert.Equal(t, "renamed-meanwhile", stale.ClientIdentifier, "the answer takes the row's identifier")
	assertNotAttemptedOnClientDatabase(t, database, "SetClientIdentifier", "GetClientByClientIdentifier")
}
