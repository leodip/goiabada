package apihandlers

import (
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

// A change of a client's identifier revokes the client's grants, in the transaction that writes the
// identifier, decided by that write: SetClientIdentifier's answer, and nothing compared before the
// transaction (#710 decisions 4 and 5). The sweep is the one the switch to public uses, its families
// recorded under client_identifier_changed, and revoked_client_grants is written after the commit
// for every rename, beside updated_client_settings, also when nothing was there to revoke.

const renameAdminSubject = "rename-admin-subject"

// serveRenamePut runs the settings save of client 7 under a manage token carrying a subject.
func serveRenamePut(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPut, "/api/v1/admin/clients/7", strings.NewReader(body))
	r = setTokenContextWithClaims(r, map[string]interface{}{"scope": "authserver:manage", "sub": renameAdminSubject})
	r = withPathValue(r, "id", "7")
	rr := httptest.NewRecorder()
	HandleClientUpdatePut(database, inputvalidation.NewIdentifierValidator(), auditLogger).ServeHTTP(rr, r)
	return rr
}

// expectRenameWrites registers a save of client 7 from old-name to new-name up to the identifier's
// write, which answers changed, with every statement on the save's transaction.
func expectRenameWrites(database *datamocks.Database, changed bool, note ...func(string)) *datamocks.RunInTransactionStub {
	database.On("GetClientByID", mock.Anything, mock.Anything, int64(7)).
		Return(&record.Client{ID: 7, ClientIdentifier: "old-name"}, nil).Once()
	stub := datamocks.ExpectRunInTransaction(database, clientUpdateTx, note...)
	database.On("AcquireClientRow", mock.Anything, clientUpdateTx, int64(7)).Return(nil).Once()
	database.On("GetClientByID", mock.Anything, clientUpdateTx, int64(7)).
		Return(&record.Client{ID: 7, ClientIdentifier: "old-name"}, nil).Once()
	database.On("GetClientByClientIdentifier", mock.Anything, clientUpdateTx, "new-name").Return(nil, nil).Once()
	database.On("GetResourceByResourceIdentifier", mock.Anything, clientUpdateTx, "new-name").Return(nil, nil).Once()
	database.On("UpdateClient", mock.Anything, clientUpdateTx, mock.Anything).Return(nil).Once()
	database.On("SetClientIdentifier", mock.Anything, clientUpdateTx, int64(7), "new-name").Return(changed, nil).Once()
	return stub
}

const renameBody = `{"clientIdentifier":"new-name","description":"d","enabled":true}`

// A rename revokes the client's codes, records each family of its refresh tokens under
// client_identifier_changed and revokes its live refresh tokens, on the save's transaction and after
// the identifier's write; the event names the reason and what was revoked, and is written after the
// commit, beside updated_client_settings.
func TestHandleClientUpdatePut_ARenameRevokesTheClientsGrantsInItsTransaction(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	var edges []string
	expectRenameWrites(database, true, func(edge string) { edges = append(edges, edge) })

	live := &record.RefreshToken{ID: 1, RefreshTokenJTI: "rt-live", FirstRefreshTokenJTI: "fam-1"}
	rotated := &record.RefreshToken{ID: 2, RefreshTokenJTI: "rt-rotated", FirstRefreshTokenJTI: "fam-1", Revoked: true}
	ropc := &record.RefreshToken{ID: 3, RefreshTokenJTI: "rt-ropc", FirstRefreshTokenJTI: "fam-2"}
	database.On("RevokeCodesByClientID", mock.Anything, clientUpdateTx, int64(7)).Return(int64(3), nil).Once()
	database.On("GetRefreshTokensByClientID", mock.Anything, clientUpdateTx, int64(7)).
		Return([]*record.RefreshToken{live, rotated, ropc}, nil).Once()
	database.On("RecordRefreshTokenFamilyRevoked", mock.Anything, clientUpdateTx, "fam-1", "client_identifier_changed").
		Return(true, nil).Once()
	database.On("RecordRefreshTokenFamilyRevoked", mock.Anything, clientUpdateTx, "fam-2", "client_identifier_changed").
		Return(true, nil).Once()
	database.On("UpdateRefreshToken", mock.Anything, clientUpdateTx, live).Return(nil).Once()
	database.On("UpdateRefreshToken", mock.Anything, clientUpdateTx, ropc).Return(nil).Once()
	stubClientResponseLoads(database)

	var revokedPayload map[string]interface{}
	auditLogger.On("Log", mock.Anything, audit.EventRevokedClientGrants, mock.Anything).
		Run(func(args mock.Arguments) {
			edges = append(edges, "revoked_client_grants")
			revokedPayload = args.Get(2).(map[string]interface{})
		}).Return().Once()
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedClientSettings, mock.Anything).Return().Once()

	rr := serveRenamePut(database, auditLogger, renameBody)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, map[string]interface{}{
		"client_id":                  int64(7),
		"reason":                     "client_identifier_changed",
		"logged_in_user":             renameAdminSubject,
		"revoked_code_count":         int64(3),
		"revoked_refresh_token_jtis": []string{"rt-live", "rt-ropc"},
	}, revokedPayload)
	assert.True(t, live.Revoked)
	assert.True(t, ropc.Revoked)

	// Decided by the write: the sweep follows SetClientIdentifier in the same transaction.
	assert.Less(t, callIndex(t, database, "SetClientIdentifier"), callIndex(t, database, "RevokeCodesByClientID"))
	// And recorded after the commit, never inside the transaction it reports.
	assert.Equal(t, []string{"begin", "commit", "revoked_client_grants"}, edges)
}

// A rename with nothing to revoke is still recorded, with nothing revoked: the event attests the
// rename's revocation ran.
func TestHandleClientUpdatePut_ARenameWithNothingToRevokeIsStillRecorded(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	expectRenameWrites(database, true)
	database.On("RevokeCodesByClientID", mock.Anything, clientUpdateTx, int64(7)).Return(int64(0), nil).Once()
	database.On("GetRefreshTokensByClientID", mock.Anything, clientUpdateTx, int64(7)).
		Return([]*record.RefreshToken{}, nil).Once()
	stubClientResponseLoads(database)

	var revokedPayload map[string]interface{}
	auditLogger.On("Log", mock.Anything, audit.EventRevokedClientGrants, mock.Anything).
		Run(func(args mock.Arguments) { revokedPayload = args.Get(2).(map[string]interface{}) }).Return().Once()
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedClientSettings, mock.Anything).Return().Once()

	rr := serveRenamePut(database, auditLogger, renameBody)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.NotNil(t, revokedPayload)
	assert.Equal(t, "client_identifier_changed", revokedPayload["reason"])
	assert.Equal(t, int64(0), revokedPayload["revoked_code_count"])
	assert.Equal(t, []string{}, revokedPayload["revoked_refresh_token_jtis"])
}

// The write found the identifier already in the row, as a rename committed meanwhile by another
// save leaves it: no change, so nothing is revoked and no revocation is recorded, whatever the copy
// the request loaded said. Its other settings are saved as always.
func TestHandleClientUpdatePut_AWriteThatChangesNoIdentifierRevokesNothing(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	expectRenameWrites(database, false)
	stubClientResponseLoads(database)
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedClientSettings, mock.Anything).Return().Once()

	rr := serveRenamePut(database, auditLogger, renameBody)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assertNotAttemptedOnClientDatabase(t, database, "RevokeCodesByClientID", "GetRefreshTokensByClientID",
		"RecordRefreshTokenFamilyRevoked", "UpdateRefreshToken")
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, audit.EventRevokedClientGrants, mock.Anything)
}

// A sweep that fails rolls the rename back with it: 500, and neither the rename nor a revocation is
// recorded.
func TestHandleClientUpdatePut_AFailedRevocationRollsTheRenameBack(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	stub := expectRenameWrites(database, true)
	database.On("RevokeCodesByClientID", mock.Anything, clientUpdateTx, int64(7)).
		Return(int64(0), errors.New("connection reset")).Once()

	rr := serveRenamePut(database, auditLogger, renameBody)

	assert.Equal(t, http.StatusInternalServerError, rr.Code, rr.Body.String())
	require.EqualError(t, stub.BodyErr, "connection reset")
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}
