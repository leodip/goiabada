package apihandlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// This file did not exist before #245's final review. Its subject is one property that no other
// tier can observe: which copy of the client row a write decides against.
//
// Every one of these endpoints loads the client at the top of the request and writes it back with
// UpdateClient, which projects every mutable column. The copy it holds is therefore a snapshot,
// and between the load and the write another request can change the row underneath it. Nothing
// reachable over HTTP can produce that gap on its own, because each request reloads; the seam
// where it is visible is the handler's own conversation with the database, which is exactly what
// a strict mock reproduces. Final review finding 1.

// clientUpdateTx is the transaction the mocked database hands back, matched by identity so a
// write that reached a different one, or nil, fails.
var clientUpdateTx = &sql.Tx{}

// authenticationPutRequest builds the PUT with its chi URL parameter and body.
func authenticationPutRequest(t *testing.T, id string, req api.UpdateClientAuthenticationRequest) *http.Request {
	t.Helper()
	body, err := json.Marshal(req)
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPut, "/api/v1/admin/clients/"+id+"/authentication", bytes.NewReader(body))
	return setChiURLParam(r, "id", id)
}

// stubClientResponseLoads registers the two related-field loads every client handler performs
// before it encodes its response. They carry nothing this file asserts on.
func stubClientResponseLoads(database *mocks_data.Database) {
	database.On("ClientLoadRedirectURIs", (*sql.Tx)(nil), mock.Anything).Return(nil).Once()
	database.On("ClientLoadWebOrigins", (*sql.Tx)(nil), mock.Anything).Return(nil).Once()
}

// =============================================================================
// updateClientNotOwningAuthenticationMode
// =============================================================================

// TestUpdateClientNotOwningAuthenticationMode_TakesTheModeFromTheRowNotTheCaller is the whole
// point of the helper. It is handed a client that says public with no secret, which is what a
// stale snapshot looks like, and the row says confidential with a secret. What must reach
// UpdateClient is the row's answer, because none of the three endpoints using this helper is
// allowed to change how the client authenticates.
//
// Getting this wrong is not a tidy-up: the write would restore public mode and delete a secret an
// administrator had just set, and no revocation runs on this path, so the client's outstanding
// grants would stay redeemable with nothing presented.
func TestUpdateClientNotOwningAuthenticationMode_TakesTheModeFromTheRowNotTheCaller(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	secret := []byte("the-secret-another-request-just-set")
	database.On("BeginTransaction").Return(clientUpdateTx, nil).Once()
	database.On("GetClientById", clientUpdateTx, int64(7)).
		Return(&models.Client{Id: 7, IsPublic: false, ClientSecretEncrypted: secret}, nil).Once()
	var written *models.Client
	database.On("UpdateClient", clientUpdateTx, mock.Anything).
		Run(func(args mock.Arguments) { written = args.Get(1).(*models.Client) }).Return(nil).Once()
	database.On("CommitTransaction", clientUpdateTx).Return(nil).Once()
	database.On("RollbackTransaction", clientUpdateTx).Return(nil).Once()

	stale := &models.Client{Id: 7, IsPublic: true, ClientSecretEncrypted: nil, Description: "edited"}
	require.NoError(t, updateClientNotOwningAuthenticationMode(database, stale))

	require.NotNil(t, written)
	assert.False(t, written.IsPublic, "the write must carry the row's authentication mode")
	assert.Equal(t, secret, written.ClientSecretEncrypted, "the write must not delete a newer secret")
	// The field this endpoint does own still lands, or the helper would be protecting the row by
	// discarding the request.
	assert.Equal(t, "edited", written.Description)

	// The read is inside the transaction that writes. Reading it before BeginTransaction would
	// leave exactly the gap this helper exists to close.
	assert.Less(t, callIndex(t, database, "BeginTransaction"), callIndex(t, database, "GetClientById"))
	assert.Less(t, callIndex(t, database, "GetClientById"), callIndex(t, database, "UpdateClient"))
}

// TestUpdateClientNotOwningAuthenticationMode_ReappliesThePublicInvariantsAgainstTheRefreshedMode
// pins what every one of these endpoints depends on. The two public-client rules, client
// credentials off and PKCE required, must be applied to the mode the ROW carries, not the mode
// the caller loaded. This is the state #245 exists to make unreachable.
//
// It is the round 2 finding as well as the round 1 one. Only the OAuth2 flows endpoint used to
// carry these rules, so a general-settings or token-settings save that loaded the client while it
// was confidential preserved the refreshed public mode and restored client credentials on and
// PKCE off underneath it. The caller below is exactly that stale snapshot, and it goes through
// the same helper the other two use, with nothing endpoint-specific handed in.
func TestUpdateClientNotOwningAuthenticationMode_ReappliesThePublicInvariantsAgainstTheRefreshedMode(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	database.On("BeginTransaction").Return(clientUpdateTx, nil).Once()
	// The row is public; the caller below thinks it is confidential.
	database.On("GetClientById", clientUpdateTx, int64(7)).
		Return(&models.Client{Id: 7, IsPublic: true}, nil).Once()
	var written *models.Client
	database.On("UpdateClient", clientUpdateTx, mock.Anything).
		Run(func(args mock.Arguments) { written = args.Get(1).(*models.Client) }).Return(nil).Once()
	database.On("CommitTransaction", clientUpdateTx).Return(nil).Once()
	database.On("RollbackTransaction", clientUpdateTx).Return(nil).Once()

	// A confidential client's legitimate settings, carried by a request that loaded it before it
	// became public.
	pkceOff := false
	stale := &models.Client{
		Id:                       7,
		IsPublic:                 false,
		PKCERequired:             &pkceOff,
		ClientCredentialsEnabled: true,
	}
	require.NoError(t, updateClientNotOwningAuthenticationMode(database, stale))

	require.NotNil(t, written)
	assert.True(t, written.IsPublic, "the write must carry the row's authentication mode")
	assert.False(t, written.ClientCredentialsEnabled,
		"a public client must not be stored with client credentials enabled")
	require.NotNil(t, written.PKCERequired,
		"a public client must not be stored with a nil pkce_required: it renders as inherit")
	assert.True(t, *written.PKCERequired,
		"a public client must not be stored with pkce_required false")
}

// TestUpdateClientNotOwningAuthenticationMode_LeavesAConfidentialClientsFlowsAlone is the boundary
// on the test above, and it is the one that would catch the rules being applied unconditionally.
// The two invariants belong to public clients only: a confidential client is entitled to client
// credentials and to PKCE optional, and a helper that forced them on every write would silently
// take a working configuration away from the larger population.
func TestUpdateClientNotOwningAuthenticationMode_LeavesAConfidentialClientsFlowsAlone(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	database.On("BeginTransaction").Return(clientUpdateTx, nil).Once()
	database.On("GetClientById", clientUpdateTx, int64(7)).
		Return(&models.Client{Id: 7, IsPublic: false}, nil).Once()
	var written *models.Client
	database.On("UpdateClient", clientUpdateTx, mock.Anything).
		Run(func(args mock.Arguments) { written = args.Get(1).(*models.Client) }).Return(nil).Once()
	database.On("CommitTransaction", clientUpdateTx).Return(nil).Once()
	database.On("RollbackTransaction", clientUpdateTx).Return(nil).Once()

	pkceOff := false
	client := &models.Client{
		Id:                       7,
		IsPublic:                 false,
		PKCERequired:             &pkceOff,
		ClientCredentialsEnabled: true,
	}
	require.NoError(t, updateClientNotOwningAuthenticationMode(database, client))

	require.NotNil(t, written)
	assert.True(t, written.ClientCredentialsEnabled,
		"a confidential client keeps client credentials")
	require.NotNil(t, written.PKCERequired)
	assert.False(t, *written.PKCERequired, "a confidential client keeps PKCE optional")
}

// TestUpdateClientNotOwningAuthenticationMode_ADisappearedClientIsAnErrorNotAnInsert covers the
// row being deleted between the handler's load and this write. UpdateClient keys on the id and
// would quietly affect no rows, so the failure has to be raised here.
func TestUpdateClientNotOwningAuthenticationMode_ADisappearedClientIsAnErrorNotAnInsert(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	database.On("BeginTransaction").Return(clientUpdateTx, nil).Once()
	database.On("GetClientById", clientUpdateTx, int64(7)).Return(nil, nil).Once()
	database.On("RollbackTransaction", clientUpdateTx).Return(nil).Once()

	err := updateClientNotOwningAuthenticationMode(database, &models.Client{Id: 7})
	require.Error(t, err)
	assertNotAttemptedOnClientDatabase(t, database, "UpdateClient", "CommitTransaction")
}

// =============================================================================
// HandleAPIClientAuthenticationPut
// =============================================================================

// TestHandleAPIClientAuthenticationPut_ClassifiesTheFlipAgainstTheRow is the finding itself.
//
// The handler loads the client, and by the time it writes, the row says something else: here the
// snapshot says public and the row says confidential, which is what a concurrent save that made
// the client confidential and issued it a grant leaves behind. Classifying from the snapshot reads
// "already public", skips the revocation, and commits a public client still holding grants that
// were issued while a secret was required. The transition is therefore decided inside the
// transaction, and this asserts it by the revocation actually running.
func TestHandleAPIClientAuthenticationPut_ClassifiesTheFlipAgainstTheRow(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	authHelper := mocks_handlerhelpers.NewAuthHelper(t)
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)

	// The snapshot the handler works from: already public.
	database.On("GetClientById", (*sql.Tx)(nil), int64(7)).
		Return(&models.Client{Id: 7, IsPublic: true}, nil).Once()
	// The row as it stands when the write runs: confidential, because another request got there
	// first and the grants it issued are the ones at stake.
	database.On("BeginTransaction").Return(clientUpdateTx, nil).Once()
	database.On("GetClientById", clientUpdateTx, int64(7)).
		Return(&models.Client{Id: 7, IsPublic: false, ClientSecretEncrypted: []byte("secret")}, nil).Once()
	database.On("UpdateClient", clientUpdateTx, mock.Anything).Return(nil).Once()
	database.On("RevokeCodesByClientId", clientUpdateTx, int64(7)).Return(int64(2), nil).Once()
	database.On("GetRefreshTokensByClientId", clientUpdateTx, int64(7)).
		Return([]*models.RefreshToken{}, nil).Once()
	database.On("CommitTransaction", clientUpdateTx).Return(nil).Once()
	database.On("RollbackTransaction", clientUpdateTx).Return(nil).Once()
	stubClientResponseLoads(database)

	authHelper.On("GetLoggedInSubject", mock.Anything).Return("the-admin")
	var revokedPayload map[string]interface{}
	auditLogger.On("Log", constants.AuditRevokedClientGrants, mock.Anything).
		Run(func(args mock.Arguments) {
			revokedPayload = args.Get(1).(map[string]interface{})
		}).Return().Once()
	auditLogger.On("Log", constants.AuditUpdatedClientAuthentication, mock.Anything).Return().Once()
	httpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.Anything).Return()

	rr := httptest.NewRecorder()
	handler := HandleAPIClientAuthenticationPut(httpHelper, authHelper, database, auditLogger)
	handler.ServeHTTP(rr, authenticationPutRequest(t, "7", api.UpdateClientAuthenticationRequest{IsPublic: true}))

	assert.Equal(t, http.StatusOK, rr.Code)
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
	require.NotNil(t, revokedPayload)
	assert.Equal(t, int64(2), revokedPayload["revokedCodeCount"])
}

// TestHandleAPIClientAuthenticationPut_ASaveOfAnAlreadyPublicClientRevokesNothing is the other
// side of the same decision, and the one that stops the fix above becoming "revoke on every
// save". Both the snapshot and the row say public, so this write removes no requirement and must
// leave the client's grants alone: revoking here would sign every user of the application out
// because an administrator re-saved a form.
func TestHandleAPIClientAuthenticationPut_ASaveOfAnAlreadyPublicClientRevokesNothing(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	authHelper := mocks_handlerhelpers.NewAuthHelper(t)
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)

	database.On("GetClientById", (*sql.Tx)(nil), int64(7)).
		Return(&models.Client{Id: 7, IsPublic: true}, nil).Once()
	database.On("BeginTransaction").Return(clientUpdateTx, nil).Once()
	database.On("GetClientById", clientUpdateTx, int64(7)).
		Return(&models.Client{Id: 7, IsPublic: true}, nil).Once()
	database.On("UpdateClient", clientUpdateTx, mock.Anything).Return(nil).Once()
	database.On("CommitTransaction", clientUpdateTx).Return(nil).Once()
	database.On("RollbackTransaction", clientUpdateTx).Return(nil).Once()
	stubClientResponseLoads(database)

	auditLogger.On("Log", constants.AuditUpdatedClientAuthentication, mock.Anything).Return().Once()
	authHelper.On("GetLoggedInSubject", mock.Anything).Return("the-admin")
	httpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.Anything).Return()

	rr := httptest.NewRecorder()
	handler := HandleAPIClientAuthenticationPut(httpHelper, authHelper, database, auditLogger)
	handler.ServeHTTP(rr, authenticationPutRequest(t, "7", api.UpdateClientAuthenticationRequest{IsPublic: true}))

	assert.Equal(t, http.StatusOK, rr.Code)
	// The strict mock carries most of this: neither revocation call is registered, so reaching
	// one fails. Naming them makes the failure say which property broke.
	assertNotAttemptedOnClientDatabase(t, database, "RevokeCodesByClientId", "GetRefreshTokensByClientId")
	auditLogger.AssertNotCalled(t, "Log", constants.AuditRevokedClientGrants, mock.Anything)
}

// assertNotAttemptedOnClientDatabase fails naming the method, where the strict mock alone would
// fail naming an unexpected call.
func assertNotAttemptedOnClientDatabase(t *testing.T, database *mocks_data.Database, methods ...string) {
	t.Helper()
	for _, method := range methods {
		database.AssertNotCalled(t, method, mock.Anything, mock.Anything)
	}
}

// callIndex reports the position of the first call to method in the mock's recorded order, so a
// test can assert that one call happened before another.
func callIndex(t *testing.T, database *mocks_data.Database, method string) int {
	t.Helper()
	for i, call := range database.Calls {
		if call.Method == method {
			return i
		}
	}
	t.Fatalf("%s was never called", method)
	return -1
}
