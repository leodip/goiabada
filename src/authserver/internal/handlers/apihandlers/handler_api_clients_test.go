package apihandlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/data"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/urlutil"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
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
	database.On("ClientLoadRedirectURIs", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(nil).Once()
	database.On("ClientLoadWebOrigins", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(nil).Once()
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
	mocks_data.ExpectRunInTransaction(database, clientUpdateTx)
	database.On("AcquireClientRow", mock.Anything, clientUpdateTx, int64(7)).Return(nil).Once()
	database.On("GetClientById", mock.Anything, clientUpdateTx, int64(7)).
		Return(&models.Client{Id: 7, IsPublic: false, ClientSecretEncrypted: secret}, nil).Once()
	var written *models.Client
	database.On("UpdateClient", mock.Anything, clientUpdateTx, mock.Anything).
		Run(func(args mock.Arguments) { written = args.Get(2).(*models.Client) }).Return(nil).Once()

	stale := &models.Client{Id: 7, IsPublic: true, ClientSecretEncrypted: nil, Description: "edited"}
	require.NoError(t, updateClientNotOwningAuthenticationMode(context.Background(), database, stale))

	require.NotNil(t, written)
	assert.False(t, written.IsPublic, "the write must carry the row's authentication mode")
	assert.Equal(t, secret, written.ClientSecretEncrypted, "the write must not delete a newer secret")
	// The field this endpoint does own still lands, or the helper would be protecting the row by
	// discarding the request.
	assert.Equal(t, "edited", written.Description)

	// The read is inside the transaction that writes. Reading it before RunInTransaction, which
	// the mock records at entry before the body runs, would leave exactly the gap this helper
	// exists to close.
	assert.Less(t, callIndex(t, database, "RunInTransaction"), callIndex(t, database, "GetClientById"))
	assert.Less(t, callIndex(t, database, "GetClientById"), callIndex(t, database, "UpdateClient"))

	// And the row is taken BEFORE it is read, which is what makes the read atomic with the write
	// that follows it. A read that runs first can be invalidated by a writer committing behind
	// it, and on mysql and postgres it is not even made to wait for one, so the order of these
	// two calls is the whole of the remedy rather than a detail of it (#245 decision 18).
	assert.Less(t, callIndex(t, database, "AcquireClientRow"), callIndex(t, database, "GetClientById"))
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

	mocks_data.ExpectRunInTransaction(database, clientUpdateTx)
	database.On("AcquireClientRow", mock.Anything, clientUpdateTx, int64(7)).Return(nil).Once()
	// The row is public; the caller below thinks it is confidential.
	database.On("GetClientById", mock.Anything, clientUpdateTx, int64(7)).
		Return(&models.Client{Id: 7, IsPublic: true}, nil).Once()
	var written *models.Client
	database.On("UpdateClient", mock.Anything, clientUpdateTx, mock.Anything).
		Run(func(args mock.Arguments) { written = args.Get(2).(*models.Client) }).Return(nil).Once()

	// A confidential client's legitimate settings, carried by a request that loaded it before it
	// became public.
	pkceOff := false
	stale := &models.Client{
		Id:                       7,
		IsPublic:                 false,
		PKCERequired:             &pkceOff,
		ClientCredentialsEnabled: true,
	}
	require.NoError(t, updateClientNotOwningAuthenticationMode(context.Background(), database, stale))

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

	mocks_data.ExpectRunInTransaction(database, clientUpdateTx)
	database.On("AcquireClientRow", mock.Anything, clientUpdateTx, int64(7)).Return(nil).Once()
	database.On("GetClientById", mock.Anything, clientUpdateTx, int64(7)).
		Return(&models.Client{Id: 7, IsPublic: false}, nil).Once()
	var written *models.Client
	database.On("UpdateClient", mock.Anything, clientUpdateTx, mock.Anything).
		Run(func(args mock.Arguments) { written = args.Get(2).(*models.Client) }).Return(nil).Once()

	pkceOff := false
	client := &models.Client{
		Id:                       7,
		IsPublic:                 false,
		PKCERequired:             &pkceOff,
		ClientCredentialsEnabled: true,
	}
	require.NoError(t, updateClientNotOwningAuthenticationMode(context.Background(), database, client))

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

	stub := mocks_data.ExpectRunInTransaction(database, clientUpdateTx)
	database.On("AcquireClientRow", mock.Anything, clientUpdateTx, int64(7)).Return(nil).Once()
	database.On("GetClientById", mock.Anything, clientUpdateTx, int64(7)).Return(nil, nil).Once()

	err := updateClientNotOwningAuthenticationMode(context.Background(), database, &models.Client{Id: 7})
	require.Error(t, err)
	assert.Equal(t, err, stub.BodyErr, "the body hands its error to the helper, which rolls back")
	assertNotAttemptedOnClientDatabase(t, database, "UpdateClient")
}

// TestUpdateClientNotOwningAuthenticationMode_AFailedAcquisitionDoesNotWrite covers the
// acquisition erroring. It must abort the save rather than fall through to a read that nothing is
// holding, because that unprotected read is exactly what this helper was changed to stop making.
// Falling through would put the endpoint back where it was with every other test here still
// green.
func TestUpdateClientNotOwningAuthenticationMode_AFailedAcquisitionDoesNotWrite(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	stub := mocks_data.ExpectRunInTransaction(database, clientUpdateTx)
	database.On("AcquireClientRow", mock.Anything, clientUpdateTx, int64(7)).
		Return(errors.New("deadlock found when trying to get lock")).Once()

	err := updateClientNotOwningAuthenticationMode(context.Background(), database, &models.Client{Id: 7, IsPublic: true})
	require.Error(t, err)
	assert.Equal(t, err, stub.BodyErr, "the body hands its error to the helper unchanged, which is what lets a real deadlock be rerun")
	assertNotAttemptedOnClientDatabase(t, database, "GetClientById", "UpdateClient")
}

// =============================================================================
// HandleAPIClientAuthenticationPut
// =============================================================================

// TestHandleAPIClientAuthenticationPut_ClassifiesTheFlipAgainstTheRow is the finding itself.
//
// The handler loads the client, and by the time it writes, the row says something else: here the
// snapshot says public while the write turns out to perform the transition, which is what a
// concurrent save that made the client confidential and issued it a grant leaves behind.
// Classifying from the snapshot reads "already public", skips the revocation, and commits a
// public client still holding grants that were issued while a secret was required. So the answer
// comes from SetClientPublic, the write itself, and this asserts that the handler acts on that
// answer rather than on the copy in its hand.
func TestHandleAPIClientAuthenticationPut_ClassifiesTheFlipAgainstTheRow(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	// The snapshot the handler works from: already public.
	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).
		Return(&models.Client{Id: 7, IsPublic: true}, nil).Once()
	// What the write reports when it runs: it really did make the client public, because another
	// request got there first with confidential mode and the grants it issued are the ones at
	// stake. The handler must believe this over its own snapshot.
	mocks_data.ExpectRunInTransaction(database, clientUpdateTx)
	database.On("SetClientPublic", mock.Anything, clientUpdateTx, int64(7)).Return(true, nil).Once()
	database.On("UpdateClient", mock.Anything, clientUpdateTx, mock.Anything).Return(nil).Once()
	database.On("RevokeCodesByClientId", mock.Anything, clientUpdateTx, int64(7)).Return(int64(2), nil).Once()
	database.On("GetRefreshTokensByClientId", mock.Anything, clientUpdateTx, int64(7)).
		Return([]*models.RefreshToken{}, nil).Once()
	stubClientResponseLoads(database)

	var revokedPayload map[string]interface{}
	auditLogger.On("Log", mock.Anything, audit.AuditRevokedClientGrants, mock.Anything).
		Run(func(args mock.Arguments) {
			revokedPayload = args.Get(2).(map[string]interface{})
		}).Return().Once()
	auditLogger.On("Log", mock.Anything, audit.AuditUpdatedClientAuthentication, mock.Anything).Return().Once()

	rr := httptest.NewRecorder()
	handler := HandleAPIClientAuthenticationPut(database, auditLogger)
	handler.ServeHTTP(rr, authenticationPutRequest(t, "7", api.UpdateClientAuthenticationRequest{IsPublic: true}))

	assert.Equal(t, http.StatusOK, rr.Code)
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
	require.NotNil(t, revokedPayload)
	assert.Equal(t, int64(2), revokedPayload["revokedCodeCount"])

	// The classification has to run BEFORE the client write, and the order is asserted rather
	// than left to reading. UpdateClient projects every mutable column from the caller's copy,
	// which says public, so a SetClientPublic placed after it would find the row already public
	// and report false on every flip there has ever been. The revocation would then never run
	// and nothing else in this file would notice.
	assert.Less(t, callIndex(t, database, "SetClientPublic"), callIndex(t, database, "UpdateClient"))
}

// TestHandleAPIClientAuthenticationPut_AFailedClassificationRevokesNothingAndSavesNothing covers
// the direction the two tests above cannot: what happens when the write cannot establish which
// transition this is. There is no safe guess. Revoking anyway would sign out the users of a
// client nobody flipped, and saving anyway would produce the very state the classification
// exists to catch, so the whole transaction is abandoned and the caller is told it failed.
func TestHandleAPIClientAuthenticationPut_AFailedClassificationRevokesNothingAndSavesNothing(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).
		Return(&models.Client{Id: 7, IsPublic: false, ClientSecretEncrypted: []byte("secret")}, nil).Once()
	stub := mocks_data.ExpectRunInTransaction(database, clientUpdateTx)
	database.On("SetClientPublic", mock.Anything, clientUpdateTx, int64(7)).
		Return(false, errors.New("no client with that id")).Once()

	rr := httptest.NewRecorder()
	handler := HandleAPIClientAuthenticationPut(database, auditLogger)
	handler.ServeHTTP(rr, authenticationPutRequest(t, "7", api.UpdateClientAuthenticationRequest{IsPublic: true}))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	// The client write is not registered on the strict mock, so reaching it fails on its own.
	// Naming it says which property broke; BodyErr says the helper was asked to roll back.
	assert.EqualError(t, stub.BodyErr, "no client with that id")
	assertNotAttemptedOnClientDatabase(t, database, "UpdateClient",
		"RevokeCodesByClientId", "GetRefreshTokensByClientId")
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, audit.AuditRevokedClientGrants, mock.Anything)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, audit.AuditUpdatedClientAuthentication, mock.Anything)
}

// TestHandleAPIClientAuthenticationPut_ASaveOfAnAlreadyPublicClientRevokesNothing is the other
// side of the same decision, and the one that stops the fix above becoming "revoke on every
// save". Both the snapshot and the row say public, so this write removes no requirement and must
// leave the client's grants alone: revoking here would sign every user of the application out
// because an administrator re-saved a form.
func TestHandleAPIClientAuthenticationPut_ASaveOfAnAlreadyPublicClientRevokesNothing(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).
		Return(&models.Client{Id: 7, IsPublic: true}, nil).Once()
	mocks_data.ExpectRunInTransaction(database, clientUpdateTx)
	database.On("SetClientPublic", mock.Anything, clientUpdateTx, int64(7)).Return(false, nil).Once()
	database.On("UpdateClient", mock.Anything, clientUpdateTx, mock.Anything).Return(nil).Once()
	stubClientResponseLoads(database)

	auditLogger.On("Log", mock.Anything, audit.AuditUpdatedClientAuthentication, mock.Anything).Return().Once()

	rr := httptest.NewRecorder()
	handler := HandleAPIClientAuthenticationPut(database, auditLogger)
	handler.ServeHTTP(rr, authenticationPutRequest(t, "7", api.UpdateClientAuthenticationRequest{IsPublic: true}))

	assert.Equal(t, http.StatusOK, rr.Code)
	// The strict mock carries most of this: neither revocation call is registered, so reaching
	// one fails. Naming them makes the failure say which property broke.
	assertNotAttemptedOnClientDatabase(t, database, "RevokeCodesByClientId", "GetRefreshTokensByClientId")
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, audit.AuditRevokedClientGrants, mock.Anything)
}

// TestHandleAPIClientAuthenticationPut_AClientMadePublicIsWrittenWithThePublicInvariants pins the
// endpoint's own call to Client.ApplyPublicClientInvariants. The client arrives confidential with
// client credentials on and PKCE explicitly optional, and is made public: the row written must
// already carry client credentials off and PKCE an explicit true, since the endpoint answers with
// that row and the console renders it (#245, #428).
func TestHandleAPIClientAuthenticationPut_AClientMadePublicIsWrittenWithThePublicInvariants(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	pkceOptional := false
	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(&models.Client{
		Id: 7, IsPublic: false, ClientSecretEncrypted: []byte("secret"),
		ClientCredentialsEnabled: true, PKCERequired: &pkceOptional,
	}, nil).Once()
	mocks_data.ExpectRunInTransaction(database, clientUpdateTx)
	database.On("SetClientPublic", mock.Anything, clientUpdateTx, int64(7)).Return(true, nil).Once()
	var written models.Client
	database.On("UpdateClient", mock.Anything, clientUpdateTx, mock.Anything).
		Run(func(args mock.Arguments) { written = *args.Get(2).(*models.Client) }).Return(nil).Once()
	database.On("RevokeCodesByClientId", mock.Anything, clientUpdateTx, int64(7)).Return(int64(0), nil).Once()
	database.On("GetRefreshTokensByClientId", mock.Anything, clientUpdateTx, int64(7)).
		Return([]*models.RefreshToken{}, nil).Once()
	stubClientResponseLoads(database)
	auditLogger.On("Log", mock.Anything, audit.AuditRevokedClientGrants, mock.Anything).Return().Once()
	auditLogger.On("Log", mock.Anything, audit.AuditUpdatedClientAuthentication, mock.Anything).Return().Once()

	rr := httptest.NewRecorder()
	handler := HandleAPIClientAuthenticationPut(database, auditLogger)
	handler.ServeHTTP(rr, authenticationPutRequest(t, "7", api.UpdateClientAuthenticationRequest{IsPublic: true}))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.True(t, written.IsPublic)
	assert.Nil(t, written.ClientSecretEncrypted, "a public client keeps no secret")
	assert.False(t, written.ClientCredentialsEnabled, "a public client was written with client credentials enabled")
	require.NotNil(t, written.PKCERequired, "a public client was written with PKCE inherited rather than required")
	assert.True(t, *written.PKCERequired, "a public client was written with PKCE optional")
}

// assertNotAttemptedOnClientDatabase fails naming the method, where the strict mock alone would
// fail naming an unexpected call.
//
// It reads the recorded calls rather than calling AssertNotCalled, because the method is named
// through a parameter here and AssertNotCalled matches on the name and the whole argument list at
// once: it was passing two matchers to methods that all take three, so it compared lists that
// could never be equal and passed at every call site whatever the handler did. Matching on the
// name alone is what this helper meant in the first place, and it is the one thing an argument
// list cannot express (#421).
func assertNotAttemptedOnClientDatabase(t *testing.T, database *mocks_data.Database, methods ...string) {
	t.Helper()
	for _, method := range methods {
		for _, call := range database.Calls {
			if call.Method == method {
				t.Errorf("%s was called, and this path must not reach it", method)
			}
		}
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

// =============================================================================
// HandleAPIClientWebOriginsPut
// =============================================================================

// webOriginsBody is the save's JSON body. A nil expected list is sent as null, which the save
// refuses; the absent-key case is written as a literal where it is tested.
func webOriginsBody(t *testing.T, wanted, expected []string) string {
	t.Helper()
	body, err := json.Marshal(api.UpdateClientWebOriginsRequest{WebOrigins: wanted, ExpectedWebOrigins: expected})
	require.NoError(t, err)
	return string(body)
}

// webOriginsPutRequest builds the PUT with its chi URL parameter and body.
func webOriginsPutRequest(t *testing.T, id string, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/admin/clients/"+id+"/web-origins", strings.NewReader(body))
	return setChiURLParam(r, "id", id)
}

// expectWebOriginsClient registers the client read the save makes before it validates. The
// client's authorization code flow is off: the save has no flow gate, since a browser client of any
// flow needs a web origin, and a client with no redirect-based flow must still be saved (#250).
func expectWebOriginsClient(database *mocks_data.Database) {
	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).
		Return(&models.Client{Id: 7, AuthorizationCodeEnabled: false}, nil).Once()
}

// expectStoredWebOrigins registers the read of the stored list on the save's transaction,
// answering the rows given.
func expectStoredWebOrigins(database *mocks_data.Database, rows ...models.WebOrigin) {
	database.On("ClientLoadWebOrigins", mock.Anything, clientUpdateTx, mock.Anything).
		Run(func(args mock.Arguments) {
			args.Get(2).(*models.Client).WebOrigins = append([]models.WebOrigin(nil), rows...)
		}).Return(nil).Once()
}

// The save is one transaction: the stored list is read on the transaction the writes use, compared
// with the list the caller loaded, and replaced by exactly replaceSet's plan, deletes then inserts,
// on that transaction, with no row acquisition before the read (#428). A wanted value is stored in
// its canonical form, the exact string a browser sends in an Origin header (#250). The audit event
// follows the commit.
func TestHandleAPIClientWebOriginsPut_SavesTheExactPlanInOneTransaction(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	expectWebOriginsClient(database)
	var order []string
	note := func(edge string) { order = append(order, edge) }
	stub := mocks_data.ExpectRunInTransaction(database, clientUpdateTx, note)
	expectStoredWebOrigins(database,
		models.WebOrigin{Id: 11, ClientId: 7, Origin: "https://old.example.com"},
		models.WebOrigin{Id: 12, ClientId: 7, Origin: "https://keep.example.com"},
	)
	var deleted []int64
	database.On("DeleteWebOrigin", mock.Anything, clientUpdateTx, mock.Anything).
		Run(func(args mock.Arguments) {
			deleted = append(deleted, args.Get(2).(int64))
			order = append(order, "delete")
		}).Return(nil).Once()
	var created []string
	database.On("CreateWebOrigin", mock.Anything, clientUpdateTx, mock.Anything).
		Run(func(args mock.Arguments) {
			wo := args.Get(2).(*models.WebOrigin)
			assert.Equal(t, int64(7), wo.ClientId)
			created = append(created, wo.Origin)
			order = append(order, "insert")
		}).Return(nil).Once()
	stubClientResponseLoads(database)
	auditLogger.On("Log", mock.Anything, audit.AuditUpdatedWebOrigins, mock.Anything).
		Run(func(mock.Arguments) { order = append(order, "audit") }).Return().Once()

	rr := httptest.NewRecorder()
	HandleAPIClientWebOriginsPut(database, auditLogger).ServeHTTP(rr, webOriginsPutRequest(t, "7",
		webOriginsBody(t,
			[]string{"https://keep.example.com", "  HTTPS://New.Example.com/  "},
			[]string{"https://old.example.com", "https://keep.example.com"})))

	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.NoError(t, stub.BodyErr)
	assert.Equal(t, []int64{11}, deleted, "the removed origin, and nothing kept")
	assert.Equal(t, []string{"https://new.example.com"}, created, "the new origin, canonical, and nothing already stored")
	assert.Equal(t, []string{"begin", "delete", "insert", "commit", "audit"}, order)
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
	assertNotAttemptedOnClientDatabase(t, database, "AcquireClientRow")
}

// A failure part way through commits nothing. Written autocommitted, as this save once was, a
// database error on the second of three writes left the first one committed, answered 500, and the
// administrator's list was neither what they sent nor what it was before; removing a compromised
// origin and adding its replacement in one save is exactly when that matters (#250). The body hands
// the driver's error to the helper, which is when the real one rolls back, and it stays reachable
// in the chain, so a real deadlock would be recognised and rerun rather than answered. The wrap
// names the origin being written, for the operator reading the one log record (#428).
func TestHandleAPIClientWebOriginsPut_AFailedWriteCommitsNothing(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	expectWebOriginsClient(database)
	stub := mocks_data.ExpectRunInTransaction(database, clientUpdateTx)
	expectStoredWebOrigins(database, models.WebOrigin{Id: 11, ClientId: 7, Origin: "https://old.example.com"})
	database.On("DeleteWebOrigin", mock.Anything, clientUpdateTx, int64(11)).Return(nil).Once()
	diskFull := errors.New("the disk is full")
	database.On("CreateWebOrigin", mock.Anything, clientUpdateTx, mock.Anything).Return(diskFull).Once()

	rr := httptest.NewRecorder()
	HandleAPIClientWebOriginsPut(database, auditLogger).ServeHTTP(rr, webOriginsPutRequest(t, "7",
		webOriginsBody(t, []string{"https://a.example.com"}, []string{"https://old.example.com"})))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, 1, strings.Count(rr.Body.String(), "INTERNAL_SERVER_ERROR"), "exactly one error response")
	assert.ErrorIs(t, stub.BodyErr, diskFull, "the body hands the driver's error to the helper, which rolls back")
	assert.Contains(t, stub.BodyErr.Error(), "https://a.example.com")
	database.AssertExpectations(t)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// The stored list failing to read inside the transaction is one 500 under its own message, with no
// write and no audit, in both of the shapes where ignoring the error would pass for something else:
// a loaded list naming a stored row would then read as outdated and answer 409, and an empty loaded
// list with nothing wanted would answer 200 over a read that never happened (#428).
func TestHandleAPIClientWebOriginsPut_AFailedLoadIsAnsweredAsALoadFailure(t *testing.T) {
	tests := []struct {
		name     string
		wanted   []string
		expected []string
	}{
		{name: "the loaded list names a stored row and nothing is wanted", wanted: []string{}, expected: []string{"https://a.example.com"}},
		{name: "the loaded list and the wanted list are both empty", wanted: []string{}, expected: []string{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_audit.NewAuditLogger(t)

			expectWebOriginsClient(database)
			stub := mocks_data.ExpectRunInTransaction(database, clientUpdateTx)
			loadErr := errors.New("the read failed")
			database.On("ClientLoadWebOrigins", mock.Anything, clientUpdateTx, mock.Anything).Return(loadErr).Once()

			rr := httptest.NewRecorder()
			HandleAPIClientWebOriginsPut(database, auditLogger).ServeHTTP(rr, webOriginsPutRequest(t, "7",
				webOriginsBody(t, test.wanted, test.expected)))

			assert.Equal(t, http.StatusInternalServerError, rr.Code, rr.Body.String())
			assert.Equal(t, 1, strings.Count(rr.Body.String(), "INTERNAL_SERVER_ERROR"), "exactly one error response")
			// The step is named on the error rather than on the wire: it is carried out of the
			// transaction body so nothing is written from an attempt that might be rerun.
			assert.ErrorIs(t, stub.BodyErr, loadErr)
			assert.Contains(t, stub.BodyErr.Error(), "database error loading client web origins before update")
			database.AssertExpectations(t)
			assertNotAttemptedOnClientDatabase(t, database, "CreateWebOrigin", "DeleteWebOrigin")
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// A body aborted as a deadlock victim on its first attempt and rerun by the helper answers ONCE:
// one 200, one audit event, and no error response for the attempt that was thrown away. This is
// why every writeJSONError sits below RunInTransaction rather than inside the closure: an attempt
// that has already written a 500 cannot be rerun into a 200 (#301).
//
// The helper's loop is scripted here: the stub runs the body, checks the driver's error is still
// reachable through what the body returned, which is what the real classifier needs, and runs it
// again. The real loop, with a real deadlock, is the data tier's.
func TestHandleAPIClientWebOriginsPut_ARerunAttemptAnswersOnce(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	expectWebOriginsClient(database)

	deadlock := errors.New("Error 1213: Deadlock found when trying to get lock")
	attempts := 0
	database.EXPECT().RunInTransaction(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, fn func(tx *sql.Tx) error) error {
		for {
			attempts++
			err := fn(clientUpdateTx)
			if err == nil {
				return nil
			}
			require.ErrorIs(t, err, deadlock,
				"the body must hand the driver's error back in the chain, or the helper cannot tell a deadlock from a fault")
			require.Less(t, attempts, 3, "the second attempt was scripted to succeed")
		}
	}).Once()

	// Both attempts read the list afresh.
	database.On("ClientLoadWebOrigins", mock.Anything, clientUpdateTx, mock.Anything).Return(nil).Twice()
	// The first insert is the deadlock victim; the second lands.
	database.On("CreateWebOrigin", mock.Anything, clientUpdateTx, mock.Anything).Return(deadlock).Once()
	database.On("CreateWebOrigin", mock.Anything, clientUpdateTx, mock.Anything).Return(nil).Once()
	stubClientResponseLoads(database)

	auditLogger.On("Log", mock.Anything, audit.AuditUpdatedWebOrigins, mock.Anything).Return().Once()

	rr := httptest.NewRecorder()
	handler := HandleAPIClientWebOriginsPut(database, auditLogger)
	handler.ServeHTTP(rr, webOriginsPutRequest(t, "7", webOriginsBody(t, []string{"https://a.example.com"}, []string{})))

	assert.Equal(t, 2, attempts)
	assert.Equal(t, http.StatusOK, rr.Code)
	// One answer. A 500 written by the first attempt would sit in the body ahead of the 200's
	// JSON, and the recorder would show it.
	assert.NotContains(t, rr.Body.String(), "INTERNAL_SERVER_ERROR")
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

// The helper giving up, a deadlock on every attempt, is one 500 under the update message and no
// audit event: the exhausted error carries no step of its own and is reported as the helper's.
func TestHandleAPIClientWebOriginsPut_AnExhaustedRetryIsOneFiveHundred(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	expectWebOriginsClient(database)
	exhausted := errors.New("transaction aborted as a deadlock victim on all 3 attempts")
	mocks_data.ExpectRunInTransactionRefused(database, exhausted)

	rr := httptest.NewRecorder()
	handler := HandleAPIClientWebOriginsPut(database, auditLogger)
	handler.ServeHTTP(rr, webOriginsPutRequest(t, "7", webOriginsBody(t, []string{"https://a.example.com"}, []string{})))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, 1, strings.Count(rr.Body.String(), "INTERNAL_SERVER_ERROR"), "exactly one error response")
	database.AssertExpectations(t)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// canonicalOriginOfLength is a canonical origin of exactly n bytes: "https://" plus a host of
// 63-character labels and one shorter label, plus ":65535". urlutil.CanonicalOrigin bounds no
// host's length, so every n from 30 up canonicalizes, which is what lets the two boundary cases
// below sit either side of models.WebOriginMaxBytes on length alone.
func canonicalOriginOfLength(t *testing.T, n int) string {
	t.Helper()
	const prefix, port = "https://", ":65535"
	hostLen := n - len(prefix) - len(port)
	var labels []string
	for hostLen > 63 {
		labels = append(labels, strings.Repeat("a", 63))
		hostLen -= 64 // the label and the dot after it
	}
	labels = append(labels, strings.Repeat("b", hostLen))
	origin := prefix + strings.Join(labels, ".") + port
	require.Len(t, origin, n)
	canonical, ok := urlutil.CanonicalOrigin(origin)
	require.True(t, ok, "the fixture must canonicalize, or the case is testing the wrong refusal")
	require.Equal(t, origin, canonical, "the fixture must already be canonical")
	return origin
}

// A canonical origin one byte longer than the column is refused rather than stored.
// web_origins.origin is 267 wide (models.WebOriginMaxBytes) on MySQL, PostgreSQL and SQL Server,
// so an unbounded save would be a 500 on three engines out of four and a silent success on sqlite,
// which is the only engine the local integration tier runs (#250, #428). The value canonicalizes
// cleanly and is refused purely on length, which is what separates this from the invalid-origin
// path.
//
// The strict mock carries GetClientById and nothing else: reaching RunInTransaction fails the test,
// so the refusal is proved to happen before any write is attempted.
func TestHandleAPIClientWebOriginsPut_AnOverlongOriginIsRefusedNotStored(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	expectWebOriginsClient(database)

	// A literal rather than models.WebOriginMaxBytes+1, so the case pins the number itself: a bound
	// raised past the column moves with a derived value and is caught only by a literal one.
	origin := canonicalOriginOfLength(t, 268)

	rr := httptest.NewRecorder()
	handler := HandleAPIClientWebOriginsPut(database, auditLogger)
	handler.ServeHTTP(rr, webOriginsPutRequest(t, "7", webOriginsBody(t, []string{origin}, []string{})))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "too long")
	database.AssertExpectations(t)
	database.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
}

// The other side of the bound: a canonical origin of exactly 267 bytes, models.WebOriginMaxBytes and
// the longest standards-valid origin, is written. It reaches CreateWebOrigin on the save's
// transaction, which is what separates an admitted value from one refused before the write (#428).
func TestHandleAPIClientWebOriginsPut_AnOriginAtTheBoundIsStored(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	origin := canonicalOriginOfLength(t, 267)

	expectWebOriginsClient(database)
	mocks_data.ExpectRunInTransaction(database, clientUpdateTx)
	expectStoredWebOrigins(database)
	var created string
	database.On("CreateWebOrigin", mock.Anything, clientUpdateTx, mock.Anything).
		Run(func(args mock.Arguments) { created = args.Get(2).(*models.WebOrigin).Origin }).Return(nil).Once()
	stubClientResponseLoads(database)
	auditLogger.On("Log", mock.Anything, audit.AuditUpdatedWebOrigins, mock.Anything).Return().Once()

	rr := httptest.NewRecorder()
	handler := HandleAPIClientWebOriginsPut(database, auditLogger)
	handler.ServeHTTP(rr, webOriginsPutRequest(t, "7", webOriginsBody(t, []string{origin}, []string{})))

	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, origin, created)
	database.AssertExpectations(t)
}

// Two saves of one client's list that both add the same origin at the same moment: no row lock
// serializes them, so both pass their reads, and web_origins' unique key on (origin, client_id)
// refuses the second insert. That whole save rolls back and answers 409 CONCURRENT_UPDATE, the
// conflict an administrator resolves by reloading, rather than a 500 that says nothing; nothing is
// audited (#428).
func TestHandleAPIClientWebOriginsPut_AUniqueKeyRaceIsAConflict(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	expectWebOriginsClient(database)
	stub := mocks_data.ExpectRunInTransaction(database, clientUpdateTx)
	expectStoredWebOrigins(database)
	refused := errs.Errorf("%w: %w", data.ErrUniqueViolation, errs.New("duplicate key value violates unique constraint \"idx_web_origins_origin_client\""))
	database.On("CreateWebOrigin", mock.Anything, clientUpdateTx, mock.Anything).Return(refused).Once()

	rr := httptest.NewRecorder()
	HandleAPIClientWebOriginsPut(database, auditLogger).ServeHTTP(rr, webOriginsPutRequest(t, "7",
		webOriginsBody(t, []string{"https://a.example.com"}, []string{})))

	assert.Equal(t, http.StatusConflict, rr.Code, rr.Body.String())
	code, _ := decodeErrorEnvelope(t, rr)
	assert.Equal(t, "CONCURRENT_UPDATE", code)
	assert.ErrorIs(t, stub.BodyErr, data.ErrUniqueViolation, "the body hands the refusal to the helper, which rolls back")
	database.AssertExpectations(t)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// A loaded list that differs from the stored rows read on the transaction is a save from an
// outdated page: 409 CONCURRENT_UPDATE, nothing written and nothing audited, where applying the
// whole list would silently undo the change the caller never saw (#428).
func TestHandleAPIClientWebOriginsPut_AnOutdatedLoadedListIsRefused(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	expectWebOriginsClient(database)
	stub := mocks_data.ExpectRunInTransaction(database, clientUpdateTx)
	expectStoredWebOrigins(database,
		models.WebOrigin{Id: 11, ClientId: 7, Origin: "https://a.example.com"},
		models.WebOrigin{Id: 12, ClientId: 7, Origin: "https://added-meanwhile.example.com"},
	)

	rr := httptest.NewRecorder()
	HandleAPIClientWebOriginsPut(database, auditLogger).ServeHTTP(rr, webOriginsPutRequest(t, "7",
		webOriginsBody(t, []string{"https://a.example.com", "https://b.example.com"}, []string{"https://a.example.com"})))

	assert.Equal(t, http.StatusConflict, rr.Code)
	code, _ := decodeErrorEnvelope(t, rr)
	assert.Equal(t, "CONCURRENT_UPDATE", code)
	assert.ErrorIs(t, stub.BodyErr, errListChanged, "the body refuses, so the helper rolls back")
	database.AssertExpectations(t)
	assertNotAttemptedOnClientDatabase(t, database, "CreateWebOrigin", "DeleteWebOrigin")
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// A loaded list equal to the stored one as a set proceeds: in another order, with a repeat, and in
// a form that canonicalizes to the stored value, since the comparison is on the canonical origin
// the rows are stored in; and [] against an empty stored list, which is a page that loaded no
// origins and not a missing field (#428).
func TestHandleAPIClientWebOriginsPut_ALoadedListEqualAsASetProceeds(t *testing.T) {
	tests := []struct {
		name     string
		stored   []models.WebOrigin
		expected []string
	}{
		{
			name: "another order, a repeat and a non-canonical spelling",
			stored: []models.WebOrigin{
				{Id: 11, ClientId: 7, Origin: "https://a.example.com"},
				{Id: 12, ClientId: 7, Origin: "https://b.example.com"},
			},
			expected: []string{"https://b.example.com", " HTTPS://A.Example.com/ ", "https://b.example.com"},
		},
		{name: "an empty loaded list against an empty stored list", stored: nil, expected: []string{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_audit.NewAuditLogger(t)

			expectWebOriginsClient(database)
			mocks_data.ExpectRunInTransaction(database, clientUpdateTx)
			expectStoredWebOrigins(database, test.stored...)
			for _, row := range test.stored {
				database.On("DeleteWebOrigin", mock.Anything, clientUpdateTx, row.Id).Return(nil).Once()
			}
			database.On("CreateWebOrigin", mock.Anything, clientUpdateTx, mock.Anything).Return(nil).Once()
			stubClientResponseLoads(database)
			auditLogger.On("Log", mock.Anything, audit.AuditUpdatedWebOrigins, mock.Anything).Return().Once()

			rr := httptest.NewRecorder()
			HandleAPIClientWebOriginsPut(database, auditLogger).ServeHTTP(rr, webOriginsPutRequest(t, "7",
				webOriginsBody(t, []string{"https://c.example.com"}, test.expected)))

			assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			database.AssertExpectations(t)
		})
	}
}

// Every refusal is decided before the transaction opens, so a refused save writes nothing: the
// strict mock carries the client read and nothing else, and reaching RunInTransaction fails the
// case. The loaded list is required, and each of its values must canonicalize, since one that does
// not can match no stored row (#428); the wanted list's rules are #250's.
func TestHandleAPIClientWebOriginsPut_ARefusedSaveNeverOpensTheTransaction(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		wantDescription string
	}{
		{
			name:            "the loaded list is absent",
			body:            `{"webOrigins":["https://a.example.com"]}`,
			wantDescription: "expectedWebOrigins is required",
		},
		{
			name:            "the loaded list is null",
			body:            `{"webOrigins":["https://a.example.com"],"expectedWebOrigins":null}`,
			wantDescription: "expectedWebOrigins is required",
		},
		{
			name:            "the loaded list carries a value that is not an origin",
			body:            webOriginsBody(t, []string{"https://a.example.com"}, []string{"ftp://a.example.com"}),
			wantDescription: "Invalid web origin in expectedWebOrigins: ftp://a.example.com",
		},
		{
			name:            "an empty origin",
			body:            webOriginsBody(t, []string{"https://a.example.com", "  "}, []string{}),
			wantDescription: "Web origin cannot be empty",
		},
		{
			name:            "a value that is not an origin",
			body:            webOriginsBody(t, []string{"ftp://a.example.com"}, []string{}),
			wantDescription: "Invalid web origin: ftp://a.example.com",
		},
		{
			name:            "an origin repeated in another spelling",
			body:            webOriginsBody(t, []string{"https://a.example.com", "HTTPS://A.EXAMPLE.COM/"}, []string{}),
			wantDescription: "Duplicate web origins are not allowed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_audit.NewAuditLogger(t)
			expectWebOriginsClient(database)

			rr := httptest.NewRecorder()
			HandleAPIClientWebOriginsPut(database, auditLogger).ServeHTTP(rr, webOriginsPutRequest(t, "7", test.body))

			assert.Equal(t, http.StatusBadRequest, rr.Code)
			code, description := decodeErrorEnvelope(t, rr)
			assert.Equal(t, "VALIDATION_ERROR", code)
			assert.Contains(t, description, test.wantDescription)
			database.AssertExpectations(t)
			assertNotAttemptedOnClientDatabase(t, database, "RunInTransaction")
		})
	}
}

// =============================================================================
// HandleAPIClientRedirectURIsPut
// =============================================================================

// redirectURIsBody is the save's JSON body. A nil expected list is sent as null, which the save
// refuses; the absent-key case is written as a literal where it is tested.
func redirectURIsBody(t *testing.T, wanted, expected []string) string {
	t.Helper()
	body, err := json.Marshal(api.UpdateClientRedirectURIsRequest{RedirectURIs: wanted, ExpectedRedirectURIs: expected})
	require.NoError(t, err)
	return string(body)
}

// redirectURIsPutRequest builds the PUT with its chi URL parameter, its body, and the settings the
// flow gate reads from the context.
func redirectURIsPutRequest(t *testing.T, id string, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/admin/clients/"+id+"/redirect-uris", strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), constants.ContextKeySettings, &models.Settings{}))
	return setChiURLParam(r, "id", id)
}

// expectRedirectURIsClient registers the client read the save makes before it validates, for a
// client whose authorization code flow is on, so the flow gate lets the request through.
func expectRedirectURIsClient(database *mocks_data.Database) {
	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).
		Return(&models.Client{Id: 7, AuthorizationCodeEnabled: true}, nil).Once()
}

// expectStoredRedirectURIs registers the read of the stored list on the save's transaction,
// answering the rows given.
func expectStoredRedirectURIs(database *mocks_data.Database, rows ...models.RedirectURI) {
	database.On("ClientLoadRedirectURIs", mock.Anything, clientUpdateTx, mock.Anything).
		Run(func(args mock.Arguments) {
			args.Get(2).(*models.Client).RedirectURIs = append([]models.RedirectURI(nil), rows...)
		}).Return(nil).Once()
}

// uriOfBytes is an absolute https redirect URI of exactly n bytes whose path is made of unit, so a
// multi-byte unit lands a URI on the same byte count in fewer characters.
func uriOfBytes(t *testing.T, n int, unit string) string {
	t.Helper()
	const prefix = "https://example.com/"
	body := n - len(prefix)
	uri := prefix + strings.Repeat("x", body%len(unit)) + strings.Repeat(unit, body/len(unit))
	require.Len(t, uri, n)
	return uri
}

// The save is one transaction: the stored list is read on the transaction the writes use, compared
// with the list the caller loaded, and replaced by exactly replaceSet's plan, deletes then inserts,
// on that transaction. Autocommitted, as it was, a failure part way through left the earlier writes
// committed under a 500 (#264). The stored list carries a URI twice, which dynamic registration
// used to store: keeping it deletes the extra copy, where the save keyed by value left it alone and a
// later removal of the URI deleted one copy and left the other live at sign-in (#428). The audit
// event follows the commit.
func TestHandleAPIClientRedirectURIsPut_SavesTheExactPlanInOneTransaction(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	expectRedirectURIsClient(database)
	var order []string
	note := func(edge string) { order = append(order, edge) }
	stub := mocks_data.ExpectRunInTransaction(database, clientUpdateTx, note)
	expectStoredRedirectURIs(database,
		models.RedirectURI{Id: 11, ClientId: 7, URI: "https://old.example.com/cb"},
		models.RedirectURI{Id: 12, ClientId: 7, URI: "https://keep.example.com/cb"},
		models.RedirectURI{Id: 13, ClientId: 7, URI: "https://keep.example.com/cb"},
	)
	var deleted []int64
	database.On("DeleteRedirectURI", mock.Anything, clientUpdateTx, mock.Anything).
		Run(func(args mock.Arguments) {
			deleted = append(deleted, args.Get(2).(int64))
			order = append(order, "delete")
		}).Return(nil).Twice()
	var created []string
	database.On("CreateRedirectURI", mock.Anything, clientUpdateTx, mock.Anything).
		Run(func(args mock.Arguments) {
			ru := args.Get(2).(*models.RedirectURI)
			assert.Equal(t, int64(7), ru.ClientId)
			created = append(created, ru.URI)
			order = append(order, "insert")
		}).Return(nil).Once()
	stubClientResponseLoads(database)
	auditLogger.On("Log", mock.Anything, audit.AuditUpdatedRedirectURIs, mock.Anything).
		Run(func(mock.Arguments) { order = append(order, "audit") }).Return().Once()

	rr := httptest.NewRecorder()
	HandleAPIClientRedirectURIsPut(database, auditLogger).ServeHTTP(rr, redirectURIsPutRequest(t, "7",
		redirectURIsBody(t,
			[]string{"https://keep.example.com/cb", "  https://new.example.com/cb  "},
			[]string{"https://old.example.com/cb", "https://keep.example.com/cb"})))

	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.NoError(t, stub.BodyErr)
	assert.Equal(t, []int64{11, 13}, deleted, "every copy of a removed URI and every extra copy of a kept one")
	assert.Equal(t, []string{"https://new.example.com/cb"}, created, "the new URI, trimmed, and nothing already stored")
	assert.Equal(t, []string{"begin", "delete", "delete", "insert", "commit", "audit"}, order)
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

// A failed write hands its error to the helper, which is when the real one rolls back, so nothing
// the save wrote before it commits; the answer is one 500 and nothing is audited, since an audit row
// for a save that did not happen is a false record of an administrator's action (#264, #428).
func TestHandleAPIClientRedirectURIsPut_AFailedWriteCommitsNothing(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	expectRedirectURIsClient(database)
	stub := mocks_data.ExpectRunInTransaction(database, clientUpdateTx)
	expectStoredRedirectURIs(database, models.RedirectURI{Id: 11, ClientId: 7, URI: "https://old.example.com/cb"})
	database.On("DeleteRedirectURI", mock.Anything, clientUpdateTx, int64(11)).Return(nil).Once()
	diskFull := errors.New("the disk is full")
	database.On("CreateRedirectURI", mock.Anything, clientUpdateTx, mock.Anything).Return(diskFull).Once()

	rr := httptest.NewRecorder()
	HandleAPIClientRedirectURIsPut(database, auditLogger).ServeHTTP(rr, redirectURIsPutRequest(t, "7",
		redirectURIsBody(t, []string{"https://new.example.com/cb"}, []string{"https://old.example.com/cb"})))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, 1, strings.Count(rr.Body.String(), "INTERNAL_SERVER_ERROR"), "exactly one error response")
	assert.ErrorIs(t, stub.BodyErr, diskFull, "the body hands the driver's error to the helper, which rolls back")
	database.AssertExpectations(t)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// The stored list failing to read inside the transaction is one 500 with no write and no audit, in
// both of the shapes where ignoring the error would pass for something else: a loaded list naming a
// stored row would then read as outdated and answer 409, and an empty loaded list with nothing wanted
// would answer 200 over a read that never happened. Every list save carries this case (#428).
func TestHandleAPIClientRedirectURIsPut_AFailedStoredReadIsOneFiveHundred(t *testing.T) {
	tests := []struct {
		name     string
		wanted   []string
		expected []string
	}{
		{name: "the loaded list names a stored row and nothing is wanted", wanted: []string{}, expected: []string{"https://a.example.com/cb"}},
		{name: "the loaded list and the wanted list are both empty", wanted: []string{}, expected: []string{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_audit.NewAuditLogger(t)

			expectRedirectURIsClient(database)
			stub := mocks_data.ExpectRunInTransaction(database, clientUpdateTx)
			readErr := errors.New("the read failed")
			database.On("ClientLoadRedirectURIs", mock.Anything, clientUpdateTx, mock.Anything).Return(readErr).Once()

			rr := httptest.NewRecorder()
			HandleAPIClientRedirectURIsPut(database, auditLogger).ServeHTTP(rr, redirectURIsPutRequest(t, "7",
				redirectURIsBody(t, test.wanted, test.expected)))

			assert.Equal(t, http.StatusInternalServerError, rr.Code, rr.Body.String())
			assert.Equal(t, 1, strings.Count(rr.Body.String(), "INTERNAL_SERVER_ERROR"), "exactly one error response")
			assert.ErrorIs(t, stub.BodyErr, readErr)
			database.AssertExpectations(t)
			assertNotAttemptedOnClientDatabase(t, database, "CreateRedirectURI", "DeleteRedirectURI")
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// A body aborted as a deadlock victim and rerun by the helper answers once and audits once: each
// attempt reads the stored list afresh and plans from it, and nothing is written to the response
// from inside an attempt that might be thrown away (#301, #428).
func TestHandleAPIClientRedirectURIsPut_ARerunAttemptAnswersOnce(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	expectRedirectURIsClient(database)
	deadlock := errors.New("Error 1213: Deadlock found when trying to get lock")
	attempts := 0
	database.EXPECT().RunInTransaction(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, fn func(tx *sql.Tx) error) error {
		for {
			attempts++
			err := fn(clientUpdateTx)
			if err == nil {
				return nil
			}
			require.ErrorIs(t, err, deadlock,
				"the body must hand the driver's error back in the chain, or the helper cannot tell a deadlock from a fault")
			require.Less(t, attempts, 3, "the second attempt was scripted to succeed")
		}
	}).Once()
	database.On("ClientLoadRedirectURIs", mock.Anything, clientUpdateTx, mock.Anything).Return(nil).Twice()
	database.On("CreateRedirectURI", mock.Anything, clientUpdateTx, mock.Anything).Return(deadlock).Once()
	database.On("CreateRedirectURI", mock.Anything, clientUpdateTx, mock.Anything).Return(nil).Once()
	stubClientResponseLoads(database)
	auditLogger.On("Log", mock.Anything, audit.AuditUpdatedRedirectURIs, mock.Anything).Return().Once()

	rr := httptest.NewRecorder()
	HandleAPIClientRedirectURIsPut(database, auditLogger).ServeHTTP(rr, redirectURIsPutRequest(t, "7",
		redirectURIsBody(t, []string{"https://a.example.com/cb"}, []string{})))

	assert.Equal(t, 2, attempts)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.NotContains(t, rr.Body.String(), "INTERNAL_SERVER_ERROR")
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

// A loaded list that differs from the stored rows read on the transaction is a save from an
// outdated page: 409 CONCURRENT_UPDATE, nothing written and nothing audited, where applying the
// whole list would silently undo the change the caller never saw (#428).
func TestHandleAPIClientRedirectURIsPut_AnOutdatedLoadedListIsRefused(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	expectRedirectURIsClient(database)
	stub := mocks_data.ExpectRunInTransaction(database, clientUpdateTx)
	expectStoredRedirectURIs(database,
		models.RedirectURI{Id: 11, ClientId: 7, URI: "https://a.example.com/cb"},
		models.RedirectURI{Id: 12, ClientId: 7, URI: "https://added-meanwhile.example.com/cb"},
	)

	rr := httptest.NewRecorder()
	HandleAPIClientRedirectURIsPut(database, auditLogger).ServeHTTP(rr, redirectURIsPutRequest(t, "7",
		redirectURIsBody(t, []string{"https://a.example.com/cb", "https://b.example.com/cb"}, []string{"https://a.example.com/cb"})))

	assert.Equal(t, http.StatusConflict, rr.Code)
	code, _ := decodeErrorEnvelope(t, rr)
	assert.Equal(t, "CONCURRENT_UPDATE", code)
	assert.ErrorIs(t, stub.BodyErr, errListChanged, "the body refuses, so the helper rolls back")
	database.AssertExpectations(t)
	assertNotAttemptedOnClientDatabase(t, database, "CreateRedirectURI", "DeleteRedirectURI")
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// A loaded list equal to the stored one as a set proceeds: in another order, with a repeat, with
// surrounding spaces, and [] against an empty stored list, which is a page that loaded no URIs and
// not a missing field (#428).
func TestHandleAPIClientRedirectURIsPut_ALoadedListEqualAsASetProceeds(t *testing.T) {
	tests := []struct {
		name     string
		stored   []models.RedirectURI
		expected []string
	}{
		{
			name: "another order, a repeat and surrounding spaces",
			stored: []models.RedirectURI{
				{Id: 11, ClientId: 7, URI: "https://a.example.com/cb"},
				{Id: 12, ClientId: 7, URI: "https://b.example.com/cb"},
			},
			expected: []string{"https://b.example.com/cb", " https://a.example.com/cb ", "https://b.example.com/cb"},
		},
		{name: "an empty loaded list against an empty stored list", stored: nil, expected: []string{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_audit.NewAuditLogger(t)

			expectRedirectURIsClient(database)
			mocks_data.ExpectRunInTransaction(database, clientUpdateTx)
			expectStoredRedirectURIs(database, test.stored...)
			for _, row := range test.stored {
				database.On("DeleteRedirectURI", mock.Anything, clientUpdateTx, row.Id).Return(nil).Once()
			}
			database.On("CreateRedirectURI", mock.Anything, clientUpdateTx, mock.Anything).Return(nil).Once()
			stubClientResponseLoads(database)
			auditLogger.On("Log", mock.Anything, audit.AuditUpdatedRedirectURIs, mock.Anything).Return().Once()

			rr := httptest.NewRecorder()
			HandleAPIClientRedirectURIsPut(database, auditLogger).ServeHTTP(rr, redirectURIsPutRequest(t, "7",
				redirectURIsBody(t, []string{"https://c.example.com/cb"}, test.expected)))

			assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			database.AssertExpectations(t)
		})
	}
}

// Every refusal is decided before the transaction opens, so a refused save writes nothing: the
// strict mock carries the client read and nothing else, and reaching RunInTransaction fails the
// case. The bounds are the model's, the same at dynamic client registration (#428): at most 60
// URIs, each at most 2048 bytes by Go len, which every engine's column holds, checked before the
// parse. A stored value over a bound, one a client could hold from before the bound existed, is
// refused like any other when the save carries it, which is #122's precedent for legacy rows.
func TestHandleAPIClientRedirectURIsPut_ARefusedSaveNeverOpensTheTransaction(t *testing.T) {
	sixtyOne := make([]string, 61)
	for i := range sixtyOne {
		sixtyOne[i] = fmt.Sprintf("https://app%d.example.com/cb", i)
	}

	tests := []struct {
		name            string
		body            string
		wantDescription string
	}{
		{
			name:            "the loaded list is absent",
			body:            `{"redirectURIs":["https://a.example.com/cb"]}`,
			wantDescription: "expectedRedirectURIs is required",
		},
		{
			name:            "the loaded list is null",
			body:            `{"redirectURIs":["https://a.example.com/cb"],"expectedRedirectURIs":null}`,
			wantDescription: "expectedRedirectURIs is required",
		},
		{
			name:            "61 redirect URIs",
			body:            redirectURIsBody(t, sixtyOne, []string{}),
			wantDescription: "at most 60 redirect URIs",
		},
		{
			name:            "an ASCII URI of 2049 bytes",
			body:            redirectURIsBody(t, []string{uriOfBytes(t, 2049, "a")}, []string{}),
			wantDescription: "too long (2049 bytes, the maximum is 2048)",
		},
		{
			name:            "a multi-byte URI of 2049 bytes",
			body:            redirectURIsBody(t, []string{uriOfBytes(t, 2049, "é")}, []string{}),
			wantDescription: "too long (2049 bytes, the maximum is 2048)",
		},
		{
			name:            "a four-byte URI of 2049 bytes",
			body:            redirectURIsBody(t, []string{uriOfBytes(t, 2049, "😀")}, []string{}),
			wantDescription: "too long (2049 bytes, the maximum is 2048)",
		},
		{
			// Length is checked before the parse, so an overlong value is never parsed.
			name:            "an overlong URI that is also malformed",
			body:            redirectURIsBody(t, []string{"not a url " + strings.Repeat("x", 2048)}, []string{}),
			wantDescription: "too long",
		},
		{
			name: "a stored URI over the bound, carried by the save",
			body: redirectURIsBody(t,
				[]string{uriOfBytes(t, 3000, "a"), "https://b.example.com/cb"},
				[]string{uriOfBytes(t, 3000, "a")}),
			wantDescription: "too long (3000 bytes, the maximum is 2048)",
		},
		{
			name:            "a repeated URI",
			body:            redirectURIsBody(t, []string{"https://a.example.com/cb", " https://a.example.com/cb"}, []string{}),
			wantDescription: "Duplicate redirect URIs are not allowed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_audit.NewAuditLogger(t)
			expectRedirectURIsClient(database)

			rr := httptest.NewRecorder()
			HandleAPIClientRedirectURIsPut(database, auditLogger).ServeHTTP(rr, redirectURIsPutRequest(t, "7", test.body))

			assert.Equal(t, http.StatusBadRequest, rr.Code)
			code, description := decodeErrorEnvelope(t, rr)
			assert.Equal(t, "VALIDATION_ERROR", code)
			assert.Contains(t, description, test.wantDescription)
			assert.Less(t, len(description), 400, "the refusal names an overlong value by its beginning, not whole")
			database.AssertExpectations(t)
			assertNotAttemptedOnClientDatabase(t, database, "RunInTransaction")
		})
	}
}

// The other side of every bound: 60 URIs of exactly 2048 bytes are stored, and a 2048-byte URI in
// two-byte and in four-byte characters too, each reaching CreateRedirectURI on the save's
// transaction. Literals rather than the model's constants, so a bound moved past its column is
// caught (#428).
func TestHandleAPIClientRedirectURIsPut_TheBoundsAreAdmitted(t *testing.T) {
	sixty := make([]string, 60)
	for i := range sixty {
		sixty[i] = uriOfBytes(t, 2048, fmt.Sprintf("%02d", i%100))
	}
	sixty[0] = uriOfBytes(t, 2048, "é")
	sixty[1] = uriOfBytes(t, 2048, "😀")
	sixty[2] = uriOfBytes(t, 2048, "a")

	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	expectRedirectURIsClient(database)
	mocks_data.ExpectRunInTransaction(database, clientUpdateTx)
	expectStoredRedirectURIs(database)
	var created []string
	database.On("CreateRedirectURI", mock.Anything, clientUpdateTx, mock.Anything).
		Run(func(args mock.Arguments) { created = append(created, args.Get(2).(*models.RedirectURI).URI) }).
		Return(nil).Times(60)
	stubClientResponseLoads(database)
	auditLogger.On("Log", mock.Anything, audit.AuditUpdatedRedirectURIs, mock.Anything).Return().Once()

	rr := httptest.NewRecorder()
	HandleAPIClientRedirectURIsPut(database, auditLogger).ServeHTTP(rr, redirectURIsPutRequest(t, "7",
		redirectURIsBody(t, sixty, []string{})))

	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, sixty, created)
	database.AssertExpectations(t)
}
