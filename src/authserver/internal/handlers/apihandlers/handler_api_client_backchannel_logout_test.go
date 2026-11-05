package apihandlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/audit"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
)

// PUT /api/v1/admin/clients/{id}/backchannel-logout sets a client's back-channel logout URI and
// whether it requires the session identifier (#784 decisions 6, 9 and 15). These hold what the
// integration tier cannot cheaply show: the save reads the client under its row before it writes,
// decides the confidential condition and the authserver:manage ceiling on that row, and audits
// after the commit.

const (
	manageScopeClaim        = "authserver:manage"
	manageClientsScopeClaim = "authserver:manage-clients"
)

// backchannelLogoutBody is the save's JSON body with both fields.
func backchannelLogoutBody(t *testing.T, uri string, sessionRequired bool) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{"backchannelLogoutUri": uri, "backchannelLogoutSessionRequired": sessionRequired})
	require.NoError(t, err)
	return string(body)
}

// serveBackchannelLogoutSave serves one save of client 7 under a token carrying scope.
func serveBackchannelLogoutSave(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/admin/clients/7/backchannel-logout", strings.NewReader(body))
	r = r.WithContext(reqctx.WithSettings(r.Context(), &record.Settings{}))
	r = setTokenContextWithClaims(r, map[string]interface{}{"scope": scope, "sub": grantCaller})
	rr := httptest.NewRecorder()
	HandleClientBackchannelLogoutPut(database, auditLogger).ServeHTTP(rr, withPathValue(r, "id", "7"))
	return rr
}

// confidentialCodeFlowClient is client 7, confidential, with its authorization code flow on and
// the back-channel logout URI given.
func confidentialCodeFlowClient(uri string) *record.Client {
	return &record.Client{Id: 7, ClientIdentifier: "an-app", AuthorizationCodeEnabled: true, BackchannelLogoutURI: uri}
}

// expectOrdinaryClient registers the read the target ceiling makes for a caller without
// authserver:manage: client 7 holds no permission, so it is no administrator.
func expectOrdinaryClient(database *datamocks.Database) {
	database.On("GetClientPermissionsByClientId", mock.Anything, (*sql.Tx)(nil), int64(7)).Return([]record.ClientPermission{}, nil).Once()
}

// expectTheRowUnderTheLock registers the acquisition of client 7's row on tx and the read after it,
// answering row, each noted in order.
func expectTheRowUnderTheLock(database *datamocks.Database, row *record.Client, note func(string)) {
	database.On("AcquireClientRow", mock.Anything, clientUpdateTx, int64(7)).
		Run(func(mock.Arguments) { note("acquire") }).Return(nil).Once()
	database.On("GetClientById", mock.Anything, clientUpdateTx, int64(7)).
		Run(func(mock.Arguments) { note("read") }).Return(row, nil).Once()
}

// expectTheAnswersLoads registers the reads the answer makes after the commit.
func expectTheAnswersLoads(database *datamocks.Database) {
	database.On("ClientLoadRedirectURIs", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(nil).Once()
	database.On("ClientLoadPostLogoutRedirectURIs", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(nil).Once()
	database.On("ClientLoadWebOrigins", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(nil).Once()
}

// The save takes the client's row, reads it on the same transaction, writes both settings through
// their one writer on that transaction, and records updated_client_backchannel_logout after the
// commit, naming the client and the caller. The answer is the client with both settings as saved,
// the URI trimmed and its query kept.
func TestHandleClientBackchannelLogoutPut_WritesUnderTheClientsRowAndAuditsAfterTheCommit(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	var order []string
	note := func(edge string) { order = append(order, edge) }

	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(confidentialCodeFlowClient(""), nil).Once()
	stub := datamocks.ExpectRunInTransaction(database, clientUpdateTx, note)
	expectTheRowUnderTheLock(database, confidentialCodeFlowClient(""), note)
	database.On("SetClientBackchannelLogout", mock.Anything, clientUpdateTx, int64(7), "http://app.internal:3000/bcl?tenant=a", true).
		Run(func(mock.Arguments) { note("write") }).Return(nil).Once()
	expectTheAnswersLoads(database)
	var details map[string]interface{}
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedClientBackchannelLogout, mock.Anything).
		Run(func(args mock.Arguments) {
			details = args.Get(2).(map[string]interface{})
			note("audit")
		}).Return().Once()

	rr := serveBackchannelLogoutSave(t, database, auditLogger, manageScopeClaim,
		backchannelLogoutBody(t, "  http://app.internal:3000/bcl?tenant=a  ", true))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.NoError(t, stub.BodyErr)
	assert.Equal(t, []string{"begin", "acquire", "read", "write", "commit", "audit"}, order)
	assert.Equal(t, map[string]interface{}{"client_id": int64(7), "logged_in_user": grantCaller}, details)

	var answer struct {
		Client map[string]any `json:"client"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &answer))
	assert.Equal(t, "http://app.internal:3000/bcl?tenant=a", answer.Client["backchannelLogoutUri"])
	assert.Equal(t, true, answer.Client["backchannelLogoutSessionRequired"])
}

// Decision 6's confidential condition is decided on the row read under the lock: a client loaded
// confidential and made public before the save took its row is refused an http URI, and nothing is
// written or audited.
func TestHandleClientBackchannelLogoutPut_AClientMadePublicUnderTheRowIsRefusedHTTP(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	var order []string
	note := func(edge string) { order = append(order, edge) }

	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(confidentialCodeFlowClient(""), nil).Once()
	datamocks.ExpectRunInTransaction(database, clientUpdateTx, note)
	madePublic := confidentialCodeFlowClient("")
	madePublic.IsPublic = true
	expectTheRowUnderTheLock(database, madePublic, note)

	rr := serveBackchannelLogoutSave(t, database, auditLogger, manageScopeClaim,
		backchannelLogoutBody(t, "http://app.internal:3000/bcl", false))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	code, description := decodeErrorEnvelope(t, rr)
	assert.Equal(t, "handler.client_backchannel_logout.uri_http_public_client", code)
	assert.Equal(t, "Back-channel logout URI must use https on a public client. Plain http is allowed only on a confidential client an administrator created: http://app.internal:3000/bcl", description)
	assert.Equal(t, []string{"begin", "acquire", "read", "rollback"}, order)
	database.AssertNotCalled(t, "SetClientBackchannelLogout", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// Decisions 6 and 7: a client that registered itself is held to https whatever its type and whoever
// sets its URI, so an http URI is refused it before anything is written, as the sender would skip
// it; https is admitted.
func TestHandleClientBackchannelLogoutPut_AClientThatRegisteredItselfTakesHTTPSOnly(t *testing.T) {
	selfRegistered := func(public bool) *record.Client {
		client := confidentialCodeFlowClient("")
		client.CreatedViaDCR = true
		client.IsPublic = public
		return client
	}
	for name, public := range map[string]bool{"confidential": false, "public": true} {
		t.Run(name+" refused http", func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(selfRegistered(public), nil).Once()

			rr := serveBackchannelLogoutSave(t, database, auditLogger, manageScopeClaim,
				backchannelLogoutBody(t, "http://app.internal:3000/bcl", false))

			assert.Equal(t, http.StatusBadRequest, rr.Code)
			code, description := decodeErrorEnvelope(t, rr)
			assert.Equal(t, "handler.client_backchannel_logout.uri_http_self_registered", code)
			assert.Equal(t, "Back-channel logout URI must use https on a client that registered itself, whatever its type. Plain http is allowed only on a confidential client an administrator created: http://app.internal:3000/bcl", description)
			database.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}

	t.Run("https admitted", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(selfRegistered(false), nil).Once()
		datamocks.ExpectRunInTransaction(database, clientUpdateTx)
		expectTheRowUnderTheLock(database, selfRegistered(false), func(string) {})
		database.On("SetClientBackchannelLogout", mock.Anything, clientUpdateTx, int64(7), "https://app.example.com/bcl", false).Return(nil).Once()
		expectTheAnswersLoads(database)
		auditLogger.On("Log", mock.Anything, audit.EventUpdatedClientBackchannelLogout, mock.Anything).Return().Once()

		rr := serveBackchannelLogoutSave(t, database, auditLogger, manageScopeClaim,
			backchannelLogoutBody(t, "https://app.example.com/bcl", false))

		assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	})
}

// Decision 15, for every caller below authserver:manage: a save that sets a URI, or changes the
// stored one, is refused 403 MANAGE_SCOPE_REQUIRED with one administrator_change_refused record
// under ceiling backchannel_logout_uri naming the client, before any transaction opens. Clearing
// the URI, or carrying the stored one back to change the flag alone, goes on.
func TestHandleClientBackchannelLogoutPut_OnlyManageSetsOrChangesTheURI(t *testing.T) {
	const stored = "https://app.example.com/bcl"
	refused := []struct {
		name   string
		scope  string
		stored string
		wanted string
	}{
		{"manage-clients setting a URI on a client with none", manageClientsScopeClaim, "", "https://app.example.com/bcl"},
		{"manage-clients changing the stored URI", manageClientsScopeClaim, stored, "https://elsewhere.example.com/bcl"},
		{"manage-clients changing only its query", manageClientsScopeClaim, stored, stored + "?x=1"},
		{"every granular scope", "authserver:admin-read authserver:manage-users authserver:manage-clients authserver:manage-settings authserver:browser-sessions",
			stored, "http://169.254.169.254/latest"},
		{"a scope that only resembles manage", "authserver:manage-clients authserver:manage-account other:manage", "", "https://app.example.com/bcl"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			records := recordLoggedEvents(auditLogger)
			database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(confidentialCodeFlowClient(tc.stored), nil).Once()
			expectOrdinaryClient(database)

			rr := serveBackchannelLogoutSave(t, database, auditLogger, tc.scope, backchannelLogoutBody(t, tc.wanted, false))

			code, description := decodeErrorEnvelope(t, rr)
			assertManageScopeRequired(t, rr, rr.Code, code, description)
			require.Len(t, *records, 1, "one record, and not the save's own")
			assert.Equal(t, "administrator_change_refused", (*records)[0].event)
			assert.Equal(t, map[string]interface{}{
				"logged_in_user": grantCaller,
				"method":         http.MethodPut,
				"route":          "",
				"ceiling":        "backchannel_logout_uri",
				"target_kind":    "client",
				"target_id":      int64(7),
			}, (*records)[0].details)
			database.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
		})
	}

	allowed := []struct {
		name   string
		scope  string
		stored string
		wanted string
	}{
		{"manage-clients clearing the URI", manageClientsScopeClaim, stored, ""},
		{"manage-clients carrying the stored URI back", manageClientsScopeClaim, stored, stored},
		{"manage-clients carrying the stored URI back with spaces", manageClientsScopeClaim, stored, "  " + stored + " "},
		{"manage-clients sending no URI to a client with none", manageClientsScopeClaim, "", ""},
		{"manage setting a URI", manageScopeClaim, "", "https://app.example.com/bcl"},
		{"manage changing the stored URI", manageScopeClaim, stored, "http://app.internal:3000/bcl"},
	}
	for _, tc := range allowed {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(confidentialCodeFlowClient(tc.stored), nil).Once()
			if tc.scope != manageScopeClaim {
				expectOrdinaryClient(database)
			}
			datamocks.ExpectRunInTransaction(database, clientUpdateTx)
			expectTheRowUnderTheLock(database, confidentialCodeFlowClient(tc.stored), func(string) {})
			database.On("SetClientBackchannelLogout", mock.Anything, clientUpdateTx, int64(7), strings.TrimSpace(tc.wanted), true).Return(nil).Once()
			expectTheAnswersLoads(database)
			auditLogger.On("Log", mock.Anything, audit.EventUpdatedClientBackchannelLogout, mock.Anything).Return().Once()

			rr := serveBackchannelLogoutSave(t, database, auditLogger, tc.scope, backchannelLogoutBody(t, tc.wanted, true))

			assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		})
	}
}

// Decision 15 compares the URI under the client's row: a caller below authserver:manage carrying
// back the URI it loaded, to change the flag alone, sets a URI when another save changed it before
// this one took the row. It is refused as the comparison before the transaction refuses, 403
// MANAGE_SCOPE_REQUIRED with its insufficient_scope challenge and one administrator_change_refused
// record under ceiling backchannel_logout_uri, written after the rollback, with nothing saved. An
// authserver:manage caller, whom the ceiling never refuses, writes.
func TestHandleClientBackchannelLogoutPut_AURIChangedUnderTheRowMeetsTheCeilingBelowManage(t *testing.T) {
	const loaded = "https://app.example.com/bcl"
	const changedMeanwhile = "https://other.example.com/bcl"

	t.Run("manage-clients", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		var order []string
		note := func(edge string) { order = append(order, edge) }
		database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(confidentialCodeFlowClient(loaded), nil).Once()
		expectOrdinaryClient(database)
		datamocks.ExpectRunInTransaction(database, clientUpdateTx, note)
		expectTheRowUnderTheLock(database, confidentialCodeFlowClient(changedMeanwhile), note)
		var records []loggedEvent
		auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
			note("audit")
			records = append(records, loggedEvent{event: args.String(1), details: args.Get(2).(map[string]interface{})})
		}).Return()

		rr := serveBackchannelLogoutSave(t, database, auditLogger, manageClientsScopeClaim, backchannelLogoutBody(t, loaded, true))

		code, description := decodeErrorEnvelope(t, rr)
		assertManageScopeRequired(t, rr, rr.Code, code, description)
		require.Len(t, records, 1, "one record, and not the save's own")
		assert.Equal(t, "administrator_change_refused", records[0].event)
		assert.Equal(t, map[string]interface{}{
			"logged_in_user": grantCaller,
			"method":         http.MethodPut,
			"route":          "",
			"ceiling":        "backchannel_logout_uri",
			"target_kind":    "client",
			"target_id":      int64(7),
		}, records[0].details)
		assert.Equal(t, []string{"begin", "acquire", "read", "rollback", "audit"}, order, "recorded after the rollback")
		database.AssertNotCalled(t, "SetClientBackchannelLogout", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("manage-clients clearing it", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(confidentialCodeFlowClient(loaded), nil).Once()
		expectOrdinaryClient(database)
		datamocks.ExpectRunInTransaction(database, clientUpdateTx)
		expectTheRowUnderTheLock(database, confidentialCodeFlowClient(changedMeanwhile), func(string) {})
		database.On("SetClientBackchannelLogout", mock.Anything, clientUpdateTx, int64(7), "", false).Return(nil).Once()
		expectTheAnswersLoads(database)
		auditLogger.On("Log", mock.Anything, audit.EventUpdatedClientBackchannelLogout, mock.Anything).Return().Once()

		rr := serveBackchannelLogoutSave(t, database, auditLogger, manageClientsScopeClaim, backchannelLogoutBody(t, "", false))

		assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	})

	t.Run("manage", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(confidentialCodeFlowClient(loaded), nil).Once()
		datamocks.ExpectRunInTransaction(database, clientUpdateTx)
		expectTheRowUnderTheLock(database, confidentialCodeFlowClient(changedMeanwhile), func(string) {})
		database.On("SetClientBackchannelLogout", mock.Anything, clientUpdateTx, int64(7), loaded, true).Return(nil).Once()
		expectTheAnswersLoads(database)
		auditLogger.On("Log", mock.Anything, audit.EventUpdatedClientBackchannelLogout, mock.Anything).Return().Once()

		rr := serveBackchannelLogoutSave(t, database, auditLogger, manageScopeClaim, backchannelLogoutBody(t, loaded, true))

		assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	})
}

// An administrator client meets the target ceiling first, whose refusal names it, as every other
// client save's does.
func TestHandleClientBackchannelLogoutPut_AnAdministratorClientMeetsTheTargetCeilingFirst(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	records := recordLoggedEvents(auditLogger)
	console := confidentialCodeFlowClient("")
	console.AdministrativeScopesAllowed = true
	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(console, nil).Once()

	rr := serveBackchannelLogoutSave(t, database, auditLogger, manageClientsScopeClaim, backchannelLogoutBody(t, "", true))

	code, description := decodeErrorEnvelope(t, rr)
	assertManageScopeRequired(t, rr, rr.Code, code, description)
	require.Len(t, *records, 1)
	assert.Equal(t, "target", (*records)[0].details["ceiling"])
	database.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
}
