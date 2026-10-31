package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/audit"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

// PUT /api/v1/admin/clients/{id}/post-logout-redirect-uris saves a client's sign-out redirect URIs
// under exactly the rules of its redirect URI save (#147 decision 4), so these tests mirror that
// save's, rule by rule, with the sign-out list's own messages and audit event.

// postLogoutRedirectURIsBody is the save's JSON body. A nil expected list is sent as null, which the
// save refuses; the absent-key case is written as a literal where it is tested.
func postLogoutRedirectURIsBody(t *testing.T, wanted, expected []string) string {
	t.Helper()
	body, err := json.Marshal(api.UpdateClientPostLogoutRedirectURIsRequest{
		PostLogoutRedirectURIs: wanted, ExpectedPostLogoutRedirectURIs: expected})
	require.NoError(t, err)
	return string(body)
}

// postLogoutRedirectURIsPutRequest builds the PUT with its path value, its body, and the settings
// the flow gate reads from the context, as a manage token whose subject the audit event names.
func postLogoutRedirectURIsPutRequest(t *testing.T, id string, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/admin/clients/"+id+"/post-logout-redirect-uris", strings.NewReader(body))
	r = r.WithContext(reqctx.WithSettings(r.Context(), &record.Settings{}))
	r = setTokenContextWithClaims(r, map[string]interface{}{"scope": "authserver:manage", "sub": grantCaller})
	return withPathValue(r, "id", id)
}

// expectPostLogoutRedirectURIsClient registers the client read the save makes before it validates.
func expectPostLogoutRedirectURIsClient(database *datamocks.Database, client *record.Client) {
	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(client, nil).Once()
}

// codeFlowClient is client 7 with its authorization code flow on, so the flow gate lets it through.
func codeFlowClient() *record.Client {
	return &record.Client{Id: 7, AuthorizationCodeEnabled: true}
}

// expectStoredPostLogoutRedirectURIs registers the read of the stored list on the save's
// transaction, answering the rows given.
func expectStoredPostLogoutRedirectURIs(database *datamocks.Database, rows ...record.PostLogoutRedirectURI) {
	database.On("ClientLoadPostLogoutRedirectURIs", mock.Anything, clientUpdateTx, mock.Anything).
		Run(func(args mock.Arguments) {
			args.Get(2).(*record.Client).PostLogoutRedirectURIs = append([]record.PostLogoutRedirectURI(nil), rows...)
		}).Return(nil).Once()
}

// servePostLogoutRedirectURIsSave serves one save of client 7.
func servePostLogoutRedirectURIsSave(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, body string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	HandleClientPostLogoutRedirectURIsPut(database, auditLogger).ServeHTTP(rr, postLogoutRedirectURIsPutRequest(t, "7", body))
	return rr
}

// The save is one transaction: the stored list is read on the transaction the writes use, compared
// with the list the caller loaded, and replaced by exactly replaceSet's plan, deletes then inserts.
// A stored list carrying a URI twice loses its extra copy. The audit event follows the commit and
// names the client and the caller, and the answer is the whole client, its sign-out list included.
func TestHandleClientPostLogoutRedirectURIsPut_SavesTheExactPlanInOneTransaction(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	expectPostLogoutRedirectURIsClient(database, codeFlowClient())
	var order []string
	note := func(edge string) { order = append(order, edge) }
	stub := datamocks.ExpectRunInTransaction(database, clientUpdateTx, note)
	expectStoredPostLogoutRedirectURIs(database,
		record.PostLogoutRedirectURI{Id: 11, ClientId: 7, URI: "https://old.example.com/bye"},
		record.PostLogoutRedirectURI{Id: 12, ClientId: 7, URI: "https://keep.example.com/bye"},
		record.PostLogoutRedirectURI{Id: 13, ClientId: 7, URI: "https://keep.example.com/bye"},
	)
	var deleted []int64
	database.On("DeletePostLogoutRedirectURI", mock.Anything, clientUpdateTx, mock.Anything).
		Run(func(args mock.Arguments) {
			deleted = append(deleted, args.Get(2).(int64))
			order = append(order, "delete")
		}).Return(nil).Twice()
	var created []string
	database.On("CreatePostLogoutRedirectURI", mock.Anything, clientUpdateTx, mock.Anything).
		Run(func(args mock.Arguments) {
			row := args.Get(2).(*record.PostLogoutRedirectURI)
			assert.Equal(t, int64(7), row.ClientId)
			created = append(created, row.URI)
			order = append(order, "insert")
		}).Return(nil).Once()
	// The answer's loads, after the commit: the sign-out list as stored now.
	createdAt := time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC)
	database.On("ClientLoadRedirectURIs", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(nil).Once()
	database.On("ClientLoadPostLogoutRedirectURIs", mock.Anything, (*sql.Tx)(nil), mock.Anything).
		Run(func(args mock.Arguments) {
			args.Get(2).(*record.Client).PostLogoutRedirectURIs = []record.PostLogoutRedirectURI{
				{Id: 12, ClientId: 7, URI: "https://keep.example.com/bye", CreatedAt: sql.NullTime{Time: createdAt, Valid: true}},
				{Id: 14, ClientId: 7, URI: "https://new.example.com/bye"},
			}
		}).Return(nil).Once()
	database.On("ClientLoadWebOrigins", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(nil).Once()
	var details map[string]interface{}
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedPostLogoutRedirectURIs, mock.Anything).
		Run(func(args mock.Arguments) {
			details = args.Get(2).(map[string]interface{})
			order = append(order, "audit")
		}).Return().Once()

	rr := servePostLogoutRedirectURIsSave(t, database, auditLogger, postLogoutRedirectURIsBody(t,
		[]string{"https://keep.example.com/bye", "  https://new.example.com/bye  "},
		[]string{"https://old.example.com/bye", "https://keep.example.com/bye"}))

	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.NoError(t, stub.BodyErr)
	assert.Equal(t, []int64{11, 13}, deleted, "every copy of a removed URI and every extra copy of a kept one")
	assert.Equal(t, []string{"https://new.example.com/bye"}, created, "the new URI, trimmed, and nothing already stored")
	assert.Equal(t, []string{"begin", "delete", "delete", "insert", "commit", "audit"}, order)
	assert.Equal(t, map[string]interface{}{"client_id": int64(7), "logged_in_user": grantCaller}, details)

	var answer struct {
		Client map[string]json.RawMessage `json:"client"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &answer))
	assert.JSONEq(t, `[{"id":12,"createdAt":"2026-10-31T09:00:00Z","uri":"https://keep.example.com/bye","clientId":7},`+
		`{"id":14,"createdAt":null,"uri":"https://new.example.com/bye","clientId":7}]`,
		string(answer.Client["postLogoutRedirectURIs"]))
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

// The save writes the sign-out list only: it never reads, creates or deletes a redirect URI, so the
// two lists stay apart (#147 decision 2).
func TestHandleClientPostLogoutRedirectURIsPut_LeavesTheRedirectURIsAlone(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	expectPostLogoutRedirectURIsClient(database, codeFlowClient())
	datamocks.ExpectRunInTransaction(database, clientUpdateTx)
	expectStoredPostLogoutRedirectURIs(database)
	database.On("CreatePostLogoutRedirectURI", mock.Anything, clientUpdateTx, mock.Anything).Return(nil).Once()
	stubClientResponseLoads(database)
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedPostLogoutRedirectURIs, mock.Anything).Return().Once()

	rr := servePostLogoutRedirectURIsSave(t, database, auditLogger,
		postLogoutRedirectURIsBody(t, []string{"https://app.example.com/bye"}, []string{}))

	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assertNotAttemptedOnClientDatabase(t, database, "CreateRedirectURI", "DeleteRedirectURI")
	for _, call := range database.Calls {
		if call.Method == "ClientLoadRedirectURIs" {
			assert.Nil(t, call.Arguments.Get(1), "the redirect URIs are read only for the answer, after the commit")
		}
	}
	database.AssertExpectations(t)
}

// A failed write hands its error to the helper, which is when the real one rolls back: one 500 and
// nothing audited.
func TestHandleClientPostLogoutRedirectURIsPut_AFailedWriteCommitsNothing(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	expectPostLogoutRedirectURIsClient(database, codeFlowClient())
	stub := datamocks.ExpectRunInTransaction(database, clientUpdateTx)
	expectStoredPostLogoutRedirectURIs(database, record.PostLogoutRedirectURI{Id: 11, ClientId: 7, URI: "https://old.example.com/bye"})
	database.On("DeletePostLogoutRedirectURI", mock.Anything, clientUpdateTx, int64(11)).Return(nil).Once()
	diskFull := errors.New("the disk is full")
	database.On("CreatePostLogoutRedirectURI", mock.Anything, clientUpdateTx, mock.Anything).Return(diskFull).Once()

	rr := servePostLogoutRedirectURIsSave(t, database, auditLogger,
		postLogoutRedirectURIsBody(t, []string{"https://new.example.com/bye"}, []string{"https://old.example.com/bye"}))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, 1, strings.Count(rr.Body.String(), "INTERNAL_SERVER_ERROR"), "exactly one error response")
	require.ErrorIs(t, stub.BodyErr, diskFull, "the body hands the driver's error to the helper, which rolls back")
	database.AssertExpectations(t)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// The stored list failing to read inside the transaction is one 500 with no write and no audit, in
// both shapes where ignoring the error would pass for a 409 or a 200.
func TestHandleClientPostLogoutRedirectURIsPut_AFailedStoredReadIsOneFiveHundred(t *testing.T) {
	tests := []struct {
		name     string
		wanted   []string
		expected []string
	}{
		{name: "the loaded list names a stored row and nothing is wanted", wanted: []string{}, expected: []string{"https://a.example.com/bye"}},
		{name: "the loaded list and the wanted list are both empty", wanted: []string{}, expected: []string{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			expectPostLogoutRedirectURIsClient(database, codeFlowClient())
			stub := datamocks.ExpectRunInTransaction(database, clientUpdateTx)
			readErr := errors.New("the read failed")
			database.On("ClientLoadPostLogoutRedirectURIs", mock.Anything, clientUpdateTx, mock.Anything).Return(readErr).Once()

			rr := servePostLogoutRedirectURIsSave(t, database, auditLogger, postLogoutRedirectURIsBody(t, test.wanted, test.expected))

			assert.Equal(t, http.StatusInternalServerError, rr.Code, rr.Body.String())
			assert.Equal(t, 1, strings.Count(rr.Body.String(), "INTERNAL_SERVER_ERROR"), "exactly one error response")
			require.ErrorIs(t, stub.BodyErr, readErr)
			database.AssertExpectations(t)
			assertNotAttemptedOnClientDatabase(t, database, "CreatePostLogoutRedirectURI", "DeletePostLogoutRedirectURI")
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// A body aborted as a deadlock victim and rerun by the helper answers once and audits once: each
// attempt reads the stored list afresh, and nothing reaches the response from inside an attempt.
func TestHandleClientPostLogoutRedirectURIsPut_ARerunAttemptAnswersOnce(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	expectPostLogoutRedirectURIsClient(database, codeFlowClient())
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
	database.On("ClientLoadPostLogoutRedirectURIs", mock.Anything, clientUpdateTx, mock.Anything).Return(nil).Twice()
	database.On("CreatePostLogoutRedirectURI", mock.Anything, clientUpdateTx, mock.Anything).Return(deadlock).Once()
	database.On("CreatePostLogoutRedirectURI", mock.Anything, clientUpdateTx, mock.Anything).Return(nil).Once()
	stubClientResponseLoads(database)
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedPostLogoutRedirectURIs, mock.Anything).Return().Once()

	rr := servePostLogoutRedirectURIsSave(t, database, auditLogger,
		postLogoutRedirectURIsBody(t, []string{"https://a.example.com/bye"}, []string{}))

	assert.Equal(t, 2, attempts)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.NotContains(t, rr.Body.String(), "INTERNAL_SERVER_ERROR")
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

// A loaded list that differs from the stored rows read on the transaction is a save from an
// outdated page: 409 CONCURRENT_UPDATE, nothing written and nothing audited.
func TestHandleClientPostLogoutRedirectURIsPut_AnOutdatedLoadedListIsRefused(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	expectPostLogoutRedirectURIsClient(database, codeFlowClient())
	stub := datamocks.ExpectRunInTransaction(database, clientUpdateTx)
	expectStoredPostLogoutRedirectURIs(database,
		record.PostLogoutRedirectURI{Id: 11, ClientId: 7, URI: "https://a.example.com/bye"},
		record.PostLogoutRedirectURI{Id: 12, ClientId: 7, URI: "https://added-meanwhile.example.com/bye"},
	)

	rr := servePostLogoutRedirectURIsSave(t, database, auditLogger, postLogoutRedirectURIsBody(t,
		[]string{"https://a.example.com/bye", "https://b.example.com/bye"}, []string{"https://a.example.com/bye"}))

	assert.Equal(t, http.StatusConflict, rr.Code)
	code, _ := decodeErrorEnvelope(t, rr)
	assert.Equal(t, "CONCURRENT_UPDATE", code)
	require.ErrorIs(t, stub.BodyErr, errListChanged, "the body refuses, so the helper rolls back")
	database.AssertExpectations(t)
	assertNotAttemptedOnClientDatabase(t, database, "CreatePostLogoutRedirectURI", "DeletePostLogoutRedirectURI")
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// A loaded list equal to the stored one as a set proceeds: in another order, with a repeat, with
// surrounding spaces, and [] against an empty stored list.
func TestHandleClientPostLogoutRedirectURIsPut_ALoadedListEqualAsASetProceeds(t *testing.T) {
	tests := []struct {
		name     string
		stored   []record.PostLogoutRedirectURI
		expected []string
	}{
		{
			name: "another order, a repeat and surrounding spaces",
			stored: []record.PostLogoutRedirectURI{
				{Id: 11, ClientId: 7, URI: "https://a.example.com/bye"},
				{Id: 12, ClientId: 7, URI: "https://b.example.com/bye"},
			},
			expected: []string{"https://b.example.com/bye", " https://a.example.com/bye ", "https://b.example.com/bye"},
		},
		{name: "an empty loaded list against an empty stored list", stored: nil, expected: []string{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			expectPostLogoutRedirectURIsClient(database, codeFlowClient())
			datamocks.ExpectRunInTransaction(database, clientUpdateTx)
			expectStoredPostLogoutRedirectURIs(database, test.stored...)
			for _, row := range test.stored {
				database.On("DeletePostLogoutRedirectURI", mock.Anything, clientUpdateTx, row.Id).Return(nil).Once()
			}
			database.On("CreatePostLogoutRedirectURI", mock.Anything, clientUpdateTx, mock.Anything).Return(nil).Once()
			stubClientResponseLoads(database)
			auditLogger.On("Log", mock.Anything, audit.EventUpdatedPostLogoutRedirectURIs, mock.Anything).Return().Once()

			rr := servePostLogoutRedirectURIsSave(t, database, auditLogger,
				postLogoutRedirectURIsBody(t, []string{"https://c.example.com/bye"}, test.expected))

			assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			database.AssertExpectations(t)
		})
	}
}

// Every refusal is decided before the transaction opens, so a refused save writes nothing: the strict
// mock carries the client read and nothing else. Each answers its catalog key in the sign-out list's
// own family, and its sentence names the sign-out list.
func TestHandleClientPostLogoutRedirectURIsPut_ARefusedSaveNeverOpensTheTransaction(t *testing.T) {
	sixtyOne := make([]string, 61)
	for i := range sixtyOne {
		sixtyOne[i] = fmt.Sprintf("https://app%d.example.com/bye", i)
	}

	tests := []struct {
		name            string
		body            string
		wantCode        string
		wantDescription string
	}{
		{
			name:            "the loaded list is absent",
			body:            `{"postLogoutRedirectURIs":["https://a.example.com/bye"]}`,
			wantCode:        "VALIDATION_ERROR",
			wantDescription: "expectedPostLogoutRedirectURIs is required: send the sign-out redirect URIs as you last read them, or [] if there were none.",
		},
		{
			name:            "the loaded list is null",
			body:            `{"postLogoutRedirectURIs":["https://a.example.com/bye"],"expectedPostLogoutRedirectURIs":null}`,
			wantCode:        "VALIDATION_ERROR",
			wantDescription: "expectedPostLogoutRedirectURIs is required: send the sign-out redirect URIs as you last read them, or [] if there were none.",
		},
		{
			name:            "61 sign-out redirect URIs",
			body:            postLogoutRedirectURIsBody(t, sixtyOne, []string{}),
			wantCode:        "handler.client_post_logout_redirect_uris.too_many",
			wantDescription: "A client can have at most 60 sign-out redirect URIs, and this list has 61.",
		},
		{
			name:            "a blank entry",
			body:            postLogoutRedirectURIsBody(t, []string{"https://a.example.com/bye", "   "}, []string{}),
			wantCode:        "handler.client_post_logout_redirect_uris.empty",
			wantDescription: "Sign-out redirect URI cannot be empty",
		},
		{
			name:            "an ASCII URI of 2049 bytes",
			body:            postLogoutRedirectURIsBody(t, []string{uriOfBytes(t, 2049, "a")}, []string{}),
			wantCode:        "handler.client_post_logout_redirect_uris.too_long",
			wantDescription: "Sign-out redirect URI is too long (2049 bytes, the maximum is 2048): https://example.com/" + strings.Repeat("a", 60) + "...",
		},
		{
			name:            "a multi-byte URI of 2049 bytes",
			body:            postLogoutRedirectURIsBody(t, []string{uriOfBytes(t, 2049, "é")}, []string{}),
			wantCode:        "handler.client_post_logout_redirect_uris.too_long",
			wantDescription: "Sign-out redirect URI is too long (2049 bytes, the maximum is 2048)",
		},
		{
			// Length is checked before the parse, so an overlong value is never parsed.
			name:            "an overlong URI that is also malformed",
			body:            postLogoutRedirectURIsBody(t, []string{"not a url " + strings.Repeat("x", 2048)}, []string{}),
			wantCode:        "handler.client_post_logout_redirect_uris.too_long",
			wantDescription: "Sign-out redirect URI is too long",
		},
		{
			name:            "a value that does not parse",
			body:            postLogoutRedirectURIsBody(t, []string{"not-a-url"}, []string{}),
			wantCode:        "handler.client_post_logout_redirect_uris.invalid",
			wantDescription: "Invalid sign-out redirect URI: not-a-url",
		},
		{
			name:            "a scheme-relative URI",
			body:            postLogoutRedirectURIsBody(t, []string{"//evil.example/bye"}, []string{}),
			wantCode:        "handler.client_post_logout_redirect_uris.not_absolute",
			wantDescription: "Sign-out redirect URI must be an absolute URI (a scheme is required, a fragment is not permitted, percent-escapes must be well formed, and an http or https URI must name a host): //evil.example/bye",
		},
		{
			name:            "a fragment",
			body:            postLogoutRedirectURIsBody(t, []string{"https://app.example.com/bye#done"}, []string{}),
			wantCode:        "handler.client_post_logout_redirect_uris.not_absolute",
			wantDescription: "an http or https URI must name a host): https://app.example.com/bye#done",
		},
		{
			name:            "an https URI with no host",
			body:            postLogoutRedirectURIsBody(t, []string{"https:///evil.example/bye"}, []string{}),
			wantCode:        "handler.client_post_logout_redirect_uris.not_absolute",
			wantDescription: "an http or https URI must name a host): https:///evil.example/bye",
		},
		{
			// url.Parse validates no escape in an opaque URI, so only the absolute-URI rule
			// refuses this one.
			name:            "a malformed percent-escape in a custom scheme",
			body:            postLogoutRedirectURIsBody(t, []string{"com.example.app:%zz"}, []string{}),
			wantCode:        "handler.client_post_logout_redirect_uris.not_absolute",
			wantDescription: "an http or https URI must name a host): com.example.app:%zz",
		},
		{
			name:            "a plain-http URI on a host other than loopback",
			body:            postLogoutRedirectURIsBody(t, []string{"http://app.example.com/bye"}, []string{}),
			wantCode:        "handler.client_post_logout_redirect_uris.insecure_http",
			wantDescription: "Sign-out redirect URI must not use plain http on a host other than the loopback interface (127.0.0.1, [::1] or localhost): http://app.example.com/bye",
		},
		{
			// A stored plain-http row receives nothing at sign-out, so a save that carries it
			// back is refused as an addition is, naming it, until the administrator removes it
			// in the same save (#590 decision 11). Here a retired entry is swapped for its
			// replacement with the http row kept: nothing is written.
			name: "a stored plain-http URI, carried back by the save",
			body: postLogoutRedirectURIsBody(t,
				[]string{"https://replacement.example.com/bye", "http://intranet.example.com/bye"},
				[]string{"http://intranet.example.com/bye", "https://retired.example.com/bye"}),
			wantCode:        "handler.client_post_logout_redirect_uris.insecure_http",
			wantDescription: "(127.0.0.1, [::1] or localhost): http://intranet.example.com/bye",
		},
		{
			// Its uppercase spelling is the same cleartext http, stored or not.
			name: "a stored plain-HTTP URI in upper case, carried back by the save",
			body: postLogoutRedirectURIsBody(t,
				[]string{"HTTP://intranet.example.com/bye"},
				[]string{"HTTP://intranet.example.com/bye"}),
			wantCode:        "handler.client_post_logout_redirect_uris.insecure_http",
			wantDescription: "(127.0.0.1, [::1] or localhost): HTTP://intranet.example.com/bye",
		},
		{
			name:            "a repeated URI, once with surrounding spaces",
			body:            postLogoutRedirectURIsBody(t, []string{"https://a.example.com/bye", " https://a.example.com/bye"}, []string{}),
			wantCode:        "handler.client_post_logout_redirect_uris.duplicate",
			wantDescription: "Duplicate sign-out redirect URIs are not allowed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			expectPostLogoutRedirectURIsClient(database, codeFlowClient())

			rr := servePostLogoutRedirectURIsSave(t, database, auditLogger, test.body)

			assert.Equal(t, http.StatusBadRequest, rr.Code)
			code, description := decodeErrorEnvelope(t, rr)
			assert.Equal(t, test.wantCode, code)
			assert.Contains(t, description, test.wantDescription)
			assert.Less(t, len(description), 400, "the refusal names an overlong value by its beginning, not whole")
			database.AssertExpectations(t)
			assertNotAttemptedOnClientDatabase(t, database, "RunInTransaction")
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// The shapes the rules admit, saved together: https with a query carrying state, loopback http on
// each spelling and on any port, and a custom scheme, which RP-Initiated Logout 1.0 section 2
// permits for a native app (#147 decision 4).
func TestHandleClientPostLogoutRedirectURIsPut_TheAdmittedShapesAreStored(t *testing.T) {
	admitted := []string{
		"https://app.example.com/bye?state=fixed",
		"https://app.example.com/signed-out?lang=en&from=app",
		"http://127.0.0.1:8765/bye",
		"http://[::1]/bye",
		"http://localhost:3000/bye",
		"com.example.app:/signed-out",
	}

	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	expectPostLogoutRedirectURIsClient(database, codeFlowClient())
	datamocks.ExpectRunInTransaction(database, clientUpdateTx)
	expectStoredPostLogoutRedirectURIs(database)
	var created []string
	database.On("CreatePostLogoutRedirectURI", mock.Anything, clientUpdateTx, mock.Anything).
		Run(func(args mock.Arguments) { created = append(created, args.Get(2).(*record.PostLogoutRedirectURI).URI) }).
		Return(nil).Times(len(admitted))
	stubClientResponseLoads(database)
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedPostLogoutRedirectURIs, mock.Anything).Return().Once()

	rr := servePostLogoutRedirectURIsSave(t, database, auditLogger, postLogoutRedirectURIsBody(t, admitted, []string{}))

	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, admitted, created)
	database.AssertExpectations(t)
}

// The other side of every bound: 60 URIs of exactly 2048 bytes are stored, and a 2048-byte URI in
// two-byte and in four-byte characters too. Literals rather than the model's constants, so a bound
// moved past its column is caught.
func TestHandleClientPostLogoutRedirectURIsPut_TheBoundsAreAdmitted(t *testing.T) {
	sixty := make([]string, 60)
	for i := range sixty {
		sixty[i] = uriOfBytes(t, 2048, fmt.Sprintf("%02d", i%100))
	}
	sixty[0] = uriOfBytes(t, 2048, "é")
	sixty[1] = uriOfBytes(t, 2048, "😀")
	sixty[2] = uriOfBytes(t, 2048, "a")

	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	expectPostLogoutRedirectURIsClient(database, codeFlowClient())
	datamocks.ExpectRunInTransaction(database, clientUpdateTx)
	expectStoredPostLogoutRedirectURIs(database)
	var created []string
	database.On("CreatePostLogoutRedirectURI", mock.Anything, clientUpdateTx, mock.Anything).
		Run(func(args mock.Arguments) { created = append(created, args.Get(2).(*record.PostLogoutRedirectURI).URI) }).
		Return(nil).Times(60)
	stubClientResponseLoads(database)
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedPostLogoutRedirectURIs, mock.Anything).Return().Once()

	rr := servePostLogoutRedirectURIsSave(t, database, auditLogger, postLogoutRedirectURIsBody(t, sixty, []string{}))

	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, sixty, created)
	database.AssertExpectations(t)
}

// The save is refused for a client with neither redirect-based flow, since a client that never signs
// a user in through a browser has no sign-out to return from, and allowed for an implicit-only one
// (#147 decision 4).
func TestHandleClientPostLogoutRedirectURIsPut_TheRedirectFlowGate(t *testing.T) {
	implicitOn, implicitOff := true, false

	t.Run("neither flow is refused before anything is read", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		expectPostLogoutRedirectURIsClient(database, &record.Client{Id: 7, ClientCredentialsEnabled: true, ImplicitGrantEnabled: &implicitOff})

		rr := servePostLogoutRedirectURIsSave(t, database, auditLogger,
			postLogoutRedirectURIsBody(t, []string{"https://app.example.com/bye"}, []string{}))

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		code, description := decodeErrorEnvelope(t, rr)
		assert.Equal(t, "handler.client_post_logout_redirect_uris.no_redirect_flow", code)
		assert.Equal(t, "Sign-out redirect URIs are used by clients that sign users in through the authorization code with PKCE flow or the implicit flow, and neither is enabled for this client.", description)
		database.AssertExpectations(t)
		assertNotAttemptedOnClientDatabase(t, database, "RunInTransaction")
	})

	t.Run("the implicit flow alone is let through", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		expectPostLogoutRedirectURIsClient(database, &record.Client{Id: 7, ImplicitGrantEnabled: &implicitOn})
		datamocks.ExpectRunInTransaction(database, clientUpdateTx)
		expectStoredPostLogoutRedirectURIs(database)
		database.On("CreatePostLogoutRedirectURI", mock.Anything, clientUpdateTx, mock.Anything).Return(nil).Once()
		stubClientResponseLoads(database)
		auditLogger.On("Log", mock.Anything, audit.EventUpdatedPostLogoutRedirectURIs, mock.Anything).Return().Once()

		rr := servePostLogoutRedirectURIsSave(t, database, auditLogger,
			postLogoutRedirectURIsBody(t, []string{"https://app.example.com/bye"}, []string{}))

		assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		database.AssertExpectations(t)
	})
}

// The path and body refusals the other list saves answer, before any validation.
func TestHandleClientPostLogoutRedirectURIsPut_TheRequestsOwnRefusals(t *testing.T) {
	t.Run("an id that is not a number", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		rr := httptest.NewRecorder()
		HandleClientPostLogoutRedirectURIsPut(database, handlersmocks.NewAuditLogger(t)).ServeHTTP(rr,
			postLogoutRedirectURIsPutRequest(t, "abc", postLogoutRedirectURIsBody(t, []string{}, []string{})))
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		code, description := decodeErrorEnvelope(t, rr)
		assert.Equal(t, "VALIDATION_ERROR", code)
		assert.Equal(t, "Invalid client ID", description)
	})

	t.Run("a client that does not exist", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(nil, nil).Once()
		rr := servePostLogoutRedirectURIsSave(t, database, handlersmocks.NewAuditLogger(t), postLogoutRedirectURIsBody(t, []string{}, []string{}))
		assert.Equal(t, http.StatusNotFound, rr.Code)
		code, _ := decodeErrorEnvelope(t, rr)
		assert.Equal(t, "NOT_FOUND", code)
	})

	t.Run("a body that does not parse", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		expectPostLogoutRedirectURIsClient(database, codeFlowClient())
		rr := servePostLogoutRedirectURIsSave(t, database, handlersmocks.NewAuditLogger(t), `{"postLogoutRedirectURIs":`)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		code, _ := decodeErrorEnvelope(t, rr)
		assert.Equal(t, "INVALID_REQUEST_BODY", code)
		assertNotAttemptedOnClientDatabase(t, database, "RunInTransaction")
	})
}
