package apihandlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// PUT /api/v1/admin/clients/{id}/dpop sets a client's "Require DPoP for token requests" (#42
// decision 12, RFC 9449 section 5.2): a required boolean, refused absent or null, never switched on
// for the admin console's own client, audited once written, and answered with the client as stored.

// serveClientDPoP sends body to the route for client 58 with an authserver:manage token. stored is
// the client the first read answers; afterWrite registers what the route reads once it has written.
func serveClientDPoP(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger,
	stored *record.Client, body string, afterWrite func(database *datamocks.Database)) *httptest.ResponseRecorder {
	t.Helper()
	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), targetClientId).Return(stored, nil).Once()
	if afterWrite != nil {
		afterWrite(database)
	}
	rr := httptest.NewRecorder()
	r := clientRequest(http.MethodPut, "/api/v1/admin/clients/58/dpop", body, "authserver:manage")
	HandleClientDPoPPut(database, auditLogger).ServeHTTP(rr, r)
	return rr
}

// answeredAs registers the read back after the write, answering client as stored, and the three
// collections the answer carries.
func answeredAs(client *record.Client) func(database *datamocks.Database) {
	return func(database *datamocks.Database) {
		database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), targetClientId).Return(client, nil).Once()
		database.On("ClientLoadRedirectURIs", mock.Anything, (*sql.Tx)(nil), client).Return(nil).Once()
		database.On("ClientLoadPostLogoutRedirectURIs", mock.Anything, (*sql.Tx)(nil), client).Return(nil).Once()
		database.On("ClientLoadWebOrigins", mock.Anything, (*sql.Tx)(nil), client).Return(nil).Once()
	}
}

// Both values are written to the one client, audited with the value saved, and answered as the
// row reads back.
func TestClientDPoPPut_SetsTheRequirementBothWays(t *testing.T) {
	for _, on := range []bool{true, false} {
		t.Run(map[bool]string{true: "on", false: "off"}[on], func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			records := recordLoggedEvents(auditLogger)
			database.On("SetClientDPoPBoundAccessTokens", mock.Anything, (*sql.Tx)(nil), targetClientId, on).Return(nil).Once()

			body := `{"dpopBoundAccessTokens":false}`
			if on {
				body = `{"dpopBoundAccessTokens":true}`
			}
			rr := serveClientDPoP(t, database, auditLogger,
				&record.Client{Id: targetClientId, ClientIdentifier: "dpop-client", DPoPBoundAccessTokens: !on}, body,
				answeredAs(&record.Client{Id: targetClientId, ClientIdentifier: "dpop-client", DPoPBoundAccessTokens: on}))

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			var answer map[string]map[string]any
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &answer))
			assert.Equal(t, on, answer["client"]["dpopBoundAccessTokens"])
			assert.InDelta(t, float64(targetClientId), answer["client"]["id"], 0)

			require.Len(t, *records, 1, "a committed save leaves exactly one entry")
			assert.Equal(t, audit.EventUpdatedClientDPoP, (*records)[0].event)
			assert.Equal(t, "updated_client_dpop", (*records)[0].event)
			assert.Equal(t, map[string]interface{}{
				"client_id":                targetClientId,
				"client_identifier":        "dpop-client",
				"dpop_bound_access_tokens": on,
				"logged_in_user":           grantCaller,
			}, (*records)[0].details)
		})
	}
}

// Absent or null is refused rather than read as false: a body that says nothing must not switch
// the requirement off. Nothing is written or audited.
func TestClientDPoPPut_TheBooleanIsRequired(t *testing.T) {
	for _, body := range []string{`{}`, `{"dpopBoundAccessTokens":null}`, `{"dpop_bound_access_tokens":true}`} {
		t.Run(body, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			rr := serveClientDPoP(t, database, auditLogger,
				&record.Client{Id: targetClientId, ClientIdentifier: "dpop-client", DPoPBoundAccessTokens: true}, body, nil)

			assert.Equal(t, http.StatusBadRequest, rr.Code)
			var answer map[string]any
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &answer))
			assert.Equal(t, "handler.client_dpop.dpop_bound_access_tokens_required", answer["error_code"])
			database.AssertNotCalled(t, "SetClientDPoPBoundAccessTokens", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// The admin console calls the auth server with Bearer tokens, so its client is never switched on:
// refused 400 with a localized validation error, as that client's other protected settings are.
// Switching it off asks for what it already is, and is saved.
func TestClientDPoPPut_TheAdminConsolesClientIsNeverSwitchedOn(t *testing.T) {
	console := func() *record.Client {
		return &record.Client{Id: targetClientId, ClientIdentifier: builtin.AdminConsoleClientIdentifier}
	}

	t.Run("on is refused", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)

		rr := serveClientDPoP(t, database, auditLogger, console(), `{"dpopBoundAccessTokens":true}`, nil)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		var answer map[string]any
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &answer))
		assert.Equal(t, "handler.client_dpop.admin_console_not_allowed", answer["error_code"])
		assert.Equal(t, "The admin console's client can't require DPoP for token requests.", answer["error_description"])
		database.AssertNotCalled(t, "SetClientDPoPBoundAccessTokens", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("off is saved", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		records := recordLoggedEvents(auditLogger)
		database.On("SetClientDPoPBoundAccessTokens", mock.Anything, (*sql.Tx)(nil), targetClientId, false).Return(nil).Once()

		rr := serveClientDPoP(t, database, auditLogger, console(), `{"dpopBoundAccessTokens":false}`, answeredAs(console()))

		assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		require.Len(t, *records, 1)
	})
}

// The request's own refusals: an id that is not a number, a client that is not there, and a body
// that is not JSON. None writes.
func TestClientDPoPPut_TheRequestsOwnRefusals(t *testing.T) {
	t.Run("an id that is not a number", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		rr := httptest.NewRecorder()
		r := membershipRequest(http.MethodPut, "/api/v1/admin/clients/abc/dpop", `{"dpopBoundAccessTokens":true}`,
			"authserver:manage", map[string]string{"id": "abc"})
		HandleClientDPoPPut(database, handlersmocks.NewAuditLogger(t)).ServeHTTP(rr, r)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "Invalid client ID")
	})

	t.Run("a client that is not there", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		rr := serveClientDPoP(t, database, handlersmocks.NewAuditLogger(t), nil, `{"dpopBoundAccessTokens":true}`, nil)
		assert.Equal(t, http.StatusNotFound, rr.Code)
		assert.Contains(t, rr.Body.String(), "Client not found")
	})

	t.Run("a body that is not JSON", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		rr := serveClientDPoP(t, database, handlersmocks.NewAuditLogger(t),
			&record.Client{Id: targetClientId, ClientIdentifier: "dpop-client"}, `{not json`, nil)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "INVALID_REQUEST_BODY")
	})
}

// A write that fails changed nothing, so it leaves no entry.
func TestClientDPoPPut_AFailedWriteIsNotAudited(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	database.On("SetClientDPoPBoundAccessTokens", mock.Anything, (*sql.Tx)(nil), targetClientId, true).
		Return(errors.New("the write failed")).Once()

	rr := serveClientDPoP(t, database, auditLogger,
		&record.Client{Id: targetClientId, ClientIdentifier: "dpop-client"}, `{"dpopBoundAccessTokens":true}`, nil)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}
