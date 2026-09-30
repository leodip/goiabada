package handlers

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_handlers "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/core/logging/logtest"
)

// Decision 2 measured end to end, on a real handler rather than on a middleware.
//
// Every other check in this change reads a call site: the lint refuses a plain slog call inside a
// function holding a request, and the handler's own tests assert that a record logged with a
// context carrying chi's id gains the attribute. Neither one proves the two halves meet in the
// product, because the middleware that puts the id on the context and the handler that reads it
// off it are mounted in different files and neither test runs both.
//
// So this drives an ordinary auth handler through chi's RequestID, exactly as initMiddleware
// mounts it, and asserts the record it writes carries an id nothing in this test named: not the
// attribute, not the key, not the value. Remove the wrapper from either server and every request
// record silently loses its correlation while every other test here stays green (#320).
func TestSlogConvention_AHandlerRecordCarriesTheRequestIdWithoutNamingIt(t *testing.T) {
	logs := logtest.CaptureSlog(t)

	pageRenderer := mocks_handlers.NewPageRenderer(t)
	ceremonyStore := mocks_handlers.NewCeremonyStore(t)
	database := mocks_data.NewDatabase(t)

	// The missing auth context is the shortest path from a request to a record: no database,
	// no template, one Warn and a redirect. No InternalServerError expectation is set, so the
	// mock fails this test if the handler takes the other branch.
	ceremonyStore.On("GetAuthContext", mock.Anything).Return(nil, ceremony.ErrNoAuthContext)

	req := httptest.NewRequest(http.MethodGet, "/auth/level2?ceremony="+testCeremonyId, nil)
	// The id the middleware will adopt. chi's RequestID takes X-Request-Id from the caller
	// verbatim, which is also why the handler clips it (#159).
	req.Header.Set("X-Request-Id", "req-level2-e2e")
	rr := httptest.NewRecorder()

	auditLogger := mocks_handlers.NewAuditLogger(t)
	chimiddleware.RequestID(HandleAuthLevel2Get(pageRenderer, ceremonyStore, database, auditLogger, testBaseURL, testAdminConsoleBaseURL)).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)

	records := logs.Records()
	require.Len(t, records, 1, "one record, which is the one under test")
	assert.Equal(t, slog.LevelWarn, records[0].Level,
		"a ceremony resumed without its context is a request refused and handled")
	assert.Equal(t, "auth context is missing, redirecting", records[0].Message,
		"one literal message, shared by all eleven copies of this branch")
	assert.Equal(t, "req-level2-e2e", records[0].Attrs["request_id"],
		"injected by the handler from chi's request id, with nothing in this file naming it")

	ceremonyStore.AssertExpectations(t)
}
