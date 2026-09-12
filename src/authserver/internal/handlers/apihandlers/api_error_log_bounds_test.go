package apihandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5/middleware"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The 500 records on this surface carry the caller's own filter values, and those values come off
// the query string, so they are as long and as arbitrary as the client cares to make them. Every
// one of them goes on the record through logging.FieldForLog, which escapes then clips, and this
// file is what holds them to it: a listing endpoint whose database fails is the one path where a
// request's query string reaches the log verbatim, and #159 bounded every other client-chosen
// scalar attribute precisely so that could not happen.
//
// Folded into #328 at the final review gate: the request-id filter this change added was bounded
// from the start, and the audit_event and query values beside it on the same records were not, so
// one record read half bounded and half not. Nothing here changes what an ordinary request logs.

// A value long enough to be clipped, whose first bytes carry a line break: raw on a record it ends
// the line and starts one the reader cannot tell from a record the server wrote.
const (
	forgedLine  = "user_login\nlevel=INFO msg=\"nothing happened\""
	padTo4096   = 4096
	requestIdOf = "req-error-log-bounds"
)

// oversized returns prefix padded out to 4096 bytes, and the exact string FieldForLog must turn it
// into: the escaped first 128 bytes, then the marker naming the limit and the true escaped length.
// Written out here rather than computed through FieldForLog, so the assertion fails if the bound is
// removed instead of following it.
func oversized(t *testing.T, prefix string) (raw, want string) {
	t.Helper()
	raw = prefix + strings.Repeat("z", padTo4096-len(prefix))
	require.Len(t, raw, padTo4096)

	escaped := strings.ReplaceAll(prefix, "\n", "%0A")
	escaped += strings.Repeat("z", padTo4096-len(prefix))
	// One escaped byte costs three, so the true count the marker quotes is the raw length plus two
	// for each byte that had to be escaped.
	total := padTo4096 + 2*strings.Count(prefix, "\n")
	want = escaped[:128] + "[truncated, 128 of " + strconv.Itoa(total) + " bytes]"
	return raw, want
}

func errorLogRequest(t *testing.T, target string, query url.Values) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, target+"?"+query.Encode(), nil)
	return r.WithContext(context.WithValue(r.Context(), middleware.RequestIDKey, requestIdOf))
}

// oneErrorRecord asserts that exactly one ERROR record was written and returns its attributes.
func oneErrorRecord(t *testing.T, capture *testutil.SlogCapture) map[string]any {
	t.Helper()
	records := capture.Records()
	require.Len(t, records, 1, "one 500 writes one record")
	assert.Equal(t, "internal server error", records[0].Message)
	return records[0].Attrs
}

// TestHandleAPIAuditLogsGet_ErrorRecordBoundsBothFilters covers the endpoint this change gave the
// request-id filter: when the query fails, both filter values reach the record clipped and escaped,
// and neither reaches it whole.
func TestHandleAPIAuditLogsGet_ErrorRecordBoundsBothFilters(t *testing.T) {
	rawEvent, wantEvent := oversized(t, forgedLine)
	rawRequestId, wantRequestId := oversized(t, "abc\ndef")

	database := mocks_data.NewDatabase(t)
	database.On("GetAuditLogsPaginated", mock.Anything, 1, 20, rawEvent, rawRequestId).
		Return([]models.AuditLog(nil), 0, errs.New("engine is down"))

	capture := testutil.CaptureSlog(t)
	rr := httptest.NewRecorder()

	HandleAPIAuditLogsGet(database).ServeHTTP(rr, errorLogRequest(t, "/api/v1/admin/audit-logs",
		url.Values{"auditEvent": {rawEvent}, "requestId": {rawRequestId}}))

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	attrs := oneErrorRecord(t, capture)

	assert.Equal(t, wantEvent, attrs["audit_event"],
		"the filter the caller sent, clipped at 128 bytes with its line break escaped")
	assert.Equal(t, wantRequestId, attrs["filter_request_id"],
		"filter_request_id is the caller's value; request_id is the handler's own")
	assert.Equal(t, requestIdOf, attrs["request_id"],
		"the handler's own id is injected from the context and is not the filter")

	// The two halves of the bound, stated as the reader of the log sees them.
	line := capture.Text()
	assert.NotContains(t, line, rawEvent, "the 4096-byte value never reaches the record whole")
	assert.NotContains(t, line, forgedLine, "nor does the line break it carried")
	database.AssertExpectations(t)
}

// TestHandleAPIUsersSearchGet_ErrorRecordBoundsTheQuery is the same property on the other endpoint
// that logs a client-chosen filter, and the reason the fix was four call sites rather than one.
func TestHandleAPIUsersSearchGet_ErrorRecordBoundsTheQuery(t *testing.T) {
	rawQuery, wantQuery := oversized(t, forgedLine)

	database := mocks_data.NewDatabase(t)
	database.On("SearchUsersPaginated", mock.Anything, rawQuery, 1, 10).
		Return([]models.User(nil), 0, errs.New("engine is down"))

	capture := testutil.CaptureSlog(t)
	rr := httptest.NewRecorder()

	HandleAPIUsersSearchGet(database).ServeHTTP(rr, errorLogRequest(t, "/api/v1/admin/users/search",
		url.Values{"query": {rawQuery}}))

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	attrs := oneErrorRecord(t, capture)

	assert.Equal(t, wantQuery, attrs["query"])
	assert.NotContains(t, capture.Text(), rawQuery,
		"the search term never reaches the record whole, however long the caller makes it")
	database.AssertExpectations(t)
}

// TestErrorRecordFiltersOfOrdinaryLengthAreUnchanged is the other half: the bound is invisible to
// every value an operator actually sends, so the record still shows the filter they used.
func TestErrorRecordFiltersOfOrdinaryLengthAreUnchanged(t *testing.T) {
	const event = "user_login"
	const filterId = "goiabada/abc123-7"

	database := mocks_data.NewDatabase(t)
	database.On("GetAuditLogsPaginated", mock.Anything, 1, 20, event, filterId).
		Return([]models.AuditLog(nil), 0, errs.New("engine is down"))

	capture := testutil.CaptureSlog(t)
	rr := httptest.NewRecorder()

	HandleAPIAuditLogsGet(database).ServeHTTP(rr, errorLogRequest(t, "/api/v1/admin/audit-logs",
		url.Values{"auditEvent": {event}, "requestId": {filterId}}))

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	attrs := oneErrorRecord(t, capture)

	assert.Equal(t, event, attrs["audit_event"], "nothing to escape and nothing to clip")
	assert.Equal(t, filterId, attrs["filter_request_id"])
	database.AssertExpectations(t)
}

// The group-annotation branch fails after the search has already succeeded, so its two records are
// the only ones on this handler a case reaches by getting further in rather than by failing sooner.
// Each binds the query at its own call, which is why the case above does not hold them: removing
// either bound leaves every test before this line green.

// searchThatSucceeds lets the search itself pass with one user, which is what carries a case past
// the first error record and into the annotation branch.
func searchThatSucceeds(database *mocks_data.Database, rawQuery string) {
	database.On("SearchUsersPaginated", mock.Anything, rawQuery, 1, 10).
		Return([]models.User{{Id: 42}}, 1, nil)
}

func TestHandleAPIUsersSearchGet_ErrorRecordBoundsTheQueryWhenTheGroupLookupFails(t *testing.T) {
	rawQuery, wantQuery := oversized(t, forgedLine)

	database := mocks_data.NewDatabase(t)
	searchThatSucceeds(database, rawQuery)
	database.On("GetGroupById", mock.Anything, int64(7)).
		Return(nil, errs.New("engine is down"))

	capture := testutil.CaptureSlog(t)
	rr := httptest.NewRecorder()

	HandleAPIUsersSearchGet(database).ServeHTTP(rr, errorLogRequest(t, "/api/v1/admin/users/search",
		url.Values{"query": {rawQuery}, "annotateGroupMembership": {"7"}}))

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	attrs := oneErrorRecord(t, capture)

	assert.Equal(t, wantQuery, attrs["query"])
	assert.Equal(t, int64(7), attrs["group_id"],
		"the group the caller named is the server's own parsed int64 and is bounded by that")
	assert.NotContains(t, capture.Text(), rawQuery,
		"the search term never reaches the record whole, on this branch either")
	database.AssertExpectations(t)
}

func TestHandleAPIUsersSearchGet_ErrorRecordBoundsTheQueryWhenLoadingGroupsFails(t *testing.T) {
	rawQuery, wantQuery := oversized(t, forgedLine)

	database := mocks_data.NewDatabase(t)
	searchThatSucceeds(database, rawQuery)
	database.On("GetGroupById", mock.Anything, int64(7)).Return(&models.Group{Id: 7}, nil)
	database.On("UsersLoadGroups", mock.Anything, mock.Anything).
		Return(errs.New("engine is down"))

	capture := testutil.CaptureSlog(t)
	rr := httptest.NewRecorder()

	HandleAPIUsersSearchGet(database).ServeHTTP(rr, errorLogRequest(t, "/api/v1/admin/users/search",
		url.Values{"query": {rawQuery}, "annotateGroupMembership": {"7"}}))

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	attrs := oneErrorRecord(t, capture)

	assert.Equal(t, wantQuery, attrs["query"])
	assert.Equal(t, int64(1), attrs["user_count"],
		"the one user the search returned; slog widens every integer, so the count reads int64")
	assert.NotContains(t, capture.Text(), rawQuery)
	database.AssertExpectations(t)
}
