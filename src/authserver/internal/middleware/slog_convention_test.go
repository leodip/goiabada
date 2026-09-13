package middleware

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// An unreadable settings row is a server fault: every page's layout reads those settings, so the
// deployment is answering 500 to everything until somebody acts. Error, and pinned.
func TestSlogConvention_SettingsReadFailureIsError(t *testing.T) {
	logged := testutil.CaptureSlog(t)

	mockDB := mocks_data.NewDatabase(t)
	mockDB.On("GetSettingsById", mock.Anything, int64(1)).Return(nil, errors.New("database error"))

	rr := httptest.NewRecorder()
	chimiddleware.RequestID(MiddlewareSettings(mockDB)(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) {
			t.Error("the handler must not be reached when the settings cannot be read")
		}))).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))

	require.Equal(t, http.StatusInternalServerError, rr.Code)

	record := requireOneRecord(t, logged)
	assert.Equal(t, slog.LevelError, record.Level)
	assert.Equal(t, "unable to load the settings", record.Message)
	err, isError := record.Attrs["error"].(error)
	require.True(t, isError, "the error attribute must be an error value, not a string")
	assert.Contains(t, err.Error(), "database error")
	requestId, isString := record.Attrs["request_id"].(string)
	require.True(t, isString, "the record must carry the request id injected from its context")
	require.NotEmpty(t, requestId)

	// The id on the record is the one the reader is shown, which is the whole point of
	// correlating them: an operator handed this number by a user greps the log for it.
	assert.Contains(t, rr.Body.String(), requestId)
	assert.Equal(t, 1, strings.Count(logged.Text(), "request_id="),
		"request_id comes from the handler alone, never also from the call site")
}

// Fail-closed, and loud: an unreadable web origins list is not an empty one, and the middleware
// answers false rather than letting script on any origin read a token response. Somebody has to
// act, so Error.
func TestSlogConvention_CorsConfigurationFailureIsError(t *testing.T) {
	logged := testutil.CaptureSlog(t)

	mockDB := mocks_data.NewDatabase(t)
	mockDB.On("WebOriginExists", mock.Anything, "https://app.example.com").
		Return(false, errors.New("the database is unreachable"))

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Origin", "https://app.example.com")

	rr := httptest.NewRecorder()
	reached := false
	// This is the production order: CORS evaluates the origin before the inner RequestID
	// middleware can put an id on the context. Reordering the two changes the record (#335).
	MiddlewareCors(mockDB)(chimiddleware.RequestID(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		}))).ServeHTTP(rr, req)

	// The request still runs; what is withheld is the header that would let script read it.
	assert.True(t, reached)
	assert.Empty(t, rr.Header().Get("Access-Control-Allow-Origin"),
		"an unreadable origin list must not approve the origin")

	record := requireOneRecord(t, logged)
	assert.Equal(t, slog.LevelError, record.Level)
	assert.Equal(t, "unable to load the cors configuration", record.Message)
	err, isError := record.Attrs["error"].(error)
	require.True(t, isError, "the error attribute must be an error value, not a string")
	assert.Contains(t, err.Error(), "the database is unreachable")
	assert.NotContains(t, record.Attrs, "request_id",
		"CORS runs before RequestID in the production chain")
}

func requireOneRecord(t *testing.T, logged *testutil.SlogCapture) testutil.CapturedRecord {
	t.Helper()
	records := logged.Records()
	require.Len(t, records, 1)
	return records[0]
}
