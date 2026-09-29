package middleware

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlerhelpers"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/sessionstore"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// This file is ServerFaults' seam: every fault the settings and session middleware can meet before a
// handler runs, and a panic, answered in each of the three formats, with the real JSON writer behind
// the protocol format so its body is the bytes on the wire. Which route is registered on which
// branch is the server package's to show (#435).

const faultRequestId = "req-fault-1"

// faultFormat is one branch's answering format and what it answers any of these faults with.
type faultFormat struct {
	name   string
	faults func() ServerFaults
	// body is the exact JSON the format answers, or "" for the page format, which answers the failing
	// middleware's own text/plain sentence.
	body string
}

func faultFormats() []faultFormat {
	return []faultFormat{
		{name: "page", faults: PageFaults},
		{name: "protocol", faults: func() ServerFaults { return ProtocolFaults(handlerhelpers.NewHttpHelper(nil)) },
			body: `{"error":"server_error","error_description":"An unexpected server error has occurred. For additional information, refer to the server logs. Request Id: ` + faultRequestId + `"}`},
		{name: "api", faults: APIFaults,
			body: `{"error_code":"INTERNAL_SERVER_ERROR","error_description":"An unexpected server error has occurred. For additional information, refer to the server logs. Request Id: ` + faultRequestId + `"}`},
	}
}

// faultRequest is a request carrying the request id chi's RequestID would have put on it.
func faultRequest() *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
	return req.WithContext(context.WithValue(req.Context(), chimiddleware.RequestIDKey, faultRequestId))
}

// sessionWithIdentifier is a session whose cookie names sid, which is what sends the session
// middleware to the database.
func sessionWithIdentifier(store sessionstore.Store, sid string) *sessionstore.Session {
	session := sessionstore.NewSession(store, sessionkeys.AuthServerSessionName)
	session.Values[sessionkeys.SessionKeySessionIdentifier] = sid
	return session
}

// TestServerFaults_EachFaultInEachFormat drives the four places the settings and session middleware
// stop a request, once per format. The page format keeps the text/plain sentence and log message
// each middleware has always written; the two JSON formats answer their surface's 500 and write the
// one record every 500 owes, whose error carries what failed and why.
func TestServerFaults_EachFaultInEachFormat(t *testing.T) {
	sites := []struct {
		name string
		// middleware builds the middleware under test, failing at this site.
		middleware   func(t *testing.T, faults ServerFaults) func(http.Handler) http.Handler
		pageSentence string
		pageMessage  string
		cause        string
	}{
		{
			name: "the settings row cannot be read",
			middleware: func(t *testing.T, faults ServerFaults) func(http.Handler) http.Handler {
				db := mocks_data.NewDatabase(t)
				db.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).Return(nil, errors.New("the database is down"))
				return MiddlewareSettings(db, faults)
			},
			pageSentence: "fatal failure in GetSettings() middleware. For additional information, refer to the server logs. Request Id: " + faultRequestId,
			pageMessage:  "unable to load the settings",
			cause:        "the database is down",
		},
		{
			name: "the session store cannot be read",
			middleware: func(t *testing.T, faults ServerFaults) func(http.Handler) http.Handler {
				store := mocks_sessionstore.NewStore(t)
				store.On("Get", mock.Anything, sessionkeys.AuthServerSessionName).Return(nil, errors.New("the session backend is down"))
				return MiddlewareSessionIdentifier(store, mocks_data.NewDatabase(t), faults)
			},
			pageSentence: "fatal failure in session middleware. For additional information, refer to the server logs. Request Id: " + faultRequestId,
			pageMessage:  "unable to get the session store",
			cause:        "the session backend is down",
		},
		{
			name: "the session row the cookie names cannot be read",
			middleware: func(t *testing.T, faults ServerFaults) func(http.Handler) http.Handler {
				store := mocks_sessionstore.NewStore(t)
				store.On("Get", mock.Anything, sessionkeys.AuthServerSessionName).Return(sessionWithIdentifier(store, "sid-1"), nil)
				db := mocks_data.NewDatabase(t)
				db.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "sid-1").Return(nil, errors.New("the database is down"))
				return MiddlewareSessionIdentifier(store, db, faults)
			},
			pageSentence: "fatal failure in session middleware. For additional information, refer to the server logs. Request Id: " + faultRequestId,
			pageMessage:  "unable to get the user session",
			cause:        "the database is down",
		},
		{
			name: "the session cannot be saved after its row was found gone",
			middleware: func(t *testing.T, faults ServerFaults) func(http.Handler) http.Handler {
				store := mocks_sessionstore.NewStore(t)
				store.On("Get", mock.Anything, sessionkeys.AuthServerSessionName).Return(sessionWithIdentifier(store, "sid-1"), nil)
				store.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("the session backend is down"))
				db := mocks_data.NewDatabase(t)
				db.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "sid-1").Return(nil, nil)
				return MiddlewareSessionIdentifier(store, db, faults)
			},
			pageSentence: "fatal failure in session middleware. For additional information, refer to the server logs. Request Id: " + faultRequestId,
			pageMessage:  "unable to save the session",
			cause:        "the session backend is down",
		},
	}

	for _, site := range sites {
		for _, format := range faultFormats() {
			t.Run(site.name+"/"+format.name, func(t *testing.T) {
				logs := logtest.CaptureSlog(t)
				rr := httptest.NewRecorder()
				site.middleware(t, format.faults())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					t.Error("a request stopped by a fault must not reach the handler")
				})).ServeHTTP(rr, faultRequest())

				require.Equal(t, http.StatusInternalServerError, rr.Code, rr.Body.String())
				// Error records only: the save site first records, at Warn, the row it found gone.
				var records []logtest.CapturedRecord
				for _, record := range logs.Records() {
					if record.Level == slog.LevelError {
						records = append(records, record)
					}
				}
				require.Len(t, records, 1, "one Error record per 500")
				assert.Contains(t, logs.Text(), site.cause, "the record carries the cause")

				if format.body == "" {
					assert.Equal(t, "text/plain; charset=utf-8", rr.Header().Get("Content-Type"))
					assert.Equal(t, site.pageSentence+"\n", rr.Body.String())
					assert.Equal(t, site.pageMessage, records[0].Message)
					return
				}
				assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
				assert.JSONEq(t, format.body, rr.Body.String())
				assert.Equal(t, "internal server error", records[0].Message)
				assert.Contains(t, logs.Text(), site.pageMessage, "the record says what failed")
			})
		}
	}
}

// TestServerFaults_RecovererAnswersAPanicInTheBranchFormat: a panic on a JSON branch is answered as
// that branch answers any other fault, where the root Recoverer answers an empty 500 no JSON client
// can parse. On the page branch the Recoverer is the next handler itself, so the panic reaches the
// root one as before.
func TestServerFaults_RecovererAnswersAPanicInTheBranchFormat(t *testing.T) {
	panicking := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("a handler panicked")
	})

	for _, format := range faultFormats() {
		t.Run(format.name, func(t *testing.T) {
			logs := logtest.CaptureSlog(t)
			recoverer := format.faults().Recoverer(panicking)

			if format.body == "" {
				assert.PanicsWithValue(t, "a handler panicked", func() {
					recoverer.ServeHTTP(httptest.NewRecorder(), faultRequest())
				}, "the page branch leaves a panic to the root Recoverer")
				assert.Empty(t, logs.Records())
				return
			}

			rr := httptest.NewRecorder()
			require.NotPanics(t, func() { recoverer.ServeHTTP(rr, faultRequest()) })
			require.Equal(t, http.StatusInternalServerError, rr.Code, rr.Body.String())
			assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
			assert.JSONEq(t, format.body, rr.Body.String())

			records := logs.Records()
			require.Len(t, records, 1, "one record per 500")
			assert.Equal(t, "internal server error", records[0].Message)
			assert.Contains(t, logs.Text(), "recovered from a panic: a handler panicked")
		})
	}
}

// http.ErrAbortHandler is how a handler aborts a response on purpose, and net/http recognizes it
// only as the panic value, so it must leave every branch's Recoverer as it arrived.
func TestServerFaults_RecovererRepanicsErrAbortHandler(t *testing.T) {
	aborting := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	})
	for _, format := range faultFormats() {
		t.Run(format.name, func(t *testing.T) {
			logs := logtest.CaptureSlog(t)
			rr := httptest.NewRecorder()
			assert.PanicsWithError(t, http.ErrAbortHandler.Error(), func() {
				format.faults().Recoverer(aborting).ServeHTTP(rr, faultRequest())
			})
			assert.Empty(t, rr.Body.String(), "an aborted response is not answered")
			assert.Empty(t, logs.Records())
		})
	}
}

// Without a panic the Recoverer is invisible on every branch.
func TestServerFaults_RecovererPassesAnAnswerThrough(t *testing.T) {
	for _, format := range faultFormats() {
		t.Run(format.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			format.faults().Recoverer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusTeapot)
				_, _ = w.Write([]byte("answered"))
			})).ServeHTTP(rr, faultRequest())

			assert.Equal(t, http.StatusTeapot, rr.Code)
			assert.Equal(t, "answered", rr.Body.String())
		})
	}
}
