package apihandlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 4 of #425 for the account logout request, which had no unit coverage. Two defects: the
// redirect-URI branch logged the function's err, nil there, instead of the failure it had just
// caught (#414 item 2), and the client and session lookups answered a database failure as the
// caller's fault, 400 and 401 (decision 6). Each lookup now answers its failure 500 and keeps its
// 400 or 401 for a missing row.

const (
	logoutPostLogoutUri = "https://app.example.com/after-logout"
	logoutClientIdent   = "the-app"
	logoutSid           = "the-sid"
)

var errLogoutLookupFailed = errs.New("the lookup query failed")

func logoutRequest(t *testing.T, clientIdentifier string) *http.Request {
	t.Helper()
	body, err := json.Marshal(api.AccountLogoutRequest{
		PostLogoutRedirectUri: logoutPostLogoutUri,
		ClientIdentifier:      clientIdentifier,
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/account/logout-request", bytes.NewReader(body))
	req = setTokenContextWithClaims(req, map[string]interface{}{"sub": "the-user", "sid": logoutSid})
	return req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{Issuer: "https://auth.example.com"}))
}

// requireErrorOnTheRecord asserts one 500 whose record carries the failure the handler caught.
func requireErrorOnTheRecord(t *testing.T, rr *httptest.ResponseRecorder, capture *logtest.SlogCapture, cause error) {
	t.Helper()
	require.Equal(t, http.StatusInternalServerError, rr.Code)
	records := capture.Records()
	require.Len(t, records, 1)
	assert.Contains(t, fmt.Sprint(records[0].Attrs["error"]), cause.Error())
}

// requireRefused asserts a refusal the caller owns, which logs nothing.
func requireRefused(t *testing.T, rr *httptest.ResponseRecorder, capture *logtest.SlogCapture, status int, code string) {
	t.Helper()
	require.Equal(t, status, rr.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, code, body["error_code"])
	assert.Empty(t, capture.Records())
}

// assertNothingAfterTheClient asserts the handler stopped before the session and the signing key.
func assertNothingAfterTheClient(t *testing.T, database *datamocks.Database) {
	t.Helper()
	database.AssertNotCalled(t, "GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "GetCurrentSigningKey", mock.Anything, mock.Anything)
}

// logout/nil-err: resolving the client by its sign-out redirect URI, the one lookup fails. The
// record carries the failure, so the 500 names its cause (#414 item 2).
func TestHandleAccountLogoutRequestPost_ASignOutLookupFailureIsOnTheRecord(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetClientsByPostLogoutRedirectURI", mock.Anything, mock.Anything, logoutPostLogoutUri).
		Return(nil, errLogoutLookupFailed).Once()

	capture := logtest.CaptureSlog(t)
	rr := httptest.NewRecorder()
	HandleAccountLogoutRequestPost(database, testDataCipher, testBaseURL).ServeHTTP(rr, logoutRequest(t, ""))

	requireErrorOnTheRecord(t, rr, capture, errLogoutLookupFailed)
	assertNothingAfterTheClient(t, database)
}

// requireRefusedSaying asserts a 400 the caller owns, with the English description a caller reads.
func requireRefusedSaying(t *testing.T, rr *httptest.ResponseRecorder, capture *logtest.SlogCapture, description string) {
	t.Helper()
	requireRefused(t, rr, capture, http.StatusBadRequest, "VALIDATION_ERROR")
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, description, body["error_description"])
}

// #147 decision 10, closing #148: with no clientIdentifier, one query finds the clients whose
// sign-out redirect URIs hold the URI, and exactly one of them is the client. None or several asks
// the caller for clientIdentifier, as before. The redirect URIs are never read: a mock that is not
// told about ClientLoadRedirectURIs or GetAllClients fails the case that calls either.
func TestHandleAccountLogoutRequestPost_ResolvesTheClientFromItsSignOutList(t *testing.T) {
	const unresolved = "Unable to resolve client from postLogoutRedirectUri; supply clientIdentifier."

	t.Run("no client holds the URI", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetClientsByPostLogoutRedirectURI", mock.Anything, mock.Anything, logoutPostLogoutUri).
			Return([]record.Client{}, nil).Once()

		capture := logtest.CaptureSlog(t)
		rr := httptest.NewRecorder()
		HandleAccountLogoutRequestPost(database, testDataCipher, testBaseURL).ServeHTTP(rr, logoutRequest(t, ""))

		requireRefusedSaying(t, rr, capture, unresolved)
		assertNothingAfterTheClient(t, database)
	})

	t.Run("two clients hold the URI", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetClientsByPostLogoutRedirectURI", mock.Anything, mock.Anything, logoutPostLogoutUri).
			Return([]record.Client{{Id: 7, ClientIdentifier: logoutClientIdent}, {Id: 8, ClientIdentifier: "another-app"}}, nil).Once()

		capture := logtest.CaptureSlog(t)
		rr := httptest.NewRecorder()
		HandleAccountLogoutRequestPost(database, testDataCipher, testBaseURL).ServeHTTP(rr, logoutRequest(t, ""))

		requireRefusedSaying(t, rr, capture, unresolved)
		assertNothingAfterTheClient(t, database)
	})

	// The one client goes on to the session check, which a sid naming no session answers 401: the
	// resolution passed, and the session row is what the request stopped at.
	t.Run("one client holds the URI", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetClientsByPostLogoutRedirectURI", mock.Anything, mock.Anything, logoutPostLogoutUri).
			Return([]record.Client{{Id: 7, ClientIdentifier: logoutClientIdent}}, nil).Once()
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, logoutSid).
			Return(nil, nil).Once()

		capture := logtest.CaptureSlog(t)
		rr := httptest.NewRecorder()
		HandleAccountLogoutRequestPost(database, testDataCipher, testBaseURL).ServeHTTP(rr, logoutRequest(t, ""))

		requireRefused(t, rr, capture, http.StatusUnauthorized, "INVALID_SESSION")
	})
}

// #147 decision 1: a named client's sign-out redirect URIs are the only list its URI is checked
// against. One of its redirect URIs that isn't on that list answers the 400 a stranger's URI gets,
// and the lookup across clients isn't made, since the caller named one.
func TestHandleAccountLogoutRequestPost_ChecksTheNamedClientsSignOutList(t *testing.T) {
	t.Run("the URI is one of the client's sign-out redirect URIs", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		stubResolvedClient(database)
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, logoutSid).
			Return(nil, nil).Once()

		capture := logtest.CaptureSlog(t)
		rr := httptest.NewRecorder()
		HandleAccountLogoutRequestPost(database, testDataCipher, testBaseURL).ServeHTTP(rr, logoutRequest(t, logoutClientIdent))

		requireRefused(t, rr, capture, http.StatusUnauthorized, "INVALID_SESSION")
		database.AssertNotCalled(t, "GetClientsByPostLogoutRedirectURI", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("the URI is one of the client's redirect URIs only", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, logoutClientIdent).
			Return(&record.Client{
				Id: 7, ClientIdentifier: logoutClientIdent,
				RedirectURIs: []record.RedirectURI{{URI: logoutPostLogoutUri}},
			}, nil).Once()
		database.On("ClientLoadPostLogoutRedirectURIs", mock.Anything, mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) {
				args.Get(2).(*record.Client).PostLogoutRedirectURIs = []record.PostLogoutRedirectURI{{URI: "https://app.example.com/bye"}}
			}).Return(nil).Once()

		capture := logtest.CaptureSlog(t)
		rr := httptest.NewRecorder()
		HandleAccountLogoutRequestPost(database, testDataCipher, testBaseURL).ServeHTTP(rr, logoutRequest(t, logoutClientIdent))

		requireRefusedSaying(t, rr, capture, "postLogoutRedirectUri is not registered for the client")
		assertNothingAfterTheClient(t, database)
	})

	t.Run("the client's sign-out redirect URIs fail to load", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, logoutClientIdent).
			Return(&record.Client{Id: 7, ClientIdentifier: logoutClientIdent}, nil).Once()
		database.On("ClientLoadPostLogoutRedirectURIs", mock.Anything, mock.Anything, mock.Anything).
			Return(errLogoutLookupFailed).Once()

		capture := logtest.CaptureSlog(t)
		rr := httptest.NewRecorder()
		HandleAccountLogoutRequestPost(database, testDataCipher, testBaseURL).ServeHTTP(rr, logoutRequest(t, logoutClientIdent))

		requireErrorOnTheRecord(t, rr, capture, errLogoutLookupFailed)
		assertNothingAfterTheClient(t, database)
	})
}

// logout/client-400, failure arm: a database error is not a bad client identifier.
func TestHandleAccountLogoutRequestPost_AClientLookupFailureAnswers500(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, logoutClientIdent).
		Return(nil, errLogoutLookupFailed).Once()

	capture := logtest.CaptureSlog(t)
	rr := httptest.NewRecorder()
	HandleAccountLogoutRequestPost(database, testDataCipher, testBaseURL).ServeHTTP(rr, logoutRequest(t, logoutClientIdent))

	requireErrorOnTheRecord(t, rr, capture, errLogoutLookupFailed)
	assert.Equal(t, logoutClientIdent, capture.Records()[0].Attrs["client_identifier"])
	assertNothingAfterTheClient(t, database)
}

// logout/client-400, missing arm: an identifier naming no client stays the caller's 400.
func TestHandleAccountLogoutRequestPost_AnUnknownClientIsStill400(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, logoutClientIdent).
		Return(nil, nil).Once()

	capture := logtest.CaptureSlog(t)
	rr := httptest.NewRecorder()
	HandleAccountLogoutRequestPost(database, testDataCipher, testBaseURL).ServeHTTP(rr, logoutRequest(t, logoutClientIdent))

	requireRefused(t, rr, capture, http.StatusBadRequest, "VALIDATION_ERROR")
	assertNothingAfterTheClient(t, database)
}

// The loopback exception holds here as at /auth/logout: plain http to 127.0.0.1, [::1] or
// localhost passes the http rule and reaches the client lookup, whose missing row is what answers
// this request (#590 decision 2).
func TestHandleAccountLogoutRequestPost_APlainHTTPLoopbackTargetReachesTheClient(t *testing.T) {
	for _, target := range []string{
		"http://127.0.0.1:8080/after-logout",
		"http://[::1]/after-logout",
		"http://LOCALHOST/after-logout",
	} {
		t.Run(target, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, logoutClientIdent).
				Return(nil, nil).Once()

			body, err := json.Marshal(api.AccountLogoutRequest{PostLogoutRedirectUri: target, ClientIdentifier: logoutClientIdent})
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/account/logout-request", bytes.NewReader(body))
			req = setTokenContextWithClaims(req, map[string]interface{}{"sub": "the-user", "sid": logoutSid})
			req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{Issuer: "https://auth.example.com"}))

			rr := httptest.NewRecorder()
			HandleAccountLogoutRequestPost(database, testDataCipher, testBaseURL).ServeHTTP(rr, req)

			require.Equal(t, http.StatusBadRequest, rr.Code)
			var out api.ErrorResponse
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
			assert.Equal(t, "Invalid client identifier", out.ErrorDescription)
			database.AssertExpectations(t)
		})
	}
}

// stubResolvedClient answers the client lookup and its sign-out redirect URIs, so the handler
// reaches the session.
func stubResolvedClient(database *datamocks.Database) {
	database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, logoutClientIdent).
		Return(&record.Client{Id: 7, ClientIdentifier: logoutClientIdent}, nil).Once()
	database.On("ClientLoadPostLogoutRedirectURIs", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			args.Get(2).(*record.Client).PostLogoutRedirectURIs = []record.PostLogoutRedirectURI{{URI: logoutPostLogoutUri}}
		}).Return(nil).Once()
}

// logout/session-401, failure arm: 401 would send the caller to re-authenticate over a fault of
// the server's.
func TestHandleAccountLogoutRequestPost_ASessionLookupFailureAnswers500(t *testing.T) {
	database := datamocks.NewDatabase(t)
	stubResolvedClient(database)
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, logoutSid).
		Return(nil, errLogoutLookupFailed).Once()

	capture := logtest.CaptureSlog(t)
	rr := httptest.NewRecorder()
	HandleAccountLogoutRequestPost(database, testDataCipher, testBaseURL).ServeHTTP(rr, logoutRequest(t, logoutClientIdent))

	requireErrorOnTheRecord(t, rr, capture, errLogoutLookupFailed)
	database.AssertNotCalled(t, "UserSessionLoadClients", mock.Anything, mock.Anything, mock.Anything)
}

// logout/session-401, missing arm: a sid naming no live session stays 401.
func TestHandleAccountLogoutRequestPost_AMissingSessionIsStill401(t *testing.T) {
	database := datamocks.NewDatabase(t)
	stubResolvedClient(database)
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, logoutSid).
		Return(nil, nil).Once()

	capture := logtest.CaptureSlog(t)
	rr := httptest.NewRecorder()
	HandleAccountLogoutRequestPost(database, testDataCipher, testBaseURL).ServeHTTP(rr, logoutRequest(t, logoutClientIdent))

	requireRefused(t, rr, capture, http.StatusUnauthorized, "INVALID_SESSION")
	database.AssertNotCalled(t, "UserSessionLoadClients", mock.Anything, mock.Anything, mock.Anything)
}
