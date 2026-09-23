package apihandlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/constants"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/testutil"
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
	return req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings,
		&models.Settings{Issuer: "https://auth.example.com"}))
}

// requireErrorOnTheRecord asserts one 500 whose record carries the failure the handler caught.
func requireErrorOnTheRecord(t *testing.T, rr *httptest.ResponseRecorder, capture *testutil.SlogCapture, cause error) {
	t.Helper()
	require.Equal(t, http.StatusInternalServerError, rr.Code)
	records := capture.Records()
	require.Len(t, records, 1)
	assert.Contains(t, fmt.Sprint(records[0].Attrs["error"]), cause.Error())
}

// requireRefused asserts a refusal the caller owns, which logs nothing.
func requireRefused(t *testing.T, rr *httptest.ResponseRecorder, capture *testutil.SlogCapture, status int, code string) {
	t.Helper()
	require.Equal(t, status, rr.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, code, body["error_code"])
	assert.Empty(t, capture.Records())
}

// assertNothingAfterTheClient asserts the handler stopped before the session and the signing key.
func assertNothingAfterTheClient(t *testing.T, database *mocks_data.Database) {
	t.Helper()
	database.AssertNotCalled(t, "GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "GetCurrentSigningKey", mock.Anything, mock.Anything)
}

// logout/nil-err: resolving the client by its redirect URI, one client's URIs fail to load. The
// record used to carry a nil error, so the 500 named no cause at all.
func TestHandleAPIAccountLogoutRequestPost_ARedirectURILoadFailureIsOnTheRecord(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	database.On("GetAllClients", mock.Anything, mock.Anything).
		Return([]models.Client{{Id: 7, ClientIdentifier: logoutClientIdent}}, nil).Once()
	database.On("ClientLoadRedirectURIs", mock.Anything, mock.Anything, mock.Anything).
		Return(errLogoutLookupFailed).Once()

	capture := testutil.CaptureSlog(t)
	rr := httptest.NewRecorder()
	HandleAPIAccountLogoutRequestPost(database).ServeHTTP(rr, logoutRequest(t, ""))

	requireErrorOnTheRecord(t, rr, capture, errLogoutLookupFailed)
	assert.Equal(t, int64(7), capture.Records()[0].Attrs["client_id"])
	assertNothingAfterTheClient(t, database)
}

// logout/client-400, failure arm: a database error is not a bad client identifier.
func TestHandleAPIAccountLogoutRequestPost_AClientLookupFailureAnswers500(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, logoutClientIdent).
		Return(nil, errLogoutLookupFailed).Once()

	capture := testutil.CaptureSlog(t)
	rr := httptest.NewRecorder()
	HandleAPIAccountLogoutRequestPost(database).ServeHTTP(rr, logoutRequest(t, logoutClientIdent))

	requireErrorOnTheRecord(t, rr, capture, errLogoutLookupFailed)
	assert.Equal(t, logoutClientIdent, capture.Records()[0].Attrs["client_identifier"])
	assertNothingAfterTheClient(t, database)
}

// logout/client-400, missing arm: an identifier naming no client stays the caller's 400.
func TestHandleAPIAccountLogoutRequestPost_AnUnknownClientIsStill400(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, logoutClientIdent).
		Return(nil, nil).Once()

	capture := testutil.CaptureSlog(t)
	rr := httptest.NewRecorder()
	HandleAPIAccountLogoutRequestPost(database).ServeHTTP(rr, logoutRequest(t, logoutClientIdent))

	requireRefused(t, rr, capture, http.StatusBadRequest, "VALIDATION_ERROR")
	assertNothingAfterTheClient(t, database)
}

// stubResolvedClient answers the client lookup and its redirect URIs, so the handler reaches the
// session.
func stubResolvedClient(database *mocks_data.Database) {
	database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, logoutClientIdent).
		Return(&models.Client{Id: 7, ClientIdentifier: logoutClientIdent}, nil).Once()
	database.On("ClientLoadRedirectURIs", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			args.Get(2).(*models.Client).RedirectURIs = []models.RedirectURI{{URI: logoutPostLogoutUri}}
		}).Return(nil).Once()
}

// logout/session-401, failure arm: 401 would send the caller to re-authenticate over a fault of
// the server's.
func TestHandleAPIAccountLogoutRequestPost_ASessionLookupFailureAnswers500(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	stubResolvedClient(database)
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, logoutSid).
		Return(nil, errLogoutLookupFailed).Once()

	capture := testutil.CaptureSlog(t)
	rr := httptest.NewRecorder()
	HandleAPIAccountLogoutRequestPost(database).ServeHTTP(rr, logoutRequest(t, logoutClientIdent))

	requireErrorOnTheRecord(t, rr, capture, errLogoutLookupFailed)
	database.AssertNotCalled(t, "UserSessionLoadClients", mock.Anything, mock.Anything, mock.Anything)
}

// logout/session-401, missing arm: a sid naming no live session stays 401.
func TestHandleAPIAccountLogoutRequestPost_AMissingSessionIsStill401(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	stubResolvedClient(database)
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, logoutSid).
		Return(nil, nil).Once()

	capture := testutil.CaptureSlog(t)
	rr := httptest.NewRecorder()
	HandleAPIAccountLogoutRequestPost(database).ServeHTTP(rr, logoutRequest(t, logoutClientIdent))

	requireRefused(t, rr, capture, http.StatusUnauthorized, "INVALID_SESSION")
	database.AssertNotCalled(t, "UserSessionLoadClients", mock.Anything, mock.Anything, mock.Anything)
}
