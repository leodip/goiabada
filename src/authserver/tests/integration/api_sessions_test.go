package integrationtests

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The browser session endpoint, from outside (#266).
//
// Everything here is judged on the endpoint's own answer. Two cases need a row the
// endpoint will not make, an expired one and one belonging to the auth server, so those
// are written directly as fixtures; nothing asserts on a row afterwards, because storage
// is the data tier's to cover and a test reaching into it would pass with this endpoint
// broken.

func sessionEndpointURL(operation string) string {
	return config.GetAuthServer().BaseURL + "/api/v1/sessions/" + operation
}

// newTestSessionId mints an identifier the way the store does, so the fixtures below hash
// the same shape of value the endpoint will be handed.
func newTestSessionId(t *testing.T) string {
	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	require.NoError(t, err)
	return hex.EncodeToString(buf)
}

func hashTestSessionId(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

// createBrowserSessionFixture writes a row the endpoint would not produce: one already
// expired, or one belonging to the other application.
func createBrowserSessionFixture(t *testing.T, owner, id string, expiresAt time.Time) {
	err := database.CreateBrowserSession(nil, &models.BrowserSession{
		Owner:         owner,
		SessionId:     id,
		SessionIdHash: hashTestSessionId(id),
		Data:          "fixture-ciphertext",
		LastAccessed:  time.Now().UTC(),
		ExpiresAt:     expiresAt,
	})
	require.NoError(t, err)
}

// postSessionEndpointNoToken sends a request carrying no Authorization header at all,
// which makeAPIRequest cannot do.
func postSessionEndpointNoToken(t *testing.T, operation string, body interface{}) *http.Response {
	jsonBody, err := json.Marshal(body)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", sessionEndpointURL(operation), bytes.NewReader(jsonBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	return resp
}

// TestAPISessions_NoTokenIsUnauthorized: the endpoint carries session ciphertext, so an
// anonymous caller gets nothing from any of the five operations.
func TestAPISessions_NoTokenIsUnauthorized(t *testing.T) {
	for _, operation := range []string{"load", "create", "update", "touch", "delete"} {
		resp := postSessionEndpointNoToken(t, operation, api.SessionLoadRequest{Id: newTestSessionId(t)})
		func() {
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "operation %s", operation)
		}()
	}
}

// TestAPISessions_WrongScopeIsForbidden: the permission is its own, so an admin API token
// that does not carry it is refused. This is what stops the admin console's secret, or any
// other client's, being a way into everyone's sessions by holding a manage-* scope.
func TestAPISessions_WrongScopeIsForbidden(t *testing.T) {
	accessToken, client := createClientWithGranularScope(t, constants.AdminReadPermissionIdentifier)
	defer func() {
		_ = database.DeleteClient(nil, client.Id)
	}()

	for _, operation := range []string{"load", "create", "update", "touch", "delete"} {
		resp := makeAPIRequest(t, "POST", sessionEndpointURL(operation), accessToken,
			api.SessionLoadRequest{Id: newTestSessionId(t)})
		func() {
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, http.StatusForbidden, resp.StatusCode, "operation %s", operation)
		}()
	}
}

// TestAPISessions_RoundTrip walks the whole lifecycle the admin console's store will walk:
// create, load, touch, update, load again, delete, and load once more to find it gone.
func TestAPISessions_RoundTrip(t *testing.T) {
	accessToken, client := createClientWithGranularScope(t, constants.BrowserSessionsPermissionIdentifier)
	defer func() {
		_ = database.DeleteClient(nil, client.Id)
	}()

	id := newTestSessionId(t)
	defer func() {
		_ = database.DeleteBrowserSession(nil, constants.AdminConsoleSessionName, hashTestSessionId(id))
	}()

	// Create. An unauthenticated session gets the flat pre-authentication lifetime, which
	// is far shorter than the deployment's idle timeout, so the two phases are told apart
	// by the deadline the endpoint chose rather than by reading anything.
	created := postSession(t, accessToken, "create", api.SessionWriteRequest{
		Id:   id,
		Data: "first-ciphertext",
	})
	var createdBody api.SessionWriteResponse
	decodeSessionBody(t, created, http.StatusOK, &createdBody)
	assert.WithinDuration(t, time.Now().UTC().Add(30*time.Minute), createdBody.ExpiresAt, time.Minute)

	// Load returns what was stored, with both timestamps.
	loaded := postSession(t, accessToken, "load", api.SessionLoadRequest{Id: id})
	var loadedBody api.SessionLoadResponse
	decodeSessionBody(t, loaded, http.StatusOK, &loadedBody)
	assert.Equal(t, "first-ciphertext", loadedBody.Data)
	assert.WithinDuration(t, time.Now().UTC(), loadedBody.LastAccessed, time.Minute)
	assert.WithinDuration(t, createdBody.ExpiresAt, loadedBody.ExpiresAt, time.Second)

	// Touch records the session was used and keeps it alive.
	touched := postSession(t, accessToken, "touch", api.SessionTouchRequest{Id: id})
	var touchedBody api.SessionWriteResponse
	decodeSessionBody(t, touched, http.StatusOK, &touchedBody)
	assert.True(t, touchedBody.ExpiresAt.After(time.Now().UTC()))

	// Update replaces the contents, and here the session reports itself authenticated.
	// That boolean is the whole reason the deadline is computed on this side: the admin
	// console cannot read the deployment's session settings, so it says what kind of
	// session it is holding and the auth server says how long that kind lives.
	updated := postSession(t, accessToken, "update", api.SessionWriteRequest{
		Id:            id,
		Data:          "second-ciphertext",
		Authenticated: true,
	})
	var updatedBody api.SessionWriteResponse
	decodeSessionBody(t, updated, http.StatusOK, &updatedBody)

	// Read the settings rather than assuming the defaults: other tests in this package
	// write them, and the claim is that the endpoint follows whatever they say.
	settings, err := database.GetSettingsById(nil, 1)
	require.NoError(t, err)
	expectedExpiry := time.Now().UTC().Add(time.Duration(settings.UserSessionIdleTimeoutInSeconds) * time.Second)
	if absolute := time.Now().UTC().Add(time.Duration(settings.UserSessionMaxLifetimeInSeconds) * time.Second); absolute.Before(expectedExpiry) {
		expectedExpiry = absolute
	}
	assert.WithinDuration(t, expectedExpiry, updatedBody.ExpiresAt, time.Minute)

	reloaded := postSession(t, accessToken, "load", api.SessionLoadRequest{Id: id})
	var reloadedBody api.SessionLoadResponse
	decodeSessionBody(t, reloaded, http.StatusOK, &reloadedBody)
	assert.Equal(t, "second-ciphertext", reloadedBody.Data)

	// Delete, then the session is gone rather than empty.
	deleted := postSession(t, accessToken, "delete", api.SessionLoadRequest{Id: id})
	defer func() { _ = deleted.Body.Close() }()
	assert.Equal(t, http.StatusNoContent, deleted.StatusCode)

	gone := postSession(t, accessToken, "load", api.SessionLoadRequest{Id: id})
	defer func() { _ = gone.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, gone.StatusCode)
}

// TestAPISessions_ExpiredSessionIsNotFound: an expired row is answered exactly as an
// absent one. The endpoint tests no date to get this; the read underneath matches only
// rows whose deadline is still ahead, so a session that ran out is already absent before
// the reaper has been anywhere near it.
func TestAPISessions_ExpiredSessionIsNotFound(t *testing.T) {
	accessToken, client := createClientWithGranularScope(t, constants.BrowserSessionsPermissionIdentifier)
	defer func() {
		_ = database.DeleteClient(nil, client.Id)
	}()

	id := newTestSessionId(t)
	createBrowserSessionFixture(t, constants.AdminConsoleSessionName, id, time.Now().UTC().Add(-time.Minute))
	defer func() {
		_ = database.DeleteBrowserSession(nil, constants.AdminConsoleSessionName, hashTestSessionId(id))
	}()

	for _, operation := range []string{"load", "update", "touch"} {
		resp := postSession(t, accessToken, operation, api.SessionWriteRequest{Id: id, Data: "x"})
		func() {
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, http.StatusNotFound, resp.StatusCode, "operation %s", operation)
		}()
	}
}

// TestAPISessions_AuthServerSessionIsNotFound is the isolation the whole one-table design
// rests on, observed from outside: an identifier naming a live auth server session is
// answered 404, because the owner is not something a request can name.
func TestAPISessions_AuthServerSessionIsNotFound(t *testing.T) {
	accessToken, client := createClientWithGranularScope(t, constants.BrowserSessionsPermissionIdentifier)
	defer func() {
		_ = database.DeleteClient(nil, client.Id)
	}()

	id := newTestSessionId(t)
	createBrowserSessionFixture(t, constants.AuthServerSessionName, id, time.Now().UTC().Add(time.Hour))
	defer func() {
		_ = database.DeleteBrowserSession(nil, constants.AuthServerSessionName, hashTestSessionId(id))
	}()

	// The row is live and the identifier is correct. Only the owner differs.
	for _, operation := range []string{"load", "update", "touch"} {
		resp := postSession(t, accessToken, operation, api.SessionWriteRequest{Id: id, Data: "x"})
		func() {
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, http.StatusNotFound, resp.StatusCode, "operation %s", operation)
		}()
	}

	// Delete answers 204 whether or not a row was there, so the isolation it needs is
	// that the auth server's row SURVIVES it. That is the one place the row itself is the
	// only available evidence.
	deleted := postSession(t, accessToken, "delete", api.SessionLoadRequest{Id: id})
	defer func() { _ = deleted.Body.Close() }()
	assert.Equal(t, http.StatusNoContent, deleted.StatusCode)

	survivor, err := database.GetBrowserSessionByOwnerAndSessionIdHash(nil,
		constants.AuthServerSessionName, hashTestSessionId(id), time.Now().UTC())
	assert.NoError(t, err)
	assert.NotNil(t, survivor, "deleting through the admin console's endpoint must not reach an auth server session")
}

// TestAPISessions_BadRequests: a body that is not JSON, and one with no identifier, are
// both refused before anything is looked up.
func TestAPISessions_BadRequests(t *testing.T) {
	accessToken, client := createClientWithGranularScope(t, constants.BrowserSessionsPermissionIdentifier)
	defer func() {
		_ = database.DeleteClient(nil, client.Id)
	}()

	req, err := http.NewRequest("POST", sessionEndpointURL("load"), bytes.NewReader([]byte("not json")))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	malformed, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	defer func() { _ = malformed.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, malformed.StatusCode)

	for _, operation := range []string{"load", "create", "update", "touch", "delete"} {
		resp := postSession(t, accessToken, operation, api.SessionWriteRequest{Id: "  "})
		func() {
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "operation %s", operation)
		}()
	}
}

func postSession(t *testing.T, accessToken, operation string, body interface{}) *http.Response {
	return makeAPIRequest(t, "POST", sessionEndpointURL(operation), accessToken, body)
}

func decodeSessionBody(t *testing.T, resp *http.Response, expectedStatus int, target interface{}) {
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, expectedStatus, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	require.NoError(t, json.NewDecoder(resp.Body).Decode(target))
}
