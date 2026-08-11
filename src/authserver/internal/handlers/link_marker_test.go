package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/sessionstore"

	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
)

// The marker tests run against a real ChunkedCookieStore rather than the store mock.
// The marker's whole contract is that it survives a round trip through an encrypted
// client-side cookie and that a copy of that cookie outlives its own clearing, and a
// mock cannot show either.
func newMarkerTestStore() *sessionstore.ChunkedCookieStore {
	return sessionstore.NewChunkedCookieStore(
		[]byte("12345678901234567890123456789012"),
		[]byte("abcdefghijklmnopqrstuvwxyz123456"),
	)
}

// requestCarrying builds a request holding the cookies a previous response set, which
// is what a browser does on the next hop.
func requestCarrying(t *testing.T, rr *httptest.ResponseRecorder) *http.Request {
	t.Helper()
	req := httptest.NewRequest("GET", "/reset-password", nil)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}
	return req
}

// writeRawMarker puts an arbitrary value under the marker key, for the states
// SaveLinkMarker cannot produce: an already-expired marker and a corrupt one.
func writeRawMarker(t *testing.T, store sessions.Store, value interface{}) *http.Request {
	t.Helper()
	req := httptest.NewRequest("GET", "/reset-password", nil)
	rr := httptest.NewRecorder()

	sess, err := store.Get(req, constants.AuthServerSessionName)
	require.NoError(t, err)
	sess.Values[constants.SessionKeyLinkMarker] = value
	require.NoError(t, store.Save(req, rr, sess))

	return requestCarrying(t, rr)
}

func marshalMarker(t *testing.T, marker *LinkMarker) string {
	t.Helper()
	data, err := json.Marshal(marker)
	require.NoError(t, err)
	return string(data)
}

func TestSaveAndGetLinkMarker(t *testing.T) {
	store := newMarkerTestStore()

	req := httptest.NewRequest("GET", "/reset-password?code=abc123", nil)
	rr := httptest.NewRecorder()

	before := time.Now().UTC()
	err := SaveLinkMarker(store, rr, req, LinkMarkerFlowResetPassword, 42, "the-code-hash")
	require.NoError(t, err)
	after := time.Now().UTC()

	marker, rejection, err := GetLinkMarker(store, requestCarrying(t, rr), LinkMarkerFlowResetPassword)

	require.NoError(t, err)
	assert.Empty(t, rejection)
	require.NotNil(t, marker)
	assert.Equal(t, LinkMarkerFlowResetPassword, marker.Flow)
	assert.Equal(t, int64(42), marker.Id)
	// The code hash is what makes the marker single-use: the consuming handler
	// re-resolves it, so a marker naming a hash that is no longer outstanding buys
	// nothing.
	assert.Equal(t, "the-code-hash", marker.CodeHash)
	// A fresh window from validation, not the code's remaining lifetime.
	assert.False(t, marker.ExpiresAt.Before(before.Add(linkMarkerLifetime)))
	assert.False(t, marker.ExpiresAt.After(after.Add(linkMarkerLifetime)))
}

func TestGetLinkMarkerMissing(t *testing.T) {
	store := newMarkerTestStore()

	// A request that never followed a link: a bookmarked clean URL, or a session
	// that has since been replaced.
	req := httptest.NewRequest("GET", "/reset-password", nil)

	marker, rejection, err := GetLinkMarker(store, req, LinkMarkerFlowResetPassword)

	require.NoError(t, err)
	assert.Nil(t, marker)
	assert.Equal(t, LinkMarkerMissing, rejection)
}

func TestGetLinkMarkerWrongFlow(t *testing.T) {
	store := newMarkerTestStore()

	req := httptest.NewRequest("GET", "/account/activate?code=abc123", nil)
	rr := httptest.NewRecorder()
	require.NoError(t, SaveLinkMarker(store, rr, req, LinkMarkerFlowAccountActivate, 7, "the-code-hash"))

	// Both flows share one session key, so an activation marker is what a reset
	// request finds when the user was mid-activation.
	marker, rejection, err := GetLinkMarker(store, requestCarrying(t, rr), LinkMarkerFlowResetPassword)

	require.NoError(t, err)
	assert.Nil(t, marker)
	assert.Equal(t, LinkMarkerWrongFlow, rejection)
}

func TestGetLinkMarkerExpired(t *testing.T) {
	store := newMarkerTestStore()

	req := writeRawMarker(t, store, marshalMarker(t, &LinkMarker{
		Flow:      LinkMarkerFlowResetPassword,
		Id:        42,
		CodeHash:  "the-code-hash",
		ExpiresAt: time.Now().UTC().Add(-time.Second),
	}))

	marker, rejection, err := GetLinkMarker(store, req, LinkMarkerFlowResetPassword)

	require.NoError(t, err)
	assert.Nil(t, marker)
	assert.Equal(t, LinkMarkerExpired, rejection)
}

// An expired marker from the other flow reports the structural mismatch, not its
// age. Both refuse the request identically; this pins which reason is audited.
func TestGetLinkMarkerWrongFlowBeatsExpired(t *testing.T) {
	store := newMarkerTestStore()

	req := writeRawMarker(t, store, marshalMarker(t, &LinkMarker{
		Flow:      LinkMarkerFlowAccountActivate,
		Id:        7,
		CodeHash:  "the-code-hash",
		ExpiresAt: time.Now().UTC().Add(-time.Second),
	}))

	_, rejection, err := GetLinkMarker(store, req, LinkMarkerFlowResetPassword)

	require.NoError(t, err)
	assert.Equal(t, LinkMarkerWrongFlow, rejection)
}

// The boundary itself: a marker expiring exactly now is still live, matching
// isForgotPasswordCodeExpired's use of Before.
func TestLinkMarkerExpiryBoundary(t *testing.T) {
	now := time.Now().UTC()

	testCases := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{name: "a second of life left", expiresAt: now.Add(time.Second), want: false},
		{name: "expiring exactly now", expiresAt: now, want: false},
		{name: "a nanosecond past", expiresAt: now.Add(-time.Nanosecond), want: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			marker := &LinkMarker{ExpiresAt: tc.expiresAt}

			assert.Equal(t, tc.want, marker.expired(now))
		})
	}
}

func TestClearLinkMarker(t *testing.T) {
	store := newMarkerTestStore()

	req := httptest.NewRequest("GET", "/reset-password?code=abc123", nil)
	rr := httptest.NewRecorder()
	require.NoError(t, SaveLinkMarker(store, rr, req, LinkMarkerFlowResetPassword, 42, "the-code-hash"))

	clearReq := requestCarrying(t, rr)
	clearRr := httptest.NewRecorder()
	require.NoError(t, ClearLinkMarker(store, clearRr, clearReq))

	marker, rejection, err := GetLinkMarker(store, requestCarrying(t, clearRr), LinkMarkerFlowResetPassword)

	require.NoError(t, err)
	assert.Nil(t, marker)
	assert.Equal(t, LinkMarkerMissing, rejection)
}

// Clearing the marker cannot invalidate a copy of the cookie taken beforehand,
// because the session is client-side. Executed here rather than asserted in prose,
// since it is the whole reason the marker names a code hash and the reason
// re-resolving that hash is the consuming handler's job on every clean request.
func TestClearedLinkMarkerSurvivesInACapturedCookie(t *testing.T) {
	store := newMarkerTestStore()

	req := httptest.NewRequest("GET", "/reset-password?code=abc123", nil)
	rr := httptest.NewRecorder()
	require.NoError(t, SaveLinkMarker(store, rr, req, LinkMarkerFlowResetPassword, 42, "the-code-hash"))

	// What an attacker holding the pre-clear cookies would replay.
	captured := requestCarrying(t, rr)

	clearRr := httptest.NewRecorder()
	require.NoError(t, ClearLinkMarker(store, clearRr, requestCarrying(t, rr)))

	// The browser now holds the cleared cookies, and refuses.
	_, rejection, err := GetLinkMarker(store, requestCarrying(t, clearRr), LinkMarkerFlowResetPassword)
	require.NoError(t, err)
	require.Equal(t, LinkMarkerMissing, rejection)

	// The captured copy does not.
	marker, rejection, err := GetLinkMarker(store, captured, LinkMarkerFlowResetPassword)

	require.NoError(t, err)
	assert.Empty(t, rejection)
	require.NotNil(t, marker)
	assert.Equal(t, "the-code-hash", marker.CodeHash)
}

// A value that will not unmarshal is a server fault, not a bad link: the session
// cookie is encrypted and signed, so only this process can have written it. It keeps
// its stack trace and keeps alerting rather than being answered as an expired link.
func TestGetLinkMarkerCorruptValueIsAnError(t *testing.T) {
	store := newMarkerTestStore()

	req := writeRawMarker(t, store, "not json")

	marker, rejection, err := GetLinkMarker(store, req, LinkMarkerFlowResetPassword)

	require.Error(t, err)
	assert.Nil(t, marker)
	assert.Empty(t, rejection)
}

// A value of the wrong type is treated as no marker rather than as a fault. Nothing
// but this file writes the key, so this is the shape a future writer would break,
// and failing closed is the safe direction.
func TestGetLinkMarkerNonStringValueIsMissing(t *testing.T) {
	store := newMarkerTestStore()

	req := writeRawMarker(t, store, 42)

	marker, rejection, err := GetLinkMarker(store, req, LinkMarkerFlowResetPassword)

	require.NoError(t, err)
	assert.Nil(t, marker)
	assert.Equal(t, LinkMarkerMissing, rejection)
}

// A session store failure is an error on every entry point, never a rejection.
func TestLinkMarkerStoreFailures(t *testing.T) {
	expectedError := errors.New("session store is unavailable")

	t.Run("save", func(t *testing.T) {
		store := mocks_sessionstore.NewStore(t)
		store.On("Get", mock.Anything, constants.AuthServerSessionName).Return(nil, expectedError)

		err := SaveLinkMarker(store, httptest.NewRecorder(),
			httptest.NewRequest("GET", "/reset-password", nil),
			LinkMarkerFlowResetPassword, 42, "the-code-hash")

		assert.ErrorIs(t, err, expectedError)
	})

	t.Run("get", func(t *testing.T) {
		store := mocks_sessionstore.NewStore(t)
		store.On("Get", mock.Anything, constants.AuthServerSessionName).Return(nil, expectedError)

		marker, rejection, err := GetLinkMarker(store,
			httptest.NewRequest("GET", "/reset-password", nil), LinkMarkerFlowResetPassword)

		assert.ErrorIs(t, err, expectedError)
		assert.Nil(t, marker)
		assert.Empty(t, rejection)
	})

	t.Run("clear", func(t *testing.T) {
		store := mocks_sessionstore.NewStore(t)
		store.On("Get", mock.Anything, constants.AuthServerSessionName).Return(nil, expectedError)

		err := ClearLinkMarker(store, httptest.NewRecorder(),
			httptest.NewRequest("GET", "/reset-password", nil))

		assert.ErrorIs(t, err, expectedError)
	})
}
