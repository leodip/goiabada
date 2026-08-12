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

// requireMarkerSaved writes a marker and fails if it was refused, for the cases whose
// subject is something other than the refusal rule.
func requireMarkerSaved(t *testing.T, store sessions.Store, rr *httptest.ResponseRecorder,
	r *http.Request, flow LinkMarkerFlow, id int64, codeHash string) {
	t.Helper()

	rejection, err := SaveLinkMarker(store, rr, r, flow, id, codeHash)
	require.NoError(t, err)
	require.Empty(t, rejection)
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
	rejection, err := SaveLinkMarker(store, rr, req, LinkMarkerFlowResetPassword, 42, "the-code-hash")
	require.NoError(t, err)
	require.Empty(t, rejection)
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
	// The continuation id is what the reset form carries back, so an empty one would make
	// every submission of that form refused.
	assert.Len(t, marker.ContinuationId, continuationIdLength)
}

// Two continuations must not share an id, or naming one would name the other and the
// binding would refuse nothing.
func TestSaveLinkMarkerIssuesADistinctContinuationId(t *testing.T) {
	ids := map[string]bool{}

	for i := 0; i < 8; i++ {
		store := newMarkerTestStore()
		rr := httptest.NewRecorder()
		requireMarkerSaved(t, store, rr,
			httptest.NewRequest("GET", "/reset-password?code=abc123", nil),
			LinkMarkerFlowResetPassword, 42, "the-code-hash")

		marker, rejection, err := GetLinkMarker(store, requestCarrying(t, rr), LinkMarkerFlowResetPassword)
		require.NoError(t, err)
		require.Empty(t, rejection)
		require.NotNil(t, marker)

		assert.False(t, ids[marker.ContinuationId], "continuation id %q was issued twice", marker.ContinuationId)
		ids[marker.ContinuationId] = true
	}
}

// The refusal rule itself, and the defect it exists for. One session holds one marker and
// the reset form names nothing about the marker that rendered it, so a second reset link
// followed between a form rendering and its submit used to retarget that submit into the
// second account. First writer wins instead (#112).
func TestSaveLinkMarkerRefusesASecondLiveContinuation(t *testing.T) {
	store := newMarkerTestStore()

	first := httptest.NewRecorder()
	requireMarkerSaved(t, store, first,
		httptest.NewRequest("GET", "/reset-password?code=first", nil),
		LinkMarkerFlowResetPassword, 42, "hash-a")

	second := httptest.NewRecorder()
	rejection, err := SaveLinkMarker(store, second, requestCarrying(t, first),
		LinkMarkerFlowResetPassword, 99, "hash-b")

	require.NoError(t, err)
	assert.Equal(t, LinkMarkerContinuationInFlight, rejection)
	assert.Empty(t, second.Result().Cookies(),
		"a refused save must not write the session back")

	// The browser still holds the first continuation, so the form already on screen keeps
	// resolving to the account whose link produced it.
	marker, rejection, err := GetLinkMarker(store, requestCarrying(t, first), LinkMarkerFlowResetPassword)
	require.NoError(t, err)
	require.Empty(t, rejection)
	require.NotNil(t, marker)
	assert.Equal(t, "hash-a", marker.CodeHash)
	assert.Equal(t, int64(42), marker.Id)
}

// The same link followed twice is one continuation, not two, and gets a fresh window. The
// seeded marker has a second left, so a replacement is visible as an ExpiresAt a full
// lifetime out rather than being indistinguishable from leaving it alone.
func TestSaveLinkMarkerRefreshesTheSameContinuation(t *testing.T) {
	store := newMarkerTestStore()

	req := writeRawMarker(t, store, marshalMarker(t, &LinkMarker{
		Flow:           LinkMarkerFlowResetPassword,
		Id:             42,
		CodeHash:       "hash-a",
		ExpiresAt:      time.Now().UTC().Add(time.Second),
		ContinuationId: "the-continuation-id",
	}))

	rr := httptest.NewRecorder()
	before := time.Now().UTC()
	requireMarkerSaved(t, store, rr, req, LinkMarkerFlowResetPassword, 42, "hash-a")

	marker, rejection, err := GetLinkMarker(store, requestCarrying(t, rr), LinkMarkerFlowResetPassword)
	require.NoError(t, err)
	require.Empty(t, rejection)
	require.NotNil(t, marker)
	assert.Equal(t, "hash-a", marker.CodeHash)
	assert.False(t, marker.ExpiresAt.Before(before.Add(linkMarkerLifetime)),
		"following the same link again must refresh the window rather than keep the old one")
	// The id survives, because a form that link already rendered is this same
	// continuation. Rotating it here would refuse a legitimate submit.
	assert.Equal(t, "the-continuation-id", marker.ContinuationId)
}

// An expired marker is replaceable, which is what bounds the refusal: nobody is locked out
// of a reset for longer than linkMarkerLifetime by a continuation they abandoned.
func TestSaveLinkMarkerReplacesAnExpiredMarker(t *testing.T) {
	store := newMarkerTestStore()

	req := writeRawMarker(t, store, expiredResetMarker(t, "hash-a"))

	rr := httptest.NewRecorder()
	requireMarkerSaved(t, store, rr, req, LinkMarkerFlowResetPassword, 99, "hash-b")

	marker, rejection, err := GetLinkMarker(store, requestCarrying(t, rr), LinkMarkerFlowResetPassword)
	require.NoError(t, err)
	require.Empty(t, rejection)
	require.NotNil(t, marker)
	assert.Equal(t, "hash-b", marker.CodeHash)
	// A different continuation, so a different id: a form rendered from the marker that
	// expired must not be accepted against this one.
	assert.NotEqual(t, "the-expired-continuation-id", marker.ContinuationId)
	assert.Len(t, marker.ContinuationId, continuationIdLength)
}

// A live marker of the OTHER flow is not replaceable either, and scoping the rule to one
// flow is what left the bridge below. A wrong-flow marker is refused by every consuming
// step, so one replacement is fail-closed, but two put the slot back into the flow it
// started in (#112).
func TestSaveLinkMarkerRefusesTheOtherFlowsLiveContinuation(t *testing.T) {
	store := newMarkerTestStore()

	activation := httptest.NewRecorder()
	requireMarkerSaved(t, store, activation,
		httptest.NewRequest("GET", "/account/activate?code=first", nil),
		LinkMarkerFlowAccountActivate, 7, "hash-a")

	rr := httptest.NewRecorder()
	rejection, err := SaveLinkMarker(store, rr, requestCarrying(t, activation),
		LinkMarkerFlowResetPassword, 42, "hash-b")

	require.NoError(t, err)
	assert.Equal(t, LinkMarkerContinuationInFlight, rejection)
	assert.Empty(t, rr.Result().Cookies(), "a refused save must not write the session back")

	// The activation continuation is intact.
	marker, rejection, err := GetLinkMarker(store, requestCarrying(t, activation),
		LinkMarkerFlowAccountActivate)
	require.NoError(t, err)
	require.Empty(t, rejection)
	require.NotNil(t, marker)
	assert.Equal(t, "hash-a", marker.CodeHash)
}

// The bridge itself, which is what scoping the refusal to one flow admitted: reset A,
// activation C, reset B. The first two steps were each individually harmless, and the
// third put the slot back into the reset flow naming an account the browser's rendered
// form knows nothing about.
func TestSaveLinkMarkerAlternatingFlowsCannotBridgeBackIntoTheFirst(t *testing.T) {
	store := newMarkerTestStore()

	first := httptest.NewRecorder()
	requireMarkerSaved(t, store, first,
		httptest.NewRequest("GET", "/reset-password?code=a", nil),
		LinkMarkerFlowResetPassword, 42, "hash-a")

	activation := httptest.NewRecorder()
	rejection, err := SaveLinkMarker(store, activation, requestCarrying(t, first),
		LinkMarkerFlowAccountActivate, 7, "hash-c")
	require.NoError(t, err)
	require.Equal(t, LinkMarkerContinuationInFlight, rejection)
	require.Empty(t, activation.Result().Cookies())

	// The second reset link, offered against the jar as it actually stands: still holding
	// the first continuation, because the activation hop wrote nothing.
	second := httptest.NewRecorder()
	rejection, err = SaveLinkMarker(store, second, requestCarrying(t, first),
		LinkMarkerFlowResetPassword, 99, "hash-b")
	require.NoError(t, err)
	assert.Equal(t, LinkMarkerContinuationInFlight, rejection)

	marker, rejection, err := GetLinkMarker(store, requestCarrying(t, first), LinkMarkerFlowResetPassword)
	require.NoError(t, err)
	require.Empty(t, rejection)
	require.NotNil(t, marker)
	assert.Equal(t, "hash-a", marker.CodeHash, "the original continuation must still own the session")
	assert.Equal(t, int64(42), marker.Id)
}

// expiredResetMarker is a reset marker already past its window, which SaveLinkMarker cannot
// write.
func expiredResetMarker(t *testing.T, codeHash string) string {
	t.Helper()
	return marshalMarker(t, &LinkMarker{
		Flow:           LinkMarkerFlowResetPassword,
		Id:             42,
		CodeHash:       codeHash,
		ExpiresAt:      time.Now().UTC().Add(-time.Second),
		ContinuationId: "the-expired-continuation-id",
	})
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
	requireMarkerSaved(t, store, rr, req, LinkMarkerFlowAccountActivate, 7, "the-code-hash")

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
	requireMarkerSaved(t, store, rr, req, LinkMarkerFlowResetPassword, 42, "the-code-hash")

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
	requireMarkerSaved(t, store, rr, req, LinkMarkerFlowResetPassword, 42, "the-code-hash")

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

// The saver reads the slot too, so it meets the same corrupt value, and it must fail
// rather than treat "cannot read what is there" as "nothing is there" and overwrite it.
func TestSaveLinkMarkerCorruptValueIsAnError(t *testing.T) {
	store := newMarkerTestStore()

	req := writeRawMarker(t, store, "not json")
	rr := httptest.NewRecorder()

	rejection, err := SaveLinkMarker(store, rr, req, LinkMarkerFlowResetPassword, 42, "hash-b")

	require.Error(t, err)
	assert.Empty(t, rejection)
	assert.Empty(t, rr.Result().Cookies(), "a failed save must not write the session back")
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

		rejection, err := SaveLinkMarker(store, httptest.NewRecorder(),
			httptest.NewRequest("GET", "/reset-password", nil),
			LinkMarkerFlowResetPassword, 42, "the-code-hash")

		assert.ErrorIs(t, err, expectedError)
		assert.Empty(t, rejection)
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
