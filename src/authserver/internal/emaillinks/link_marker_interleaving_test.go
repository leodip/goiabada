package emaillinks

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/core/sessionstore"
)

// The marker's save and clear write only the marker's own key onto the browser session as it is
// stored when they write, rather than the copy their request read when it began, so a value another
// request of the same browser wrote in between is kept, and the in-flight rule is decided on what is
// stored then (#579 decision 5). Each case sets the interleaving up in sequence: request A reads the
// session, request B writes it, request A writes.

// seedSession stores a session holding values and answers the cookies naming it.
func seedSession(t *testing.T, store *sessionstore.ConditionalStore, values map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	sess, err := store.Get(req, sessionkeys.AuthServerSessionName)
	require.NoError(t, err)
	for k, v := range values {
		sess.Values[k] = v
	}
	require.NoError(t, store.Save(req, rr, sess))
	return rr
}

// loadedRequest is request A: a request of the browser holding the cookies seed set, which has
// read its session, so the request-start copy is the one cached on it.
func loadedRequest(t *testing.T, store *sessionstore.ConditionalStore, seed *httptest.ResponseRecorder) *http.Request {
	t.Helper()
	req := requestCarrying(t, seed)
	_, err := store.Get(req, sessionkeys.AuthServerSessionName)
	require.NoError(t, err)
	return req
}

// writeMeanwhile is request B: another request of the same browser writing key into the session.
func writeMeanwhile(t *testing.T, store *sessionstore.ConditionalStore, seed *httptest.ResponseRecorder,
	key string, value any) {
	t.Helper()
	req := requestCarrying(t, seed)
	sess, err := store.Get(req, sessionkeys.AuthServerSessionName)
	require.NoError(t, err)
	sess.Values[key] = value
	require.NoError(t, store.Save(req, httptest.NewRecorder(), sess))
}

// storedValues is the session as a later request of the browser reads it.
func storedValues(t *testing.T, store *sessionstore.ConditionalStore, seed *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	sess, err := store.Get(requestCarrying(t, seed), sessionkeys.AuthServerSessionName)
	require.NoError(t, err)
	return sess.Values
}

func TestSaveLinkMarker_KeepsWhatAnotherRequestWroteMeanwhile(t *testing.T) {
	store := newMarkerTestStore()
	seed := seedSession(t, store, map[string]any{sessionkeys.AuthContext: "ceremony A"})

	reqA := loadedRequest(t, store, seed)
	writeMeanwhile(t, store, seed, sessionkeys.AuthContext, "ceremony B")
	requireMarkerSaved(t, store, httptest.NewRecorder(), reqA, LinkMarkerFlowResetPassword, 42, "hash-a")

	values := storedValues(t, store, seed)
	assert.Equal(t, "ceremony B", values[sessionkeys.AuthContext],
		"the marker's save must not put back the copy its request began with")
	marker, rejection, err := GetLinkMarker(store, requestCarrying(t, seed), LinkMarkerFlowResetPassword)
	require.NoError(t, err)
	require.Empty(t, rejection)
	require.NotNil(t, marker)
	assert.Equal(t, "hash-a", marker.CodeHash)
}

// The request began with no marker in the session, and another link's continuation started before it
// wrote. The rule refuses this second, different link on what is stored now, rather than replacing
// the first continuation because the request's own copy held none.
func TestSaveLinkMarker_DecidesTheContinuationInFlightOnTheStoredSession(t *testing.T) {
	store := newMarkerTestStore()
	seed := seedSession(t, store, map[string]any{sessionkeys.AuthContext: "ceremony A"})

	reqA := loadedRequest(t, store, seed)
	requireMarkerSaved(t, store, httptest.NewRecorder(), requestCarrying(t, seed),
		LinkMarkerFlowResetPassword, 42, "hash-a")

	rrA := httptest.NewRecorder()
	rejection, err := SaveLinkMarker(store, rrA, reqA, LinkMarkerFlowResetPassword, 99, "hash-b")

	require.NoError(t, err)
	assert.Equal(t, LinkMarkerContinuationInFlight, rejection)
	assert.Empty(t, rrA.Result().Cookies(), "a refused save must not write the session")
	marker, rejection, err := GetLinkMarker(store, requestCarrying(t, seed), LinkMarkerFlowResetPassword)
	require.NoError(t, err)
	require.Empty(t, rejection)
	require.NotNil(t, marker)
	assert.Equal(t, "hash-a", marker.CodeHash, "the first continuation must still own the session")
	assert.Equal(t, int64(42), marker.Id)
}

// The same link followed again while its own first follow wrote meanwhile: one continuation, so the
// id the stored marker carries is kept, as the form that follow rendered names it.
func TestSaveLinkMarker_KeepsTheStoredContinuationIdOfTheSameLink(t *testing.T) {
	store := newMarkerTestStore()
	seed := seedSession(t, store, map[string]any{sessionkeys.AuthContext: "ceremony A"})

	reqA := loadedRequest(t, store, seed)
	requireMarkerSaved(t, store, httptest.NewRecorder(), requestCarrying(t, seed),
		LinkMarkerFlowResetPassword, 42, "hash-a")
	first, _, err := GetLinkMarker(store, requestCarrying(t, seed), LinkMarkerFlowResetPassword)
	require.NoError(t, err)
	require.NotNil(t, first)

	requireMarkerSaved(t, store, httptest.NewRecorder(), reqA, LinkMarkerFlowResetPassword, 42, "hash-a")

	marker, rejection, err := GetLinkMarker(store, requestCarrying(t, seed), LinkMarkerFlowResetPassword)
	require.NoError(t, err)
	require.Empty(t, rejection)
	require.NotNil(t, marker)
	assert.Equal(t, first.ContinuationId, marker.ContinuationId,
		"a form the first follow rendered must not be refused")
}

func TestClearLinkMarker_KeepsWhatAnotherRequestWroteMeanwhile(t *testing.T) {
	store := newMarkerTestStore()
	seed := seedSession(t, store, map[string]any{sessionkeys.AuthContext: "ceremony A"})
	requireMarkerSaved(t, store, httptest.NewRecorder(), requestCarrying(t, seed),
		LinkMarkerFlowResetPassword, 42, "hash-a")

	reqA := loadedRequest(t, store, seed)
	writeMeanwhile(t, store, seed, sessionkeys.AuthContext, "ceremony B")
	require.NoError(t, ClearLinkMarker(store, httptest.NewRecorder(), reqA))

	values := storedValues(t, store, seed)
	assert.Equal(t, "ceremony B", values[sessionkeys.AuthContext],
		"the marker's clear must not put back the copy its request began with")
	assert.NotContains(t, values, sessionkeys.LinkMarker)
}

// A clear finding no marker stored, because another request cleared it meanwhile, has nothing to
// remove, so it writes nothing.
func TestClearLinkMarker_WritesNothingWhenNoMarkerIsStored(t *testing.T) {
	store := newMarkerTestStore()
	seed := seedSession(t, store, map[string]any{sessionkeys.AuthContext: "ceremony A"})
	requireMarkerSaved(t, store, httptest.NewRecorder(), requestCarrying(t, seed),
		LinkMarkerFlowResetPassword, 42, "hash-a")

	reqA := loadedRequest(t, store, seed)
	require.NoError(t, ClearLinkMarker(store, httptest.NewRecorder(), requestCarrying(t, seed)))

	rrA := httptest.NewRecorder()
	require.NoError(t, ClearLinkMarker(store, rrA, reqA))

	assert.Empty(t, rrA.Result().Cookies(), "a clear with nothing to remove must not write the session")
	_, rejection, err := GetLinkMarker(store, reqA, LinkMarkerFlowResetPassword)
	require.NoError(t, err)
	assert.Equal(t, LinkMarkerMissing, rejection, "the request's own session must not hold the marker either")
}

// A clear finding the session gone, signed out or rotated away meanwhile, finds the marker gone with
// it: nothing to remove, so no error, and the session is not put back.
func TestClearLinkMarker_ASessionGoneMeanwhileIsCleared(t *testing.T) {
	store := newMarkerTestStore()
	seed := seedSession(t, store, map[string]any{sessionkeys.AuthContext: "ceremony A"})
	requireMarkerSaved(t, store, httptest.NewRecorder(), requestCarrying(t, seed),
		LinkMarkerFlowResetPassword, 42, "hash-a")

	reqA := loadedRequest(t, store, seed)
	deleteMeanwhile(t, store, seed)

	rrA := httptest.NewRecorder()
	require.NoError(t, ClearLinkMarker(store, rrA, reqA))

	assert.Empty(t, rrA.Result().Cookies(), "a gone session must not be put back")
	assert.Empty(t, storedValues(t, store, seed), "a gone session must not be put back")
}

// deleteMeanwhile is request B signing the browser out: the session row is deleted.
func deleteMeanwhile(t *testing.T, store *sessionstore.ConditionalStore, seed *httptest.ResponseRecorder) {
	t.Helper()
	req := requestCarrying(t, seed)
	sess, err := store.Get(req, sessionkeys.AuthServerSessionName)
	require.NoError(t, err)
	sess.Options.MaxAge = -1
	require.NoError(t, store.Save(req, httptest.NewRecorder(), sess))
}
