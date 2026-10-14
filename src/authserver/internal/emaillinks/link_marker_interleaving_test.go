package emaillinks

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
	consumed := consumeMarker(t, store, reqA, LinkMarkerFlowResetPassword)
	writeMeanwhile(t, store, seed, sessionkeys.AuthContext, "ceremony B")
	require.NoError(t, ClearLinkMarker(store, httptest.NewRecorder(), reqA, consumed.ContinuationId))

	values := storedValues(t, store, seed)
	assert.Equal(t, "ceremony B", values[sessionkeys.AuthContext],
		"the marker's clear must not put back the copy its request began with")
	assert.NotContains(t, values, sessionkeys.LinkMarker)
}

// A clear removes only the marker of the continuation its request consumed. That marker may expire
// while its request finishes, and a different link followed in another tab may take the slot then,
// which SaveLinkMarker allows once a marker has expired; the older request's clear must leave the
// newer continuation's marker in place, or its next step is refused as marker_missing (#579).
func TestClearLinkMarker_KeepsANewerContinuationsMarker(t *testing.T) {
	for _, flow := range []LinkMarkerFlow{LinkMarkerFlowResetPassword, LinkMarkerFlowAccountActivate} {
		t.Run(string(flow), func(t *testing.T) {
			store := newMarkerTestStore()
			expiresAt := time.Now().UTC().Add(-time.Second)
			seed := seedSession(t, store, map[string]any{sessionkeys.LinkMarker: marshalMarker(t, &LinkMarker{
				Flow:           flow,
				Id:             42,
				CodeHash:       "hash-a",
				ExpiresAt:      expiresAt,
				ContinuationId: "the-older-continuation-id",
			})})

			// Request A read marker A while it was still live, and is finishing its flow.
			reqA := loadedRequest(t, store, seed)
			sessA, err := store.Get(reqA, sessionkeys.AuthServerSessionName)
			require.NoError(t, err)
			consumed, rejection, err := readLinkMarker(sessA, flow, expiresAt.Add(-time.Second))
			require.NoError(t, err)
			require.Empty(t, rejection)
			require.NotNil(t, consumed)

			// Meanwhile marker A expired, and another tab followed a different link.
			rrB := httptest.NewRecorder()
			requireMarkerSaved(t, store, rrB, requestCarrying(t, seed), flow, 99, "hash-b")
			newer := consumeMarker(t, store, requestCarrying(t, rrB), flow)
			require.NotEqual(t, consumed.ContinuationId, newer.ContinuationId)

			rrA := httptest.NewRecorder()
			require.NoError(t, ClearLinkMarker(store, rrA, reqA, consumed.ContinuationId))

			assert.Empty(t, rrA.Result().Cookies(), "a clear with nothing of its own to remove must not write the session")
			marker, rejection, err := GetLinkMarker(store, requestCarrying(t, rrB), flow)
			require.NoError(t, err)
			require.Empty(t, rejection, "the newer continuation's marker must survive the older request's clear")
			require.NotNil(t, marker)
			assert.Equal(t, newer.ContinuationId, marker.ContinuationId)
			assert.Equal(t, "hash-b", marker.CodeHash)
		})
	}
}

// A clear finding no marker stored, because another request cleared it meanwhile, has nothing to
// remove, so it writes nothing.
func TestClearLinkMarker_WritesNothingWhenNoMarkerIsStored(t *testing.T) {
	store := newMarkerTestStore()
	seed := seedSession(t, store, map[string]any{sessionkeys.AuthContext: "ceremony A"})
	requireMarkerSaved(t, store, httptest.NewRecorder(), requestCarrying(t, seed),
		LinkMarkerFlowResetPassword, 42, "hash-a")

	reqA := loadedRequest(t, store, seed)
	consumed := consumeMarker(t, store, reqA, LinkMarkerFlowResetPassword)
	require.NoError(t, ClearLinkMarker(store, httptest.NewRecorder(), requestCarrying(t, seed),
		consumed.ContinuationId))

	rrA := httptest.NewRecorder()
	require.NoError(t, ClearLinkMarker(store, rrA, reqA, consumed.ContinuationId))

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
	consumed := consumeMarker(t, store, reqA, LinkMarkerFlowResetPassword)
	deleteMeanwhile(t, store, seed)

	rrA := httptest.NewRecorder()
	require.NoError(t, ClearLinkMarker(store, rrA, reqA, consumed.ContinuationId))

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
