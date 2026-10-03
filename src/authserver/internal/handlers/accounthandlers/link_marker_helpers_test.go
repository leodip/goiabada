package accounthandlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/emaillinks"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
)

// The session-marker helpers both emailed-link flows' tests share. Activation and password reset
// each carried an identical copy while they lived in two packages; #435 moved reset here, and one
// package holds one copy. They are this package's own rather than exported from emaillinks, whose
// tests carry the same shapes: a test helper exported from production code widens that package's
// surface for nobody's benefit but the test (#387).
//
// Each seeds the store from a bare request rather than either flow's own: a marker is written to
// the session, which neither path nor settings reach, so the seed decides nothing a test asserts.

// newMarkerTestStore is a real store rather than the mock, because these cases turn on the marker
// surviving a round trip between the two hops and a mock cannot show one. A ServerSideStore over
// an in-memory backend since #266 moved the session out of the browser: every copy of the cookie
// names the same row, so clearing the marker reaches all of them.
func newMarkerTestStore() *sessionstore.ServerSideStore {
	store, err := sessionstore.NewServerSideStore(
		sessiontest.NewMemoryBackend(),
		sessionkeys.SessionIdentifier,
		false,
		sessionstore.PersistentCookie,
		sessionstore.KeyPair{
			AuthenticationKey: []byte("12345678901234567890123456789012"),
			EncryptionKey:     []byte("abcdefghijklmnopqrstuvwxyz123456"),
		},
		nil,
	)
	if err != nil {
		// The keys are literals above and the derivation cannot fail on them, so this is
		// unreachable. Panicking rather than dropping it keeps it that way.
		panic(err)
	}
	return store
}

// markerSeedRequest is the request a marker is written through before the request under test
// carries it.
func markerSeedRequest() *http.Request {
	return httptest.NewRequest("GET", "/", nil)
}

// withMarker attaches the session cookies a first hop would have set, which is what makes a
// request a clean-hop request rather than a bare one.
func withMarker(t *testing.T, store sessionstore.Store, req *http.Request, flow emaillinks.LinkMarkerFlow,
	id int64, codeHash string) *http.Request {
	t.Helper()

	rr := httptest.NewRecorder()
	rejection, err := emaillinks.SaveLinkMarker(store, rr, markerSeedRequest(), flow, id, codeHash)
	require.NoError(t, err)
	require.Empty(t, rejection)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}
	return req
}

// withRawMarker attaches cookies holding an arbitrary marker value, for the states
// emaillinks.SaveLinkMarker cannot produce: an already-expired marker, and a corrupt one.
func withRawMarker(t *testing.T, store sessionstore.Store, req *http.Request, value interface{}) *http.Request {
	t.Helper()

	seed := markerSeedRequest()
	rr := httptest.NewRecorder()
	sess, err := store.Get(seed, sessionkeys.AuthServerSessionName)
	require.NoError(t, err)
	sess.Values[sessionkeys.LinkMarker] = value
	require.NoError(t, store.Save(seed, rr, sess))

	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}
	return req
}

func marshalMarker(t *testing.T, marker *emaillinks.LinkMarker) string {
	t.Helper()
	data, err := json.Marshal(marker)
	require.NoError(t, err)
	return string(data)
}

// expiredMarkerJSON is a marker already past its window, which emaillinks.SaveLinkMarker cannot write.
func expiredMarkerJSON(t *testing.T, flow emaillinks.LinkMarkerFlow, id int64, codeHash string) string {
	t.Helper()
	return marshalMarker(t, &emaillinks.LinkMarker{
		Flow:      flow,
		Id:        id,
		CodeHash:  codeHash,
		ExpiresAt: time.Now().UTC().Add(-time.Second),
	})
}

// nextBrowserRequest models what the browser sends after this exchange: the cookies it already
// held, with the response's Set-Cookie applied on top, on the clean-hop request of the flow
// under test, which cleanHop builds.
//
// Building it from the response alone would be vacuous for anything that asserts a cookie is
// GONE: a handler that set no cookie at all produces the same empty request as one that
// cleared it, so such an assertion passes against code that never clears anything.
func nextBrowserRequest(t *testing.T, sent *http.Request, rr *httptest.ResponseRecorder,
	cleanHop func() *http.Request) *http.Request {
	t.Helper()

	byName := map[string]*http.Cookie{}
	for _, c := range sent.Cookies() {
		byName[c.Name] = c
	}
	for _, c := range rr.Result().Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(byName, c.Name)
			continue
		}
		byName[c.Name] = c
	}

	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)

	next := cleanHop()
	for _, name := range names {
		next.AddCookie(byName[name])
	}
	return next
}
