package sessionstore

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Whether the auth server's signed-in cookie outlives the browser is decided per write, by the
// KeepSignedIn its store was built with: Always, Never, and under Let each user choose the answer the
// session recorded, which the auth server's rule reads. The store writes a Max-Age from the row's
// expiry when the rule keeps the session signed in, and neither Max-Age nor Expires when it does
// not. A sign-in in progress keeps its flat 30 minutes whatever the rule would answer (#743
// decisions 2 and 5).

// keepEverySignedInSession is the rule under Always.
func keepEverySignedInSession(context.Context, map[string]any) (bool, error) { return true, nil }

// keepNoSignedInSession is the rule under Never.
func keepNoSignedInSession(context.Context, map[string]any) (bool, error) { return false, nil }

// keepTestNow is the clock of these tests; their rows expire keepTestRowLifetime after it.
var keepTestNow = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

const keepTestRowLifetime = 2 * time.Hour

// keepTestStore is the auth server's kind of store over a fresh backend, on keepTestNow's clock,
// with keepSignedIn as its rule. Every row it writes expires two hours from now.
func keepTestStore(t *testing.T, keepSignedIn KeepSignedIn) (*ConditionalStore, *fakeBackend) {
	t.Helper()
	backend := newFakeBackend()
	backend.expiresAt = keepTestNow.Add(keepTestRowLifetime)
	store, err := NewServerSideStore(backend, "SessionIdentifier", false, PersistentCookie(keepSignedIn), storeTestPair(), nil)
	require.NoError(t, err)
	store.now = func() time.Time { return keepTestNow }
	conditional, err := NewConditionalStore(store, backend)
	require.NoError(t, err)
	return conditional, backend
}

// theSessionCookie is the one Set-Cookie of the store's session cookie a response carries, as the
// header says it: whether Max-Age or Expires was written at all is only in the raw header, since
// net/http parses an absent Max-Age and a Max-Age of zero alike.
func theSessionCookie(t *testing.T, store *ConditionalStore, w *httptest.ResponseRecorder) (string, *http.Cookie) {
	t.Helper()
	var headers []string
	var cookies []*http.Cookie
	for _, header := range w.Result().Header.Values("Set-Cookie") {
		parsed, err := http.ParseSetCookie(header)
		require.NoError(t, err)
		if parsed.Name == store.CookieName(storeTestName) {
			headers = append(headers, header)
			cookies = append(cookies, parsed)
		}
	}
	require.Len(t, cookies, 1, "the response names the session with one cookie")
	return headers[0], cookies[0]
}

// writeEveryWay writes a session holding values through each of the store's writes that name it
// with a cookie, and returns each write's response.
func writeEveryWay(t *testing.T, store *ConditionalStore, values map[string]any) map[string]*httptest.ResponseRecorder {
	t.Helper()
	responses := map[string]*httptest.ResponseRecorder{}

	put := func(target map[string]any) {
		for k, v := range values {
			target[k] = v
		}
	}

	// A save that creates the row, and its cookie for the writes that load it.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	session, err := store.Get(req, storeTestName)
	require.NoError(t, err)
	put(session.Values)
	responses["a save that creates the row"] = httptest.NewRecorder()
	require.NoError(t, store.Save(req, responses["a save that creates the row"], session))
	created := responses["a save that creates the row"].Result().Cookies()
	require.Len(t, created, 1)

	loaded := func() (*http.Request, *Session) {
		loadReq := requestWith(created[0])
		loadedSession, loadErr := store.Get(loadReq, storeTestName)
		require.NoError(t, loadErr)
		require.NotEmpty(t, loadedSession.ID, "the row is loaded")
		return loadReq, loadedSession
	}

	req, session = loaded()
	responses["a save that updates it"] = httptest.NewRecorder()
	require.NoError(t, store.Save(req, responses["a save that updates it"], session))

	req, session = loaded()
	responses["a conditional save"] = httptest.NewRecorder()
	require.NoError(t, store.ChangeAndSave(req, responses["a conditional save"], session, func(v map[string]any) error {
		v["changed"] = true
		return nil
	}))

	req, session = loaded()
	responses["a conditional rotation, as a sign-in binds the session"] = httptest.NewRecorder()
	require.NoError(t, store.ChangeAndRegenerate(responses["a conditional rotation, as a sign-in binds the session"], req, session,
		func(v map[string]any) error { put(v); return nil }))

	// The conditional rotation removed the row the cookie named; a save never stored goes last.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	session, err = store.Get(req, storeTestName)
	require.NoError(t, err)
	put(session.Values)
	responses["a rotation"] = httptest.NewRecorder()
	require.NoError(t, store.Regenerate(responses["a rotation"], req, session))

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	session, err = store.Get(req, storeTestName)
	require.NoError(t, err)
	responses["a conditional save of a session never stored"] = httptest.NewRecorder()
	require.NoError(t, store.ChangeAndSave(req, responses["a conditional save of a session never stored"], session,
		func(v map[string]any) error { put(v); return nil }))

	return responses
}

// Under a rule that keeps the session signed in, as under Always or a ticked box, every write of a
// signed-in session gives its cookie the row's remaining lifetime as its Max-Age.
func TestServerSideStore_ASignedInCookieTheRuleKeepsCarriesTheRowsExpiry(t *testing.T) {
	store, _ := keepTestStore(t, keepEverySignedInSession)

	for write, w := range writeEveryWay(t, store, signedInValues()) {
		header, cookie := theSessionCookie(t, store, w)
		assert.Contains(t, header, "Max-Age=7200", "%s: the cookie outlives the browser, as long as the row", write)
		assert.Equal(t, 7200, cookie.MaxAge, write)
	}
}

// Under a rule that does not, as under Never or an unticked box, every write of a signed-in session
// gives its cookie neither Max-Age nor Expires, so the browser drops it when it closes.
func TestServerSideStore_ASignedInCookieTheRuleDoesNotKeepEndsWithTheBrowser(t *testing.T) {
	store, _ := keepTestStore(t, keepNoSignedInSession)

	for write, w := range writeEveryWay(t, store, signedInValues()) {
		header, cookie := theSessionCookie(t, store, w)
		assert.NotContains(t, header, "Max-Age", "%s: the cookie ends with the browser", write)
		assert.NotContains(t, header, "Expires", write)
		assert.NotEmpty(t, cookie.Value, "%s: and still names the session", write)
		assert.Equal(t, "/", cookie.Path, write)
		assert.True(t, cookie.HttpOnly, write)
		assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite, write)
	}
}

// A sign-in in progress holds no session yet: its cookie keeps the row's flat 30 minutes whatever
// the rule would answer, and the rule is never asked about it.
func TestServerSideStore_ASignInInProgressKeepsItsExpiryWhateverTheRule(t *testing.T) {
	asked := 0
	store, backend := keepTestStore(t, func(context.Context, map[string]any) (bool, error) {
		asked++
		return false, nil
	})
	backend.expiresAt = keepTestNow.Add(PreAuthLifetime)

	for write, w := range writeEveryWay(t, store, map[string]any{"AuthContexts": "a sign-in in progress"}) {
		header, cookie := theSessionCookie(t, store, w)
		assert.Contains(t, header, "Max-Age=1800", "%s: thirty minutes, as the row", write)
		assert.Equal(t, 1800, cookie.MaxAge, write)
	}
	assert.Zero(t, asked, "the rule decides only a signed-in session's cookie")
}

// The rule is asked with the request's context, where the auth server's settings are, and the
// values the session is written with, where its recorded answer is: the values as written, after
// the change a conditional write applied to a fresh read.
func TestServerSideStore_TheRuleIsAskedWithTheRequestsContextAndTheValuesWritten(t *testing.T) {
	type marker struct{}
	var gotMarker any
	var gotValues map[string]any
	store, _ := keepTestStore(t, func(ctx context.Context, values map[string]any) (bool, error) {
		gotMarker = ctx.Value(marker{})
		gotValues = values
		return true, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), marker{}, "the request's"))
	session, err := store.Get(req, storeTestName)
	require.NoError(t, err)
	require.NoError(t, store.ChangeAndSave(req, httptest.NewRecorder(), session, func(v map[string]any) error {
		v["SessionIdentifier"] = "a-user-session"
		v["KeepSignedIn"] = true
		return nil
	}))

	assert.Equal(t, "the request's", gotMarker)
	assert.Equal(t, map[string]any{"SessionIdentifier": "a-user-session", "KeepSignedIn": true}, gotValues)
}

// A rule that cannot answer, because the settings could not be read, refuses the write of the
// cookie rather than guess: the save fails, and no cookie is sent.
func TestServerSideStore_ARuleThatCannotAnswerFailsTheSaveAndSendsNoCookie(t *testing.T) {
	cause := errors.New("settings unreadable")
	store, _ := keepTestStore(t, func(context.Context, map[string]any) (bool, error) { return false, cause })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	session, err := store.Get(req, storeTestName)
	require.NoError(t, err)
	session.Values["SessionIdentifier"] = "a-user-session"

	err = store.Save(req, w, session)

	require.ErrorIs(t, err, cause)
	assert.Empty(t, w.Result().Header.Values("Set-Cookie"))
}

// A page request that refreshes a signed-in session the rule does not keep still moves the row's
// idle deadline, and sends no cookie: one that ends with the browser has no expiry to keep up
// (#743 decision 8). One the rule keeps is sent again, as TestServerSideStore_APageRequestThat…
// pins.
func TestServerSideStore_ARefreshOfASessionTheRuleDoesNotKeepSendsNoCookie(t *testing.T) {
	backend := newFakeBackend()
	backend.expiresAt = refreshTestNow.Add(time.Minute)
	store, err := NewServerSideStore(backend, "SessionIdentifier", false, PersistentCookie(keepNoSignedInSession), storeTestPair(), nil)
	require.NoError(t, err)
	store.now = func() time.Time { return refreshTestNow }
	cookie := saveNew(t, store, signedInValues())
	id := decodeCookieId(t, store, cookie)
	backend.rows[id].LastAccessed = refreshTestNow.Add(-time.Minute)
	backend.expiresAt = refreshTestNow.Add(2 * time.Hour)

	session, cookies := readSession(t, store, requestWith(cookie), true)

	assert.Equal(t, id, session.ID)
	assert.Equal(t, 1, backend.touches, "the stale row is touched")
	assert.Empty(t, cookies, "and no cookie is sent")
}

// The rule decides for the values the session holds when it is refreshed, which is what the
// session recorded at its last password entry: answered keep, the cookie is sent again.
func TestServerSideStore_ARefreshAsksTheRuleAboutTheSessionsValues(t *testing.T) {
	backend := newFakeBackend()
	backend.expiresAt = refreshTestNow.Add(time.Minute)
	keepTicked := func(_ context.Context, values map[string]any) (bool, error) {
		ticked, _ := values["KeepSignedIn"].(bool)
		return ticked, nil
	}
	store, err := NewServerSideStore(backend, "SessionIdentifier", false, PersistentCookie(keepTicked), storeTestPair(), nil)
	require.NoError(t, err)
	store.now = func() time.Time { return refreshTestNow }

	for name, test := range map[string]struct {
		values     map[string]any
		wantCookie bool
	}{
		"ticked":   {values: map[string]any{"SessionIdentifier": "a-user-session", "KeepSignedIn": true}, wantCookie: true},
		"unticked": {values: map[string]any{"SessionIdentifier": "a-user-session", "KeepSignedIn": false}},
	} {
		t.Run(name, func(t *testing.T) {
			backend.expiresAt = refreshTestNow.Add(time.Minute)
			cookie := saveNew(t, store, test.values)
			id := decodeCookieId(t, store, cookie)
			backend.rows[id].LastAccessed = refreshTestNow.Add(-time.Minute)
			backend.expiresAt = refreshTestNow.Add(2 * time.Hour)

			_, cookies := readSession(t, store, requestWith(cookie), true)

			if test.wantCookie {
				require.Len(t, cookies, 1)
				assert.Equal(t, 7200, cookies[0].MaxAge)
			} else {
				assert.Empty(t, cookies)
			}
		})
	}
}

// A persistent cookie without a rule would have to choose for the deployment; the store refuses to
// be built that way.
func TestNewServerSideStore_RefusesAPersistentCookieWithNoRule(t *testing.T) {
	store, err := NewServerSideStore(newFakeBackend(), "SessionIdentifier", false, PersistentCookie(nil), storeTestPair(), nil)

	require.Error(t, err)
	assert.Nil(t, store)
}
