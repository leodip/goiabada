package ceremony

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAuthContext(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ceremonyStore, store, _ := newRealStore(t)
		cookies := seedBrowserSession(t, store, map[string]any{
			sessionkeys.AuthContext: authContextJSON(t, &AuthContext{ClientId: "test-client"}),
		})

		result, err := ceremonyStore.GetAuthContext(browserRequest(cookies))

		require.NoError(t, err)
		assert.Equal(t, "test-client", result.ClientId)
	})

	t.Run("SessionError", func(t *testing.T) {
		ceremonyStore, store, backend := newRealStore(t)
		cookies := seedBrowserSession(t, store, map[string]any{
			sessionkeys.AuthContext: authContextJSON(t, &AuthContext{ClientId: "test-client"}),
		})
		backend.failLoad = true

		result, err := ceremonyStore.GetAuthContext(browserRequest(cookies))

		require.ErrorIs(t, err, errLoadRefused)
		assert.Nil(t, result)
	})

	t.Run("NoAuthContext", func(t *testing.T) {
		ceremonyStore, store, _ := newRealStore(t)
		cookies := seedBrowserSession(t, store, map[string]any{"unrelated": "value"})

		result, err := ceremonyStore.GetAuthContext(browserRequest(cookies))

		require.ErrorIs(t, err, ErrNoAuthContext)
		assert.Nil(t, result)
		requireSessionDecoded(t, store, browserRequest(cookies))
	})

	t.Run("UnmarshalError", func(t *testing.T) {
		ceremonyStore, store, _ := newRealStore(t)
		cookies := seedBrowserSession(t, store, map[string]any{sessionkeys.AuthContext: "invalid json"})

		result, err := ceremonyStore.GetAuthContext(browserRequest(cookies))

		require.Error(t, err)
		require.NotErrorIs(t, err, ErrNoAuthContext, "a context that is there but will not decode is not an absent one")
		assert.Nil(t, result)
	})
}

// ceremonyA and ceremonyB are the two sign-ins of one browser the conditional writes are decided
// between: A the one a step loaded, B the one another tab's /auth/authorize replaced it with.
const ceremonyA, ceremonyB = "ceremony-a", "ceremony-b"

// loadedStep seeds ceremony A as /auth/authorize stores it and loads it on a step's request,
// which is what every step does before it saves or clears.
func loadedStep(t *testing.T, ceremonyStore *Store) ([]*http.Cookie, *http.Request, *AuthContext) {
	t.Helper()
	seedReq := browserRequest(nil)
	seedRR := httptest.NewRecorder()
	require.NoError(t, ceremonyStore.ReplaceAuthContext(seedRR, seedReq,
		&AuthContext{CeremonyId: ceremonyA, ClientId: "client-a", AuthState: AuthStateRequiresLevel1}))
	cookies := seedRR.Result().Cookies()
	require.Len(t, cookies, 1)

	stepReq := browserRequest(cookies)
	loaded, err := ceremonyStore.GetAuthContext(stepReq)
	require.NoError(t, err)
	require.Equal(t, ceremonyA, loaded.CeremonyId)
	return cookies, stepReq, loaded
}

// SaveAuthContext is every step's save after /auth/authorize, and it lands only while the browser
// session still holds the ceremony the step loaded (#579). Each case loads ceremony A as a step's
// request would, lets another request of the same browser write in between, and then has the step
// save: what the save answers, and what the session then holds, is the whole of the rule.
func TestSaveAuthContext(t *testing.T) {
	t.Run("LandsWhileTheSessionHoldsItsCeremony", func(t *testing.T) {
		ceremonyStore, _, _ := newRealStore(t)
		cookies, stepReq, loaded := loadedStep(t, ceremonyStore)
		rr := httptest.NewRecorder()

		loaded.AuthState = AuthStateLevel1Password
		require.NoError(t, ceremonyStore.SaveAuthContext(rr, stepReq, loaded))

		stored, err := ceremonyStore.GetAuthContext(browserRequest(cookies))
		require.NoError(t, err)
		assert.Equal(t, ceremonyA, stored.CeremonyId)
		assert.Equal(t, AuthStateLevel1Password, stored.AuthState)
	})

	t.Run("AnotherCeremonyWrittenInBetweenIsNotOverwritten", func(t *testing.T) {
		// The issue's interleaving: tab A's step has loaded ceremony A, tab B's /auth/authorize
		// replaces it with ceremony B, and tab A's step saves.
		ceremonyStore, _, _ := newRealStore(t)
		cookies, stepReq, loaded := loadedStep(t, ceremonyStore)

		require.NoError(t, ceremonyStore.ReplaceAuthContext(httptest.NewRecorder(), browserRequest(cookies),
			&AuthContext{CeremonyId: ceremonyB, ClientId: "client-b", AuthState: AuthStateRequiresLevel1}))

		rr := httptest.NewRecorder()
		loaded.AuthState = AuthStateLevel1Password
		err := ceremonyStore.SaveAuthContext(rr, stepReq, loaded)

		require.ErrorIs(t, err, ErrCeremonyReplaced)
		assert.Empty(t, rr.Result().Cookies(), "a step that wrote nothing tells the browser nothing")
		stored, err := ceremonyStore.GetAuthContext(browserRequest(cookies))
		require.NoError(t, err)
		assert.Equal(t, ceremonyB, stored.CeremonyId, "the newer ceremony is what the browser session keeps")
		assert.Equal(t, "client-b", stored.ClientId)
		assert.Equal(t, AuthStateRequiresLevel1, stored.AuthState)
	})

	t.Run("NoCeremonyLeftInBetweenIsNotPutBack", func(t *testing.T) {
		ceremonyStore, store, _ := newRealStore(t)
		cookies, stepReq, loaded := loadedStep(t, ceremonyStore)

		// Another request of this browser ended the ceremony, keeping the session.
		other := browserRequest(cookies)
		sess, err := store.Get(other, realStoreSessionName)
		require.NoError(t, err)
		delete(sess.Values, sessionkeys.AuthContext)
		require.NoError(t, store.Save(other, httptest.NewRecorder(), sess))

		rr := httptest.NewRecorder()
		err = ceremonyStore.SaveAuthContext(rr, stepReq, loaded)

		require.ErrorIs(t, err, ErrCeremonyReplaced)
		assert.Empty(t, rr.Result().Cookies())
		_, err = ceremonyStore.GetAuthContext(browserRequest(cookies))
		require.ErrorIs(t, err, ErrNoAuthContext, "the ended ceremony stays ended")
		requireSessionDecoded(t, store, browserRequest(cookies))
	})

	t.Run("ASessionGoneInBetweenIsNotRecreated", func(t *testing.T) {
		ceremonyStore, store, backend := newRealStore(t)
		cookies, stepReq, loaded := loadedStep(t, ceremonyStore)

		// Signed out in another tab, rotated away by another request, or expired.
		require.NoError(t, backend.Delete(context.Background(), sessionIdentifier(t, store, cookies[0])))

		rr := httptest.NewRecorder()
		err := ceremonyStore.SaveAuthContext(rr, stepReq, loaded)

		require.ErrorIs(t, err, ErrCeremonyReplaced)
		assert.Empty(t, rr.Result().Cookies())
		_, err = backend.Load(context.Background(), sessionIdentifier(t, store, cookies[0]))
		require.ErrorIs(t, err, sessionstore.ErrNotFound, "the request's own copy is not put back")
	})

	t.Run("AnUnrelatedWriteInBetweenIsKept", func(t *testing.T) {
		// Only the ceremony decides ownership: a write of another value to the same session is not
		// a replaced ceremony, and the step's save applies its change over it rather than putting
		// back the copy it loaded.
		ceremonyStore, store, _ := newRealStore(t)
		cookies, stepReq, loaded := loadedStep(t, ceremonyStore)

		other := browserRequest(cookies)
		sess, err := store.Get(other, realStoreSessionName)
		require.NoError(t, err)
		sess.Values["unrelated"] = "written meanwhile"
		require.NoError(t, store.Save(other, httptest.NewRecorder(), sess))

		loaded.AuthState = AuthStateLevel1Password
		require.NoError(t, ceremonyStore.SaveAuthContext(httptest.NewRecorder(), stepReq, loaded))

		stored, err := store.Get(browserRequest(cookies), realStoreSessionName)
		require.NoError(t, err)
		assert.Equal(t, "written meanwhile", stored.Values["unrelated"])
		authContext, err := ceremonyStore.GetAuthContext(browserRequest(cookies))
		require.NoError(t, err)
		assert.Equal(t, AuthStateLevel1Password, authContext.AuthState)
	})

	t.Run("TheRequestSeesWhatItStored", func(t *testing.T) {
		// A later read in the same request reads the session as stored, the step's change on the
		// fresh values, not the copy the request began with.
		ceremonyStore, store, _ := newRealStore(t)
		cookies, stepReq, loaded := loadedStep(t, ceremonyStore)

		other := browserRequest(cookies)
		sess, err := store.Get(other, realStoreSessionName)
		require.NoError(t, err)
		sess.Values["unrelated"] = "written meanwhile"
		require.NoError(t, store.Save(other, httptest.NewRecorder(), sess))

		loaded.AuthState = AuthStateLevel1Password
		require.NoError(t, ceremonyStore.SaveAuthContext(httptest.NewRecorder(), stepReq, loaded))

		same, err := store.Get(stepReq, realStoreSessionName)
		require.NoError(t, err)
		assert.Equal(t, "written meanwhile", same.Values["unrelated"])
		authContext, err := ceremonyStore.GetAuthContext(stepReq)
		require.NoError(t, err)
		assert.Equal(t, AuthStateLevel1Password, authContext.AuthState)
	})

	t.Run("ASessionNeverStoredHoldsNoCeremony", func(t *testing.T) {
		ceremonyStore, _, _ := newRealStore(t)
		rr := httptest.NewRecorder()

		err := ceremonyStore.SaveAuthContext(rr, browserRequest(nil), &AuthContext{CeremonyId: ceremonyA})

		require.ErrorIs(t, err, ErrCeremonyReplaced, "only /auth/authorize starts a ceremony")
		assert.Empty(t, rr.Result().Cookies(), "no row is created for it, and no cookie names one")
	})

	t.Run("AStoredContextNamingNoCeremonyIsNotOwned", func(t *testing.T) {
		// A context from before #79 carries no ceremony id, and "" is never matched against "",
		// as ceremonyMatches refuses it for the same reason.
		ceremonyStore, store, _ := newRealStore(t)
		cookies := seedBrowserSession(t, store, map[string]any{
			sessionkeys.AuthContext: authContextJSON(t, &AuthContext{ClientId: "test-client"}),
		})
		stepReq := browserRequest(cookies)
		loaded, err := ceremonyStore.GetAuthContext(stepReq)
		require.NoError(t, err)

		loaded.AuthState = AuthStateLevel1Password
		err = ceremonyStore.SaveAuthContext(httptest.NewRecorder(), stepReq, loaded)

		require.ErrorIs(t, err, ErrCeremonyReplaced)
	})

	t.Run("SessionError", func(t *testing.T) {
		ceremonyStore, store, backend := newRealStore(t)
		cookies := seedBrowserSession(t, store, map[string]any{"unrelated": "value"})
		backend.failLoad = true
		rr := httptest.NewRecorder()

		err := ceremonyStore.SaveAuthContext(rr, browserRequest(cookies), &AuthContext{CeremonyId: ceremonyA})

		require.ErrorIs(t, err, errLoadRefused)
		assert.Empty(t, rr.Result().Cookies(), "a session that could not be read is not written")
	})

	t.Run("AFreshReadThatFailsIsNotReplaced", func(t *testing.T) {
		// A backend fault on the step's own fresh read is a fault, the 500 a failed save answers,
		// and not a ceremony the browser replaced.
		ceremonyStore, _, backend := newRealStore(t)
		_, stepReq, loaded := loadedStep(t, ceremonyStore)
		backend.failLoad = true
		rr := httptest.NewRecorder()

		err := ceremonyStore.SaveAuthContext(rr, stepReq, loaded)

		require.ErrorIs(t, err, errLoadRefused)
		require.NotErrorIs(t, err, ErrCeremonyReplaced)
		assert.Empty(t, rr.Result().Cookies())
	})
}

// ReplaceAuthContext is /auth/authorize's save, which starts a ceremony and so replaces whatever
// the browser session held, as every save did before #579.
func TestReplaceAuthContext(t *testing.T) {
	t.Run("StartsACeremonyInABrowserWithNoSession", func(t *testing.T) {
		ceremonyStore, _, _ := newRealStore(t)
		rr := httptest.NewRecorder()

		err := ceremonyStore.ReplaceAuthContext(rr, browserRequest(nil), &AuthContext{CeremonyId: "c", ClientId: "test-client"})
		require.NoError(t, err)

		result, err := ceremonyStore.GetAuthContext(replayThroughJar(t, rr.Result(), nil))
		require.NoError(t, err)
		assert.Equal(t, "test-client", result.ClientId)
	})

	t.Run("ReplacesTheCeremonyTheSessionHeld", func(t *testing.T) {
		ceremonyStore, store, _ := newRealStore(t)
		cookies := seedBrowserSession(t, store, map[string]any{
			sessionkeys.AuthContext: authContextJSON(t, &AuthContext{CeremonyId: "older", ClientId: "client-a"}),
		})

		err := ceremonyStore.ReplaceAuthContext(httptest.NewRecorder(), browserRequest(cookies),
			&AuthContext{CeremonyId: "newer", ClientId: "client-b"})
		require.NoError(t, err)

		result, err := ceremonyStore.GetAuthContext(browserRequest(cookies))
		require.NoError(t, err)
		assert.Equal(t, "newer", result.CeremonyId)
		assert.Equal(t, "client-b", result.ClientId)
	})

	t.Run("SaveError", func(t *testing.T) {
		ceremonyStore, _, backend := newRealStore(t)
		backend.failCreate = true
		rr := httptest.NewRecorder()

		err := ceremonyStore.ReplaceAuthContext(rr, browserRequest(nil), &AuthContext{ClientId: "test-client"})

		require.ErrorIs(t, err, errCreateRefused)
		assert.Empty(t, rr.Result().Cookies(), "no cookie names a row that was never written")
	})
}

// The fixtures below back every case in this file, each of which drives a real store over an
// in-memory backend and reads the result back as the browser's next request would. The
// RealStore* subtests of TestClearAuthContext are the ones about the wire: a store's in-memory
// state says nothing about it, which is how seven handlers came to clear the auth context after
// committing the client response, where the header is never sent (#141).
//
// There is no mock store here since #431. Store's port names Regenerate, which the
// generated sessionstore mock does not have, and RegenerateSession's only test used to be the
// no-op a mock produced. A failure is reached through armableBackend instead.
//
// A ServerSideStore over an in-memory backend since #266. Which half of a clear these cases
// observe changed with it, and the change is worth having: under the cookie store the Set-Cookie
// was the only way a deletion reached anything, so a dropped header meant a retained auth
// context. Now the row is written whether or not the header ships, and the ordering matters for
// what the browser is told rather than for what the server believes. See
// RealStoreClearAfterCommitIsDropped, which is where that difference is pinned.
const (
	realStoreSessionName = "test-session"
	realStoreBaseURL     = "https://as.example.com"
	// Where a refused ceremony sends the client, and the commit these cases order against.
	clientRefusalURL = "https://example.com/callback?error=access_denied"
)

// errLoadRefused and errCreateRefused are what armableBackend answers when armed, so a case can
// tell its own failure from any other with errors.Is through the store's wrapping.
var (
	errLoadRefused   = errors.New("the backend refused the read")
	errCreateRefused = errors.New("the backend refused the write")
	errUpdateRefused = errors.New("the backend refused the update")
)

// armableBackend is the in-memory backend with the two operations Store reaches through the
// store made to fail on demand, once a session has been seeded. It is the admin console's
// callback pattern (#427): the shared MemoryBackend injects nothing, and a test that needs one
// failure wraps it in a type of its own.
type armableBackend struct {
	*sessiontest.MemoryBackend
	failLoad   bool
	failCreate bool
	failUpdate bool

	// created counts the rows written, so a case can say no row was created for a browser that
	// held none.
	created int
}

func (b *armableBackend) Load(ctx context.Context, id string) (*sessionstore.Record, error) {
	if b.failLoad {
		return nil, errLoadRefused
	}
	return b.MemoryBackend.Load(ctx, id)
}

func (b *armableBackend) Create(ctx context.Context, id string, data []byte, authenticated bool) (time.Time, error) {
	if b.failCreate {
		return time.Time{}, errCreateRefused
	}
	b.created++
	return b.MemoryBackend.Create(ctx, id, data, authenticated)
}

func (b *armableBackend) Update(ctx context.Context, id string, data []byte, authenticated bool) (time.Time, error) {
	if b.failUpdate {
		return time.Time{}, errUpdateRefused
	}
	return b.MemoryBackend.Update(ctx, id, data, authenticated)
}

func (b *armableBackend) UpdateIfUnchanged(ctx context.Context, id string, expected, data []byte, authenticated bool) (time.Time, error) {
	if b.failUpdate {
		return time.Time{}, errUpdateRefused
	}
	return b.MemoryBackend.UpdateIfUnchanged(ctx, id, expected, data, authenticated)
}

// newRealStore returns the Store, the session store behind it and the backend behind that. The
// store is returned because requireSessionDecoded needs to read a replayed session directly, which
// is the only way to tell a valid cleared session from an unreadable one; the backend so a case can
// arm a failure.
func newRealStore(t *testing.T) (*Store, *sessionstore.ServerSideStore, *armableBackend) {
	t.Helper()
	authKey := []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	encKey := []byte("0123456789abcdef0123456789abcdef")
	backend := &armableBackend{MemoryBackend: sessiontest.NewMemoryBackend()}
	store, err := sessionstore.NewServerSideStore(backend,
		sessionkeys.SessionIdentifier, false, sessionstore.PersistentCookie,
		sessionstore.KeyPair{AuthenticationKey: authKey, EncryptionKey: encKey}, nil)
	if err != nil {
		// The keys are literals above and the derivation cannot fail on them, so this is
		// unreachable. Panicking rather than dropping it keeps it that way.
		panic(err)
	}
	conditional, err := sessionstore.NewConditionalStore(store, backend)
	require.NoError(t, err)

	return NewStore(conditional, realStoreSessionName), store, backend
}

// seedBrowserSession stores values as a browser's session and returns the cookies that name it.
func seedBrowserSession(t *testing.T, store *sessionstore.ServerSideStore, values map[string]any) []*http.Cookie {
	t.Helper()
	req := browserRequest(nil)
	sess, err := store.Get(req, realStoreSessionName)
	require.NoError(t, err)
	for k, v := range values {
		sess.Values[k] = v
	}
	rr := httptest.NewRecorder()
	require.NoError(t, store.Save(req, rr, sess))
	cookies := rr.Result().Cookies()
	require.Len(t, cookies, 1)
	return cookies
}

// browserRequest is a fresh request carrying cookies, as the browser's next request would. A fresh
// one each time, because the store memoises a session on the request it loaded it for.
func browserRequest(cookies []*http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodGet, realStoreBaseURL+"/auth/issue", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

// authContextJSON is an auth context as Store stores it.
func authContextJSON(t *testing.T, authContext *AuthContext) string {
	t.Helper()
	jsonData, err := json.Marshal(authContext)
	require.NoError(t, err)
	return string(jsonData)
}

// sessionIdentifier is the identifier a cookie names, which the store alone can read: comparing
// cookie values proves nothing, since every seal draws a fresh nonce.
func sessionIdentifier(t *testing.T, store *sessionstore.ServerSideStore, cookie *http.Cookie) string {
	t.Helper()
	id, err := store.OpenCookie(realStoreSessionName, cookie.Value)
	require.NoError(t, err)
	return id
}

// requireSessionDecoded proves the session the browser holds on req decoded successfully, and must
// accompany every assertion that the auth context is absent.
//
// The store answers a load failure with a fresh empty session: a cookie that will not decode, a
// cookie naming no row, stored data that will not decode. GetAuthContext finds no auth context in
// that session and reports ErrNoAuthContext, which is the same error a genuine clear produces. So
// ErrNoAuthContext alone cannot distinguish "the clear reached the browser and it decoded" from
// "the clearing write reached the browser corrupt", and a regression that emitted malformed
// clearing state would leave the absence cases green. IsNew is false only when the whole load
// succeeded, so it separates the two (#141).
func requireSessionDecoded(t *testing.T, store *sessionstore.ServerSideStore, req *http.Request) {
	t.Helper()
	sess, err := store.Get(req, realStoreSessionName)
	require.NoError(t, err)
	require.False(t, sess.IsNew,
		"the replayed session did not decode, so an absent auth context proves nothing about the clear")
}

// replayThroughJar pushes a committed response through a real net/http/cookiejar and returns a
// fresh request carrying whatever the browser would then hold. extra is what the browser already
// held beforehand, applied first so the response's own Set-Cookie headers land on top of it, as a
// browser would apply them. This is the only view that answers "what does the browser hold", which
// is the question sess.Values cannot answer.
func replayThroughJar(t *testing.T, res *http.Response, extra []*http.Cookie) *http.Request {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(realStoreBaseURL + "/auth/issue")
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(u, extra)
	jar.SetCookies(u, res.Cookies())

	next := httptest.NewRequest(http.MethodGet, realStoreBaseURL+"/auth/issue", nil)
	for _, c := range jar.Cookies(u) {
		next.AddCookie(c)
	}
	return next
}

// multiChunkAuthContext returns a context whose encoded form spans more than one cookie chunk, so
// every case also covers the stale higher chunks that a one-chunk clearing write leaves behind.
// largeAuthContext is a context far bigger than anything the ceremony normally carries: 400
// scope entries, several kilobytes once encoded. Under the store this replaced it spilled across
// several cookies, which is what the RealStore cases used to be built around. It stays large for
// the opposite reason now: one cookie whatever the payload is the property #266 exists to
// establish, and a fixture that fits comfortably would not test it.
func largeAuthContext() *AuthContext {
	long := ""
	for i := 0; i < 400; i++ {
		long += "scope" + string(rune('a'+i%26)) + ":permission "
	}
	return &AuthContext{
		CeremonyId:  "large-ceremony",
		AuthState:   AuthStateReadyToIssueCode,
		ClientId:    "test-client",
		UserId:      123,
		RedirectURI: "https://example.com/callback",
		State:       "test-state",
		Scope:       long,
	}
}

// ClearAuthContext is a step's clear, which ends the ceremony only while the browser session still
// holds it (#579). The cases mirror TestSaveAuthContext's: the step loads ceremony A, another
// request of the same browser writes in between, and the step clears.
func TestClearAuthContext(t *testing.T) {
	t.Run("ClearsTheCeremonyTheSessionHolds", func(t *testing.T) {
		ceremonyStore, store, _ := newRealStore(t)
		cookies, stepReq, _ := loadedStep(t, ceremonyStore)

		err := ceremonyStore.ClearAuthContext(httptest.NewRecorder(), stepReq, ceremonyA)
		require.NoError(t, err)

		// The row the browser's cookie names is the one the clear emptied.
		_, err = ceremonyStore.GetAuthContext(browserRequest(cookies))
		require.ErrorIs(t, err, ErrNoAuthContext)
		requireSessionDecoded(t, store, browserRequest(cookies))
	})

	t.Run("AnotherCeremonyWrittenInBetweenIsNotCleared", func(t *testing.T) {
		// The issue's interleaving at an error answer or at issuance: tab A's step has loaded
		// ceremony A, tab B's /auth/authorize replaces it with ceremony B, and tab A's step ends.
		ceremonyStore, _, _ := newRealStore(t)
		cookies, stepReq, _ := loadedStep(t, ceremonyStore)

		require.NoError(t, ceremonyStore.ReplaceAuthContext(httptest.NewRecorder(), browserRequest(cookies),
			&AuthContext{CeremonyId: ceremonyB, ClientId: "client-b", AuthState: AuthStateRequiresLevel1}))

		rr := httptest.NewRecorder()
		err := ceremonyStore.ClearAuthContext(rr, stepReq, ceremonyA)

		require.ErrorIs(t, err, ErrCeremonyReplaced)
		assert.Empty(t, rr.Result().Cookies(), "a clear that wrote nothing tells the browser nothing")
		stored, err := ceremonyStore.GetAuthContext(browserRequest(cookies))
		require.NoError(t, err)
		assert.Equal(t, ceremonyB, stored.CeremonyId, "the newer ceremony is what the browser session keeps")
		assert.Equal(t, "client-b", stored.ClientId)
	})

	t.Run("NoCeremonyLeftInBetweenWritesNothing", func(t *testing.T) {
		ceremonyStore, store, _ := newRealStore(t)
		cookies, stepReq, _ := loadedStep(t, ceremonyStore)

		other := browserRequest(cookies)
		sess, err := store.Get(other, realStoreSessionName)
		require.NoError(t, err)
		delete(sess.Values, sessionkeys.AuthContext)
		sess.Values["unrelated"] = "written meanwhile"
		require.NoError(t, store.Save(other, httptest.NewRecorder(), sess))

		rr := httptest.NewRecorder()
		err = ceremonyStore.ClearAuthContext(rr, stepReq, ceremonyA)

		require.ErrorIs(t, err, ErrCeremonyReplaced)
		assert.Empty(t, rr.Result().Cookies())
		stored, err := store.Get(browserRequest(cookies), realStoreSessionName)
		require.NoError(t, err)
		assert.Equal(t, "written meanwhile", stored.Values["unrelated"])
	})

	t.Run("ASessionGoneInBetweenIsNotRecreated", func(t *testing.T) {
		ceremonyStore, store, backend := newRealStore(t)
		cookies, stepReq, _ := loadedStep(t, ceremonyStore)
		createdBefore := backend.created

		require.NoError(t, backend.Delete(context.Background(), sessionIdentifier(t, store, cookies[0])))

		rr := httptest.NewRecorder()
		err := ceremonyStore.ClearAuthContext(rr, stepReq, ceremonyA)

		require.ErrorIs(t, err, ErrCeremonyReplaced)
		assert.Empty(t, rr.Result().Cookies())
		assert.Equal(t, createdBefore, backend.created, "no row is written in place of the one that is gone")
		_, err = backend.Load(context.Background(), sessionIdentifier(t, store, cookies[0]))
		require.ErrorIs(t, err, sessionstore.ErrNotFound)
	})

	t.Run("ASessionNeverStoredWritesNothing", func(t *testing.T) {
		// A browser that holds no session holds no ceremony, so there is nothing of this step's to
		// clear and nothing is created to clear it in.
		ceremonyStore, _, backend := newRealStore(t)
		rr := httptest.NewRecorder()

		err := ceremonyStore.ClearAuthContext(rr, browserRequest(nil), ceremonyA)

		require.ErrorIs(t, err, ErrCeremonyReplaced)
		assert.Empty(t, rr.Result().Cookies(), "no cookie names a session")
		assert.Zero(t, backend.created, "no row is created")
	})

	t.Run("AnUnrelatedWriteInBetweenIsKept", func(t *testing.T) {
		ceremonyStore, store, _ := newRealStore(t)
		cookies, stepReq, _ := loadedStep(t, ceremonyStore)

		other := browserRequest(cookies)
		sess, err := store.Get(other, realStoreSessionName)
		require.NoError(t, err)
		sess.Values["unrelated"] = "written meanwhile"
		require.NoError(t, store.Save(other, httptest.NewRecorder(), sess))

		require.NoError(t, ceremonyStore.ClearAuthContext(httptest.NewRecorder(), stepReq, ceremonyA))

		stored, err := store.Get(browserRequest(cookies), realStoreSessionName)
		require.NoError(t, err)
		assert.Equal(t, "written meanwhile", stored.Values["unrelated"])
		_, err = ceremonyStore.GetAuthContext(browserRequest(cookies))
		require.ErrorIs(t, err, ErrNoAuthContext)
	})

	t.Run("SessionError", func(t *testing.T) {
		ceremonyStore, store, backend := newRealStore(t)
		cookies := seedBrowserSession(t, store, map[string]any{
			sessionkeys.AuthContext: authContextJSON(t, &AuthContext{CeremonyId: ceremonyA, ClientId: "test-client"}),
		})
		backend.failLoad = true
		rr := httptest.NewRecorder()

		err := ceremonyStore.ClearAuthContext(rr, browserRequest(cookies), ceremonyA)

		require.ErrorIs(t, err, errLoadRefused)
		require.NotErrorIs(t, err, ErrCeremonyReplaced)
		assert.Empty(t, rr.Result().Cookies())
	})

	t.Run("SaveError", func(t *testing.T) {
		// A write the backend refuses is a fault, the 500 a failed clear answers, and not a
		// ceremony the browser replaced.
		ceremonyStore, _, backend := newRealStore(t)
		_, stepReq, _ := loadedStep(t, ceremonyStore)
		backend.failUpdate = true
		rr := httptest.NewRecorder()

		err := ceremonyStore.ClearAuthContext(rr, stepReq, ceremonyA)

		require.ErrorIs(t, err, errUpdateRefused)
		require.NotErrorIs(t, err, ErrCeremonyReplaced)
		assert.Empty(t, rr.Result().Cookies())
	})

	t.Run("RealStoreClearBeforeCommitReachesBrowser", func(t *testing.T) {
		ceremonyStore, store, _ := newRealStore(t)

		seedReq := httptest.NewRequest(http.MethodGet, realStoreBaseURL+"/auth/issue", nil)
		seedRR := httptest.NewRecorder()
		err := ceremonyStore.ReplaceAuthContext(seedRR, seedReq, largeAuthContext())
		require.NoError(t, err)

		seedRes := seedRR.Result()
		// Exactly one cookie, for a context of several kilobytes. That is the whole of #266 in
		// one assertion, and it is the inverse of what this line used to say: the store this
		// replaced answered the same fixture with a master cookie plus at least two chunks.
		assert.Len(t, seedRes.Cookies(), 1)

		browserReq := replayThroughJar(t, seedRes, nil)

		rr := httptest.NewRecorder()
		err = ceremonyStore.ClearAuthContext(rr, browserReq, largeAuthContext().CeremonyId)
		require.NoError(t, err)
		http.Redirect(rr, browserReq, clientRefusalURL, http.StatusFound)

		res := rr.Result()
		// A response carrying no cookies at all would satisfy the jar assertion below for entirely
		// the wrong reason, so pin that the clear did write something.
		assert.NotEmpty(t, res.Cookies())

		replayed := replayThroughJar(t, res, seedRes.Cookies())
		_, err = ceremonyStore.GetAuthContext(replayed)
		require.ErrorIs(t, err, ErrNoAuthContext)
		requireSessionDecoded(t, store, replayed)
	})

	t.Run("RealStoreClearAfterCommitIsDropped", func(t *testing.T) {
		// This case asserts the defect, and it is expected to keep passing once the handler sites
		// are reordered, because it drives the Store directly and no handler. It is what makes
		// the other three cases mean something: delete it as obsolete and nothing is left recording
		// why the ordering is load-bearing rather than a matter of style (#141).
		//
		// What the dropped response costs changed with #266, and this is the only place it is
		// recorded. Under the cookie store the Set-Cookie was the entire clear, so a committed
		// response meant the browser kept a working auth context. The clear now writes a row
		// first, and that write lands whether or not the header ships, so the context is gone
		// server-side even here. The ordering still matters, for the cookie rather than for the
		// context, and the failure it causes is now a user losing a ceremony rather than a
		// refused ceremony staying usable, which is the safe direction to fail in.
		ceremonyStore, store, _ := newRealStore(t)

		seedReq := httptest.NewRequest(http.MethodGet, realStoreBaseURL+"/auth/issue", nil)
		seedRR := httptest.NewRecorder()
		err := ceremonyStore.ReplaceAuthContext(seedRR, seedReq, largeAuthContext())
		require.NoError(t, err)

		seedRes := seedRR.Result()
		browserReq := replayThroughJar(t, seedRes, nil)

		rr := httptest.NewRecorder()
		http.Redirect(rr, browserReq, clientRefusalURL, http.StatusFound)
		err = ceremonyStore.ClearAuthContext(rr, browserReq, largeAuthContext().CeremonyId)
		require.NoError(t, err)

		res := rr.Result()
		// The clear succeeded and its Set-Cookie header is in the live header map, but the
		// response was committed before it was written, so it does not reach the wire.
		assert.Empty(t, res.Cookies())

		// The browser therefore still holds the cookie it was seeded with. It names the row the
		// clear emptied, so the auth context is gone anyway.
		replayed := replayThroughJar(t, res, seedRes.Cookies())
		_, err = ceremonyStore.GetAuthContext(replayed)
		require.ErrorIs(t, err, ErrNoAuthContext)
		// And the session still loads, which is what separates "the clear landed" from "the
		// browser is holding something unreadable".
		requireSessionDecoded(t, store, replayed)
	})
}

// DiscardAuthContext is /auth/authorize's clear, before its immediate error answer. It starts no
// step of a ceremony, so it holds no ceremony to check: it ends whatever the browser session held,
// as /auth/authorize's own saves replace it. But a browser that holds no stored session gets no
// row and no cookie for the clear of nothing (#579 decision 6).
func TestDiscardAuthContext(t *testing.T) {
	t.Run("ClearsWhateverCeremonyTheSessionHolds", func(t *testing.T) {
		ceremonyStore, store, _ := newRealStore(t)
		cookies := seedBrowserSession(t, store, map[string]any{
			sessionkeys.AuthContext: authContextJSON(t, &AuthContext{CeremonyId: ceremonyB, ClientId: "client-b"}),
		})

		rr := httptest.NewRecorder()
		require.NoError(t, ceremonyStore.DiscardAuthContext(rr, browserRequest(cookies)))

		assert.NotEmpty(t, rr.Result().Cookies())
		_, err := ceremonyStore.GetAuthContext(browserRequest(cookies))
		require.ErrorIs(t, err, ErrNoAuthContext)
		requireSessionDecoded(t, store, browserRequest(cookies))
	})

	t.Run("ABrowserWithNoSessionGetsNoRowAndNoCookie", func(t *testing.T) {
		ceremonyStore, _, backend := newRealStore(t)
		rr := httptest.NewRecorder()

		require.NoError(t, ceremonyStore.DiscardAuthContext(rr, browserRequest(nil)))

		assert.Empty(t, rr.Result().Cookies(), "no cookie names a session holding nothing")
		assert.Zero(t, backend.created, "no row is created to hold nothing")
	})

	t.Run("ABrowserWhoseSessionIsGoneGetsNoRowAndNoCookie", func(t *testing.T) {
		// A cookie naming a row that has expired or was removed is a browser with no stored
		// session, as the store reads it.
		ceremonyStore, store, backend := newRealStore(t)
		cookies := seedBrowserSession(t, store, map[string]any{
			sessionkeys.AuthContext: authContextJSON(t, &AuthContext{CeremonyId: ceremonyB}),
		})
		require.NoError(t, backend.Delete(context.Background(), sessionIdentifier(t, store, cookies[0])))
		createdBefore := backend.created
		rr := httptest.NewRecorder()

		require.NoError(t, ceremonyStore.DiscardAuthContext(rr, browserRequest(cookies)))

		assert.Empty(t, rr.Result().Cookies())
		assert.Equal(t, createdBefore, backend.created)
	})

	t.Run("SessionError", func(t *testing.T) {
		ceremonyStore, store, backend := newRealStore(t)
		cookies := seedBrowserSession(t, store, map[string]any{
			sessionkeys.AuthContext: authContextJSON(t, &AuthContext{CeremonyId: ceremonyB}),
		})
		backend.failLoad = true
		rr := httptest.NewRecorder()

		err := ceremonyStore.DiscardAuthContext(rr, browserRequest(cookies))

		require.ErrorIs(t, err, errLoadRefused)
		assert.Empty(t, rr.Result().Cookies())
	})

	t.Run("SaveError", func(t *testing.T) {
		ceremonyStore, store, backend := newRealStore(t)
		cookies := seedBrowserSession(t, store, map[string]any{
			sessionkeys.AuthContext: authContextJSON(t, &AuthContext{CeremonyId: ceremonyB}),
		})
		backend.failUpdate = true
		rr := httptest.NewRecorder()

		err := ceremonyStore.DiscardAuthContext(rr, browserRequest(cookies))

		require.ErrorIs(t, err, errUpdateRefused)
		assert.Empty(t, rr.Result().Cookies())
	})

	t.Run("RealStoreSaveThenClearLastWins", func(t *testing.T) {
		// The /auth/authorize shape at sites 1 and 2: ReplaceAuthContext has already written the
		// context earlier in the same response, so clearing before the commit puts two session
		// writes, under duplicate cookie names, in one response. Both must reach the wire and the
		// later one must win (#141).
		ceremonyStore, store, _ := newRealStore(t)

		req := httptest.NewRequest(http.MethodGet, realStoreBaseURL+"/auth/authorize?client_id=test-client", nil)
		rr := httptest.NewRecorder()

		err := ceremonyStore.ReplaceAuthContext(rr, req, largeAuthContext())
		require.NoError(t, err)
		err = ceremonyStore.DiscardAuthContext(rr, req)
		require.NoError(t, err)
		http.Redirect(rr, req, clientRefusalURL, http.StatusFound)

		res := rr.Result()
		counts := map[string]int{}
		for _, c := range res.Cookies() {
			counts[c.Name]++
		}
		// Both writes are on the wire, rather than the second having replaced the first in the
		// header map. Each names the same session under the same single cookie, since the second
		// save updates the row the first created rather than starting another.
		assert.Equal(t, 2, counts[realStoreSessionName])
		assert.Len(t, counts, 1, "a session costs one cookie name, however many times it is saved")

		replayed := replayThroughJar(t, res, nil)
		_, err = ceremonyStore.GetAuthContext(replayed)
		require.ErrorIs(t, err, ErrNoAuthContext)
		requireSessionDecoded(t, store, replayed)
	})

	t.Run("RealStoreClearThenSaveLastWins", func(t *testing.T) {
		// Control for the case above. Without it, that case passes just as well if the jar simply
		// discards everything when a cookie name repeats, which would make it evidence of nothing.
		// Here the later write is the save, so the jar must keep the context. The browser holds a
		// session already, so the clear writes too and both reach the wire.
		//
		// No requireSessionDecoded here either: keeping the context requires a successful decode.
		ceremonyStore, store, _ := newRealStore(t)
		cookies := seedBrowserSession(t, store, map[string]any{
			sessionkeys.AuthContext: authContextJSON(t, &AuthContext{CeremonyId: ceremonyB}),
		})

		req := httptest.NewRequest(http.MethodGet, realStoreBaseURL+"/auth/authorize?client_id=test-client", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()

		err := ceremonyStore.DiscardAuthContext(rr, req)
		require.NoError(t, err)
		err = ceremonyStore.ReplaceAuthContext(rr, req, largeAuthContext())
		require.NoError(t, err)
		http.Redirect(rr, req, clientRefusalURL, http.StatusFound)

		res := rr.Result()
		require.Len(t, res.Cookies(), 2, "both writes reach the wire, or this controls nothing")
		authContext, err := ceremonyStore.GetAuthContext(replayThroughJar(t, res, nil))
		require.NoError(t, err)
		assert.Equal(t, AuthStateReadyToIssueCode, authContext.AuthState)
	})
}

// RegenerateSession is what the auth server's handlers call at a privilege change. It drives the real
// store and reads the outcome back through the cookies a browser would hold (#266, #431). Since #579
// it rotates only while the browser session still holds the ceremony the step loaded, building the
// new row from the session as it is stored now, and the cases after the first three are about that:
// the step loads ceremony A, another request of the same browser writes in between, and the step
// rotates.
func TestRegenerateSession(t *testing.T) {
	t.Run("Rotates", func(t *testing.T) {
		ceremonyStore, store, _ := newRealStore(t)
		cookies, stepReq, _ := loadedStep(t, ceremonyStore)
		rr := httptest.NewRecorder()

		require.NoError(t, ceremonyStore.RegenerateSession(rr, stepReq, ceremonyA))

		rotated := rr.Result().Cookies()
		require.Len(t, rotated, 1, "the browser is told the new identifier, once")
		assert.NotEqual(t, sessionIdentifier(t, store, cookies[0]), sessionIdentifier(t, store, rotated[0]),
			"the new cookie names a different identifier")

		authContext, err := ceremonyStore.GetAuthContext(browserRequest(rotated))
		require.NoError(t, err, "the session's contents survive the rotation")
		assert.Equal(t, ceremonyA, authContext.CeremonyId)
		assert.Equal(t, "client-a", authContext.ClientId)

		old, err := store.Get(browserRequest(cookies), realStoreSessionName)
		require.NoError(t, err)
		assert.True(t, old.IsNew, "the identifier the browser brought names nothing any more")
	})

	t.Run("LoadFails", func(t *testing.T) {
		ceremonyStore, _, backend := newRealStore(t)
		_, stepReq, _ := loadedStep(t, ceremonyStore)
		backend.failLoad = true
		rr := httptest.NewRecorder()

		err := ceremonyStore.RegenerateSession(rr, stepReq, ceremonyA)

		require.ErrorIs(t, err, errLoadRefused)
		require.NotErrorIs(t, err, ErrCeremonyReplaced, "a backend fault is not a ceremony the browser replaced")
		assert.Empty(t, rr.Result().Cookies(), "no cookie is written")
	})

	t.Run("CreateFails", func(t *testing.T) {
		ceremonyStore, _, backend := newRealStore(t)
		cookies, stepReq, _ := loadedStep(t, ceremonyStore)
		backend.failCreate = true
		rr := httptest.NewRecorder()

		err := ceremonyStore.RegenerateSession(rr, stepReq, ceremonyA)

		require.ErrorIs(t, err, errCreateRefused)
		assert.Empty(t, rr.Result().Cookies(), "no cookie is written")

		backend.failCreate = false
		authContext, err := ceremonyStore.GetAuthContext(browserRequest(cookies))
		require.NoError(t, err, "the old session is intact: nothing was deleted before the new row existed")
		assert.Equal(t, ceremonyA, authContext.CeremonyId)
	})

	t.Run("AnotherCeremonyWrittenInBetweenIsNotPutBack", func(t *testing.T) {
		// The issue's interleaving at a rotation: tab A's password step has loaded ceremony A, tab
		// B's /auth/authorize replaces it with ceremony B, and tab A rotates. A rotation from the
		// request's own copy would write ceremony A under the new identifier and delete the row
		// holding ceremony B.
		ceremonyStore, _, backend := newRealStore(t)
		cookies, stepReq, _ := loadedStep(t, ceremonyStore)
		require.NoError(t, ceremonyStore.ReplaceAuthContext(httptest.NewRecorder(), browserRequest(cookies),
			&AuthContext{CeremonyId: ceremonyB, ClientId: "client-b", AuthState: AuthStateRequiresLevel1}))
		created := backend.created

		rr := httptest.NewRecorder()
		err := ceremonyStore.RegenerateSession(rr, stepReq, ceremonyA)

		require.ErrorIs(t, err, ErrCeremonyReplaced)
		assert.Empty(t, rr.Result().Cookies(), "a step that rotated nothing tells the browser nothing")
		assert.Equal(t, created, backend.created, "no row is written under a new identifier")
		stored, err := ceremonyStore.GetAuthContext(browserRequest(cookies))
		require.NoError(t, err, "the browser's identifier still names its session")
		assert.Equal(t, ceremonyB, stored.CeremonyId, "the newer ceremony is what the browser session keeps")
		assert.Equal(t, "client-b", stored.ClientId)
	})

	t.Run("NoCeremonyLeftInBetweenIsNotPutBack", func(t *testing.T) {
		ceremonyStore, store, _ := newRealStore(t)
		cookies, stepReq, _ := loadedStep(t, ceremonyStore)

		other := browserRequest(cookies)
		sess, err := store.Get(other, realStoreSessionName)
		require.NoError(t, err)
		delete(sess.Values, sessionkeys.AuthContext)
		require.NoError(t, store.Save(other, httptest.NewRecorder(), sess))

		rr := httptest.NewRecorder()
		err = ceremonyStore.RegenerateSession(rr, stepReq, ceremonyA)

		require.ErrorIs(t, err, ErrCeremonyReplaced)
		assert.Empty(t, rr.Result().Cookies())
		_, err = ceremonyStore.GetAuthContext(browserRequest(cookies))
		require.ErrorIs(t, err, ErrNoAuthContext, "the ended ceremony stays ended")
		requireSessionDecoded(t, store, browserRequest(cookies))
	})

	t.Run("ASessionGoneInBetweenIsNotRecreated", func(t *testing.T) {
		// Signed out in another tab, rotated away by another request of this browser, or expired.
		// A rotation used to re-create the session from the request's own copy under a new name,
		// which is what would let a stalled step end a newer ceremony that had passed its own
		// rotation meanwhile (#579 decision 3).
		ceremonyStore, store, backend := newRealStore(t)
		cookies, stepReq, _ := loadedStep(t, ceremonyStore)
		require.NoError(t, backend.Delete(context.Background(), sessionIdentifier(t, store, cookies[0])))
		created := backend.created

		rr := httptest.NewRecorder()
		err := ceremonyStore.RegenerateSession(rr, stepReq, ceremonyA)

		require.ErrorIs(t, err, ErrCeremonyReplaced)
		assert.Empty(t, rr.Result().Cookies())
		assert.Equal(t, created, backend.created, "the request's own copy is not put back under a new name")
	})

	t.Run("ASessionNeverStoredHoldsNoCeremony", func(t *testing.T) {
		ceremonyStore, _, backend := newRealStore(t)
		rr := httptest.NewRecorder()

		err := ceremonyStore.RegenerateSession(rr, browserRequest(nil), ceremonyA)

		require.ErrorIs(t, err, ErrCeremonyReplaced)
		assert.Empty(t, rr.Result().Cookies())
		assert.Zero(t, backend.created, "no row is created for a ceremony the browser does not hold")
	})

	t.Run("AnUnrelatedWriteInBetweenIsKept", func(t *testing.T) {
		// The new row is built from the session as it is stored now, not from the copy the request
		// began with, so a value another request wrote meanwhile goes with it.
		ceremonyStore, store, _ := newRealStore(t)
		cookies, stepReq, _ := loadedStep(t, ceremonyStore)

		other := browserRequest(cookies)
		sess, err := store.Get(other, realStoreSessionName)
		require.NoError(t, err)
		sess.Values["unrelated"] = "written meanwhile"
		require.NoError(t, store.Save(other, httptest.NewRecorder(), sess))

		rr := httptest.NewRecorder()
		require.NoError(t, ceremonyStore.RegenerateSession(rr, stepReq, ceremonyA))

		rotated := rr.Result().Cookies()
		require.Len(t, rotated, 1)
		stored, err := store.Get(browserRequest(rotated), realStoreSessionName)
		require.NoError(t, err)
		assert.Equal(t, "written meanwhile", stored.Values["unrelated"])

		// The request's own session is the rotated one, so the step's save after it lands there.
		authContext, err := ceremonyStore.GetAuthContext(stepReq)
		require.NoError(t, err)
		authContext.AuthState = AuthStateLevel1PasswordCompleted
		require.NoError(t, ceremonyStore.SaveAuthContext(httptest.NewRecorder(), stepReq, authContext))
		saved, err := ceremonyStore.GetAuthContext(browserRequest(rotated))
		require.NoError(t, err)
		assert.Equal(t, AuthStateLevel1PasswordCompleted, saved.AuthState)
	})
}

// ConfirmCeremony is /auth/completed's create arm asking, before it ends or creates anything, whether
// the browser session still holds its ceremony (#579 decision 4). It reads the session afresh and
// writes nothing either way.
func TestConfirmCeremony(t *testing.T) {
	t.Run("AnswersNilWhileTheSessionHoldsItsCeremony", func(t *testing.T) {
		ceremonyStore, store, backend := newRealStore(t)
		cookies, stepReq, _ := loadedStep(t, ceremonyStore)
		stored, err := backend.Load(context.Background(), sessionIdentifier(t, store, cookies[0]))
		require.NoError(t, err)
		before := append([]byte(nil), stored.Data...)
		created := backend.created
		rr := httptest.NewRecorder()

		require.NoError(t, ceremonyStore.ConfirmCeremony(rr, stepReq, ceremonyA))

		assert.Empty(t, rr.Result().Cookies(), "a confirmation writes nothing")
		assert.Equal(t, created, backend.created)
		after, err := backend.Load(context.Background(), sessionIdentifier(t, store, cookies[0]))
		require.NoError(t, err)
		assert.Equal(t, before, after.Data, "the stored session is untouched")
	})

	t.Run("AnotherCeremonyWrittenInBetween", func(t *testing.T) {
		// Read afresh: the request's own copy still holds ceremony A.
		ceremonyStore, _, _ := newRealStore(t)
		cookies, stepReq, _ := loadedStep(t, ceremonyStore)
		require.NoError(t, ceremonyStore.ReplaceAuthContext(httptest.NewRecorder(), browserRequest(cookies),
			&AuthContext{CeremonyId: ceremonyB, ClientId: "client-b", AuthState: AuthStateRequiresLevel1}))
		rr := httptest.NewRecorder()

		err := ceremonyStore.ConfirmCeremony(rr, stepReq, ceremonyA)

		require.ErrorIs(t, err, ErrCeremonyReplaced)
		assert.Empty(t, rr.Result().Cookies())
		stored, err := ceremonyStore.GetAuthContext(browserRequest(cookies))
		require.NoError(t, err)
		assert.Equal(t, ceremonyB, stored.CeremonyId)
	})

	t.Run("ASessionGoneInBetween", func(t *testing.T) {
		ceremonyStore, store, backend := newRealStore(t)
		cookies, stepReq, _ := loadedStep(t, ceremonyStore)
		require.NoError(t, backend.Delete(context.Background(), sessionIdentifier(t, store, cookies[0])))
		rr := httptest.NewRecorder()

		err := ceremonyStore.ConfirmCeremony(rr, stepReq, ceremonyA)

		require.ErrorIs(t, err, ErrCeremonyReplaced)
		assert.Empty(t, rr.Result().Cookies())
	})

	t.Run("ASessionNeverStoredHoldsNoCeremony", func(t *testing.T) {
		ceremonyStore, _, backend := newRealStore(t)
		rr := httptest.NewRecorder()

		err := ceremonyStore.ConfirmCeremony(rr, browserRequest(nil), ceremonyA)

		require.ErrorIs(t, err, ErrCeremonyReplaced)
		assert.Empty(t, rr.Result().Cookies())
		assert.Zero(t, backend.created)
	})

	t.Run("AFreshReadThatFailsIsNotReplaced", func(t *testing.T) {
		ceremonyStore, _, backend := newRealStore(t)
		_, stepReq, _ := loadedStep(t, ceremonyStore)
		backend.failLoad = true

		err := ceremonyStore.ConfirmCeremony(httptest.NewRecorder(), stepReq, ceremonyA)

		require.ErrorIs(t, err, errLoadRefused)
		require.NotErrorIs(t, err, ErrCeremonyReplaced)
	})
}

// lastAttemptBackend is the in-memory backend with a turn for the test before every conditional
// comparison, which is where another request of the browser can land between a step's fresh read
// and its write. It records the rows it creates, so a case can say every losing rotation's row is
// gone.
type lastAttemptBackend struct {
	*sessiontest.MemoryBackend
	beforeConditional func(id string)
	comparisons       int
	createdIds        []string
}

func (b *lastAttemptBackend) Create(ctx context.Context, id string, data []byte, authenticated bool) (time.Time, error) {
	b.createdIds = append(b.createdIds, id)
	return b.MemoryBackend.Create(ctx, id, data, authenticated)
}

func (b *lastAttemptBackend) UpdateIfUnchanged(ctx context.Context, id string, expected, data []byte, authenticated bool) (time.Time, error) {
	b.comparisons++
	b.beforeConditional(id)
	return b.MemoryBackend.UpdateIfUnchanged(ctx, id, expected, data, authenticated)
}

func (b *lastAttemptBackend) DeleteIfUnchanged(ctx context.Context, id string, expected []byte) error {
	b.comparisons++
	b.beforeConditional(id)
	return b.MemoryBackend.DeleteIfUnchanged(ctx, id, expected)
}

// A step's save, clear and rotation answer a replaced ceremony the same whichever comparison the
// replacement wins: here the first two lose to unrelated writes of the same browser and the third
// to another ceremony, to none, or to the row's removal. The answer is ErrCeremonyReplaced, not the
// fault that losing every attempt to unrelated writes is, so the step answers the "no longer
// active" page and sends nothing to the client (#579 decision 2).
func TestStepWrites_ReplacedAtTheLastAttemptAnswerReplaced(t *testing.T) {
	const lastAttempt = 3
	for _, operation := range []string{"save", "clear", "rotate"} {
		for _, replacement := range []string{"another ceremony", "no ceremony", "the row removed"} {
			t.Run(operation+" finding "+replacement, func(t *testing.T) {
				backend := &lastAttemptBackend{MemoryBackend: sessiontest.NewMemoryBackend()}
				store, err := sessionstore.NewServerSideStore(backend, sessionkeys.SessionIdentifier, false,
					sessionstore.PersistentCookie, sessionstore.KeyPair{
						AuthenticationKey: []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
						EncryptionKey:     []byte("0123456789abcdef0123456789abcdef"),
					}, nil)
				require.NoError(t, err)
				conditional, err := sessionstore.NewConditionalStore(store, backend)
				require.NoError(t, err)
				ceremonyStore := NewStore(conditional, realStoreSessionName)
				cookies, stepReq, loaded := loadedStep(t, ceremonyStore)
				oldId := sessionIdentifier(t, store, cookies[0])

				backend.beforeConditional = func(id string) {
					if backend.comparisons == lastAttempt && replacement == "the row removed" {
						require.NoError(t, backend.Delete(context.Background(), id))
						return
					}
					other := browserRequest(cookies)
					sess, getErr := store.Get(other, realStoreSessionName)
					require.NoError(t, getErr)
					switch {
					case backend.comparisons < lastAttempt:
						sess.Values["unrelated"] = backend.comparisons
					case replacement == "another ceremony":
						sess.Values[sessionkeys.AuthContext] = authContextJSON(t,
							&AuthContext{CeremonyId: ceremonyB, AuthState: AuthStateRequiresLevel1})
					default:
						delete(sess.Values, sessionkeys.AuthContext)
					}
					require.NoError(t, store.Save(other, httptest.NewRecorder(), sess))
				}

				rr := httptest.NewRecorder()
				switch operation {
				case "save":
					loaded.AuthState = AuthStateLevel1Password
					err = ceremonyStore.SaveAuthContext(rr, stepReq, loaded)
				case "clear":
					err = ceremonyStore.ClearAuthContext(rr, stepReq, ceremonyA)
				case "rotate":
					err = ceremonyStore.RegenerateSession(rr, stepReq, ceremonyA)
				}

				require.ErrorIs(t, err, ErrCeremonyReplaced)
				assert.Equal(t, lastAttempt, backend.comparisons)
				assert.Empty(t, rr.Result().Cookies(), "a step that wrote nothing tells the browser nothing")
				for _, id := range backend.createdIds[1:] {
					_, loadErr := backend.Load(context.Background(), id)
					require.ErrorIs(t, loadErr, sessionstore.ErrNotFound, "every losing rotation's row is removed")
				}
				switch replacement {
				case "the row removed":
					_, loadErr := backend.Load(context.Background(), oldId)
					require.ErrorIs(t, loadErr, sessionstore.ErrNotFound, "a gone session is not put back")
				case "another ceremony":
					stored, loadErr := ceremonyStore.GetAuthContext(browserRequest(cookies))
					require.NoError(t, loadErr)
					assert.Equal(t, ceremonyB, stored.CeremonyId, "the newer ceremony is what the browser session keeps")
				default:
					_, loadErr := ceremonyStore.GetAuthContext(browserRequest(cookies))
					require.ErrorIs(t, loadErr, ErrNoAuthContext)
					requireSessionDecoded(t, store, browserRequest(cookies))
				}
			})
		}
	}
}

// Held is the condition a write of this ceremony to the browser session is made on, for a writer
// outside this package: /auth/completed's create arm hands it to the rotation that binds the new
// user session (#579 decision 4).
func TestHeld(t *testing.T) {
	stored := func(t *testing.T, ceremonyId string) map[string]any {
		return map[string]any{sessionkeys.AuthContext: authContextJSON(t, &AuthContext{CeremonyId: ceremonyId})}
	}

	require.NoError(t, Held(ceremonyA)(stored(t, ceremonyA)))
	require.ErrorIs(t, Held(ceremonyA)(stored(t, ceremonyB)), ErrCeremonyReplaced)
	require.ErrorIs(t, Held(ceremonyA)(map[string]any{"unrelated": "value"}), ErrCeremonyReplaced)
	require.ErrorIs(t, Held(ceremonyA)(map[string]any{}), ErrCeremonyReplaced)
	require.ErrorIs(t, Held("")(stored(t, "")), ErrCeremonyReplaced, "an empty ceremony id is never held")

	err := Held(ceremonyA)(map[string]any{sessionkeys.AuthContext: "not json"})
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrCeremonyReplaced, "a context that does not decode is a fault, not a replacement")
}

func TestUILocales(t *testing.T) {
	tests := []struct {
		name        string
		authContext *AuthContext
		want        []string
	}{
		{
			name:        "StoredTags",
			authContext: &AuthContext{UILocales: []string{"pt-BR", "es"}},
			want:        []string{"pt-BR", "es"},
		},
		{
			name: "MissingContext",
		},
		{
			name:        "EmptyTags",
			authContext: &AuthContext{UILocales: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ceremonyStore, store, _ := newRealStore(t)
			values := map[string]any{"unrelated": "value"}
			if tt.authContext != nil {
				values[sessionkeys.AuthContext] = authContextJSON(t, tt.authContext)
			}
			cookies := seedBrowserSession(t, store, values)

			assert.Equal(t, tt.want, ceremonyStore.UILocales(browserRequest(cookies)))
		})
	}
}
