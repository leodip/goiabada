package handlerhelpers

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAuthContext(t *testing.T) {
	const testSessionName = "test-session"

	t.Run("Success", func(t *testing.T) {
		mockStore := mocks_sessionstore.NewStore(t)
		helper := NewAuthHelper(mockStore, testSessionName, "http://localhost:9091", "http://localhost:9090")

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		sess := sessions.NewSession(mockStore, testSessionName)
		authContext := &oauth.AuthContext{ClientId: "test-client"}
		jsonData, _ := json.Marshal(authContext)
		sess.Values[constants.SessionKeyAuthContext] = string(jsonData)

		mockStore.On("Get", req, testSessionName).Return(sess, nil)

		result, err := helper.GetAuthContext(req)

		assert.NoError(t, err)
		assert.Equal(t, authContext.ClientId, result.ClientId)
		mockStore.AssertExpectations(t)
	})

	t.Run("SessionError", func(t *testing.T) {
		mockStore := mocks_sessionstore.NewStore(t)
		helper := NewAuthHelper(mockStore, testSessionName, "http://localhost:9091", "http://localhost:9090")

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		mockStore.On("Get", req, testSessionName).Return(nil, assert.AnError)

		result, err := helper.GetAuthContext(req)

		assert.Error(t, err)
		assert.Nil(t, result)
		mockStore.AssertExpectations(t)
	})

	t.Run("NoAuthContext", func(t *testing.T) {
		mockStore := mocks_sessionstore.NewStore(t)
		helper := NewAuthHelper(mockStore, testSessionName, "http://localhost:9091", "http://localhost:9090")

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		sess := sessions.NewSession(mockStore, testSessionName)

		mockStore.On("Get", req, testSessionName).Return(sess, nil)

		result, err := helper.GetAuthContext(req)

		assert.Error(t, err)
		assert.Nil(t, result)
		mockStore.AssertExpectations(t)
	})

	t.Run("UnmarshalError", func(t *testing.T) {
		mockStore := mocks_sessionstore.NewStore(t)
		helper := NewAuthHelper(mockStore, testSessionName, "http://localhost:9091", "http://localhost:9090")

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		sess := sessions.NewSession(mockStore, testSessionName)
		sess.Values[constants.SessionKeyAuthContext] = "invalid json"

		mockStore.On("Get", req, testSessionName).Return(sess, nil)

		result, err := helper.GetAuthContext(req)

		assert.Error(t, err)
		assert.Nil(t, result)
		mockStore.AssertExpectations(t)
	})
}

func TestGetLoggedInSubject(t *testing.T) {
	const testSessionName = "test-session"
	helper := NewAuthHelper(nil, testSessionName, "http://localhost:9091", "http://localhost:9090")

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		jwtInfo := oauth.JwtInfo{
			IdToken: &oauth.JwtToken{
				Claims: map[string]interface{}{"sub": "test-subject"},
			},
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeyJwtInfo, jwtInfo)
		req = req.WithContext(ctx)

		subject := helper.GetLoggedInSubject(req)

		assert.Equal(t, "test-subject", subject)
	})

	t.Run("NoJwtInfo", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)

		subject := helper.GetLoggedInSubject(req)

		assert.Empty(t, subject)
	})

	t.Run("InvalidJwtInfo", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyJwtInfo, "invalid")
		req = req.WithContext(ctx)

		// Capture log output
		var buf bytes.Buffer
		log.SetOutput(&buf)
		defer log.SetOutput(os.Stderr)

		subject := helper.GetLoggedInSubject(req)

		assert.Empty(t, subject)
		assert.Contains(t, buf.String(), "ERROR unable to cast jwtInfo")
	})

	t.Run("NoIdToken", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		jwtInfo := oauth.JwtInfo{}
		ctx := context.WithValue(req.Context(), constants.ContextKeyJwtInfo, jwtInfo)
		req = req.WithContext(ctx)

		subject := helper.GetLoggedInSubject(req)

		assert.Empty(t, subject)
	})
}

func TestSaveAuthContext(t *testing.T) {
	const testSessionName = "test-session"

	t.Run("Success", func(t *testing.T) {
		mockStore := mocks_sessionstore.NewStore(t)
		helper := NewAuthHelper(mockStore, testSessionName, "http://localhost:9091", "http://localhost:9090")

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		sess := sessions.NewSession(mockStore, testSessionName)
		authContext := &oauth.AuthContext{ClientId: "test-client"}

		mockStore.On("Get", req, testSessionName).Return(sess, nil)
		mockStore.On("Save", req, w, sess).Return(nil)

		err := helper.SaveAuthContext(w, req, authContext)

		assert.NoError(t, err)
		assert.Contains(t, sess.Values, constants.SessionKeyAuthContext)
		mockStore.AssertExpectations(t)
	})

	t.Run("SessionError", func(t *testing.T) {
		mockStore := mocks_sessionstore.NewStore(t)
		helper := NewAuthHelper(mockStore, testSessionName, "http://localhost:9091", "http://localhost:9090")

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		authContext := &oauth.AuthContext{ClientId: "test-client"}

		mockStore.On("Get", req, testSessionName).Return(nil, assert.AnError)

		err := helper.SaveAuthContext(w, req, authContext)

		assert.Error(t, err)
		mockStore.AssertExpectations(t)
	})

	t.Run("SaveError", func(t *testing.T) {
		mockStore := mocks_sessionstore.NewStore(t)
		helper := NewAuthHelper(mockStore, testSessionName, "http://localhost:9091", "http://localhost:9090")

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		sess := sessions.NewSession(mockStore, testSessionName)
		authContext := &oauth.AuthContext{ClientId: "test-client"}

		mockStore.On("Get", req, testSessionName).Return(sess, nil)
		mockStore.On("Save", req, w, sess).Return(assert.AnError)

		err := helper.SaveAuthContext(w, req, authContext)

		assert.Error(t, err)
		mockStore.AssertExpectations(t)
	})
}

// The fixtures below back the RealStore* subtests of TestClearAuthContext, which drive the real
// ChunkedCookieStore instead of a mock. The session store is cookie-only, so a Set-Cookie is the
// only way a deletion reaches the browser and there is no server-side row to fall back on. Every
// other subtest here inspects sess.Values, which is the store's in-memory state and says nothing
// about the wire: that is how seven handlers came to clear the auth context after committing the
// client response, where the header is never sent (#141).
const (
	realStoreSessionName = "test-session"
	realStoreBaseURL     = "https://as.example.com"
	// Where a refused ceremony sends the client, and the commit these cases order against.
	clientRefusalURL = "https://example.com/callback?error=access_denied"
)

// newRealStoreAuthHelper returns the helper and the store behind it. The store is returned because
// requireSessionDecoded needs to read a replayed session directly, which is the only way to tell a
// valid cleared session from an unreadable one.
func newRealStoreAuthHelper(t *testing.T) (*AuthHelper, *sessionstore.ChunkedCookieStore) {
	t.Helper()
	authKey := []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	encKey := []byte("0123456789abcdef0123456789abcdef")
	store := sessionstore.NewChunkedCookieStore(authKey, encKey)
	return NewAuthHelper(store, realStoreSessionName, realStoreBaseURL, realStoreBaseURL), store
}

// requireSessionDecoded proves the session the browser holds on req decoded successfully, and must
// accompany every assertion that the auth context is absent.
//
// ChunkedCookieStore.New swallows every load failure (a metadata cookie that will not decode, a
// missing chunk, a failed SHA-256 integrity check, an undecodable payload) and hands back a new
// empty session. GetAuthContext finds no auth context in that session and reports ErrNoAuthContext,
// which is the same error a genuine clear produces. So ErrNoAuthContext alone cannot distinguish
// "the clear reached the browser and it decoded" from "the clearing write reached the browser
// corrupt", and a regression that emitted malformed clearing state would leave the absence cases
// green. IsNew is false only when the whole load succeeded, so it separates the two (#141).
func requireSessionDecoded(t *testing.T, store *sessionstore.ChunkedCookieStore, req *http.Request) {
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
func multiChunkAuthContext() *oauth.AuthContext {
	long := ""
	for i := 0; i < 400; i++ {
		long += "scope" + string(rune('a'+i%26)) + ":permission "
	}
	return &oauth.AuthContext{
		AuthState:   oauth.AuthStateReadyToIssueCode,
		ClientId:    "test-client",
		UserId:      123,
		RedirectURI: "https://example.com/callback",
		State:       "test-state",
		Scope:       long,
	}
}

func TestClearAuthContext(t *testing.T) {
	const testSessionName = "test-session"

	t.Run("Success", func(t *testing.T) {
		mockStore := mocks_sessionstore.NewStore(t)
		helper := NewAuthHelper(mockStore, testSessionName, "http://localhost:9091", "http://localhost:9090")

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		sess := sessions.NewSession(mockStore, testSessionName)
		sess.Values[constants.SessionKeyAuthContext] = "test-context"

		mockStore.On("Get", req, testSessionName).Return(sess, nil)
		mockStore.On("Save", req, w, sess).Return(nil)

		err := helper.ClearAuthContext(w, req)

		assert.NoError(t, err)
		assert.NotContains(t, sess.Values, constants.SessionKeyAuthContext)
		mockStore.AssertExpectations(t)
	})

	t.Run("SessionError", func(t *testing.T) {
		mockStore := mocks_sessionstore.NewStore(t)
		helper := NewAuthHelper(mockStore, testSessionName, "http://localhost:9091", "http://localhost:9090")

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()

		mockStore.On("Get", req, testSessionName).Return(nil, assert.AnError)

		err := helper.ClearAuthContext(w, req)

		assert.Error(t, err)
		mockStore.AssertExpectations(t)
	})

	t.Run("SaveError", func(t *testing.T) {
		mockStore := mocks_sessionstore.NewStore(t)
		helper := NewAuthHelper(mockStore, testSessionName, "http://localhost:9091", "http://localhost:9090")

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		sess := sessions.NewSession(mockStore, testSessionName)

		mockStore.On("Get", req, testSessionName).Return(sess, nil)
		mockStore.On("Save", req, w, sess).Return(assert.AnError)

		err := helper.ClearAuthContext(w, req)

		assert.Error(t, err)
		mockStore.AssertExpectations(t)
	})

	t.Run("RealStoreClearBeforeCommitReachesBrowser", func(t *testing.T) {
		helper, store := newRealStoreAuthHelper(t)

		seedReq := httptest.NewRequest(http.MethodGet, realStoreBaseURL+"/auth/issue", nil)
		seedRR := httptest.NewRecorder()
		err := helper.SaveAuthContext(seedRR, seedReq, multiChunkAuthContext())
		require.NoError(t, err)

		seedRes := seedRR.Result()
		// Master plus at least two chunks. Keep this: a change to DefaultChunkSize that collapsed
		// the context into a single cookie would leave all four cases passing while none of them
		// still covered the stale higher chunks the clearing write has to survive.
		assert.Greater(t, len(seedRes.Cookies()), 2)

		browserReq := replayThroughJar(t, seedRes, nil)

		rr := httptest.NewRecorder()
		err = helper.ClearAuthContext(rr, browserReq)
		require.NoError(t, err)
		http.Redirect(rr, browserReq, clientRefusalURL, http.StatusFound)

		res := rr.Result()
		// A response carrying no cookies at all would satisfy the jar assertion below for entirely
		// the wrong reason, so pin that the clear did write something.
		assert.NotEmpty(t, res.Cookies())

		replayed := replayThroughJar(t, res, seedRes.Cookies())
		_, err = helper.GetAuthContext(replayed)
		assert.ErrorIs(t, err, customerrors.ErrNoAuthContext)
		requireSessionDecoded(t, store, replayed)
	})

	t.Run("RealStoreClearAfterCommitIsDropped", func(t *testing.T) {
		// This case asserts the defect, and it is expected to keep passing once the handler sites
		// are reordered, because it drives the helper directly and no handler. It is what makes
		// the other three cases mean something: delete it as obsolete and nothing is left recording
		// why the ordering is load-bearing rather than a matter of style (#141).
		//
		// This case needs no requireSessionDecoded: it asserts the retained auth context decodes
		// and carries ready_to_issue_code, which an unreadable session cannot satisfy.
		helper, _ := newRealStoreAuthHelper(t)

		seedReq := httptest.NewRequest(http.MethodGet, realStoreBaseURL+"/auth/issue", nil)
		seedRR := httptest.NewRecorder()
		err := helper.SaveAuthContext(seedRR, seedReq, multiChunkAuthContext())
		require.NoError(t, err)

		seedRes := seedRR.Result()
		browserReq := replayThroughJar(t, seedRes, nil)

		rr := httptest.NewRecorder()
		http.Redirect(rr, browserReq, clientRefusalURL, http.StatusFound)
		err = helper.ClearAuthContext(rr, browserReq)
		require.NoError(t, err)

		res := rr.Result()
		// The clear succeeded and its Set-Cookie headers are in the live header map, but the
		// response was committed before they were written, so none of them reach the wire.
		assert.Empty(t, res.Cookies())

		// The dropped response set no cookies, so the browser still holds what it was seeded with.
		authContext, err := helper.GetAuthContext(replayThroughJar(t, res, seedRes.Cookies()))
		require.NoError(t, err)
		assert.Equal(t, oauth.AuthStateReadyToIssueCode, authContext.AuthState)
	})

	t.Run("RealStoreSaveThenClearLastWins", func(t *testing.T) {
		// The /auth/authorize shape at sites 1 and 2: SaveAuthContext has already written the
		// context earlier in the same response, so clearing before the commit puts two session
		// writes, under duplicate cookie names, in one response. Both must reach the wire and the
		// later one must win (#141).
		helper, store := newRealStoreAuthHelper(t)

		req := httptest.NewRequest(http.MethodGet, realStoreBaseURL+"/auth/authorize?client_id=test-client", nil)
		rr := httptest.NewRecorder()

		err := helper.SaveAuthContext(rr, req, multiChunkAuthContext())
		require.NoError(t, err)
		err = helper.ClearAuthContext(rr, req)
		require.NoError(t, err)
		http.Redirect(rr, req, clientRefusalURL, http.StatusFound)

		res := rr.Result()
		counts := map[string]int{}
		for _, c := range res.Cookies() {
			counts[c.Name]++
		}
		// Both writes are on the wire, rather than the second having replaced the first in the
		// header map. The clearing write fits in one chunk, so it re-sets only the master cookie
		// and chunk 0; the stale higher chunks are ignored because the master's ChunkCount bounds
		// the reassembly.
		assert.Equal(t, 2, counts[realStoreSessionName])
		assert.Equal(t, 2, counts[realStoreSessionName+"-chunk-0"])

		replayed := replayThroughJar(t, res, nil)
		_, err = helper.GetAuthContext(replayed)
		assert.ErrorIs(t, err, customerrors.ErrNoAuthContext)
		requireSessionDecoded(t, store, replayed)
	})

	t.Run("RealStoreClearThenSaveLastWins", func(t *testing.T) {
		// Control for the case above. Without it, that case passes just as well if the jar simply
		// discards everything when a cookie name repeats, which would make it evidence of nothing.
		// Here the later write is the save, so the jar must keep the context.
		//
		// No requireSessionDecoded here either: keeping the context requires a successful decode.
		helper, _ := newRealStoreAuthHelper(t)

		req := httptest.NewRequest(http.MethodGet, realStoreBaseURL+"/auth/authorize?client_id=test-client", nil)
		rr := httptest.NewRecorder()

		err := helper.ClearAuthContext(rr, req)
		require.NoError(t, err)
		err = helper.SaveAuthContext(rr, req, multiChunkAuthContext())
		require.NoError(t, err)
		http.Redirect(rr, req, clientRefusalURL, http.StatusFound)

		authContext, err := helper.GetAuthContext(replayThroughJar(t, rr.Result(), nil))
		require.NoError(t, err)
		assert.Equal(t, oauth.AuthStateReadyToIssueCode, authContext.AuthState)
	})
}
