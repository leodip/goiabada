package sessionstore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests live inside the package rather than beside it in sessionstore_test so the
// CSPRNG can be replaced. A session identifier that silently becomes a constant is the
// one failure this store must not have, and it cannot be provoked from outside.

const (
	storeTestName    = "authserver"
	storeTestAuthKey = "12345678901234567890123456789012" // exactly 32 bytes
	storeTestEncKey  = "abcdefghijklmnopqrstuvwxyz123456" // exactly 32 bytes
)

// fakeBackend is a Backend at its own boundary, not a mock standing in for the thing
// under test. The store is what is under test here; the real database backend is covered
// at the data tier and the whole chain end to end at the integration tier.
type fakeBackend struct {
	rows map[string]*Record

	loadErr   error
	createErr error
	updateErr error
	touchErr  error
	deleteErr error

	loads   int
	creates int
	updates int
	touches int
	deletes int

	lastData          []byte
	lastAuthenticated bool
	lastDeletedId     string

	expiresAt time.Time
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{
		rows:      map[string]*Record{},
		expiresAt: time.Now().UTC().Add(time.Hour),
	}
}

func (f *fakeBackend) Load(ctx context.Context, id string) (*Record, error) {
	f.loads++
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	record, ok := f.rows[id]
	if !ok {
		return nil, ErrNotFound
	}
	return record, nil
}

func (f *fakeBackend) Create(ctx context.Context, id string, data []byte, authenticated bool) (time.Time, error) {
	f.creates++
	f.lastData = data
	f.lastAuthenticated = authenticated
	if f.createErr != nil {
		return time.Time{}, f.createErr
	}
	f.rows[id] = &Record{Data: data, LastAccessed: time.Now().UTC(), ExpiresAt: f.expiresAt}
	return f.expiresAt, nil
}

func (f *fakeBackend) Update(ctx context.Context, id string, data []byte, authenticated bool) (time.Time, error) {
	f.updates++
	f.lastData = data
	f.lastAuthenticated = authenticated
	if f.updateErr != nil {
		return time.Time{}, f.updateErr
	}
	record, ok := f.rows[id]
	if !ok {
		return time.Time{}, ErrNotFound
	}
	record.Data = data
	return f.expiresAt, nil
}

func (f *fakeBackend) Touch(ctx context.Context, id string, authenticated bool) (time.Time, error) {
	f.touches++
	if f.touchErr != nil {
		return time.Time{}, f.touchErr
	}
	record, ok := f.rows[id]
	if !ok {
		return time.Time{}, ErrNotFound
	}
	record.LastAccessed = time.Now().UTC()
	return f.expiresAt, nil
}

func (f *fakeBackend) Delete(ctx context.Context, id string) error {
	f.deletes++
	f.lastDeletedId = id
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.rows, id)
	return nil
}

func newTestStore(backend Backend, secure bool) *ServerSideStore {
	return NewServerSideStore(backend, "SessionIdentifier", secure,
		[]byte(storeTestAuthKey), []byte(storeTestEncKey))
}

// saveNew runs the ordinary create path: a request carrying no cookie, one save.
func saveNew(t *testing.T, store *ServerSideStore, values map[interface{}]interface{}) *http.Cookie {
	t.Helper()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	session, err := store.New(req, storeTestName)
	require.NoError(t, err)
	for k, v := range values {
		session.Values[k] = v
	}
	require.NoError(t, store.Save(req, w, session))

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1, "a session must cost exactly one cookie")
	return cookies[0]
}

func decodeCookieId(t *testing.T, store *ServerSideStore, cookie *http.Cookie) string {
	t.Helper()

	var id string
	require.NoError(t, securecookie.DecodeMulti(storeTestName, cookie.Value, &id, store.Codecs...))
	return id
}

func requestWith(cookie *http.Cookie) *http.Request {
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookie)
	return req
}

// --- identifier and carriage -------------------------------------------------------

func TestServerSideStore_SaveCreatesOneRowAndOneCookie(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	cookie := saveNew(t, store, map[interface{}]interface{}{"greeting": "hello"})

	assert.Equal(t, storeTestName, cookie.Name)
	assert.Equal(t, 1, backend.creates)
	assert.Len(t, backend.rows, 1)
}

func TestServerSideStore_CookieCarriesA64HexIdentifier(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	cookie := saveNew(t, store, nil)
	id := decodeCookieId(t, store, cookie)

	assert.Len(t, id, 64, "256 bits, hex encoded")
	assert.Regexp(t, "^[0-9a-f]{64}$", id)
	assert.Contains(t, backend.rows, id)
}

func TestServerSideStore_EachSessionGetsItsOwnIdentifier(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	first := decodeCookieId(t, store, saveNew(t, store, nil))
	second := decodeCookieId(t, store, saveNew(t, store, nil))

	assert.NotEqual(t, first, second)
}

// failingReader is a CSPRNG that cannot produce anything.
type failingReader struct{}

func (failingReader) Read(p []byte) (int, error) { return 0, errors.New("no entropy") }

func TestServerSideStore_CSPRNGFailureFailsTheSave(t *testing.T) {
	original := randReader
	randReader = failingReader{}
	defer func() { randReader = original }()

	backend := newFakeBackend()
	store := newTestStore(backend, false)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	session, err := store.New(req, storeTestName)
	require.NoError(t, err)

	err = store.Save(req, w, session)

	// The alternative, which stringutil.GenerateSecurityRandomString takes, is to return
	// the empty string. Every session would then share one identifier (#211, #266).
	require.Error(t, err)
	assert.Empty(t, w.Result().Cookies(), "no cookie may be issued without an identifier")
	assert.Equal(t, 0, backend.creates)
}

func TestServerSideStore_BackendNeverSeesPlaintext(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	const marker = "a-value-nobody-else-should-be-able-to-read"
	saveNew(t, store, map[interface{}]interface{}{"secret": marker})

	require.NotEmpty(t, backend.lastData)
	assert.NotContains(t, string(backend.lastData), marker,
		"the storage half holds ciphertext and no key for it")
}

// --- loading -----------------------------------------------------------------------

func TestServerSideStore_RoundTrip(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	cookie := saveNew(t, store, map[interface{}]interface{}{"greeting": "hello", "count": 7})

	session, err := store.New(requestWith(cookie), storeTestName)
	require.NoError(t, err)
	assert.False(t, session.IsNew)
	assert.Equal(t, "hello", session.Values["greeting"])
	assert.Equal(t, 7, session.Values["count"])
	assert.Equal(t, decodeCookieId(t, store, cookie), session.ID)
}

func TestServerSideStore_TamperedCookieGivesAFreshSession(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	cookie := saveNew(t, store, map[interface{}]interface{}{"greeting": "hello"})
	tampered := &http.Cookie{Name: cookie.Name, Value: cookie.Value[:len(cookie.Value)-4] + "AAAA"}

	session, err := store.New(requestWith(tampered), storeTestName)

	require.NoError(t, err)
	assert.True(t, session.IsNew)
	assert.Empty(t, session.Values)
	assert.Equal(t, 0, backend.loads, "a cookie that fails its HMAC never reaches storage")
}

func TestServerSideStore_CookieFromOtherKeysGivesAFreshSession(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)
	other := NewServerSideStore(newFakeBackend(), "SessionIdentifier", false,
		[]byte("00000000000000000000000000000000"), []byte("11111111111111111111111111111111"))

	cookie := saveNew(t, other, map[interface{}]interface{}{"greeting": "hello"})

	session, err := store.New(requestWith(cookie), storeTestName)

	require.NoError(t, err)
	assert.True(t, session.IsNew)
	assert.Equal(t, 0, backend.loads)
}

func TestServerSideStore_NotFoundGivesAFreshSession(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	cookie := saveNew(t, store, map[interface{}]interface{}{"greeting": "hello"})
	backend.rows = map[string]*Record{} // logged out, expired or reaped

	session, err := store.New(requestWith(cookie), storeTestName)

	require.NoError(t, err)
	assert.True(t, session.IsNew)
	assert.Empty(t, session.Values)
}

func TestServerSideStore_StorageFailurePropagates(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	cookie := saveNew(t, store, map[interface{}]interface{}{"greeting": "hello"})
	backend.loadErr = errors.New("the database is unreachable")

	session, err := store.New(requestWith(cookie), storeTestName)

	// Failing open here would discard every session in flight during any database
	// interruption, and would erase the difference between "this session is gone" and
	// "I could not check" (#266).
	require.Error(t, err)
	assert.Nil(t, session)
}

func TestServerSideStore_NoCookieCostsNoRead(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	session, err := store.New(httptest.NewRequest("GET", "/", nil), storeTestName)

	require.NoError(t, err)
	assert.True(t, session.IsNew)
	assert.Equal(t, 0, backend.loads, "a visitor presenting nothing must cost nothing")
}

// --- the lazy last_accessed write ---------------------------------------------------

func TestServerSideStore_StaleSessionIsTouched(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	cookie := saveNew(t, store, nil)
	id := decodeCookieId(t, store, cookie)
	backend.rows[id].LastAccessed = time.Now().UTC().Add(-30 * time.Second)

	_, err := store.New(requestWith(cookie), storeTestName)

	require.NoError(t, err)
	assert.Equal(t, 1, backend.touches)
}

func TestServerSideStore_FreshSessionIsNotTouched(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	cookie := saveNew(t, store, nil)
	id := decodeCookieId(t, store, cookie)
	backend.rows[id].LastAccessed = time.Now().UTC().Add(-1 * time.Second)

	// Two reads inside the threshold, which is the case the threshold exists for: a
	// person clicking through pages must not pay a write per click.
	_, err := store.New(requestWith(cookie), storeTestName)
	require.NoError(t, err)
	_, err = store.New(requestWith(cookie), storeTestName)
	require.NoError(t, err)

	assert.Equal(t, 0, backend.touches)
}

func TestServerSideStore_TouchOnAVanishedRowGivesAFreshSession(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	cookie := saveNew(t, store, map[interface{}]interface{}{"greeting": "hello"})
	id := decodeCookieId(t, store, cookie)
	backend.rows[id].LastAccessed = time.Now().UTC().Add(-30 * time.Second)
	backend.touchErr = ErrNotFound

	session, err := store.New(requestWith(cookie), storeTestName)

	require.NoError(t, err)
	assert.True(t, session.IsNew)
	assert.Empty(t, session.Values, "a row that went away must not keep serving its contents")
}

func TestServerSideStore_TouchFailurePropagates(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	cookie := saveNew(t, store, nil)
	id := decodeCookieId(t, store, cookie)
	backend.rows[id].LastAccessed = time.Now().UTC().Add(-30 * time.Second)
	backend.touchErr = errors.New("the database is unreachable")

	_, err := store.New(requestWith(cookie), storeTestName)

	require.Error(t, err)
}

// --- saving an existing session ------------------------------------------------------

func TestServerSideStore_SaveOnALoadedSessionUpdates(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	cookie := saveNew(t, store, map[interface{}]interface{}{"greeting": "hello"})
	backend.creates = 0

	req := requestWith(cookie)
	w := httptest.NewRecorder()
	session, err := store.New(req, storeTestName)
	require.NoError(t, err)
	session.Values["greeting"] = "goodbye"
	require.NoError(t, store.Save(req, w, session))

	assert.Equal(t, 1, backend.updates)
	assert.Equal(t, 0, backend.creates)
	assert.Len(t, backend.rows, 1, "an update must not leave a second row behind")
}

func TestServerSideStore_SaveOnAVanishedRowFailsAndWritesNothing(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	cookie := saveNew(t, store, map[interface{}]interface{}{"greeting": "hello"})
	id := decodeCookieId(t, store, cookie)

	req := requestWith(cookie)
	w := httptest.NewRecorder()
	session, err := store.New(req, storeTestName)
	require.NoError(t, err)

	// What actually happens between the load and the save is the rotation at sign-in:
	// it deletes this row and writes a new one under a new identifier. A request still
	// in flight under the old identifier must not put the old row back, and must not
	// emit a cookie either, because a deletion here would clobber the cookie rotation
	// just set (#266).
	delete(backend.rows, id)
	backend.creates = 0

	err = store.Save(req, w, session)

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotFound))
	assert.Equal(t, 0, backend.creates, "a gone session must never be inserted back")
	assert.Empty(t, w.Result().Cookies(), "no cookie, not even a deletion")
}

// --- deleting ------------------------------------------------------------------------

func TestServerSideStore_NegativeMaxAgeDeletesRowAndCookie(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	cookie := saveNew(t, store, map[interface{}]interface{}{"greeting": "hello"})
	id := decodeCookieId(t, store, cookie)

	req := requestWith(cookie)
	w := httptest.NewRecorder()
	session, err := store.New(req, storeTestName)
	require.NoError(t, err)
	session.Options.MaxAge = -1
	require.NoError(t, store.Save(req, w, session))

	assert.Equal(t, 1, backend.deletes)
	assert.Equal(t, id, backend.lastDeletedId)
	assert.Empty(t, backend.rows, "logging out has to invalidate the server's half too")

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, -1, cookies[0].MaxAge)
	assert.Empty(t, cookies[0].Value)
}

func TestServerSideStore_NegativeMaxAgeWithNoSessionTouchesNoBackend(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	session, err := store.New(req, storeTestName)
	require.NoError(t, err)
	session.Options.MaxAge = -1

	require.NoError(t, store.Save(req, w, session))

	assert.Equal(t, 0, backend.deletes)
	require.Len(t, w.Result().Cookies(), 1)
	assert.Equal(t, -1, w.Result().Cookies()[0].MaxAge)
}

// --- cookie attributes ----------------------------------------------------------------

func TestServerSideStore_PersistentCookieFollowsTheRowsExpiry(t *testing.T) {
	backend := newFakeBackend()
	backend.expiresAt = time.Now().UTC().Add(2 * time.Hour)
	store := newTestStore(backend, false)
	store.PersistentCookie = true

	cookie := saveNew(t, store, nil)

	// The browser then never holds a handle that outlives what it names, and the
	// operator's session timeout governs both halves through one setting.
	assert.InDelta(t, 7200, cookie.MaxAge, 5)
}

func TestServerSideStore_NonPersistentCookieCarriesNoExpiry(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)
	store.PersistentCookie = false

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	session, err := store.New(req, storeTestName)
	require.NoError(t, err)
	require.NoError(t, store.Save(req, w, session))

	// Asserted on the header rather than on the parsed cookie: net/http parses an
	// absent Max-Age and a Max-Age of zero to different values, but only the raw header
	// says which one was written, and the administrator's half of decision 9 is that
	// nothing is written at all.
	setCookie := w.Result().Header.Values("Set-Cookie")
	require.Len(t, setCookie, 1)
	assert.NotContains(t, setCookie[0], "Max-Age")
	assert.NotContains(t, setCookie[0], "Expires")
}

func TestServerSideStore_SecureUsesTheHostPrefix(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, true)

	cookie := saveNew(t, store, nil)

	// __Host- is accepted by a browser only when all three of these hold, and what it
	// buys is that a sibling subdomain cannot set a cookie this server will receive,
	// which is the practical way an attacker plants an identifier (#266).
	assert.Equal(t, "__Host-"+storeTestName, cookie.Name)
	assert.True(t, cookie.Secure)
	assert.Equal(t, "/", cookie.Path)
	assert.Empty(t, cookie.Domain)
}

func TestServerSideStore_CodecNameDoesNotFollowThePrefix(t *testing.T) {
	backend := newFakeBackend()
	secureStore := newTestStore(backend, true)
	plainStore := newTestStore(backend, false)

	secureCookie := saveNew(t, secureStore, nil)
	plainCookie := saveNew(t, plainStore, nil)

	assert.Equal(t, storeTestName, plainCookie.Name)

	// Both decode under the logical name. Deriving the codec name from the cookie name
	// would make every live session unreadable the moment a deployment moved between
	// http and https, and would make the owner column's value depend on the scheme.
	var id string
	require.NoError(t, securecookie.DecodeMulti(storeTestName, secureCookie.Value, &id, plainStore.Codecs...))
	assert.Len(t, id, 64)
	require.NoError(t, securecookie.DecodeMulti(storeTestName, plainCookie.Value, &id, secureStore.Codecs...))
	assert.Len(t, id, 64)
}

func TestServerSideStore_SecureLoadsWhatSecureSaved(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, true)

	cookie := saveNew(t, store, map[interface{}]interface{}{"greeting": "hello"})

	session, err := store.New(requestWith(cookie), storeTestName)

	require.NoError(t, err)
	assert.False(t, session.IsNew, "the prefixed name must be the one read back")
	assert.Equal(t, "hello", session.Values["greeting"])
}

// --- the names left behind by the cookie store ------------------------------------------

func TestServerSideStore_StaleCookieNames(t *testing.T) {
	secure := newTestStore(newFakeBackend(), true).StaleCookieNames(storeTestName)
	plain := newTestStore(newFakeBackend(), false).StaleCookieNames(storeTestName)

	assert.Len(t, secure, 51)
	assert.Equal(t, storeTestName, secure[0])
	assert.Contains(t, secure, storeTestName+"-chunk-0")
	assert.Contains(t, secure, storeTestName+"-chunk-49")

	// On plain http the bare name IS the live cookie, so deleting it would delete the
	// session the same response just wrote.
	assert.Len(t, plain, 50)
	assert.NotContains(t, plain, storeTestName)
	assert.Contains(t, plain, storeTestName+"-chunk-0")
}

// --- rotation ---------------------------------------------------------------------------

func TestServerSideStore_RegenerateMovesTheSessionToANewIdentifier(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	oldCookie := saveNew(t, store, map[interface{}]interface{}{"greeting": "hello"})
	oldId := decodeCookieId(t, store, oldCookie)

	req := requestWith(oldCookie)
	w := httptest.NewRecorder()
	session, err := store.New(req, storeTestName)
	require.NoError(t, err)

	require.NoError(t, store.Regenerate(w, req, session))

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	newId := decodeCookieId(t, store, cookies[0])

	assert.NotEqual(t, oldId, newId, "an identifier that existed before must not name what comes after")
	assert.NotContains(t, backend.rows, oldId)
	assert.Contains(t, backend.rows, newId)
	assert.Equal(t, newId, session.ID)

	// The contents survive: rotation replaces the name, not the session.
	loaded, err := store.New(requestWith(cookies[0]), storeTestName)
	require.NoError(t, err)
	assert.Equal(t, "hello", loaded.Values["greeting"])
}

func TestServerSideStore_RegenerateWithAFailedCreateEmitsNothing(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	oldCookie := saveNew(t, store, map[interface{}]interface{}{"greeting": "hello"})
	oldId := decodeCookieId(t, store, oldCookie)

	req := requestWith(oldCookie)
	w := httptest.NewRecorder()
	session, err := store.New(req, storeTestName)
	require.NoError(t, err)
	backend.createErr = errors.New("the database is unreachable")

	err = store.Regenerate(w, req, session)

	require.Error(t, err)
	assert.Empty(t, w.Result().Cookies())
	assert.Contains(t, backend.rows, oldId, "a failed rotation leaves the session it started with")
	assert.Equal(t, 0, backend.deletes)
}

func TestServerSideStore_RegenerateWithAFailedDeleteEmitsNoCookie(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	oldCookie := saveNew(t, store, map[interface{}]interface{}{"greeting": "hello"})

	req := requestWith(oldCookie)
	w := httptest.NewRecorder()
	session, err := store.New(req, storeTestName)
	require.NoError(t, err)
	backend.deleteErr = errors.New("the database is unreachable")

	err = store.Regenerate(w, req, session)

	// This is the ordering the whole rotation rests on. A Set-Cookie already written is
	// not retracted by a later failure, so emitting the new cookie before the old row is
	// gone would leave the old identifier live AND the browser already moved on, which
	// is the one outcome rotation exists to prevent (#266).
	require.Error(t, err)
	assert.Empty(t, w.Result().Cookies())
}

func TestServerSideStore_RegenerateOnAFreshSessionCreatesWithoutDeleting(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	session, err := store.New(req, storeTestName)
	require.NoError(t, err)

	require.NoError(t, store.Regenerate(w, req, session))

	assert.Equal(t, 1, backend.creates)
	assert.Equal(t, 0, backend.deletes, "there is no earlier row to remove")
	assert.Len(t, w.Result().Cookies(), 1)
}

func TestServerSideStore_ImplementsRegenerator(t *testing.T) {
	var _ Regenerator = newTestStore(newFakeBackend(), false)
	var _ sessions.Store = newTestStore(newFakeBackend(), false)
}

// --- which lifetime applies --------------------------------------------------------------

func TestServerSideStore_AuthenticatedFlagFollowsTheConfiguredKey(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	saveNew(t, store, map[interface{}]interface{}{"AuthContext": "a ceremony in progress"})
	assert.False(t, backend.lastAuthenticated, "a ceremony nobody finished has not authenticated")

	saveNew(t, store, map[interface{}]interface{}{"SessionIdentifier": "a-user-session-uuid"})
	assert.True(t, backend.lastAuthenticated)

	saveNew(t, store, map[interface{}]interface{}{"SessionIdentifier": ""})
	assert.False(t, backend.lastAuthenticated, "an empty identifier names no user session")
}

func TestExpiresAt(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	idle := 2 * time.Hour
	max := 24 * time.Hour

	tests := []struct {
		name          string
		createdAt     time.Time
		authenticated bool
		expected      time.Time
	}{
		{
			// Neither setting is consulted: an idle timeout means "this person stopped
			// using the application", which says nothing about a form nobody submitted.
			name:          "before authentication it is a flat 30 minutes",
			createdAt:     now,
			authenticated: false,
			expected:      now.Add(30 * time.Minute),
		},
		{
			name:          "before authentication an old row still gets 30 minutes from now",
			createdAt:     now.Add(-20 * time.Hour),
			authenticated: false,
			expected:      now.Add(30 * time.Minute),
		},
		{
			name:          "after authentication the idle window binds while the day is young",
			createdAt:     now,
			authenticated: true,
			expected:      now.Add(2 * time.Hour),
		},
		{
			name:          "the maximum lifetime binds once it is nearer than the idle window",
			createdAt:     now.Add(-23 * time.Hour),
			authenticated: true,
			expected:      now.Add(1 * time.Hour),
		},
		{
			// The row is then already unusable, which is the intended answer: no amount
			// of activity may move the maximum lifetime.
			name:          "a session past its maximum lifetime expires in the past",
			createdAt:     now.Add(-25 * time.Hour),
			authenticated: true,
			expected:      now.Add(-1 * time.Hour),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, ExpiresAt(now, test.createdAt, test.authenticated, idle, max))
		})
	}
}

func TestServerSideStore_PreAuthLifetimeIsThirtyMinutes(t *testing.T) {
	// Named on its own because it is a constant nothing else would notice changing, and
	// it is what bounds how many rows an unauthenticated caller can leave behind (#266).
	assert.Equal(t, 30*time.Minute, PreAuthLifetime)
	assert.Equal(t, 10*time.Second, TouchThreshold)
}
