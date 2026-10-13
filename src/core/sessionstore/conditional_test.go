package sessionstore

import (
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/gob"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fake's conditional pair: Update and Delete on condition that the stored contents are the
// ones expected, after beforeConditional has had its turn (#579).

var _ ConditionalBackend = (*fakeBackend)(nil)

func (f *fakeBackend) UpdateIfUnchanged(ctx context.Context, id string, expected, data []byte, authenticated bool) (time.Time, error) {
	f.conditionalUpdates++
	if f.beforeConditional != nil {
		f.beforeConditional(id)
	}
	if f.conditionalUpdateErr != nil {
		return time.Time{}, f.conditionalUpdateErr
	}
	record, ok := f.rows[id]
	if !ok || !bytes.Equal(record.Data, expected) {
		return time.Time{}, ErrChanged
	}
	f.lastData = data
	f.lastAuthenticated = authenticated
	record.Data = data
	return f.expiresAt, nil
}

func (f *fakeBackend) DeleteIfUnchanged(ctx context.Context, id string, expected []byte) error {
	f.conditionalDeletes++
	if f.beforeConditional != nil {
		f.beforeConditional(id)
	}
	if f.conditionalDeleteErr != nil {
		return f.conditionalDeleteErr
	}
	record, ok := f.rows[id]
	if !ok || !bytes.Equal(record.Data, expected) {
		return ErrChanged
	}
	delete(f.rows, id)
	return nil
}

func newConditionalTestStore(backend ConditionalBackend) *ConditionalStore {
	store, err := NewConditionalStore(newTestStore(backend, false), backend)
	if err != nil {
		panic(err)
	}
	return store
}

// storedValues opens the row id names, the way a later request would read it.
func storedValues(t *testing.T, store *ConditionalStore, backend *fakeBackend, id string) map[string]any {
	t.Helper()

	record, ok := backend.rows[id]
	require.True(t, ok, "no row for %s", id)
	plaintext, err := store.openWithEither(func(sl *sealer) cipher.AEAD { return sl.data }, storeTestName, string(record.Data))
	require.NoError(t, err)
	var values map[string]any
	require.NoError(t, gob.NewDecoder(bytes.NewReader(plaintext)).Decode(&values))
	return values
}

// loadedRequest is the request whose step is under test: it carries the browser's cookie and has
// read its session through Get, so the request's cache holds the copy it began with.
func loadedRequest(t *testing.T, store *ConditionalStore, cookie *http.Cookie) (*http.Request, *Session) {
	t.Helper()

	req := requestWith(cookie)
	session, err := store.Get(req, storeTestName)
	require.NoError(t, err)
	require.NotEmpty(t, session.ID)
	return req, session
}

// anotherRequestWrites is another request of the same browser saving its own change, the whole
// copy it read, as every save does.
func anotherRequestWrites(t *testing.T, store *ConditionalStore, cookie *http.Cookie, key string, value any) {
	t.Helper()

	req := requestWith(cookie)
	session, err := store.Get(req, storeTestName)
	require.NoError(t, err)
	session.Values[key] = value
	require.NoError(t, store.Save(req, httptest.NewRecorder(), session))
}

func set(key string, value any) func(map[string]any) error {
	return func(values map[string]any) error {
		values[key] = value
		return nil
	}
}

// --- ChangeAndSave ----------------------------------------------------------------------------

// The change lands on what is stored now, not on the copy the request read: the other request's
// write survives, and the request's own session then holds what was stored.
func TestConditionalStore_ChangeAndSaveAppliesTheChangeToTheFreshValues(t *testing.T) {
	backend := newFakeBackend()
	store := newConditionalTestStore(backend)
	cookie := saveNew(t, store.ServerSideStore, map[string]any{"ceremony": "A"})
	id := decodeCookieId(t, store.ServerSideStore, cookie)

	req, session := loadedRequest(t, store, cookie)
	anotherRequestWrites(t, store, cookie, "ceremony", "B")

	w := httptest.NewRecorder()
	require.NoError(t, store.ChangeAndSave(req, w, session, set("locale", "pt-BR")))

	want := map[string]any{"ceremony": "B", "locale": "pt-BR"}
	assert.Equal(t, want, storedValues(t, store, backend, id))
	assert.Equal(t, want, session.Values, "the request's session holds what was stored")
	assert.Equal(t, id, session.ID)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1, "a conditional save names the session as a save does")
	assert.Equal(t, id, decodeCookieId(t, store.ServerSideStore, cookies[0]))

	// The request's cache holds the same session, so a later read in the request sees it too.
	again, err := store.Get(req, storeTestName)
	require.NoError(t, err)
	assert.Equal(t, want, again.Values)
}

// The change sees the fresh values, which is what lets a caller refuse on them, and a refusal
// is returned as it is and writes nothing at all.
func TestConditionalStore_ChangeAndSaveRefusedWritesNothing(t *testing.T) {
	backend := newFakeBackend()
	store := newConditionalTestStore(backend)
	cookie := saveNew(t, store.ServerSideStore, map[string]any{"ceremony": "A"})
	id := decodeCookieId(t, store.ServerSideStore, cookie)

	req, session := loadedRequest(t, store, cookie)
	anotherRequestWrites(t, store, cookie, "ceremony", "B")
	storedBefore := append([]byte(nil), backend.rows[id].Data...)

	replaced := errors.New("the ceremony was replaced")
	var seen any
	w := httptest.NewRecorder()
	err := store.ChangeAndSave(req, w, session, func(values map[string]any) error {
		seen = values["ceremony"]
		return replaced
	})

	require.ErrorIs(t, err, replaced)
	assert.Equal(t, "B", seen, "the change is handed the values stored now")
	assert.Equal(t, 0, backend.conditionalUpdates)
	assert.Equal(t, storedBefore, backend.rows[id].Data)
	assert.Empty(t, w.Result().Cookies())
	assert.Equal(t, map[string]any{"ceremony": "A"}, session.Values, "a refused write leaves the request's session")
}

// A row gone since the request read it stays gone: nothing is created, no cookie is set, and
// the answer is ErrNotFound, which a caller reads as its session no longer being there.
func TestConditionalStore_ChangeAndSaveOfAGoneRowAnswersNotFound(t *testing.T) {
	backend := newFakeBackend()
	store := newConditionalTestStore(backend)
	cookie := saveNew(t, store.ServerSideStore, map[string]any{"ceremony": "A"})
	id := decodeCookieId(t, store.ServerSideStore, cookie)

	req, session := loadedRequest(t, store, cookie)
	delete(backend.rows, id)
	creates := backend.creates

	called := false
	w := httptest.NewRecorder()
	err := store.ChangeAndSave(req, w, session, func(map[string]any) error {
		called = true
		return nil
	})

	require.ErrorIs(t, err, ErrNotFound)
	assert.False(t, called, "there is nothing to apply the change to")
	assert.Equal(t, creates, backend.creates)
	assert.Empty(t, backend.rows)
	assert.Empty(t, w.Result().Cookies())
}

// A write that loses reads again and applies the change to what won, so neither is lost.
func TestConditionalStore_ChangeAndSaveThatLosesOnceTriesAgain(t *testing.T) {
	backend := newFakeBackend()
	store := newConditionalTestStore(backend)
	cookie := saveNew(t, store.ServerSideStore, map[string]any{"ceremony": "A"})
	id := decodeCookieId(t, store.ServerSideStore, cookie)

	req, session := loadedRequest(t, store, cookie)
	loads := backend.loads
	backend.beforeConditional = func(string) {
		backend.beforeConditional = nil
		anotherRequestWrites(t, store, cookie, "marker", "set meanwhile")
	}

	w := httptest.NewRecorder()
	require.NoError(t, store.ChangeAndSave(req, w, session, set("locale", "pt-BR")))

	want := map[string]any{"ceremony": "A", "marker": "set meanwhile", "locale": "pt-BR"}
	assert.Equal(t, want, storedValues(t, store, backend, id))
	assert.Equal(t, want, session.Values)
	assert.Equal(t, 2, backend.conditionalUpdates)
	assert.Equal(t, 3, backend.loads-loads, "two fresh reads, and the other request's own")
	assert.Len(t, w.Result().Cookies(), 1)
}

// The retry is bounded: three attempts, then the failure, with nothing of this request's written
// and no cookie.
func TestConditionalStore_ChangeAndSaveGivesUpAfterThreeAttempts(t *testing.T) {
	backend := newFakeBackend()
	store := newConditionalTestStore(backend)
	cookie := saveNew(t, store.ServerSideStore, map[string]any{"ceremony": "A"})
	id := decodeCookieId(t, store.ServerSideStore, cookie)

	req, session := loadedRequest(t, store, cookie)
	writes := 0
	backend.beforeConditional = func(string) {
		writes++
		anotherRequestWrites(t, store, cookie, "counter", writes)
	}

	w := httptest.NewRecorder()
	err := store.ChangeAndSave(req, w, session, set("locale", "pt-BR"))

	require.ErrorIs(t, err, ErrChanged)
	assert.Equal(t, 3, backend.conditionalUpdates)
	assert.NotContains(t, storedValues(t, store, backend, id), "locale")
	assert.Empty(t, w.Result().Cookies())
}

func TestConditionalStore_ChangeAndSaveFailureIsReturnedAndSetsNoCookie(t *testing.T) {
	backend := newFakeBackend()
	store := newConditionalTestStore(backend)
	cookie := saveNew(t, store.ServerSideStore, map[string]any{"ceremony": "A"})

	t.Run("fresh read", func(t *testing.T) {
		req, session := loadedRequest(t, store, cookie)
		cause := errors.New("the database is unreachable")
		backend.loadErr = cause
		defer func() { backend.loadErr = nil }()

		w := httptest.NewRecorder()
		err := store.ChangeAndSave(req, w, session, set("locale", "pt-BR"))

		require.ErrorIs(t, err, cause)
		require.NotErrorIs(t, err, ErrNotFound)
		assert.Empty(t, w.Result().Cookies())
	})

	t.Run("conditional write", func(t *testing.T) {
		req, session := loadedRequest(t, store, cookie)
		cause := errors.New("the database is unreachable")
		backend.conditionalUpdateErr = cause
		defer func() { backend.conditionalUpdateErr = nil }()
		updates := backend.conditionalUpdates

		w := httptest.NewRecorder()
		err := store.ChangeAndSave(req, w, session, set("locale", "pt-BR"))

		require.ErrorIs(t, err, cause)
		assert.Equal(t, 1, backend.conditionalUpdates-updates, "a failure is not a lost race, and is not retried")
		assert.Empty(t, w.Result().Cookies())
	})
}

// A session never stored has no row anyone could have written in between, so the change is
// applied to an empty session and the row created, as a first save creates one. Only the change
// is written: whatever else the request put in its copy is not this write's.
func TestConditionalStore_ChangeAndSaveOfANeverStoredSessionCreatesIt(t *testing.T) {
	backend := newFakeBackend()
	store := newConditionalTestStore(backend)

	req := httptest.NewRequest("GET", "/", nil)
	session, err := store.Get(req, storeTestName)
	require.NoError(t, err)
	session.Values["unsaved"] = "not this write's"

	w := httptest.NewRecorder()
	require.NoError(t, store.ChangeAndSave(req, w, session, set("marker", "set")))

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	id := decodeCookieId(t, store.ServerSideStore, cookies[0])
	assert.Equal(t, map[string]any{"marker": "set"}, storedValues(t, store, backend, id))
	assert.Equal(t, id, session.ID)
	assert.False(t, session.IsNew)
	assert.Equal(t, map[string]any{"marker": "set"}, session.Values)
}

// Which lifetime the row gets follows the values written, not the copy the request read.
func TestConditionalStore_ChangeAndSaveIsAuthenticatedByTheValuesItWrites(t *testing.T) {
	backend := newFakeBackend()
	store := newConditionalTestStore(backend)
	cookie := saveNew(t, store.ServerSideStore, map[string]any{"ceremony": "A"})

	req, session := loadedRequest(t, store, cookie)
	anotherRequestWrites(t, store, cookie, "SessionIdentifier", "the user's session")

	require.NoError(t, store.ChangeAndSave(req, httptest.NewRecorder(), session, set("locale", "pt-BR")))
	assert.True(t, backend.lastAuthenticated)
}

// --- ChangeAndRegenerate ----------------------------------------------------------------------

func TestConditionalStore_ChangeAndRegenerateMovesTheFreshValuesToANewIdentifier(t *testing.T) {
	backend := newFakeBackend()
	store := newConditionalTestStore(backend)
	cookie := saveNew(t, store.ServerSideStore, map[string]any{"ceremony": "A"})
	oldId := decodeCookieId(t, store.ServerSideStore, cookie)

	req, session := loadedRequest(t, store, cookie)
	anotherRequestWrites(t, store, cookie, "marker", "set meanwhile")

	w := httptest.NewRecorder()
	require.NoError(t, store.ChangeAndRegenerate(w, req, session, set("state", "password verified")))

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	newId := decodeCookieId(t, store.ServerSideStore, cookies[0])
	assert.NotEqual(t, oldId, newId)
	assert.NotContains(t, backend.rows, oldId)
	assert.Len(t, backend.rows, 1)

	want := map[string]any{"ceremony": "A", "marker": "set meanwhile", "state": "password verified"}
	assert.Equal(t, want, storedValues(t, store, backend, newId))
	assert.Equal(t, want, session.Values)
	assert.Equal(t, newId, session.ID)
	assert.False(t, session.IsNew)
}

// The old row written between the fresh read and its removal: it is kept, the new row built from
// the stale read is removed, and the attempt repeated from a fresh read.
func TestConditionalStore_ChangeAndRegenerateThatLosesRemovesItsNewRowAndTriesAgain(t *testing.T) {
	backend := newFakeBackend()
	store := newConditionalTestStore(backend)
	cookie := saveNew(t, store.ServerSideStore, map[string]any{"ceremony": "A"})
	oldId := decodeCookieId(t, store.ServerSideStore, cookie)

	req, session := loadedRequest(t, store, cookie)
	var firstNewRows []string
	backend.beforeConditional = func(id string) {
		backend.beforeConditional = nil
		require.Equal(t, oldId, id, "the conditional removal is of the old row")
		for rowId := range backend.rows {
			if rowId != oldId {
				firstNewRows = append(firstNewRows, rowId)
			}
		}
		anotherRequestWrites(t, store, cookie, "ceremony", "B")
	}

	w := httptest.NewRecorder()
	require.NoError(t, store.ChangeAndRegenerate(w, req, session, set("state", "password verified")))

	require.Len(t, firstNewRows, 1, "the first attempt had written its new row before the removal")
	assert.NotContains(t, backend.rows, firstNewRows[0], "the losing attempt's new row is removed")
	assert.NotContains(t, backend.rows, oldId)
	require.Len(t, backend.rows, 1)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1, "one cookie, for the attempt that won")
	newId := decodeCookieId(t, store.ServerSideStore, cookies[0])
	assert.Equal(t, map[string]any{"ceremony": "B", "state": "password verified"}, storedValues(t, store, backend, newId))
	assert.Equal(t, 2, backend.conditionalDeletes)
}

// A row gone since the request read it is not re-created under a new identifier: that is what
// would put a stale session back after another request rotated it away.
func TestConditionalStore_ChangeAndRegenerateOfAGoneRowAnswersNotFound(t *testing.T) {
	backend := newFakeBackend()
	store := newConditionalTestStore(backend)
	cookie := saveNew(t, store.ServerSideStore, map[string]any{"ceremony": "A"})
	oldId := decodeCookieId(t, store.ServerSideStore, cookie)

	req, session := loadedRequest(t, store, cookie)
	delete(backend.rows, oldId)
	creates := backend.creates

	w := httptest.NewRecorder()
	err := store.ChangeAndRegenerate(w, req, session, set("state", "password verified"))

	require.ErrorIs(t, err, ErrNotFound)
	assert.Equal(t, creates, backend.creates)
	assert.Empty(t, backend.rows)
	assert.Empty(t, w.Result().Cookies())
	assert.Equal(t, oldId, session.ID)
}

func TestConditionalStore_ChangeAndRegenerateRefusedCreatesNothing(t *testing.T) {
	backend := newFakeBackend()
	store := newConditionalTestStore(backend)
	cookie := saveNew(t, store.ServerSideStore, map[string]any{"ceremony": "A"})
	oldId := decodeCookieId(t, store.ServerSideStore, cookie)

	req, session := loadedRequest(t, store, cookie)
	creates := backend.creates
	replaced := errors.New("the ceremony was replaced")

	w := httptest.NewRecorder()
	err := store.ChangeAndRegenerate(w, req, session, func(map[string]any) error { return replaced })

	require.ErrorIs(t, err, replaced)
	assert.Equal(t, creates, backend.creates)
	assert.Contains(t, backend.rows, oldId)
	assert.Len(t, backend.rows, 1)
	assert.Empty(t, w.Result().Cookies())
}

// Losing three times gives up with the old row as the other request left it, no new row
// standing, and no cookie.
func TestConditionalStore_ChangeAndRegenerateGivesUpAfterThreeAttempts(t *testing.T) {
	backend := newFakeBackend()
	store := newConditionalTestStore(backend)
	cookie := saveNew(t, store.ServerSideStore, map[string]any{"ceremony": "A"})
	oldId := decodeCookieId(t, store.ServerSideStore, cookie)

	req, session := loadedRequest(t, store, cookie)
	writes := 0
	backend.beforeConditional = func(string) {
		writes++
		anotherRequestWrites(t, store, cookie, "counter", writes)
	}

	w := httptest.NewRecorder()
	err := store.ChangeAndRegenerate(w, req, session, set("state", "password verified"))

	require.ErrorIs(t, err, ErrChanged)
	assert.Equal(t, 3, backend.conditionalDeletes)
	require.Len(t, backend.rows, 1)
	assert.Equal(t, map[string]any{"ceremony": "A", "counter": 3}, storedValues(t, store, backend, oldId))
	assert.Empty(t, w.Result().Cookies())
	assert.Equal(t, oldId, session.ID)
}

// The order a rotation rests on (#266) holds for the conditional one: a failure before the
// cookie emits no header at all.
func TestConditionalStore_ChangeAndRegenerateFailureEmitsNoCookie(t *testing.T) {
	t.Run("new row", func(t *testing.T) {
		backend := newFakeBackend()
		store := newConditionalTestStore(backend)
		cookie := saveNew(t, store.ServerSideStore, map[string]any{"ceremony": "A"})
		oldId := decodeCookieId(t, store.ServerSideStore, cookie)

		req, session := loadedRequest(t, store, cookie)
		cause := errors.New("the database is unreachable")
		backend.createErr = cause

		w := httptest.NewRecorder()
		err := store.ChangeAndRegenerate(w, req, session, set("state", "password verified"))

		require.ErrorIs(t, err, cause)
		assert.Empty(t, w.Result().Cookies())
		assert.Contains(t, backend.rows, oldId)
		assert.Equal(t, 0, backend.conditionalDeletes)
	})

	t.Run("conditional removal", func(t *testing.T) {
		backend := newFakeBackend()
		store := newConditionalTestStore(backend)
		cookie := saveNew(t, store.ServerSideStore, map[string]any{"ceremony": "A"})

		req, session := loadedRequest(t, store, cookie)
		cause := errors.New("the database is unreachable")
		backend.conditionalDeleteErr = cause

		w := httptest.NewRecorder()
		err := store.ChangeAndRegenerate(w, req, session, set("state", "password verified"))

		require.ErrorIs(t, err, cause)
		assert.Empty(t, w.Result().Cookies())
		assert.Equal(t, 1, backend.conditionalDeletes, "a failure is not a lost race, and is not retried")
	})

	t.Run("removal of the losing attempt's new row", func(t *testing.T) {
		backend := newFakeBackend()
		store := newConditionalTestStore(backend)
		cookie := saveNew(t, store.ServerSideStore, map[string]any{"ceremony": "A"})

		req, session := loadedRequest(t, store, cookie)
		cause := errors.New("the database is unreachable")
		backend.beforeConditional = func(string) {
			backend.beforeConditional = nil
			anotherRequestWrites(t, store, cookie, "ceremony", "B")
			backend.deleteErr = cause
		}

		w := httptest.NewRecorder()
		err := store.ChangeAndRegenerate(w, req, session, set("state", "password verified"))

		require.ErrorIs(t, err, cause)
		assert.Empty(t, w.Result().Cookies())
		assert.Equal(t, 1, backend.conditionalDeletes)
	})
}

// A session never stored is rotated as Regenerate rotates one: created, with nothing to remove.
func TestConditionalStore_ChangeAndRegenerateOfANeverStoredSessionCreatesWithoutRemoving(t *testing.T) {
	backend := newFakeBackend()
	store := newConditionalTestStore(backend)

	req := httptest.NewRequest("GET", "/", nil)
	session, err := store.Get(req, storeTestName)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	require.NoError(t, store.ChangeAndRegenerate(w, req, session, set("state", "password verified")))

	assert.Equal(t, 1, backend.creates)
	assert.Equal(t, 0, backend.conditionalDeletes)
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	id := decodeCookieId(t, store.ServerSideStore, cookies[0])
	assert.Equal(t, map[string]any{"state": "password verified"}, storedValues(t, store, backend, id))
}

// The conditional writes and the store's own must read and write the same rows, so a backend
// other than the store's is refused when the store is built, not at the first write.
func TestNewConditionalStore_RefusesABackendOtherThanTheStores(t *testing.T) {
	store := newTestStore(newFakeBackend(), false)

	conditional, err := NewConditionalStore(store, newFakeBackend())

	require.Error(t, err)
	assert.Nil(t, conditional)
}
