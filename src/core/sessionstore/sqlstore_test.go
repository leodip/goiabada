package sessionstore

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
)

// =============================================================================
// SQLStore
//
// The server-side half of the session: the cookie carries only an opaque row id
// and the values live in the http_sessions table. That makes three things worth
// testing carefully: that an expired row is never loaded, that a session id from
// a cookie is parsed strictly, and that the background cleanup actually deletes
// expired rows (otherwise the table grows without bound).
// =============================================================================

var (
	testAuthKey = []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	testEncKey  = []byte("0123456789abcdef0123456789abcdef")
)

func newTestSQLStore(t *testing.T) (*SQLStore, *mocks_data.Database) {
	t.Helper()
	db := mocks_data.NewDatabase(t)
	store := NewSQLStore(db, "/", 3600, true, true, http.SameSiteStrictMode, testAuthKey, testEncKey)
	return store, db
}

// encodeSessionID produces the cookie value the store would have written for a
// given session id, so tests can hand a realistic cookie back to New.
func encodeSessionID(t *testing.T, store *SQLStore, name string, id string) string {
	t.Helper()
	encoded, err := securecookie.EncodeMulti(name, id, store.Codecs...)
	assert.NoError(t, err)
	return encoded
}

// encodeValues produces the stored `data` column contents for a set of values.
func encodeValues(t *testing.T, store *SQLStore, name string, values map[interface{}]interface{}) string {
	t.Helper()
	encoded, err := securecookie.EncodeMulti(name, values, store.Codecs...)
	assert.NoError(t, err)
	return encoded
}

// -----------------------------------------------------------------------------
// NewSQLStore
// -----------------------------------------------------------------------------

func TestNewSQLStore_AppliesOptions(t *testing.T) {
	db := mocks_data.NewDatabase(t)

	store := NewSQLStore(db, "/some-path", 7200, true, true, http.SameSiteLaxMode, testAuthKey, testEncKey)

	assert.Equal(t, "/some-path", store.Options.Path)
	assert.Equal(t, 7200, store.Options.MaxAge)
	assert.True(t, store.Options.HttpOnly)
	assert.True(t, store.Options.Secure)
	assert.Equal(t, http.SameSiteLaxMode, store.Options.SameSite)
	assert.NotEmpty(t, store.Codecs, "key pairs must produce codecs")
}

func TestNewSQLStore_InsecureOptions(t *testing.T) {
	db := mocks_data.NewDatabase(t)

	store := NewSQLStore(db, "/", 60, false, false, http.SameSiteNoneMode, testAuthKey, testEncKey)

	assert.False(t, store.Options.HttpOnly)
	assert.False(t, store.Options.Secure)
	assert.Equal(t, http.SameSiteNoneMode, store.Options.SameSite)
}

// -----------------------------------------------------------------------------
// parseSessionID
// -----------------------------------------------------------------------------

func TestParseSessionID(t *testing.T) {
	testCases := []struct {
		name    string
		input   string
		want    int64
		wantErr bool
	}{
		{name: "plain number", input: "123", want: 123},
		{name: "zero", input: "0", want: 0},
		{name: "large number", input: "9007199254740993", want: 9007199254740993},
		{name: "negative", input: "-5", want: -5},
		{name: "empty", input: "", wantErr: true},
		{name: "not a number", input: "abc", wantErr: true},
		{name: "leading space is skipped by Sscanf", input: " 42", want: 42},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSessionID(tc.input)

			if tc.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "unable to parse session ID")
				assert.Equal(t, int64(0), got)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// Sscanf stops at the first non-digit, so a trailing suffix is silently
// discarded rather than rejected. Pinned because it means a tampered cookie
// value like "12abc" resolves to row 12 instead of erroring.
func TestParseSessionID_TrailingGarbageIsIgnored(t *testing.T) {
	got, err := parseSessionID("12abc")

	assert.NoError(t, err)
	assert.Equal(t, int64(12), got)
}

// -----------------------------------------------------------------------------
// Save and insert
// -----------------------------------------------------------------------------

func TestSave_NewSessionInsertsAndSetsCookie(t *testing.T) {
	store, db := newTestSQLStore(t)

	session := sessions.NewSession(store, "goiabada-session")
	session.Options = store.Options
	session.Values["user"] = "jane"

	var inserted *models.HttpSession
	db.On("CreateHttpSession", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		inserted = args.Get(1).(*models.HttpSession)
		inserted.Id = 77
	}).Return(nil).Once()

	recorder := httptest.NewRecorder()
	err := store.Save(httptest.NewRequest("GET", "/", nil), recorder, session)

	assert.NoError(t, err)
	assert.Equal(t, "77", session.ID, "the generated row id becomes the session id")

	assert.NotNil(t, inserted)
	assert.NotEmpty(t, inserted.Data)
	assert.True(t, inserted.CreatedAt.Valid)
	assert.True(t, inserted.UpdatedAt.Valid)
	assert.True(t, inserted.ExpiresOn.Valid)
	assert.Equal(t, inserted.CreatedAt.Time, inserted.UpdatedAt.Time,
		"a new row is created and modified at the same instant")

	// The expiry is now plus MaxAge.
	expectedExpiry := time.Now().UTC().Add(3600 * time.Second)
	assert.WithinDuration(t, expectedExpiry, inserted.ExpiresOn.Time, 5*time.Second)

	cookies := recorder.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, "goiabada-session", cookies[0].Name)
	assert.NotEmpty(t, cookies[0].Value)
	assert.True(t, cookies[0].HttpOnly)
	assert.True(t, cookies[0].Secure)
}

// created_on and expires_on may already be present in Values (they are set by
// load). When they are, insert must honour them instead of recomputing.
func TestInsert_HonoursExistingTimestamps(t *testing.T) {
	store, db := newTestSQLStore(t)

	createdOn := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	expiresOn := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)

	session := sessions.NewSession(store, "goiabada-session")
	session.Options = store.Options
	session.Values["created_on"] = createdOn
	session.Values["expires_on"] = expiresOn
	session.Values["user"] = "jane"

	var inserted *models.HttpSession
	db.On("CreateHttpSession", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		inserted = args.Get(1).(*models.HttpSession)
		inserted.Id = 5
	}).Return(nil).Once()

	err := store.Save(httptest.NewRequest("GET", "/", nil), httptest.NewRecorder(), session)

	assert.NoError(t, err)
	assert.Equal(t, createdOn, inserted.CreatedAt.Time)
	assert.Equal(t, expiresOn, inserted.ExpiresOn.Time)
}

// The three bookkeeping keys are stripped before encoding, so they never end up
// duplicated inside the encoded blob.
func TestInsert_StripsBookkeepingKeysFromValues(t *testing.T) {
	store, db := newTestSQLStore(t)

	session := sessions.NewSession(store, "goiabada-session")
	session.Options = store.Options
	session.Values["created_on"] = time.Now().UTC()
	session.Values["expires_on"] = time.Now().UTC().Add(time.Hour)
	session.Values["modified_on"] = time.Now().UTC()
	session.Values["user"] = "jane"

	db.On("CreateHttpSession", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		args.Get(1).(*models.HttpSession).Id = 5
	}).Return(nil).Once()

	err := store.Save(httptest.NewRequest("GET", "/", nil), httptest.NewRecorder(), session)

	assert.NoError(t, err)
	assert.NotContains(t, session.Values, "created_on")
	assert.NotContains(t, session.Values, "expires_on")
	assert.NotContains(t, session.Values, "modified_on")
	assert.Equal(t, "jane", session.Values["user"], "real values must survive")
}

func TestSave_InsertErrorPropagates(t *testing.T) {
	store, db := newTestSQLStore(t)

	session := sessions.NewSession(store, "goiabada-session")
	session.Options = store.Options

	db.On("CreateHttpSession", mock.Anything, mock.Anything).Return(errors.New("insert failed")).Once()

	recorder := httptest.NewRecorder()
	err := store.Save(httptest.NewRequest("GET", "/", nil), recorder, session)

	assert.Error(t, err)
	assert.Empty(t, recorder.Result().Cookies(), "no cookie may be set when the row was not written")
}

// -----------------------------------------------------------------------------
// Save on an existing session
// -----------------------------------------------------------------------------

func TestSave_ExistingSessionUpdates(t *testing.T) {
	store, db := newTestSQLStore(t)

	session := sessions.NewSession(store, "goiabada-session")
	session.Options = store.Options
	session.ID = "42"
	session.IsNew = false
	session.Values["user"] = "jane"

	var updated *models.HttpSession
	db.On("UpdateHttpSession", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		updated = args.Get(1).(*models.HttpSession)
	}).Return(nil).Once()

	err := store.Save(httptest.NewRequest("GET", "/", nil), httptest.NewRecorder(), session)

	assert.NoError(t, err)
	assert.NotNil(t, updated)
	assert.Equal(t, int64(42), updated.Id)
	assert.NotEmpty(t, updated.Data)
	assert.True(t, updated.UpdatedAt.Valid)
}

// A session that carries an id but is still flagged new is inserted rather than
// updated, so a stale cookie cannot cause an update against a row that is gone.
func TestSave_ExistingIdButStillNewInserts(t *testing.T) {
	store, db := newTestSQLStore(t)

	session := sessions.NewSession(store, "goiabada-session")
	session.Options = store.Options
	session.ID = "42"
	session.IsNew = true

	db.On("CreateHttpSession", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		args.Get(1).(*models.HttpSession).Id = 43
	}).Return(nil).Once()

	err := store.Save(httptest.NewRequest("GET", "/", nil), httptest.NewRecorder(), session)

	assert.NoError(t, err)
	assert.Equal(t, "43", session.ID)
}

// Saving is a sliding expiration: an expiry that falls sooner than now+MaxAge is
// pushed out to now+MaxAge, so an active session keeps living.
func TestSave_ExtendsAnExpiryThatIsSoonerThanMaxAge(t *testing.T) {
	store, db := newTestSQLStore(t)

	session := sessions.NewSession(store, "goiabada-session")
	session.Options = store.Options
	session.ID = "42"
	session.IsNew = false
	// Only a minute left, well short of the 3600s MaxAge.
	session.Values["expires_on"] = time.Now().UTC().Add(time.Minute)

	var updated *models.HttpSession
	db.On("UpdateHttpSession", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		updated = args.Get(1).(*models.HttpSession)
	}).Return(nil).Once()

	err := store.Save(httptest.NewRequest("GET", "/", nil), httptest.NewRecorder(), session)

	assert.NoError(t, err)
	assert.WithinDuration(t, time.Now().UTC().Add(3600*time.Second), updated.ExpiresOn.Time, 5*time.Second)
}

// The comparison only ever moves the expiry later, never earlier: an expiry
// already beyond now+MaxAge is written through unchanged. Nothing in this layer
// caps it, so the effective ceiling is whatever put the value into Values in the
// first place (load, from the row that a previous save wrote).
func TestSave_LeavesAnExpiryBeyondMaxAgeUntouched(t *testing.T) {
	store, db := newTestSQLStore(t)

	farFuture := time.Now().UTC().Add(500 * time.Hour)

	session := sessions.NewSession(store, "goiabada-session")
	session.Options = store.Options
	session.ID = "42"
	session.IsNew = false
	session.Values["expires_on"] = farFuture

	var updated *models.HttpSession
	db.On("UpdateHttpSession", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		updated = args.Get(1).(*models.HttpSession)
	}).Return(nil).Once()

	err := store.Save(httptest.NewRequest("GET", "/", nil), httptest.NewRecorder(), session)

	assert.NoError(t, err)
	assert.Equal(t, farFuture, updated.ExpiresOn.Time,
		"save never shortens an expiry, it only pushes it out")
}

func TestSave_UsesExistingCreatedOnWhenUpdating(t *testing.T) {
	store, db := newTestSQLStore(t)

	createdOn := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	session := sessions.NewSession(store, "goiabada-session")
	session.Options = store.Options
	session.ID = "42"
	session.IsNew = false
	session.Values["created_on"] = createdOn

	var updated *models.HttpSession
	db.On("UpdateHttpSession", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		updated = args.Get(1).(*models.HttpSession)
	}).Return(nil).Once()

	err := store.Save(httptest.NewRequest("GET", "/", nil), httptest.NewRecorder(), session)

	assert.NoError(t, err)
	assert.Equal(t, createdOn, updated.CreatedAt.Time)
}

func TestSave_UpdateErrorPropagates(t *testing.T) {
	store, db := newTestSQLStore(t)

	session := sessions.NewSession(store, "goiabada-session")
	session.Options = store.Options
	session.ID = "42"
	session.IsNew = false

	db.On("UpdateHttpSession", mock.Anything, mock.Anything).Return(errors.New("update failed")).Once()

	err := store.Save(httptest.NewRequest("GET", "/", nil), httptest.NewRecorder(), session)

	assert.Error(t, err)
}

func TestSave_UnparseableSessionIdErrors(t *testing.T) {
	store, _ := newTestSQLStore(t)

	session := sessions.NewSession(store, "goiabada-session")
	session.Options = store.Options
	session.ID = "not-a-number"
	session.IsNew = false

	err := store.Save(httptest.NewRequest("GET", "/", nil), httptest.NewRecorder(), session)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to parse session ID")
}

// -----------------------------------------------------------------------------
// New and load
// -----------------------------------------------------------------------------

func TestNew_WithoutCookieReturnsFreshSession(t *testing.T) {
	store, _ := newTestSQLStore(t)

	session, err := store.New(httptest.NewRequest("GET", "/", nil), "goiabada-session")

	assert.NoError(t, err)
	assert.NotNil(t, session)
	assert.True(t, session.IsNew)
	assert.Empty(t, session.ID)
	assert.Equal(t, store.Options.Path, session.Options.Path)
	assert.Equal(t, store.Options.MaxAge, session.Options.MaxAge)
	assert.Equal(t, store.Options.SameSite, session.Options.SameSite)
	assert.Equal(t, store.Options.HttpOnly, session.Options.HttpOnly)
	assert.Equal(t, store.Options.Secure, session.Options.Secure)
}

func TestNew_WithValidCookieLoadsStoredValues(t *testing.T) {
	store, db := newTestSQLStore(t)
	const name = "goiabada-session"

	storedData := encodeValues(t, store, name, map[interface{}]interface{}{"user": "jane"})
	createdAt := time.Date(2024, 5, 1, 10, 0, 0, 0, time.UTC)
	updatedAt := time.Date(2024, 5, 1, 11, 0, 0, 0, time.UTC)
	expiresOn := time.Now().UTC().Add(time.Hour)

	db.On("GetHttpSessionById", mock.Anything, int64(77)).Return(&models.HttpSession{
		Id:        77,
		Data:      storedData,
		CreatedAt: sql.NullTime{Time: createdAt, Valid: true},
		UpdatedAt: sql.NullTime{Time: updatedAt, Valid: true},
		ExpiresOn: sql.NullTime{Time: expiresOn, Valid: true},
	}, nil).Once()

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: name, Value: encodeSessionID(t, store, name, "77")})

	session, err := store.New(req, name)

	assert.NoError(t, err)
	assert.False(t, session.IsNew, "a successfully loaded session is not new")
	assert.Equal(t, "77", session.ID)
	assert.Equal(t, "jane", session.Values["user"])
	assert.Equal(t, createdAt, session.Values["created_on"])
	assert.Equal(t, updatedAt, session.Values["modified_on"])
	assert.Equal(t, expiresOn, session.Values["expires_on"])
}

// An expired row must not be loaded. The load error is swallowed and the caller
// gets a fresh session instead, which is how an expired session silently becomes
// a new one.
func TestNew_ExpiredRowYieldsFreshSession(t *testing.T) {
	store, db := newTestSQLStore(t)
	const name = "goiabada-session"

	db.On("GetHttpSessionById", mock.Anything, int64(77)).Return(&models.HttpSession{
		Id:        77,
		Data:      encodeValues(t, store, name, map[interface{}]interface{}{"user": "jane"}),
		ExpiresOn: sql.NullTime{Time: time.Now().UTC().Add(-time.Hour), Valid: true},
	}, nil).Once()

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: name, Value: encodeSessionID(t, store, name, "77")})

	session, err := store.New(req, name)

	assert.NoError(t, err, "an expired session is not surfaced as an error")
	assert.True(t, session.IsNew)
	assert.NotContains(t, session.Values, "user", "no values may be loaded from an expired row")
}

func TestNew_MissingRowYieldsFreshSession(t *testing.T) {
	store, db := newTestSQLStore(t)
	const name = "goiabada-session"

	db.On("GetHttpSessionById", mock.Anything, int64(77)).Return(nil, nil).Once()

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: name, Value: encodeSessionID(t, store, name, "77")})

	session, err := store.New(req, name)

	assert.NoError(t, err)
	assert.True(t, session.IsNew)
}

func TestNew_DatabaseErrorYieldsFreshSession(t *testing.T) {
	store, db := newTestSQLStore(t)
	const name = "goiabada-session"

	db.On("GetHttpSessionById", mock.Anything, int64(77)).Return(nil, errors.New("database is down")).Once()

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: name, Value: encodeSessionID(t, store, name, "77")})

	session, err := store.New(req, name)

	assert.NoError(t, err, "a load failure is swallowed and a new session returned")
	assert.True(t, session.IsNew)
}

// A cookie that cannot be decoded is a tampered or stale-key cookie. That error
// is surfaced, unlike a load failure.
func TestNew_UndecodableCookieReturnsError(t *testing.T) {
	store, _ := newTestSQLStore(t)
	const name = "goiabada-session"

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: name, Value: "this-is-not-a-valid-encoded-value"})

	session, err := store.New(req, name)

	assert.Error(t, err)
	assert.NotNil(t, session)
	assert.True(t, session.IsNew)
}

// A cookie signed with different keys must not be accepted.
func TestNew_CookieFromAnotherKeyIsRejected(t *testing.T) {
	store, _ := newTestSQLStore(t)
	otherDB := mocks_data.NewDatabase(t)
	otherStore := NewSQLStore(otherDB, "/", 3600, true, true, http.SameSiteStrictMode,
		[]byte("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		[]byte("ffffffffffffffffffffffffffffffff"))

	const name = "goiabada-session"
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: name, Value: encodeSessionID(t, otherStore, name, "77")})

	_, err := store.New(req, name)

	assert.Error(t, err)
}

func TestLoad_UnparseableSessionIdErrors(t *testing.T) {
	store, _ := newTestSQLStore(t)

	session := sessions.NewSession(store, "goiabada-session")
	session.ID = "not-a-number"

	err := store.load(session)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to parse session ID")
}

func TestLoad_MissingRowReportsNotFound(t *testing.T) {
	store, db := newTestSQLStore(t)

	db.On("GetHttpSessionById", mock.Anything, int64(9)).Return(nil, nil).Once()

	session := sessions.NewSession(store, "goiabada-session")
	session.ID = "9"

	err := store.load(session)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session not found")
}

func TestLoad_ExpiredRowReportsExpired(t *testing.T) {
	store, db := newTestSQLStore(t)

	db.On("GetHttpSessionById", mock.Anything, int64(9)).Return(&models.HttpSession{
		Id:        9,
		ExpiresOn: sql.NullTime{Time: time.Now().UTC().Add(-time.Minute), Valid: true},
	}, nil).Once()

	session := sessions.NewSession(store, "goiabada-session")
	session.ID = "9"

	err := store.load(session)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session expired")
}

// Data that does not decode with the store's keys must be rejected rather than
// producing a half-populated session.
func TestLoad_UndecodableDataErrors(t *testing.T) {
	store, db := newTestSQLStore(t)

	db.On("GetHttpSessionById", mock.Anything, int64(9)).Return(&models.HttpSession{
		Id:        9,
		Data:      "not-a-valid-encoded-blob",
		ExpiresOn: sql.NullTime{Time: time.Now().UTC().Add(time.Hour), Valid: true},
	}, nil).Once()

	session := sessions.NewSession(store, "goiabada-session")
	session.ID = "9"

	err := store.load(session)

	assert.Error(t, err)
}

// -----------------------------------------------------------------------------
// Get
// -----------------------------------------------------------------------------

func TestGet_ReturnsASessionAndCachesItPerRequest(t *testing.T) {
	store, _ := newTestSQLStore(t)
	req := httptest.NewRequest("GET", "/", nil)

	first, err := store.Get(req, "goiabada-session")
	assert.NoError(t, err)
	assert.NotNil(t, first)

	second, err := store.Get(req, "goiabada-session")
	assert.NoError(t, err)
	assert.Same(t, first, second, "the registry must return the same session within one request")
}

// -----------------------------------------------------------------------------
// Delete
// -----------------------------------------------------------------------------

func TestDelete_RemovesRowClearsValuesAndExpiresCookie(t *testing.T) {
	store, db := newTestSQLStore(t)

	session := sessions.NewSession(store, "goiabada-session")
	session.Options = store.Options
	session.ID = "42"
	session.Values["user"] = "jane"
	session.Values["other"] = 7

	db.On("DeleteHttpSession", mock.Anything, int64(42)).Return(nil).Once()

	recorder := httptest.NewRecorder()
	err := store.Delete(recorder, session)

	assert.NoError(t, err)
	assert.Empty(t, session.Values, "all values must be cleared")

	cookies := recorder.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, "goiabada-session", cookies[0].Name)
	assert.Equal(t, "", cookies[0].Value)
	assert.Equal(t, -1, cookies[0].MaxAge, "the cookie must be expired immediately")
}

// Delete must not mutate the store's shared Options when it sets MaxAge to -1.
func TestDelete_DoesNotMutateStoreOptions(t *testing.T) {
	store, db := newTestSQLStore(t)

	session := sessions.NewSession(store, "goiabada-session")
	session.Options = store.Options
	session.ID = "42"

	db.On("DeleteHttpSession", mock.Anything, int64(42)).Return(nil).Once()

	err := store.Delete(httptest.NewRecorder(), session)

	assert.NoError(t, err)
	assert.Equal(t, 3600, store.Options.MaxAge, "the store's options must be untouched")
}

func TestDelete_UnparseableSessionIdErrors(t *testing.T) {
	store, _ := newTestSQLStore(t)

	session := sessions.NewSession(store, "goiabada-session")
	session.Options = store.Options
	session.ID = "not-a-number"

	err := store.Delete(httptest.NewRecorder(), session)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to parse session ID")
}

func TestDelete_DatabaseErrorPropagates(t *testing.T) {
	store, db := newTestSQLStore(t)

	session := sessions.NewSession(store, "goiabada-session")
	session.Options = store.Options
	session.ID = "42"

	db.On("DeleteHttpSession", mock.Anything, int64(42)).Return(errors.New("delete failed")).Once()

	err := store.Delete(httptest.NewRecorder(), session)

	assert.Error(t, err)
}

// -----------------------------------------------------------------------------
// Expiry cleanup
//
// If this stops working the http_sessions table grows without bound, so the
// tests below verify the delete actually fires on a tick and that the goroutine
// shuts down cleanly.
// -----------------------------------------------------------------------------

func TestDeleteExpired_DelegatesToTheDatabase(t *testing.T) {
	store, db := newTestSQLStore(t)

	db.On("DeleteHttpSessionExpired", mock.Anything).Return(nil).Once()

	err := store.deleteExpired()

	assert.NoError(t, err)
}

func TestDeleteExpired_ErrorPropagates(t *testing.T) {
	store, db := newTestSQLStore(t)

	db.On("DeleteHttpSessionExpired", mock.Anything).Return(errors.New("delete failed")).Once()

	err := store.deleteExpired()

	assert.Error(t, err)
}

func TestCleanup_DeletesExpiredSessionsOnEachTick(t *testing.T) {
	store, db := newTestSQLStore(t)

	deleted := make(chan struct{}, 16)
	db.On("DeleteHttpSessionExpired", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		select {
		case deleted <- struct{}{}:
		default:
		}
	})

	quit, done := store.Cleanup(10 * time.Millisecond)

	select {
	case <-deleted:
	case <-time.After(5 * time.Second):
		t.Fatal("expected expired sessions to be deleted on a tick")
	}

	store.StopCleanup(quit, done)
}

// A cleanup error is logged and the loop keeps running, so one database blip
// does not silently stop expiry forever.
func TestCleanup_SurvivesADeleteError(t *testing.T) {
	store, db := newTestSQLStore(t)

	calls := make(chan struct{}, 16)
	db.On("DeleteHttpSessionExpired", mock.Anything).Return(errors.New("delete failed")).Run(func(args mock.Arguments) {
		select {
		case calls <- struct{}{}:
		default:
		}
	})

	quit, done := store.Cleanup(10 * time.Millisecond)

	// Two ticks means the loop did not exit after the first failure.
	for i := 0; i < 2; i++ {
		select {
		case <-calls:
		case <-time.After(5 * time.Second):
			t.Fatal("expected the cleanup loop to keep ticking after an error")
		}
	}

	store.StopCleanup(quit, done)
}

// A non-positive interval falls back to the package default rather than
// spinning on a zero-length ticker.
func TestCleanup_NonPositiveIntervalUsesTheDefault(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Second} {
		store, _ := newTestSQLStore(t)

		quit, done := store.Cleanup(interval)

		// With the 5 minute default no tick fires during the test, so no
		// DeleteHttpSessionExpired call is expected at all.
		store.StopCleanup(quit, done)
	}
}

func TestStopCleanup_ReturnsAfterTheGoroutineExits(t *testing.T) {
	store, _ := newTestSQLStore(t)

	quit, done := store.Cleanup(time.Hour)

	finished := make(chan struct{})
	go func() {
		store.StopCleanup(quit, done)
		close(finished)
	}()

	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("StopCleanup did not return")
	}
}
