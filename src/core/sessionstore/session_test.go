package sessionstore

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These cases drive Session's own methods and nothing else, and the thinness is
// deliberate rather than a gap: the round trip through a real store, which is the only
// thing that can show whether a flash survives being stored and read back, belongs to
// TestServerSideStore_FlashSurvivesAReloadAndIsReadOnce beside the store it exercises.
// Here there is no backend, no cookie and no serialisation, so what is left to check is
// the contract a handler holds a *Session for.
//
// There is no default-key case and no multi-value case. Those were the shape of the
// library this replaced; this package's flash pair has neither, so writing them would be
// asserting somebody else's contract (#269).

// recordingStore is the smallest thing Session.Save can reach: it records the call and
// answers whatever the test wants it to.
type recordingStore struct {
	saved      *Session
	savedTimes int
	saveErr    error
}

func (s *recordingStore) Get(r *http.Request, name string) (*Session, error) {
	return NewSession(s, name), nil
}

func (s *recordingStore) Save(r *http.Request, w http.ResponseWriter, session *Session) error {
	s.saved = session
	s.savedTimes++
	return s.saveErr
}

func TestNewSession(t *testing.T) {
	store := &recordingStore{}
	session := NewSession(store, "goiabada-test")

	// Non-nil Values is the contract every handler leans on: they write into the map
	// without checking it, so a nil here is a panic at the first write.
	require.NotNil(t, session.Values)
	assert.Empty(t, session.Values)

	// Non-nil Options for the same reason: the store copies its defaults over this and
	// two logout handlers assign to Options.MaxAge on a session they were handed.
	require.NotNil(t, session.Options)
	assert.Equal(t, Options{}, *session.Options)

	assert.Equal(t, "goiabada-test", session.Name())
	assert.Empty(t, session.ID)
	assert.False(t, session.IsNew, "IsNew is the store's to set, not the constructor's")
}

func TestSession_SaveReachesTheStore(t *testing.T) {
	store := &recordingStore{}
	session := NewSession(store, "goiabada-test")
	session.Values["greeting"] = "hello"

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	require.NoError(t, session.Save(req, httptest.NewRecorder()))

	assert.Equal(t, 1, store.savedTimes)
	assert.Same(t, session, store.saved, "the store must be handed this session, not a copy")
}

func TestSession_SavePassesTheStoresErrorBack(t *testing.T) {
	store := &recordingStore{saveErr: assert.AnError}
	session := NewSession(store, "goiabada-test")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	assert.ErrorIs(t, session.Save(req, httptest.NewRecorder()), assert.AnError)
}

func TestSession_Flashes(t *testing.T) {
	tests := []struct {
		name  string
		drive func(t *testing.T, session *Session)
	}{
		{
			name: "a flash is read once and then gone",
			drive: func(t *testing.T, session *Session) {
				session.SetFlash("savedSuccessfully", "true")

				value, ok := session.TakeFlash("savedSuccessfully")
				assert.True(t, ok)
				assert.Equal(t, "true", value)

				value, ok = session.TakeFlash("savedSuccessfully")
				assert.False(t, ok, "a second read must not see it")
				assert.Empty(t, value)
			},
		},
		{
			name: "reading clears the key rather than blanking it",
			drive: func(t *testing.T, session *Session) {
				session.SetFlash("savedSuccessfully", "true")
				_, _ = session.TakeFlash("savedSuccessfully")

				// The key itself has to go, not merely its value: what gets stored is
				// Values, so a key left behind is a key written back on every save for
				// the rest of the session's life.
				assert.NotContains(t, session.Values, "savedSuccessfully")
			},
		},
		{
			name: "a key that was never set reports absence",
			drive: func(t *testing.T, session *Session) {
				value, ok := session.TakeFlash("neverSet")
				assert.False(t, ok)
				assert.Empty(t, value)
			},
		},
		{
			name: "two writes under one key leave the second value",
			drive: func(t *testing.T, session *Session) {
				session.SetFlash("notice", "first")
				session.SetFlash("notice", "second")

				value, ok := session.TakeFlash("notice")
				assert.True(t, ok)
				assert.Equal(t, "second", value)
			},
		},
		{
			name: "an empty flash is still a flash",
			drive: func(t *testing.T, session *Session) {
				// Absence is reported in the boolean, not by an empty string, so these
				// two are distinguishable. A caller reducing the flash to a boolean, as
				// all 35 of them do, would otherwise silently lose this one.
				session.SetFlash("notice", "")

				value, ok := session.TakeFlash("notice")
				assert.True(t, ok)
				assert.Empty(t, value)
			},
		},
		{
			name: "a non-string value under a flash key is absence, not a panic",
			drive: func(t *testing.T, session *Session) {
				// Values is shared with everything else the session carries, so a flash
				// key can collide with a key some other writer owns. Reporting absence
				// is what keeps that a wrong answer rather than a crashed request.
				session.Values["notice"] = 42

				value, ok := session.TakeFlash("notice")
				assert.False(t, ok)
				assert.Empty(t, value)
				assert.Equal(t, 42, session.Values["notice"], "and the other writer's value stays")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.drive(t, NewSession(&recordingStore{}, "goiabada-test"))
		})
	}
}

// TestStoreIsImplementedByTheRecordingStore is the compile-time half of seam 3: it says
// out loud that two methods are the whole interface, so adding a third breaks here with a
// message rather than breaking every hand-written double in the tree.
func TestStoreIsImplementedByTheRecordingStore(t *testing.T) {
	var _ Store = (*recordingStore)(nil)
}
