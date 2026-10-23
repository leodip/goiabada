package datatests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/sessionbackend"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The interleavings #579 and #246 name, through the real ceremony store over the real database
// backend: tab A's step loads its ceremony, tab B's /auth/authorize adds another in the same
// browser session, and tab A's step saves, and the same with each write landing between the other's
// fresh read and its conditional write. Only a real engine shows the condition each write is made
// on, the stored ciphertext, holds on its text type and collation, so this is where both sign-ins
// are shown surviving. The order is plain sequence: nothing here needs a goroutine, because each
// request's read and write are separate calls, and a write that lands inside another runs from the
// backend's turn before that one's conditional write.

const interleavingSessionName = "goiabada-auth-test"

// rotatingUserId is the user a rotation here is for, whose password or code the step has just accepted.
const rotatingUserId int64 = 1

// newDatabaseCeremonyStore is the ceremony store as the auth server builds it, over this run's
// database, with the session store and the backend under it.
func newDatabaseCeremonyStore(t *testing.T) (*ceremony.Store, *sessionstore.ServerSideStore, sessionstore.ConditionalBackend) {
	t.Helper()
	return ceremonyStoreOver(t, sessionbackend.NewAuthServerBackend(database))
}

// ceremonyStoreOver is newDatabaseCeremonyStore over backend.
func ceremonyStoreOver(t *testing.T, backend sessionstore.ConditionalBackend) (*ceremony.Store, *sessionstore.ServerSideStore, sessionstore.ConditionalBackend) {
	t.Helper()
	store, err := sessionstore.NewServerSideStore(backend, sessionkeys.SessionIdentifier, false,
		sessionstore.PersistentCookie, sessionstore.KeyPair{
			AuthenticationKey: []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
			EncryptionKey:     []byte("0123456789abcdef0123456789abcdef"),
		}, nil)
	require.NoError(t, err)
	conditional, err := sessionstore.NewConditionalStore(store, backend)
	require.NoError(t, err)
	return ceremony.NewStore(conditional, interleavingSessionName), store, backend
}

// ceremonyRequest is one request of the browser, carrying its cookies and the session lifetimes the
// settings middleware puts on every request, which is where the backend reads a row's deadlines.
func ceremonyRequest(cookies []*http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "https://as.example.com/auth/level1", nil)
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{
		UserSessionIdleTimeoutInSeconds: 1800,
		UserSessionMaxLifetimeInSeconds: 3600,
	}))
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

// stepRequest is ceremonyRequest naming ceremonyId in its URL, as every request of a step after
// /auth/authorize names the ceremony it belongs to.
func stepRequest(cookies []*http.Cookie, ceremonyId string) *http.Request {
	req := ceremonyRequest(cookies)
	req.URL.RawQuery = url.Values{ceremony.QueryParameter: {ceremonyId}}.Encode()
	return req
}

// startCeremony stores a ceremony as /auth/authorize does, in a browser with no session, and
// answers the cookie naming it.
func startCeremony(t *testing.T, ceremonyStore *ceremony.Store, ceremonyId string) []*http.Cookie {
	t.Helper()
	rr := httptest.NewRecorder()
	require.NoError(t, ceremonyStore.AddAuthContext(rr, ceremonyRequest(nil), &ceremony.AuthContext{
		CeremonyId: ceremonyId, ClientId: "client-" + ceremonyId, AuthState: ceremony.AuthStateRequiresLevel1,
	}))
	cookies := rr.Result().Cookies()
	require.Len(t, cookies, 1)
	return cookies
}

func TestCeremonyStore_AStepThatResumesAfterANewerAuthorizeLeavesBothCeremoniesStored(t *testing.T) {
	ceremonyStore, _, _ := newDatabaseCeremonyStore(t)
	cookies := startCeremony(t, ceremonyStore, "ceremony-a")

	// Tab A's step loads ceremony A.
	tabA := stepRequest(cookies, "ceremony-a")
	loaded, err := ceremonyStore.GetAuthContext(tabA)
	require.NoError(t, err)
	require.Equal(t, "ceremony-a", loaded.CeremonyId)

	// Tab B's /auth/authorize, carrying the same cookie, adds ceremony B.
	require.NoError(t, ceremonyStore.AddAuthContext(httptest.NewRecorder(), ceremonyRequest(cookies),
		&ceremony.AuthContext{CeremonyId: "ceremony-b", ClientId: "client-b", AuthState: ceremony.AuthStateRequiresLevel1}))

	// Tab A's step resumes and saves the ceremony it loaded.
	loaded.AuthState = ceremony.AuthStateLevel1Password
	require.NoError(t, ceremonyStore.SaveAuthContext(httptest.NewRecorder(), tabA, loaded))

	requireHeld(t, ceremonyStore, cookies, "ceremony-a", ceremony.AuthStateLevel1Password)
	requireHeld(t, ceremonyStore, cookies, "ceremony-b", ceremony.AuthStateRequiresLevel1)
}

// requireHeld is that the browser cookies name holds the ceremony ceremonyId names, at state.
func requireHeld(t *testing.T, ceremonyStore *ceremony.Store, cookies []*http.Cookie, ceremonyId string,
	state ceremony.AuthState) {
	t.Helper()
	stored, err := ceremonyStore.GetAuthContext(stepRequest(cookies, ceremonyId))
	require.NoError(t, err, "the browser session holds %s", ceremonyId)
	assert.Equal(t, state, stored.AuthState, "%s is at its own state", ceremonyId)
}

// interleavingBackend is the database backend with a turn for the test before its next conditional
// write, which is where another request of the browser lands between a write's fresh read and its
// write. The turn is taken once.
type interleavingBackend struct {
	sessionstore.ConditionalBackend
	meanwhile func()
}

func (b *interleavingBackend) UpdateIfUnchanged(ctx context.Context, id string, expected, data []byte,
	authenticated bool) (time.Time, error) {
	if meanwhile := b.meanwhile; meanwhile != nil {
		b.meanwhile = nil
		meanwhile()
	}
	return b.ConditionalBackend.UpdateIfUnchanged(ctx, id, expected, data, authenticated)
}

// Each write of one ceremony landing between another's fresh read and its conditional write: the
// one inside lands, the one around it finds the row changed, reads again and lands on top, and the
// browser session holds both ceremonies at the states their own steps left them (#246).
func TestCeremonyStore_WritesOfTwoCeremoniesLandingInsideEachOtherAreBothKept(t *testing.T) {
	for _, tc := range []struct {
		name    string
		outside string
		inside  string
	}{
		{name: "an add inside a step's save", outside: "save", inside: "add"},
		{name: "a step's save inside an add", outside: "add", inside: "save"},
		{name: "a step's save inside another sign-in's save", outside: "save", inside: "save of b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := &interleavingBackend{ConditionalBackend: sessionbackend.NewAuthServerBackend(database)}
			ceremonyStore, _, _ := ceremonyStoreOver(t, backend)
			cookies := startCeremony(t, ceremonyStore, "ceremony-a")
			if tc.inside == "save of b" {
				require.NoError(t, ceremonyStore.AddAuthContext(httptest.NewRecorder(), ceremonyRequest(cookies),
					&ceremony.AuthContext{CeremonyId: "ceremony-b", AuthState: ceremony.AuthStateRequiresLevel1}))
			}

			want := map[string]ceremony.AuthState{
				"ceremony-a": ceremony.AuthStateRequiresLevel1,
				"ceremony-b": ceremony.AuthStateRequiresLevel1,
			}
			write := func(which string) {
				switch which {
				case "add":
					require.NoError(t, ceremonyStore.AddAuthContext(httptest.NewRecorder(), ceremonyRequest(cookies),
						&ceremony.AuthContext{CeremonyId: "ceremony-b", AuthState: ceremony.AuthStateRequiresLevel1}))
				case "save", "save of b":
					id, state := "ceremony-a", ceremony.AuthStateLevel1Password
					if which == "save of b" {
						id, state = "ceremony-b", ceremony.AuthStateLevel2OTP
					}
					step := stepRequest(cookies, id)
					loaded, err := ceremonyStore.GetAuthContext(step)
					require.NoError(t, err)
					loaded.AuthState = state
					require.NoError(t, ceremonyStore.SaveAuthContext(httptest.NewRecorder(), step, loaded))
					want[id] = state
				}
			}

			backend.meanwhile = func() { write(tc.inside) }
			write(tc.outside)

			require.Nil(t, backend.meanwhile, "the inside write ran between the outside one's read and write")
			for id, state := range want {
				requireHeld(t, ceremonyStore, cookies, id, state)
			}
		})
	}
}

func TestCeremonyStore_AStepThatStillHoldsItsCeremonySaves(t *testing.T) {
	ceremonyStore, _, _ := newDatabaseCeremonyStore(t)
	cookies := startCeremony(t, ceremonyStore, "ceremony-a")

	tabA := stepRequest(cookies, "ceremony-a")
	loaded, err := ceremonyStore.GetAuthContext(tabA)
	require.NoError(t, err)

	loaded.AuthState = ceremony.AuthStateLevel1Password
	require.NoError(t, ceremonyStore.SaveAuthContext(httptest.NewRecorder(), tabA, loaded))

	stored, err := ceremonyStore.LatestAuthContext(ceremonyRequest(cookies))
	require.NoError(t, err)
	assert.Equal(t, "ceremony-a", stored.CeremonyId)
	assert.Equal(t, ceremony.AuthStateLevel1Password, stored.AuthState)
}

func TestCeremonyStore_AStepWhoseSessionIsGoneDoesNotPutItBack(t *testing.T) {
	ceremonyStore, store, backend := newDatabaseCeremonyStore(t)
	cookies := startCeremony(t, ceremonyStore, "ceremony-a")

	tabA := stepRequest(cookies, "ceremony-a")
	loaded, err := ceremonyStore.GetAuthContext(tabA)
	require.NoError(t, err)

	// The browser signs out in another tab while tab A's step runs, which deletes the row.
	id, err := store.OpenCookie(interleavingSessionName, cookies[0].Value)
	require.NoError(t, err)
	require.NoError(t, backend.Delete(context.Background(), id))

	rr := httptest.NewRecorder()
	err = ceremonyStore.SaveAuthContext(rr, tabA, loaded)

	require.ErrorIs(t, err, ceremony.ErrCeremonyReplaced)
	assert.Empty(t, rr.Result().Cookies())
	_, err = backend.Load(context.Background(), id)
	require.ErrorIs(t, err, sessionstore.ErrNotFound, "the signed-out session is not re-created from tab A's copy")
}

// The same interleaving at a rotation, the password's or a code's: the rotation used to write tab
// A's copy under a new identifier and delete the row holding ceremony B. Over the real backend it
// rotates the session as it is stored now, so the new identifier names a session holding both, and
// tab B's next step finds its ceremony.
func TestCeremonyStore_ARotationThatResumesAfterANewerAuthorizeCarriesBothCeremonies(t *testing.T) {
	ceremonyStore, _, _ := newDatabaseCeremonyStore(t)
	cookies := startCeremony(t, ceremonyStore, "ceremony-a")

	tabA := stepRequest(cookies, "ceremony-a")
	loaded, err := ceremonyStore.GetAuthContext(tabA)
	require.NoError(t, err)
	require.Equal(t, "ceremony-a", loaded.CeremonyId)

	require.NoError(t, ceremonyStore.AddAuthContext(httptest.NewRecorder(), ceremonyRequest(cookies),
		&ceremony.AuthContext{CeremonyId: "ceremony-b", ClientId: "client-b", AuthState: ceremony.AuthStateRequiresLevel1}))

	rr := httptest.NewRecorder()
	require.NoError(t, ceremonyStore.RegenerateSession(rr, tabA, loaded.CeremonyId, rotatingUserId))

	rotated := rr.Result().Cookies()
	require.Len(t, rotated, 1)
	requireHeld(t, ceremonyStore, rotated, "ceremony-a", ceremony.AuthStateRequiresLevel1)
	requireHeld(t, ceremonyStore, rotated, "ceremony-b", ceremony.AuthStateRequiresLevel1)
}

// A rotation of a ceremony five newer sign-ins have pushed out rotates nothing, and the identifier
// the browser holds still names its session with the five newer ceremonies.
func TestCeremonyStore_ARotationOfAPushedOutCeremonyLeavesTheNewerOnesStored(t *testing.T) {
	ceremonyStore, _, _ := newDatabaseCeremonyStore(t)
	cookies := startCeremony(t, ceremonyStore, "ceremony-a")

	tabA := stepRequest(cookies, "ceremony-a")
	loaded, err := ceremonyStore.GetAuthContext(tabA)
	require.NoError(t, err)

	newer := []string{"newer-1", "newer-2", "newer-3", "newer-4", "newer-5"}
	for _, id := range newer {
		require.NoError(t, ceremonyStore.AddAuthContext(httptest.NewRecorder(), ceremonyRequest(cookies),
			&ceremony.AuthContext{CeremonyId: id, AuthState: ceremony.AuthStateRequiresLevel1}))
	}

	rr := httptest.NewRecorder()
	err = ceremonyStore.RegenerateSession(rr, tabA, loaded.CeremonyId, rotatingUserId)

	require.ErrorIs(t, err, ceremony.ErrCeremonyReplaced)
	assert.Empty(t, rr.Result().Cookies(), "tab A rotated nothing, so it tells the browser nothing")
	for _, id := range newer {
		requireHeld(t, ceremonyStore, cookies, id, ceremony.AuthStateRequiresLevel1)
	}
	_, err = ceremonyStore.GetAuthContext(stepRequest(cookies, "ceremony-a"))
	require.ErrorIs(t, err, ceremony.ErrCeremonyNotHeld)
}

// A rotation of the ceremony the browser still holds lands: the new identifier names the session,
// and the old one names nothing.
func TestCeremonyStore_ARotationThatStillHoldsItsCeremonyRotates(t *testing.T) {
	ceremonyStore, store, backend := newDatabaseCeremonyStore(t)
	cookies := startCeremony(t, ceremonyStore, "ceremony-a")
	oldId, err := store.OpenCookie(interleavingSessionName, cookies[0].Value)
	require.NoError(t, err)

	tabA := stepRequest(cookies, "ceremony-a")
	_, err = ceremonyStore.GetAuthContext(tabA)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	require.NoError(t, ceremonyStore.RegenerateSession(rr, tabA, "ceremony-a", rotatingUserId))

	rotated := rr.Result().Cookies()
	require.Len(t, rotated, 1)
	newId, err := store.OpenCookie(interleavingSessionName, rotated[0].Value)
	require.NoError(t, err)
	assert.NotEqual(t, oldId, newId)
	stored, err := ceremonyStore.LatestAuthContext(ceremonyRequest(rotated))
	require.NoError(t, err)
	assert.Equal(t, "ceremony-a", stored.CeremonyId)
	_, err = backend.Load(context.Background(), oldId)
	require.ErrorIs(t, err, sessionstore.ErrNotFound, "the identifier the browser arrived with names nothing any more")
}

// A rotation whose session is gone, signed out in another tab, is not re-created under a new name.
func TestCeremonyStore_ARotationWhoseSessionIsGoneDoesNotPutItBack(t *testing.T) {
	ceremonyStore, store, backend := newDatabaseCeremonyStore(t)
	cookies := startCeremony(t, ceremonyStore, "ceremony-a")

	tabA := stepRequest(cookies, "ceremony-a")
	_, err := ceremonyStore.GetAuthContext(tabA)
	require.NoError(t, err)

	id, err := store.OpenCookie(interleavingSessionName, cookies[0].Value)
	require.NoError(t, err)
	require.NoError(t, backend.Delete(context.Background(), id))

	rr := httptest.NewRecorder()
	err = ceremonyStore.RegenerateSession(rr, tabA, "ceremony-a", rotatingUserId)

	require.ErrorIs(t, err, ceremony.ErrCeremonyReplaced)
	assert.Empty(t, rr.Result().Cookies(), "no cookie names a session re-created from tab A's copy")
}
