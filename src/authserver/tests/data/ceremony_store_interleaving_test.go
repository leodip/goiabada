package datatests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/sessionbackend"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The interleaving #579 names, through the real ceremony store over the real database backend:
// tab A's step loads its ceremony, tab B's /auth/authorize replaces it in the same browser session,
// and tab A's step saves. Only a real engine shows the condition the save writes on, the stored
// ciphertext, holds on its text type and collation, so this is where the newer ceremony is shown
// surviving. The order is plain sequence: nothing here needs a goroutine, because each request's
// read and write are separate calls.

const interleavingSessionName = "goiabada-auth-test"

// newDatabaseCeremonyStore is the ceremony store as the auth server builds it, over this run's
// database, with the session store and the backend under it.
func newDatabaseCeremonyStore(t *testing.T) (*ceremony.Store, *sessionstore.ServerSideStore, sessionstore.ConditionalBackend) {
	t.Helper()
	backend := sessionbackend.NewAuthServerBackend(database)
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

// startCeremony stores a ceremony as /auth/authorize does, in a browser with no session, and
// answers the cookie naming it.
func startCeremony(t *testing.T, ceremonyStore *ceremony.Store, ceremonyId string) []*http.Cookie {
	t.Helper()
	rr := httptest.NewRecorder()
	require.NoError(t, ceremonyStore.ReplaceAuthContext(rr, ceremonyRequest(nil), &ceremony.AuthContext{
		CeremonyId: ceremonyId, ClientId: "client-" + ceremonyId, AuthState: ceremony.AuthStateRequiresLevel1,
	}))
	cookies := rr.Result().Cookies()
	require.Len(t, cookies, 1)
	return cookies
}

func TestCeremonyStore_AStepThatResumesAfterANewerAuthorizeLeavesTheNewerCeremonyStored(t *testing.T) {
	ceremonyStore, _, _ := newDatabaseCeremonyStore(t)
	cookies := startCeremony(t, ceremonyStore, "ceremony-a")

	// Tab A's step loads ceremony A.
	tabA := ceremonyRequest(cookies)
	loaded, err := ceremonyStore.GetAuthContext(tabA)
	require.NoError(t, err)
	require.Equal(t, "ceremony-a", loaded.CeremonyId)

	// Tab B's /auth/authorize, carrying the same cookie, replaces it with ceremony B.
	require.NoError(t, ceremonyStore.ReplaceAuthContext(httptest.NewRecorder(), ceremonyRequest(cookies),
		&ceremony.AuthContext{CeremonyId: "ceremony-b", ClientId: "client-b", AuthState: ceremony.AuthStateRequiresLevel1}))

	// Tab A's step resumes and saves the ceremony it loaded.
	rr := httptest.NewRecorder()
	loaded.AuthState = ceremony.AuthStateLevel1Password
	err = ceremonyStore.SaveAuthContext(rr, tabA, loaded)

	require.ErrorIs(t, err, ceremony.ErrCeremonyReplaced)
	assert.Empty(t, rr.Result().Cookies(), "tab A's step wrote nothing, so it tells the browser nothing")

	stored, err := ceremonyStore.GetAuthContext(ceremonyRequest(cookies))
	require.NoError(t, err)
	assert.Equal(t, "ceremony-b", stored.CeremonyId, "the browser session keeps the newer ceremony")
	assert.Equal(t, "client-b", stored.ClientId)
	assert.Equal(t, ceremony.AuthStateRequiresLevel1, stored.AuthState, "tab A's state did not land on it")
}

func TestCeremonyStore_AStepThatStillHoldsItsCeremonySaves(t *testing.T) {
	ceremonyStore, _, _ := newDatabaseCeremonyStore(t)
	cookies := startCeremony(t, ceremonyStore, "ceremony-a")

	tabA := ceremonyRequest(cookies)
	loaded, err := ceremonyStore.GetAuthContext(tabA)
	require.NoError(t, err)

	loaded.AuthState = ceremony.AuthStateLevel1Password
	require.NoError(t, ceremonyStore.SaveAuthContext(httptest.NewRecorder(), tabA, loaded))

	stored, err := ceremonyStore.GetAuthContext(ceremonyRequest(cookies))
	require.NoError(t, err)
	assert.Equal(t, "ceremony-a", stored.CeremonyId)
	assert.Equal(t, ceremony.AuthStateLevel1Password, stored.AuthState)
}

func TestCeremonyStore_AStepWhoseSessionIsGoneDoesNotPutItBack(t *testing.T) {
	ceremonyStore, store, backend := newDatabaseCeremonyStore(t)
	cookies := startCeremony(t, ceremonyStore, "ceremony-a")

	tabA := ceremonyRequest(cookies)
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
// rotates nothing, and the identifier the browser holds still names its session with ceremony B.
func TestCeremonyStore_ARotationThatResumesAfterANewerAuthorizeLeavesTheNewerCeremonyStored(t *testing.T) {
	ceremonyStore, _, _ := newDatabaseCeremonyStore(t)
	cookies := startCeremony(t, ceremonyStore, "ceremony-a")

	tabA := ceremonyRequest(cookies)
	loaded, err := ceremonyStore.GetAuthContext(tabA)
	require.NoError(t, err)
	require.Equal(t, "ceremony-a", loaded.CeremonyId)

	require.NoError(t, ceremonyStore.ReplaceAuthContext(httptest.NewRecorder(), ceremonyRequest(cookies),
		&ceremony.AuthContext{CeremonyId: "ceremony-b", ClientId: "client-b", AuthState: ceremony.AuthStateRequiresLevel1}))

	rr := httptest.NewRecorder()
	err = ceremonyStore.RegenerateSession(rr, tabA, loaded.CeremonyId)

	require.ErrorIs(t, err, ceremony.ErrCeremonyReplaced)
	assert.Empty(t, rr.Result().Cookies(), "tab A rotated nothing, so it tells the browser nothing")

	stored, err := ceremonyStore.GetAuthContext(ceremonyRequest(cookies))
	require.NoError(t, err, "the identifier the browser holds still names its session")
	assert.Equal(t, "ceremony-b", stored.CeremonyId, "the browser session keeps the newer ceremony")
	assert.Equal(t, "client-b", stored.ClientId)
}

// A rotation of the ceremony the browser still holds lands: the new identifier names the session,
// and the old one names nothing.
func TestCeremonyStore_ARotationThatStillHoldsItsCeremonyRotates(t *testing.T) {
	ceremonyStore, store, backend := newDatabaseCeremonyStore(t)
	cookies := startCeremony(t, ceremonyStore, "ceremony-a")
	oldId, err := store.OpenCookie(interleavingSessionName, cookies[0].Value)
	require.NoError(t, err)

	tabA := ceremonyRequest(cookies)
	_, err = ceremonyStore.GetAuthContext(tabA)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	require.NoError(t, ceremonyStore.RegenerateSession(rr, tabA, "ceremony-a"))

	rotated := rr.Result().Cookies()
	require.Len(t, rotated, 1)
	newId, err := store.OpenCookie(interleavingSessionName, rotated[0].Value)
	require.NoError(t, err)
	assert.NotEqual(t, oldId, newId)
	stored, err := ceremonyStore.GetAuthContext(ceremonyRequest(rotated))
	require.NoError(t, err)
	assert.Equal(t, "ceremony-a", stored.CeremonyId)
	_, err = backend.Load(context.Background(), oldId)
	require.ErrorIs(t, err, sessionstore.ErrNotFound, "the identifier the browser arrived with names nothing any more")
}

// A rotation whose session is gone, signed out in another tab, is not re-created under a new name.
func TestCeremonyStore_ARotationWhoseSessionIsGoneDoesNotPutItBack(t *testing.T) {
	ceremonyStore, store, backend := newDatabaseCeremonyStore(t)
	cookies := startCeremony(t, ceremonyStore, "ceremony-a")

	tabA := ceremonyRequest(cookies)
	_, err := ceremonyStore.GetAuthContext(tabA)
	require.NoError(t, err)

	id, err := store.OpenCookie(interleavingSessionName, cookies[0].Value)
	require.NoError(t, err)
	require.NoError(t, backend.Delete(context.Background(), id))

	rr := httptest.NewRecorder()
	err = ceremonyStore.RegenerateSession(rr, tabA, "ceremony-a")

	require.ErrorIs(t, err, ceremony.ErrCeremonyReplaced)
	assert.Empty(t, rr.Result().Cookies(), "no cookie names a session re-created from tab A's copy")
}
