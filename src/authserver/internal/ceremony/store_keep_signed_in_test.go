package ceremony

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// /auth/completed records the answer the password page's Keep me signed in box was given in the
// browser session, where the auth server's Keep users signed in rule reads it on every cookie write
// (#743 decisions 2 and 5): true ticked, false unticked, and no key at all when the password was
// entered with no box.

// signedInStep is a browser session holding ceremony A beside the answer an earlier sign-in of the
// browser recorded (none when earlier is nil), and a step's request of ceremony A that has read it.
func signedInStep(t *testing.T, ceremonyStore *Store, store *sessionstore.ServerSideStore,
	earlier *bool) ([]*http.Cookie, *http.Request) {

	t.Helper()
	values := map[string]any{
		sessionkeys.AuthContexts: heldJSON(t, &AuthContext{CeremonyId: ceremonyA, ClientId: "client-a",
			UserId: userA, AuthState: AuthStateAuthenticationCompleted}),
		sessionkeys.SessionIdentifier: "the-earlier-user-session",
	}
	if earlier != nil {
		values[sessionkeys.KeepSignedIn] = *earlier
	}
	cookies := seedBrowserSession(t, store, values)

	stepReq := namingRequest(http.MethodGet, cookies, ceremonyA, "")
	loaded, err := ceremonyStore.GetAuthContext(stepReq)
	require.NoError(t, err)
	require.Equal(t, ceremonyA, loaded.CeremonyId)
	return cookies, stepReq
}

// storedValues is the browser session the cookies name, as the store holds it.
func storedValues(t *testing.T, store *sessionstore.ServerSideStore, cookies []*http.Cookie) map[string]any {
	t.Helper()
	sess, err := store.Get(browserRequest(cookies), realStoreSessionName)
	require.NoError(t, err)
	require.False(t, sess.IsNew, "the cookies name a stored session")
	return sess.Values
}

// assertKeepSignedIn holds values to the answer want: the bool under sessionkeys.KeepSignedIn, or no
// key at all for no answer.
func assertKeepSignedIn(t *testing.T, want *bool, values map[string]any) {
	t.Helper()
	if want == nil {
		assert.NotContains(t, values, sessionkeys.KeepSignedIn, "a password entered with no box leaves no answer")
		return
	}
	assert.Equal(t, *want, values[sessionkeys.KeepSignedIn])
}

// keepSignedInCases is every answer recorded over every answer an earlier sign-in left.
func keepSignedInCases() []struct {
	name            string
	earlier, answer *bool
} {
	ticked, unticked := true, false
	answers := []struct {
		name   string
		answer *bool
	}{{"ticked", &ticked}, {"unticked", &unticked}, {"no box", nil}}

	var cases []struct {
		name            string
		earlier, answer *bool
	}
	for _, earlier := range answers {
		for _, answer := range answers {
			cases = append(cases, struct {
				name            string
				earlier, answer *bool
			}{answer.name + " over " + earlier.name, earlier.answer, answer.answer})
		}
	}
	return cases
}

// The create arm's rotation records the answer in the same write that binds the user session, so
// the sign-in reaches the browser as one Set-Cookie that already follows it.
func TestRegenerateSessionAndBind_RecordsTheKeepMeSignedInAnswer(t *testing.T) {
	for _, tc := range keepSignedInCases() {
		t.Run(tc.name, func(t *testing.T) {
			ceremonyStore, store, _ := newRealStore(t)
			_, stepReq := signedInStep(t, ceremonyStore, store, tc.earlier)
			rr := httptest.NewRecorder()

			require.NoError(t, ceremonyStore.RegenerateSessionAndBind(rr, stepReq, ceremonyA, userA,
				"the-new-user-session", tc.answer))

			rotated := rr.Result().Cookies()
			require.Len(t, rotated, 1, "one Set-Cookie")
			values := storedValues(t, store, rotated)
			assert.Equal(t, "the-new-user-session", values[sessionkeys.SessionIdentifier])
			assertKeepSignedIn(t, tc.answer, values)
		})
	}
}

// A refused rotation records nothing: the answer an earlier sign-in left stays as it was.
func TestRegenerateSessionAndBind_ARefusedRotationRecordsNoAnswer(t *testing.T) {
	ticked, unticked := true, false
	ceremonyStore, store, _ := newRealStore(t)
	cookies, stepReq := signedInStep(t, ceremonyStore, store, &ticked)
	rr := httptest.NewRecorder()

	err := ceremonyStore.RegenerateSessionAndBind(rr, stepReq, ceremonyB, userA, "the-new-user-session", &unticked)

	require.ErrorIs(t, err, ErrCeremonyReplaced)
	assert.Empty(t, rr.Result().Cookies())
	assertKeepSignedIn(t, &ticked, storedValues(t, store, cookies))
}

// The reuse arm's write records the answer in the browser session as it is stored now, keeping its
// identifier, the user session it names and the ceremonies it holds.
func TestRecordKeepSignedIn_RecordsTheAnswer(t *testing.T) {
	for _, tc := range keepSignedInCases() {
		t.Run(tc.name, func(t *testing.T) {
			ceremonyStore, store, _ := newRealStore(t)
			cookies, stepReq := signedInStep(t, ceremonyStore, store, tc.earlier)
			rr := httptest.NewRecorder()

			require.NoError(t, ceremonyStore.RecordKeepSignedIn(rr, stepReq, ceremonyA, tc.answer))

			written := rr.Result().Cookies()
			require.Len(t, written, 1, "the write sends the cookie, which follows the answer")
			assert.Equal(t, sessionIdentifier(t, store, cookies[0]), sessionIdentifier(t, store, written[0]),
				"the identifier is not rotated")
			values := storedValues(t, store, cookies)
			assertKeepSignedIn(t, tc.answer, values)
			assert.Equal(t, "the-earlier-user-session", values[sessionkeys.SessionIdentifier])
			held, err := ceremonyStore.HeldAuthContext(browserRequest(cookies), ceremonyA)
			require.NoError(t, err, "the ceremony is still held")
			assert.Equal(t, AuthStateAuthenticationCompleted, held.AuthState)
		})
	}
}

// The write lands only while the browser session still holds the ceremony, as every step's write
// does (#579): a ceremony the browser no longer holds, or a session gone, records nothing.
func TestRecordKeepSignedIn_LandsOnlyWhileTheSessionHoldsItsCeremony(t *testing.T) {
	ticked, unticked := true, false

	t.Run("AnotherCeremony", func(t *testing.T) {
		ceremonyStore, store, _ := newRealStore(t)
		cookies, stepReq := signedInStep(t, ceremonyStore, store, &ticked)
		rr := httptest.NewRecorder()

		err := ceremonyStore.RecordKeepSignedIn(rr, stepReq, ceremonyB, &unticked)

		require.ErrorIs(t, err, ErrCeremonyReplaced)
		assert.Empty(t, rr.Result().Cookies())
		assertKeepSignedIn(t, &ticked, storedValues(t, store, cookies))
	})

	t.Run("TheSessionIsGone", func(t *testing.T) {
		ceremonyStore, store, backend := newRealStore(t)
		cookies, stepReq := signedInStep(t, ceremonyStore, store, &ticked)
		require.NoError(t, backend.Delete(context.Background(), sessionIdentifier(t, store, cookies[0])))
		rr := httptest.NewRecorder()

		err := ceremonyStore.RecordKeepSignedIn(rr, stepReq, ceremonyA, &unticked)

		require.ErrorIs(t, err, ErrCeremonyReplaced)
		assert.Empty(t, rr.Result().Cookies())
	})
}
