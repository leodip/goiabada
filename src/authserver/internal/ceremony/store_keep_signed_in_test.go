package ceremony

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

// stampedStep is signedInStep with ceremony A having verified its password at passwordAt (none when
// nil), and the browser session holding an earlier sign-in's answer stamped earlierAt (no stamp when
// empty).
func stampedStep(t *testing.T, ceremonyStore *Store, store *sessionstore.ServerSideStore,
	passwordAt *time.Time, earlier *bool, earlierAt string) ([]*http.Cookie, *http.Request) {

	t.Helper()
	values := map[string]any{
		sessionkeys.AuthContexts: heldJSON(t, &AuthContext{CeremonyId: ceremonyA, ClientId: "client-a",
			UserId: userA, AuthState: AuthStateAuthenticationCompleted, PasswordVerifiedAt: passwordAt}),
		sessionkeys.SessionIdentifier: "the-earlier-user-session",
	}
	if earlier != nil {
		values[sessionkeys.KeepSignedIn] = *earlier
	}
	if earlierAt != "" {
		values[sessionkeys.KeepSignedInPasswordAt] = earlierAt
	}
	cookies := seedBrowserSession(t, store, values)
	return cookies, namingRequest(http.MethodGet, cookies, ceremonyA, "")
}

// The reuse arm's write stamps the answer with the instant its ceremony verified the password, and
// leaves the answer of a later password entry as it is, writing nothing and sending no cookie, so an
// older completion reaching the browser session after a newer one cannot replace the newer answer
// (#743 decision 2). An answer of the same or an earlier entry, or with no stamp, is replaced.
func TestRecordKeepSignedIn_LeavesTheAnswerOfALaterPasswordEntry(t *testing.T) {
	ticked, unticked := true, false
	passwordAt := time.Date(2026, 11, 3, 10, 0, 0, 500, time.UTC)
	const passwordStamp = "2026-11-03T10:00:00.0000005Z"

	for _, tc := range []struct {
		name       string
		passwordAt *time.Time
		earlier    *bool
		earlierAt  string
		replaced   bool
	}{
		{"a later unticked answer", &passwordAt, &unticked, "2026-11-03T10:00:00.000000501Z", false},
		{"a later entry with no box", &passwordAt, nil, "2026-11-03T10:01:00Z", false},
		{"a stamped answer, the ceremony having no password instant", nil, &unticked, "2026-11-03T09:00:00Z", false},
		{"the same entry's answer", &passwordAt, &unticked, passwordStamp, true},
		{"an earlier answer", &passwordAt, &unticked, "2026-11-03T09:59:59.9999Z", true},
		{"an answer with no stamp", &passwordAt, &unticked, "", true},
		{"an answer whose stamp does not read", &passwordAt, &unticked, "yesterday", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ceremonyStore, store, _ := newRealStore(t)
			cookies, stepReq := stampedStep(t, ceremonyStore, store, tc.passwordAt, tc.earlier, tc.earlierAt)
			rr := httptest.NewRecorder()

			require.NoError(t, ceremonyStore.RecordKeepSignedIn(rr, stepReq, ceremonyA, &ticked))

			values := storedValues(t, store, cookies)
			if !tc.replaced {
				assert.Empty(t, rr.Result().Cookies(), "nothing is written")
				assertKeepSignedIn(t, tc.earlier, values)
				assert.Equal(t, tc.earlierAt, values[sessionkeys.KeepSignedInPasswordAt])
				return
			}
			require.Len(t, rr.Result().Cookies(), 1)
			assertKeepSignedIn(t, &ticked, values)
			assert.Equal(t, passwordStamp, values[sessionkeys.KeepSignedInPasswordAt])
		})
	}
}

// The create arm's rotation binds a session started from its ceremony's password entry, so it records
// that entry's answer and stamp whatever answer the browser session held, and leaves no stamp when
// the ceremony has no password instant.
func TestRegenerateSessionAndBind_StampsTheAnswerWithItsPasswordEntry(t *testing.T) {
	ticked, unticked := true, false
	passwordAt := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)

	t.Run("OverALaterStamp", func(t *testing.T) {
		ceremonyStore, store, _ := newRealStore(t)
		_, stepReq := stampedStep(t, ceremonyStore, store, &passwordAt, &unticked, "2026-11-03T11:00:00Z")
		rr := httptest.NewRecorder()

		require.NoError(t, ceremonyStore.RegenerateSessionAndBind(rr, stepReq, ceremonyA, userA,
			"the-new-user-session", &ticked))

		rotated := rr.Result().Cookies()
		require.Len(t, rotated, 1)
		values := storedValues(t, store, rotated)
		assertKeepSignedIn(t, &ticked, values)
		assert.Equal(t, "2026-11-03T10:00:00Z", values[sessionkeys.KeepSignedInPasswordAt])
	})

	t.Run("NoPasswordInstant", func(t *testing.T) {
		ceremonyStore, store, _ := newRealStore(t)
		_, stepReq := stampedStep(t, ceremonyStore, store, nil, &unticked, "2026-11-03T11:00:00Z")
		rr := httptest.NewRecorder()

		require.NoError(t, ceremonyStore.RegenerateSessionAndBind(rr, stepReq, ceremonyA, userA,
			"the-new-user-session", nil))

		rotated := rr.Result().Cookies()
		require.Len(t, rotated, 1)
		values := storedValues(t, store, rotated)
		assertKeepSignedIn(t, nil, values)
		assert.NotContains(t, values, sessionkeys.KeepSignedInPasswordAt)
	})
}
