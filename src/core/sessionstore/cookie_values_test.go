package sessionstore

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The sealed values a cookie carries itself, which the admin console's sign-in handshake rides
// in so an anonymous request writes no row (#620).

const valuesTestName = "the-handshake"

func valuesTestValues() map[string]string {
	return map[string]string{"State": "the-state", "RedirectBack": "https://console.example/admin/clients"}
}

func TestCookieValues_RoundTrip(t *testing.T) {
	store := newTestStore(newFakeBackend(), false)

	sealed, err := store.SealCookieValues(valuesTestName, valuesTestValues())
	require.NoError(t, err)
	assert.NotContains(t, sealed, "the-state", "the values are sealed, not merely encoded")

	opened, err := store.OpenCookieValues(valuesTestName, sealed)
	require.NoError(t, err)
	assert.Equal(t, valuesTestValues(), opened)

	again, err := store.SealCookieValues(valuesTestName, valuesTestValues())
	require.NoError(t, err)
	assert.NotEqual(t, sealed, again, "every seal draws a fresh nonce")
}

// What every refusal shares is that nothing opens: a value the store did not seal under this
// name, as values, with keys it holds.
func TestCookieValues_OpensNothingElse(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)
	sealed, err := store.SealCookieValues(valuesTestName, valuesTestValues())
	require.NoError(t, err)

	// A session cookie and a stored blob under the same logical name the values are opened
	// under: only the separate key stops either from opening, the name being equal.
	sessionCookie := saveNew(t, newTestStore(backend, false), map[string]any{"State": "the-state"})
	sessionStore := newTestStore(newFakeBackend(), false)
	sessionCookieUnderName := saveNewNamed(t, sessionStore, valuesTestName)

	testCases := []struct {
		name  string
		open  string
		value string
	}{
		{"another logical name", "another-handshake", sealed},
		{"a session cookie value", storeTestName, sessionCookie.Value},
		{"a session cookie value sealed under the values' own name", valuesTestName, sessionCookieUnderName.Value},
		{"a stored session blob", storeTestName, string(backend.lastData)},
		{"a tampered value", valuesTestName, tamper(sealed)},
		{"not base64", valuesTestName, "not*base64"},
		{"empty", valuesTestName, ""},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opened, err := store.OpenCookieValues(tc.open, tc.value)
			require.Error(t, err)
			assert.Nil(t, opened)
		})
	}

	// And the reverse: a values cookie is no session identifier, so a store handed one as its
	// session cookie answers a fresh session without reaching storage.
	t.Run("a values cookie presented as the session cookie", func(t *testing.T) {
		forged, err := store.SealCookieValues(storeTestName, valuesTestValues())
		require.NoError(t, err)
		loadsBefore := backend.loads

		session, err := store.New(requestWith(&http.Cookie{Name: storeTestName, Value: forged}), storeTestName)
		require.NoError(t, err)
		assert.True(t, session.IsNew)
		assert.Equal(t, loadsBefore, backend.loads, "it never names a row")
	})
}

// saveNewNamed stores an empty session under name and returns its cookie.
func saveNewNamed(t *testing.T, store *ServerSideStore, name string) *http.Cookie {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	session, err := store.New(req, name)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	require.NoError(t, store.Save(req, w, session))
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	return cookies[0]
}

// tamper flips one character inside the envelope, past the version byte.
func tamper(sealed string) string {
	b := []byte(sealed)
	i := len(b) / 2
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

// The bound applies both ways: a seal past it is refused rather than handed to a browser that
// may drop it in silence, and an open past it is refused before anything is decrypted.
func TestCookieValues_RefusesAValuePastTheBound(t *testing.T) {
	store := newTestStore(newFakeBackend(), false)

	_, err := store.SealCookieValues(valuesTestName, map[string]string{"RedirectBack": strings.Repeat("a", MaxCookieValuesBytes)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too long")

	// The largest value that fits opens, and one byte more does not, even though it would
	// otherwise be a value this store sealed: the check is on the length, before the tag.
	atBound := sealOfLength(t, store, MaxCookieValuesBytes)
	_, err = store.OpenCookieValues(valuesTestName, atBound)
	require.NoError(t, err, "a value of exactly the bound opens")

	_, err = store.OpenCookieValues(valuesTestName, atBound+"A")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too long")
}

// sealOfLength seals a value whose sealed form is exactly n bytes, by growing the plaintext one
// byte at a time until the encoding lands on n.
func sealOfLength(t *testing.T, store *ServerSideStore, n int) string {
	t.Helper()
	for size := n / 2; size < n; size++ {
		sealed, err := store.SealCookieValues(valuesTestName, map[string]string{"k": strings.Repeat("a", size)})
		if err != nil {
			break
		}
		if len(sealed) == n {
			return sealed
		}
	}
	t.Fatalf("no plaintext seals to exactly %d bytes", n)
	return ""
}

// A sign-in in flight across a key rotation still finishes: the previous pair opens what it
// sealed, what the rotating store seals opens under the new pair alone, and without the
// previous pair configured the old value does not open.
func TestCookieValues_RotationOpensBothGenerations(t *testing.T) {
	first := storeTestPair()
	second := storeTestPair2()

	before := newTestStoreWithKeys(newFakeBackend(), false, first, nil)
	sealedBefore, err := before.SealCookieValues(valuesTestName, valuesTestValues())
	require.NoError(t, err)

	rotating := newTestStoreWithKeys(newFakeBackend(), false, second, &first)
	opened, err := rotating.OpenCookieValues(valuesTestName, sealedBefore)
	require.NoError(t, err)
	assert.Equal(t, valuesTestValues(), opened)

	sealedRotating, err := rotating.SealCookieValues(valuesTestName, valuesTestValues())
	require.NoError(t, err)
	after := newTestStoreWithKeys(newFakeBackend(), false, second, nil)
	_, err = after.OpenCookieValues(valuesTestName, sealedRotating)
	require.NoError(t, err, "everything is sealed with the current pair")

	_, err = after.OpenCookieValues(valuesTestName, sealedBefore)
	require.Error(t, err, "without the previous pair the old generation does not open")
}

// The cookie carries the store's own attributes, under its physical name, for the pre-auth
// lifetime; and DeletionCookie on the same physical name removes it.
func TestCookieValues_TheCookie(t *testing.T) {
	testCases := []struct {
		name     string
		secure   bool
		wantName string
	}{
		{"https", true, "__Host-" + valuesTestName},
		{"plain http", false, valuesTestName},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := newTestStore(newFakeBackend(), tc.secure)

			cookie := store.ValuesCookie(valuesTestName, "the-sealed-value")
			assert.Equal(t, tc.wantName, cookie.Name)
			assert.Equal(t, store.CookieName(valuesTestName), cookie.Name)
			assert.Equal(t, "the-sealed-value", cookie.Value)
			assert.Equal(t, "/", cookie.Path, "the __Host- prefix requires Path=/")
			assert.Empty(t, cookie.Domain, "the __Host- prefix forbids a Domain")
			assert.Equal(t, tc.secure, cookie.Secure)
			assert.True(t, cookie.HttpOnly)
			assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
			assert.Equal(t, int((30 * time.Minute).Seconds()), cookie.MaxAge, "the pre-authentication lifetime")

			deletion := store.DeletionCookie(store.CookieName(valuesTestName))
			assert.Equal(t, cookie.Name, deletion.Name)
			assert.Equal(t, cookie.Path, deletion.Path)
			assert.Equal(t, tc.secure, deletion.Secure)
			assert.Equal(t, -1, deletion.MaxAge)
		})
	}
}
