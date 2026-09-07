package sessionstore

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/constants"
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

	// The second pair, for the rotation table. Both differ from the pair above in every
	// byte, so a value that opens under one of them says nothing about the other.
	storeTestAuthKey2 = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
	storeTestEncKey2  = "9876543210zyxwvutsrqponmlkjihgfe"
)

// storeTestPair and storeTestPair2 are those literals as the store takes them.
func storeTestPair() KeyPair {
	return KeyPair{
		AuthenticationKey: []byte(storeTestAuthKey),
		EncryptionKey:     []byte(storeTestEncKey),
	}
}

func storeTestPair2() KeyPair {
	return KeyPair{
		AuthenticationKey: []byte(storeTestAuthKey2),
		EncryptionKey:     []byte(storeTestEncKey2),
	}
}

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
	return newTestStoreWithKeys(backend, secure, storeTestPair(), nil)
}

// newTestStoreWithKeys is newTestStore for the rotation table, which is the only thing
// that needs a store keyed with something other than the one pair above.
//
// The error is asserted rather than swallowed even though the derivation cannot fail on
// these literals: a helper that drops it would hide a real failure at every one of its
// call sites at once.
func newTestStoreWithKeys(backend Backend, secure bool, current KeyPair, previous *KeyPair) *ServerSideStore {
	store, err := NewServerSideStore(backend, "SessionIdentifier", secure, current, previous)
	if err != nil {
		panic(err)
	}
	return store
}

// saveNew runs the ordinary create path: a request carrying no cookie, one save.
func saveNew(t *testing.T, store *ServerSideStore, values map[string]any) *http.Cookie {
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

	id, err := store.OpenCookie(storeTestName, cookie.Value)
	require.NoError(t, err)
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

	cookie := saveNew(t, store, map[string]any{"greeting": "hello"})

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

// TestServerSideStore_CSPRNGFailureFailsTheSave drives both reads a save makes from the
// CSPRNG, separately, because a save that fails at the first one proves nothing about the
// second.
//
// The order is seal then identifier, so a reader that always fails only ever exercises the
// nonce. The second case lets the nonce read succeed and fails the one after it, which is
// the identifier's, and it is the case that would survive if newSessionId went back to
// returning the empty string on failure (#211, #266, #270).
func TestServerSideStore_CSPRNGFailureFailsTheSave(t *testing.T) {
	cases := []struct {
		label  string
		reader io.Reader
	}{
		{"the nonce read fails", failingReader{}},
		{"the identifier read fails", &failAfterReader{ok: 1}},
	}

	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			original := randReader
			randReader = c.reader
			defer func() { randReader = original }()

			backend := newFakeBackend()
			store := newTestStore(backend, false)

			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()
			session, err := store.New(req, storeTestName)
			require.NoError(t, err)

			err = store.Save(req, w, session)

			// The alternative, which stringutil.GenerateSecurityRandomString takes, is to
			// return the empty string. Every session would then share one identifier, or
			// every seal one nonce.
			require.Error(t, err)
			assert.Empty(t, w.Result().Cookies(), "no cookie may be issued without an identifier")
			assert.Equal(t, 0, backend.creates)
		})
	}
}

// failAfterReader serves ok successful reads from a fixed pattern and fails every read
// after them, which is how a single read in a sequence is singled out.
//
// The bytes it does serve are constant rather than random, which is fine and is why this
// is a test double: nothing in the case that uses it looks at what was sealed.
type failAfterReader struct {
	ok int
}

func (r *failAfterReader) Read(p []byte) (int, error) {
	if r.ok <= 0 {
		return 0, errors.New("the CSPRNG is unavailable")
	}
	r.ok--
	for i := range p {
		p[i] = byte(i)
	}
	return len(p), nil
}

func TestServerSideStore_BackendNeverSeesPlaintext(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	const marker = "a-value-nobody-else-should-be-able-to-read"
	saveNew(t, store, map[string]any{"secret": marker})

	require.NotEmpty(t, backend.lastData)
	assert.NotContains(t, string(backend.lastData), marker,
		"the storage half holds ciphertext and no key for it")
}

// --- loading -----------------------------------------------------------------------

func TestServerSideStore_RoundTrip(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	cookie := saveNew(t, store, map[string]any{"greeting": "hello", "count": 7})

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

	cookie := saveNew(t, store, map[string]any{"greeting": "hello"})
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
	other := newTestStoreWithKeys(newFakeBackend(), false, KeyPair{
		AuthenticationKey: []byte("00000000000000000000000000000000"),
		EncryptionKey:     []byte("11111111111111111111111111111111"),
	}, nil)

	cookie := saveNew(t, other, map[string]any{"greeting": "hello"})

	session, err := store.New(requestWith(cookie), storeTestName)

	require.NoError(t, err)
	assert.True(t, session.IsNew)
	assert.Equal(t, 0, backend.loads)
}

// --- the envelope and the sealing keys --------------------------------------------

// TestServerSideStore_TamperedBlobGivesAFreshSession is the cookie case's twin on the
// other side of the store. The row is what an untrusted backend holds -- on the admin
// console it is literally another application's database -- so a blob that has been
// altered by one byte has to be refused, and the AEAD tag over the whole envelope is what
// refuses it.
func TestServerSideStore_TamperedBlobGivesAFreshSession(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	cookie := saveNew(t, store, map[string]any{"greeting": "hello"})
	id := decodeCookieId(t, store, cookie)

	record := backend.rows[id]
	record.Data = flipLastByte(t, record.Data)

	session, err := store.New(requestWith(cookie), storeTestName)

	require.NoError(t, err, "a blob that will not open is a fresh session, not an error")
	assert.True(t, session.IsNew)
	assert.Empty(t, session.Values)
	assert.Equal(t, 1, backend.loads, "and it is refused after the read, not before it")
}

// TestServerSideStore_AStoredBlobDoesNotOpenAsACookie is the case that fails if decision
// 9's per-purpose key derivation is collapsed to one key.
//
// **Keep this, and keep it here.** The obvious place to assert it is downstream, through
// the fresh session New answers with, and that assertion passes with the derivation
// collapsed: a blob presented as a cookie would then decrypt successfully to a gob stream,
// which is not a 64 character identifier, so the load finds no row and the visitor still
// gets a fresh session. The rejection has to be observed at the opener, where the only
// thing that can produce it is the key being a different key (decision 9, #270).
func TestServerSideStore_AStoredBlobDoesNotOpenAsACookie(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	saveNew(t, store, map[string]any{"greeting": "hello"})
	require.NotEmpty(t, backend.lastData, "the save has to have written a blob to present")

	_, err := store.OpenCookie(storeTestName, string(backend.lastData))

	require.Error(t, err,
		"a value sealed for the backend must not open as a cookie, which is what two "+
			"derived keys buy and one key does not")
}

// TestServerSideStore_ACookieValueStoredAsABlobGivesAFreshSession is the other direction,
// and it claims less on purpose: it says the visitor ends up with a fresh session, which is
// a public outcome, and not that the key separation is what produced it. The blob opener is
// private and asserting through it would mean either reaching inside or exporting an API
// for one test; the case above already pins the separation itself.
func TestServerSideStore_ACookieValueStoredAsABlobGivesAFreshSession(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	cookie := saveNew(t, store, map[string]any{"greeting": "hello"})
	id := decodeCookieId(t, store, cookie)
	backend.rows[id].Data = []byte(cookie.Value)

	session, err := store.New(requestWith(cookie), storeTestName)

	require.NoError(t, err)
	assert.True(t, session.IsNew)
	assert.Empty(t, session.Values)
	assert.Equal(t, 1, backend.loads)
}

// TestServerSideStore_AnUnknownEnvelopeVersionIsRefused. The version byte is what gives the
// next format change a discriminator instead of a guess, and it is only worth having if an
// unrecognised value is refused rather than parsed hopefully.
func TestServerSideStore_AnUnknownEnvelopeVersionIsRefused(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	cookie := saveNew(t, store, map[string]any{"greeting": "hello"})

	envelope, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	require.NoError(t, err)
	require.Equal(t, byte(envelopeVersion), envelope[0], "version 1 is what this store writes")
	envelope[0] = envelopeVersion + 1
	restamped := base64.RawURLEncoding.EncodeToString(envelope)

	_, err = store.OpenCookie(storeTestName, restamped)
	require.Error(t, err, "rejected by the version check, before any key is used")

	// And the visitor's outcome, which is the same fresh session every unopenable cookie
	// produces. The backend is never reached, because there is no identifier to look up.
	session, newErr := store.New(requestWith(&http.Cookie{Name: cookie.Name, Value: restamped}), storeTestName)
	require.NoError(t, newErr)
	assert.True(t, session.IsNew)
	assert.Zero(t, backend.loads)
}

// TestServerSideStore_AMalformedEnvelopeIsRefused covers the ways a value fails before
// there is anything to decrypt.
//
// What the length check buys is precisely that these are errors rather than panics: with
// it removed, an empty value is indexed at [0] and a value shorter than the nonce is
// sliced past its end, and a session store that panics on a cookie anyone can send is a
// denial of service rather than a refusal. So the mechanism named for each of the last
// three is the length check, and the way it fails without it is a panic, not a wrong
// answer.
//
// Every case below carries a valid version byte where it is long enough to have one, so
// nothing here is rejected by the version check instead and passes for the wrong reason.
func TestServerSideStore_AMalformedEnvelopeIsRefused(t *testing.T) {
	store := newTestStore(newFakeBackend(), false)

	// Two lengths that would be sliced out of bounds, and one that would reach the AEAD
	// with a ciphertext shorter than a tag.
	shortOfNonce := append([]byte{envelopeVersion}, make([]byte, 9)...)
	shortOfTag := append([]byte{envelopeVersion}, make([]byte, envelopeMinBytes-2)...)

	cases := []struct {
		label string
		value string
	}{
		{"not base64 at all", "!!! not base64 !!!"},
		{"empty", ""},
		{"shorter than the nonce", base64.RawURLEncoding.EncodeToString(shortOfNonce)},
		{"one byte short of a whole envelope", base64.RawURLEncoding.EncodeToString(shortOfTag)},
	}

	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			_, err := store.OpenCookie(storeTestName, c.value)
			assert.Error(t, err)
		})
	}
}

// TestServerSideStore_ACookieSealedUnderAnotherNameDoesNotOpen is what binding the session
// name as associated data is for.
//
// The two applications keep different sessions under different logical names, and one of
// the two backends is the other application's server. Without the binding a value would
// be openable wherever the same keys are held, whatever it was sealed as; with it, the
// name is part of what the tag covers, so presenting an auth server cookie as an admin
// console one fails in exactly the way a forged one does.
//
// Asserted at the opener rather than through New, for the reason the blob case states: a
// value presented under the wrong name would fail downstream anyway, on the identifier it
// did not decrypt to, and that assertion cannot tell the binding from its absence.
func TestServerSideStore_ACookieSealedUnderAnotherNameDoesNotOpen(t *testing.T) {
	store := newTestStore(newFakeBackend(), false)

	cookie := saveNew(t, store, map[string]any{"greeting": "hello"})

	_, err := store.OpenCookie(storeTestName, cookie.Value)
	require.NoError(t, err, "the name it was sealed under opens it")

	_, err = store.OpenCookie(constants.AdminConsoleSessionName, cookie.Value)
	require.Error(t, err, "and no other name does, because the name is associated data")
}

// --- rotation with a previous key pair (decision 10) ------------------------------

// TestServerSideStore_RotationOpensBothGenerations is the whole of what the previous pair
// buys: an operator swaps the keys, restarts, and nobody is signed out.
//
// Both halves of a session are exercised by the first case rather than only the cookie: New
// opens the cookie and then the blob, so a store that tried the previous pair on one and not
// the other would answer a fresh session and the assertion on Values would fail.
func TestServerSideStore_RotationOpensBothGenerations(t *testing.T) {
	first := storeTestPair()
	second := storeTestPair2()

	t.Run("a value sealed under the previous pair still opens", func(t *testing.T) {
		backend := newFakeBackend()
		before := newTestStoreWithKeys(backend, false, first, nil)
		cookie := saveNew(t, before, map[string]any{"greeting": "hello"})

		rotating := newTestStoreWithKeys(backend, false, second, &first)
		session, err := rotating.New(requestWith(cookie), storeTestName)

		require.NoError(t, err)
		assert.False(t, session.IsNew, "the session survives the key change")
		assert.Equal(t, "hello", session.Values["greeting"],
			"the blob is opened with the previous pair too, not only the cookie")
	})

	t.Run("what the rotating store writes opens under the new pair alone", func(t *testing.T) {
		backend := newFakeBackend()
		rotating := newTestStoreWithKeys(backend, false, second, &first)
		cookie := saveNew(t, rotating, map[string]any{"greeting": "hello"})

		after := newTestStoreWithKeys(backend, false, second, nil)
		session, err := after.New(requestWith(cookie), storeTestName)

		require.NoError(t, err)
		assert.False(t, session.IsNew,
			"everything is sealed with the current pair, so a session that has been "+
				"saved once since the restart no longer needs the previous one")
		assert.Equal(t, "hello", session.Values["greeting"])
	})

	// The negative case, and the reason the previous pair has to be configured rather than
	// inferred: without it the old generation is simply not openable. Rejected by the AEAD
	// tag on the cookie, which is why the backend is never reached.
	t.Run("without the previous pair the old generation does not open", func(t *testing.T) {
		backend := newFakeBackend()
		before := newTestStoreWithKeys(backend, false, first, nil)
		cookie := saveNew(t, before, map[string]any{"greeting": "hello"})

		after := newTestStoreWithKeys(backend, false, second, nil)
		session, err := after.New(requestWith(cookie), storeTestName)

		require.NoError(t, err, "an unopenable cookie is a fresh session, not an error")
		assert.True(t, session.IsNew)
		assert.Zero(t, backend.loads, "a cookie that fails its tag never reaches storage")
	})
}

// --- what each configured key contributes, and nonce freshness --------------------

// TestServerSideStore_BothConfiguredKeysSealTheValue pins the half of decision 9 that
// says both configured secrets keep a job.
//
// The pair is fed to HKDF as a secret and a salt, and dropping either input still yields a
// perfectly valid 32 byte key, so a derivation that quietly stopped reading one of them
// would seal and open exactly as it does today. The existing wrong-key case cannot see
// that: it varies both halves at once, so the derived keys differ whichever input is
// actually consulted. Varying one half at a time is what makes each input observable, and
// it is the difference between the authentication key having a job and being a variable
// three documentation pages call required while nothing reads it.
func TestServerSideStore_BothConfiguredKeysSealTheValue(t *testing.T) {
	t.Run("only the authentication key differs", func(t *testing.T) {
		requireNeitherHalfOpens(t, KeyPair{
			AuthenticationKey: []byte(storeTestAuthKey2),
			EncryptionKey:     []byte(storeTestEncKey), // the very same encryption key
		})
	})

	t.Run("only the encryption key differs", func(t *testing.T) {
		requireNeitherHalfOpens(t, KeyPair{
			AuthenticationKey: []byte(storeTestAuthKey), // the very same authentication key
			EncryptionKey:     []byte(storeTestEncKey2),
		})
	})
}

// requireNeitherHalfOpens saves a session through a store keyed with varied, and requires
// that the store under test opens neither the cookie nor the blob.
//
// Both halves are checked, and separately, because they are sealed under two derived keys
// and a derivation could lose an input on one path only. The blob is checked by
// transplanting it behind a cookie this store did write, which is the only way to reach
// the blob path at all: presenting the foreign cookie stops at the cookie, and a store
// that opened the blob but not the cookie would otherwise read as a pass.
func requireNeitherHalfOpens(t *testing.T, varied KeyPair) {
	t.Helper()

	foreignBackend := newFakeBackend()
	foreign := newTestStoreWithKeys(foreignBackend, false, varied, nil)
	foreignCookie := saveNew(t, foreign, map[string]any{"greeting": "hello"})

	backend := newFakeBackend()
	store := newTestStore(backend, false)

	session, err := store.New(requestWith(foreignCookie), storeTestName)
	require.NoError(t, err, "an unopenable cookie is a fresh session, not an error")
	assert.True(t, session.IsNew, "a cookie sealed under a different pair must not open")
	assert.Zero(t, backend.loads, "a cookie that fails its tag never reaches storage")

	ownCookie := saveNew(t, store, map[string]any{"greeting": "hello"})
	id := decodeCookieId(t, store, ownCookie)
	foreignId := decodeCookieId(t, foreign, foreignCookie)
	backend.rows[id].Data = foreignBackend.rows[foreignId].Data

	session, err = store.New(requestWith(ownCookie), storeTestName)
	require.NoError(t, err, "an unopenable blob is a fresh session, not an error")
	assert.True(t, session.IsNew, "a blob sealed under a different pair must not open")
	assert.Empty(t, session.Values, "and none of its contents may reach the caller")
}

// TestServerSideStore_EverySealUsesAFreshNonce pins the property decision 8 was chosen
// for: the nonce is read from the CSPRNG on every seal, never derived and never reused.
//
// XChaCha20-Poly1305's 24 byte nonce is the whole reason that variant was picked over
// AES-GCM, and it buys nothing if a nonce is repeated: under a fixed nonce two plaintexts
// sealed with one key leak their difference, and the existing CSPRNG-failure case says
// only that a *failed* read is reported, not that a successful one is used. Saving twice
// with nothing changed is what makes freshness observable from outside, because Save
// re-seals both halves every time, so identical inputs must still produce different
// ciphertexts.
func TestServerSideStore_EverySealUsesAFreshNonce(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	first := saveNew(t, store, map[string]any{"greeting": "hello"})
	id := decodeCookieId(t, store, first)
	firstBlob := string(backend.rows[id].Data)

	// The same session, saved again with nothing about it changed.
	req := requestWith(first)
	w := httptest.NewRecorder()
	session, err := store.New(req, storeTestName)
	require.NoError(t, err)
	require.False(t, session.IsNew)
	require.NoError(t, store.Save(req, w, session))

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	second := cookies[0]
	secondBlob := string(backend.rows[id].Data)

	assert.NotEqual(t, first.Value, second.Value,
		"two seals of one identifier must not produce one ciphertext")
	assert.NotEqual(t, firstBlob, secondBlob,
		"two seals of one set of values must not produce one ciphertext")

	// And the difference is the nonce rather than the contents: both still open, to the
	// same identifier and the same values.
	assert.Equal(t, id, decodeCookieId(t, store, second),
		"the identifier is unchanged, so only the sealing may differ")

	reloaded, err := store.New(requestWith(second), storeTestName)
	require.NoError(t, err)
	assert.False(t, reloaded.IsNew)
	assert.Equal(t, "hello", reloaded.Values["greeting"])
}

// TestServerSideStore_ABlobDoesNotOpenUnderAnotherSessionName is the blob's half of the
// name binding, and the cookie's half is above at ACookieSealedUnderAnotherNameDoesNotOpen.
//
// The two halves are separate assertions because they are sealed under two derived keys
// with the name passed as associated data at each site, so a call that stopped binding the
// name on the blob path alone changes nothing the cookie cases can see. What it would
// change is real: the auth server holds the admin console's rows, and the admin console
// reaches them through an endpoint keyed by owner, so a blob accepted under a name it was
// not sealed under is one module's session contents opening as the other's.
func TestServerSideStore_ABlobDoesNotOpenUnderAnotherSessionName(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	// One store, one key, two logical names: the name is the only thing that differs.
	otherName := constants.AdminConsoleSessionName
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	otherSession, err := store.New(req, otherName)
	require.NoError(t, err)
	otherSession.Values["greeting"] = "hello"
	require.NoError(t, store.Save(req, w, otherSession))
	otherId := otherSession.ID
	require.Contains(t, backend.rows, otherId)

	cookie := saveNew(t, store, map[string]any{"greeting": "hello"})
	id := decodeCookieId(t, store, cookie)
	backend.rows[id].Data = backend.rows[otherId].Data

	session, err := store.New(requestWith(cookie), storeTestName)

	require.NoError(t, err, "an unopenable blob is a fresh session, not an error")
	assert.True(t, session.IsNew,
		"a blob sealed under another session name must not open under this one")
	assert.Empty(t, session.Values, "and none of its contents may reach the caller")
}

// flipLastByte changes one byte of the envelope a sealed value carries, and returns it
// re-encoded.
//
// It goes through the base64 rather than editing the text in place, which matters: the
// final character of a base64 group carries unused bits, so two different characters there
// can decode to the very same bytes and the alteration would be a no-op. Decoding first
// makes the change land in the tag or the ciphertext, which is what the cases using this
// claim to have altered.
func flipLastByte(t *testing.T, encoded []byte) []byte {
	t.Helper()

	envelope, err := base64.RawURLEncoding.DecodeString(string(encoded))
	require.NoError(t, err)
	require.NotEmpty(t, envelope)

	envelope[len(envelope)-1] ^= 0xff
	return []byte(base64.RawURLEncoding.EncodeToString(envelope))
}

func TestServerSideStore_NotFoundGivesAFreshSession(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	cookie := saveNew(t, store, map[string]any{"greeting": "hello"})
	backend.rows = map[string]*Record{} // logged out, expired or reaped

	session, err := store.New(requestWith(cookie), storeTestName)

	require.NoError(t, err)
	assert.True(t, session.IsNew)
	assert.Empty(t, session.Values)
}

func TestServerSideStore_StorageFailurePropagates(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	cookie := saveNew(t, store, map[string]any{"greeting": "hello"})
	backend.loadErr = errors.New("the database is unreachable")

	session, err := store.New(requestWith(cookie), storeTestName)

	// Failing open here would discard every session in flight during any database
	// interruption, and would erase the difference between "this session is gone" and
	// "I could not check" (#266).
	require.Error(t, err)
	// Non-nil beside the error, which is the store's own rule now that New is off the
	// interface (#269), and which every caller relies on: Get memoises whatever New
	// returns and hands it to every middleware that asks. Asserting nil here is what let
	// the panic in TestServerSideStore_GetSurvivesAStorageFailure below go unnoticed: it
	// pinned the contract violation rather than the behaviour (#266).
	require.NotNil(t, session)
	assert.True(t, session.IsNew)
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

	cookie := saveNew(t, store, map[string]any{"greeting": "hello"})
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

// TestServerSideStore_GetSurvivesAStorageFailure drives Get rather than New, and that is
// the whole point of it: nothing outside the store calls New, which is why New is not on
// Store at all (#269). Every caller reaches the store through Get, which memoises the
// (session, error) pair New handed back, so a nil session is handed to every middleware on
// the request and dereferenced by whichever one reads Values before it reads the error. A
// store that answered a storage fault that way therefore panicked on the one path that
// exists to make a database outage diagnosable, and the request came back as an empty 500
// with the cause nowhere, which is the opposite of what failing closed buys.
//
// Both failure points are driven, because they are two different returns in New (#266).
// The same pointer coming back from a second Get is asserted here too, because "answered
// identically to every middleware that asks" is a claim about the object and not only
// about the error.
func TestServerSideStore_GetSurvivesAStorageFailure(t *testing.T) {
	t.Run("the load fails", func(t *testing.T) {
		backend := newFakeBackend()
		store := newTestStore(backend, false)

		cookie := saveNew(t, store, map[string]any{"greeting": "hello"})
		backend.loadErr = errors.New("the database is unreachable")

		req := requestWith(cookie)
		session, err := store.Get(req, storeTestName)

		require.Error(t, err, "a lookup that could not be performed is a refused request")
		require.NotNil(t, session)

		// Get memoises the pair, so the next middleware in the same request is answered
		// identically rather than being handed a fresh empty session. Identically means
		// the same object as well as the same error: a second Get that retried the
		// backend would answer one middleware differently from the last, and a second
		// Get that returned a different empty session would let two middlewares on one
		// request disagree about what the session holds (#269).
		again, errAgain := store.Get(req, storeTestName)
		require.Error(t, errAgain)
		require.NotNil(t, again)
		assert.Same(t, session, again)
		assert.Equal(t, err, errAgain)
		assert.Equal(t, 1, backend.loads, "and the failed lookup is not retried")
	})

	t.Run("the touch fails", func(t *testing.T) {
		backend := newFakeBackend()
		store := newTestStore(backend, false)

		cookie := saveNew(t, store, map[string]any{"greeting": "hello"})
		id := decodeCookieId(t, store, cookie)
		backend.rows[id].LastAccessed = time.Now().UTC().Add(-30 * time.Second)
		backend.touchErr = errors.New("the database is unreachable")

		session, err := store.Get(requestWith(cookie), storeTestName)

		require.Error(t, err)
		require.NotNil(t, session)
		assert.Empty(t, session.Values,
			"a session whose liveness could not be confirmed must not hand its contents back")
	})
}

// TestServerSideStore_RegenerateRotatesAnAdminConsoleSession is the store half of the admin
// console's one privilege transition: a session already carrying the token set rotates onto
// a new identifier and the old row goes. The call site that owes this lives in a module with
// no handler harness (#237), so it is guarded there by a source lint instead.
func TestServerSideStore_RegenerateRotatesAnAdminConsoleSession(t *testing.T) {
	owner := matrixOwners[1] // adminconsole
	backend := newFakeBackend()
	store := newMatrixStore(owner, backend, false)

	cookie := liveCookie(t, store, owner, map[string]any{"state": "the handshake"})
	plantedId := decodeCookieId2(t, store, owner, cookie)

	req := requestWith(cookie)
	w := httptest.NewRecorder()
	session, err := store.New(req, owner.sessionName)
	require.NoError(t, err)

	session.Values[owner.authenticatedKey] = "the administrator's tokens"
	require.NoError(t, store.Regenerate(w, req, session))

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	rotatedId := decodeCookieId2(t, store, owner, cookies[0])

	assert.NotEqual(t, plantedId, rotatedId,
		"an identifier that existed before sign-in must not name the session sign-in produces")
	_, planted := backend.rows[plantedId]
	assert.False(t, planted, "the row the old identifier named has to go, or it still works")
	require.Contains(t, backend.rows, rotatedId)
}

// decodeCookieId2 is decodeCookieId for a matrix owner, whose codec name is not the one
// the single-owner helpers hardcode.
func decodeCookieId2(t *testing.T, store *ServerSideStore, owner matrixOwner, cookie *http.Cookie) string {
	t.Helper()

	id, err := store.OpenCookie(owner.sessionName, cookie.Value)
	require.NoError(t, err)
	return id
}

func TestServerSideStore_SaveOnALoadedSessionUpdates(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	cookie := saveNew(t, store, map[string]any{"greeting": "hello"})
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

	cookie := saveNew(t, store, map[string]any{"greeting": "hello"})
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

	cookie := saveNew(t, store, map[string]any{"greeting": "hello"})
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
	// Both attributes, exactly as DeletionCookie carries them: Max-Age is what a current
	// browser acts on and the past expiry is what one predating it acts on. Logging out is
	// the path where the two disagreeing matters most, and it is the one that had only
	// Max-Age (#266).
	// IsZero first, and not merely "before now": an absent Expires parses back as the
	// zero time, which is year 1 and therefore also before now, so the obvious assertion
	// passes against a cookie carrying no expiry at all. The mutation that made this
	// branch unreachable survived it.
	require.False(t, cookies[0].Expires.IsZero(),
		"a cookie being removed carries an expiry in the past as well as Max-Age")
	assert.True(t, cookies[0].Expires.Before(time.Now()))
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
	id, err := plainStore.OpenCookie(storeTestName, secureCookie.Value)
	require.NoError(t, err)
	assert.Len(t, id, 64)
	id, err = secureStore.OpenCookie(storeTestName, plainCookie.Value)
	require.NoError(t, err)
	assert.Len(t, id, 64)
}

func TestServerSideStore_SecureLoadsWhatSecureSaved(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, true)

	cookie := saveNew(t, store, map[string]any{"greeting": "hello"})

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

	oldCookie := saveNew(t, store, map[string]any{"greeting": "hello"})
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

	oldCookie := saveNew(t, store, map[string]any{"greeting": "hello"})
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

	oldCookie := saveNew(t, store, map[string]any{"greeting": "hello"})

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

// --- the per-request cache (decision 3) ----------------------------------------------

// TestServerSideStore_GetIsMemoisedPerRequest pins the property three middlewares and the
// JWT refresh depend on: every Get for one name on one request is the same *Session.
//
// The JWT middleware is the caller that makes this load bearing rather than merely
// efficient. It obtains the session, calls refreshToken, which obtains the session again
// through a second Get, writes the refreshed tokens into that object and saves it, and
// then the outer function reads the refreshed tokens back out of the object it is still
// holding. Two objects and the outer function serves the tokens from before the refresh
// (#269).
func TestServerSideStore_GetIsMemoisedPerRequest(t *testing.T) {
	t.Run("a fresh session is the same object on every Get", func(t *testing.T) {
		backend := newFakeBackend()
		store := newTestStore(backend, false)

		req := httptest.NewRequest("GET", "/", nil)
		first, err := store.Get(req, storeTestName)
		require.NoError(t, err)
		second, err := store.Get(req, storeTestName)
		require.NoError(t, err)

		assert.Same(t, first, second)

		// And a write through one is visible through the other, which is the whole of
		// what the JWT refresh needs.
		first.Values["refreshed"] = "yes"
		assert.Equal(t, "yes", second.Values["refreshed"])
	})

	t.Run("a loaded session costs one read however many middlewares ask", func(t *testing.T) {
		backend := newFakeBackend()
		store := newTestStore(backend, false)

		cookie := saveNew(t, store, map[string]any{"greeting": "hello"})
		backend.loads = 0

		req := requestWith(cookie)
		first, err := store.Get(req, storeTestName)
		require.NoError(t, err)
		second, err := store.Get(req, storeTestName)
		require.NoError(t, err)
		third, err := store.Get(req, storeTestName)
		require.NoError(t, err)

		assert.Same(t, first, second)
		assert.Same(t, first, third)
		assert.Equal(t, 1, backend.loads,
			"on the admin console each load is an HTTP round trip to the auth server")
	})

	t.Run("two names on one request are two sessions", func(t *testing.T) {
		backend := newFakeBackend()
		store := newTestStore(backend, false)

		req := httptest.NewRequest("GET", "/", nil)
		first, err := store.Get(req, storeTestName)
		require.NoError(t, err)
		other, err := store.Get(req, "SomeOtherSession")
		require.NoError(t, err)

		// The cache is keyed by name, so collapsing it to one entry per request would
		// serve one module's session under the other's name.
		assert.NotSame(t, first, other)
		assert.Equal(t, storeTestName, first.Name())
		assert.Equal(t, "SomeOtherSession", other.Name())
	})

	t.Run("two requests are two sessions", func(t *testing.T) {
		backend := newFakeBackend()
		store := newTestStore(backend, false)

		cookie := saveNew(t, store, map[string]any{"greeting": "hello"})

		first, err := store.Get(requestWith(cookie), storeTestName)
		require.NoError(t, err)
		second, err := store.Get(requestWith(cookie), storeTestName)
		require.NoError(t, err)

		// The cache is per request and must not outlive one. A store-wide cache would
		// serve one visitor's session to the next request that named it.
		assert.NotSame(t, first, second)
		assert.Equal(t, "hello", second.Values["greeting"])
	})
}

// --- flashes (decision 4) -------------------------------------------------------------

// TestServerSideStore_FlashSurvivesAReloadAndIsReadOnce is the flash pair through the
// store rather than on a bare Session, and the reload is the point of it. A flash is
// written on one request and read on the next, so it has to cross the serialisation the
// store performs on save. This is the case that catches a stored shape the serialiser
// cannot encode, which is the requirement the library this replaced satisfied with a
// package-level type registration; storing a plain string retires it, and this case is
// what says so rather than the absence of a registration saying nothing (#269).
func TestServerSideStore_FlashSurvivesAReloadAndIsReadOnce(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	// Request one: the handler that saved something sets the notice and redirects.
	writeReq := httptest.NewRequest("GET", "/", nil)
	writeRec := httptest.NewRecorder()
	session, err := store.Get(writeReq, storeTestName)
	require.NoError(t, err)
	session.SetFlash("savedSuccessfully", "true")
	require.NoError(t, store.Save(writeReq, writeRec, session))

	cookies := writeRec.Result().Cookies()
	require.Len(t, cookies, 1)

	// Request two: the page renders the notice and consumes it.
	readReq := requestWith(cookies[0])
	reloaded, err := store.Get(readReq, storeTestName)
	require.NoError(t, err)
	value, ok := reloaded.TakeFlash("savedSuccessfully")
	assert.True(t, ok, "the flash must survive the round trip through the backend")
	assert.Equal(t, "true", value)
	require.NoError(t, store.Save(readReq, httptest.NewRecorder(), reloaded))

	// Request three: the same page, reloaded, and the notice is gone. Without the save
	// above the consumption would live only in the object request two threw away.
	third, err := store.Get(requestWith(cookies[0]), storeTestName)
	require.NoError(t, err)
	_, ok = third.TakeFlash("savedSuccessfully")
	assert.False(t, ok, "a notice must not show a second time")
}

func TestServerSideStore_ImplementsRegenerator(t *testing.T) {
	var _ Regenerator = newTestStore(newFakeBackend(), false)
	var _ Store = newTestStore(newFakeBackend(), false)
}

// --- which lifetime applies --------------------------------------------------------------

func TestServerSideStore_AuthenticatedFlagFollowsTheConfiguredKey(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	saveNew(t, store, map[string]any{"AuthContext": "a ceremony in progress"})
	assert.False(t, backend.lastAuthenticated, "a ceremony nobody finished has not authenticated")

	saveNew(t, store, map[string]any{"SessionIdentifier": "a-user-session-uuid"})
	assert.True(t, backend.lastAuthenticated)

	saveNew(t, store, map[string]any{"SessionIdentifier": ""})
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

// --- deletion cookies --------------------------------------------------------------

// TestServerSideStore_DeletionCookieCarriesWhatADeletionNeeds pins the attributes a
// deletion must carry to land, which is the half of a cookie deletion that fails
// silently: a browser matches a deletion to the cookie it replaces by name, domain and
// path, and refuses a __Host- prefixed cookie outright unless it is Secure. A deletion
// written with the wrong path, or without Secure on https, is accepted by every test that
// only checks a Set-Cookie was emitted and does nothing at all in a browser.
func TestServerSideStore_DeletionCookieCarriesWhatADeletionNeeds(t *testing.T) {
	for _, secure := range []bool{true, false} {
		store := newTestStore(newFakeBackend(), secure)
		cookie := store.DeletionCookie(store.CookieName(storeTestName))

		assert.Equal(t, -1, cookie.MaxAge)
		assert.True(t, cookie.Expires.Before(time.Now()), "the expiry must be in the past")
		assert.Empty(t, cookie.Value)
		assert.Equal(t, store.Options.Path, cookie.Path)
		assert.Equal(t, secure, cookie.Secure,
			"a __Host- cookie is refused unless the deletion is Secure too")
		assert.Equal(t, store.Options.HttpOnly, cookie.HttpOnly)
		assert.Equal(t, store.Options.SameSite, cookie.SameSite)
	}
}

// TestServerSideStore_DeletionCookieNamesWhatItWasGiven: the two callers name different
// things, this store's own cookie and the chunked store's leftovers, so the name is passed
// in whole rather than derived here.
func TestServerSideStore_DeletionCookieNamesWhatItWasGiven(t *testing.T) {
	store := newTestStore(newFakeBackend(), true)

	assert.Equal(t, "__Host-"+storeTestName, store.DeletionCookie(store.CookieName(storeTestName)).Name)
	assert.Equal(t, storeTestName+"-chunk-7", store.DeletionCookie(storeTestName+"-chunk-7").Name)
}

// The cutover matrix.
//
// Both owners, both schemes, against every state a browser can arrive in. It is here rather
// than spread across the cases above because no stage before the admin console cut over had
// both owners to run it against, and because the cross product is finite and small: the
// interesting failures are the combinations, not the individual cells.
//
// The auth server's owner keeps a persistent cookie and looks for SessionIdentifier; the
// admin console's keeps none and looks for Jwt. Those four values are what the two main.go
// files pass, and getting either pair crossed would give administrators single sign-on
// across browser restarts and end users none, silently (#266).

type matrixOwner struct {
	label            string
	sessionName      string
	authenticatedKey string
	persistent       bool
}

var matrixOwners = []matrixOwner{
	{"authserver", constants.AuthServerSessionName, constants.SessionKeySessionIdentifier, true},
	{"adminconsole", constants.AdminConsoleSessionName, constants.SessionKeyJwt, false},
}

func newMatrixStore(owner matrixOwner, backend Backend, secure bool) *ServerSideStore {
	store, err := NewServerSideStore(backend, owner.authenticatedKey, secure, storeTestPair(), nil)
	if err != nil {
		panic(err)
	}
	store.PersistentCookie = owner.persistent
	return store
}

// liveCookie saves a session carrying value and returns the cookie the browser would then
// hold, along with the backend it was written to.
func liveCookie(t *testing.T, store *ServerSideStore, owner matrixOwner, values map[string]any) *http.Cookie {
	t.Helper()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	session, err := store.New(req, owner.sessionName)
	require.NoError(t, err)
	for k, v := range values {
		session.Values[k] = v
	}
	require.NoError(t, store.Save(req, w, session))

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1, "a session must cost exactly one cookie, in either module")
	return cookies[0]
}

// loadWith runs New against a request carrying the given cookies.
func loadWith(t *testing.T, store *ServerSideStore, owner matrixOwner, cookies ...*http.Cookie) (*Session, error) {
	t.Helper()

	req := httptest.NewRequest("GET", "/", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return store.New(req, owner.sessionName)
}

func TestServerSideStore_CutoverMatrix(t *testing.T) {
	for _, owner := range matrixOwners {
		for _, secure := range []bool{false, true} {
			label := owner.label
			if secure {
				label += "/https"
			} else {
				label += "/http"
			}

			t.Run(label+"/no cookie", func(t *testing.T) {
				backend := newFakeBackend()
				store := newMatrixStore(owner, backend, secure)

				session, err := loadWith(t, store, owner)
				require.NoError(t, err)
				assert.True(t, session.IsNew)
				assert.Zero(t, backend.loads, "a visitor presenting nothing costs no read")
			})

			t.Run(label+"/a valid cookie", func(t *testing.T) {
				backend := newFakeBackend()
				store := newMatrixStore(owner, backend, secure)
				cookie := liveCookie(t, store, owner, map[string]any{
					owner.authenticatedKey: "the-value",
				})

				// The physical name follows the scheme; the codec name does not.
				expectedName := owner.sessionName
				if secure {
					expectedName = "__Host-" + owner.sessionName
				}
				assert.Equal(t, expectedName, cookie.Name)
				assert.Equal(t, secure, cookie.Secure)

				if owner.persistent {
					assert.Greater(t, cookie.MaxAge, 0,
						"the end user's cookie carries an expiry, so single sign-on survives a restart")
				} else {
					assert.Equal(t, 0, cookie.MaxAge)
					assert.True(t, cookie.Expires.IsZero(),
						"the administrator's cookie carries neither, so the browser drops it when it closes")
				}

				session, err := loadWith(t, store, owner, cookie)
				require.NoError(t, err)
				assert.False(t, session.IsNew)
				assert.Equal(t, "the-value", session.Values[owner.authenticatedKey])
			})

			t.Run(label+"/an undecodable cookie", func(t *testing.T) {
				backend := newFakeBackend()
				store := newMatrixStore(owner, backend, secure)
				cookie := liveCookie(t, store, owner, nil)
				cookie.Value = "not-a-signed-value"

				session, err := loadWith(t, store, owner, cookie)
				require.NoError(t, err, "a cookie that will not decode is a fresh session, not an error")
				assert.True(t, session.IsNew)
			})

			t.Run(label+"/a valid cookie naming no row", func(t *testing.T) {
				backend := newFakeBackend()
				store := newMatrixStore(owner, backend, secure)
				cookie := liveCookie(t, store, owner, nil)
				backend.rows = map[string]*Record{}

				session, err := loadWith(t, store, owner, cookie)
				require.NoError(t, err)
				assert.True(t, session.IsNew,
					"expired, logged out and reaped all mean the same thing to the browser")
				assert.Equal(t, 1, backend.loads)
			})

			t.Run(label+"/a storage failure", func(t *testing.T) {
				backend := newFakeBackend()
				store := newMatrixStore(owner, backend, secure)
				cookie := liveCookie(t, store, owner, nil)
				backend.loadErr = errors.New("the database is unreachable")

				session, err := loadWith(t, store, owner, cookie)
				require.Error(t, err, "a lookup that could not be performed is not a fresh session")
				require.NotNil(t, session,
					"Get memoises whatever New returns and hands it to every middleware that "+
						"asks, so a nil session here is a panic rather than the 500 this cell "+
						"exists to pin")
			})

			t.Run(label+"/the old bare master cookie", func(t *testing.T) {
				backend := newFakeBackend()
				store := newMatrixStore(owner, backend, secure)

				// What the chunked cookie store's master cookie looks like on arrival: the
				// bare session name carrying a value this store cannot read.
				stale := &http.Cookie{Name: owner.sessionName, Value: "the old master cookie"}

				session, err := loadWith(t, store, owner, stale)
				require.NoError(t, err)
				assert.True(t, session.IsNew)

				if secure {
					assert.Contains(t, store.StaleCookieNames(owner.sessionName), owner.sessionName,
						"on https the bare name is a leftover and is safe to delete")
				} else {
					assert.NotContains(t, store.StaleCookieNames(owner.sessionName), owner.sessionName,
						"on plain http the bare name is this store's own live cookie")
				}
			})

			t.Run(label+"/the chunk siblings", func(t *testing.T) {
				backend := newFakeBackend()
				store := newMatrixStore(owner, backend, secure)
				cookie := liveCookie(t, store, owner, map[string]any{
					owner.authenticatedKey: "the-value",
				})

				chunks := []*http.Cookie{cookie}
				for i := 0; i < 3; i++ {
					chunks = append(chunks, &http.Cookie{
						Name:  chunkCookieName(owner.sessionName, i),
						Value: "leftover",
					})
				}

				session, err := loadWith(t, store, owner, chunks...)
				require.NoError(t, err)
				assert.False(t, session.IsNew,
					"leftovers riding along must not stop the live session from loading")
				assert.Equal(t, "the-value", session.Values[owner.authenticatedKey])

				names := store.StaleCookieNames(owner.sessionName)
				for i := 0; i < legacyMaxChunks; i++ {
					assert.Contains(t, names, chunkCookieName(owner.sessionName, i))
				}
			})
		}
	}
}

// TestServerSideStore_ASessionLargerThanACookieRoundTrips is the regression for a ceiling
// that used to bind where nothing said it did.
//
// The codec this replaced capped an encoded value at 4096 bytes by default, and the store
// encodes two very different things: a 64 character identifier for the cookie and the entire
// session for the backend. Sharing one codec set left the second capped at the first's limit,
// so any session over about 4 KB failed its save with "the value is too long". The auth server
// never reached it, because its ceremony session is a couple of kilobytes; an admin console
// session holds a whole token set, about 13 KB, so every save it made would have failed. The
// blob is now bounded by MaxSessionDataBytes and the cookie by nothing but its contents, which
// are a fixed 64 characters (#266, #270).
func TestServerSideStore_ASessionLargerThanACookieRoundTrips(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	// Comfortably past a cookie's 4096 bytes, and past it again once encoded.
	large := strings.Repeat("scope:permission ", 1200)
	require.Greater(t, len(large), 4096)

	cookie := saveNew(t, store, map[string]any{"payload": large})

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookie)
	session, err := store.New(req, storeTestName)
	require.NoError(t, err)
	assert.Equal(t, large, session.Values["payload"])

	// And the cookie stayed the fixed size the whole change exists to produce, which is what
	// says the payload went to the backend rather than into the browser.
	assert.Less(t, len(cookie.Value), 300)
}

// TestServerSideStore_ASessionPastTheStoresOwnCeilingIsRefused. The ceiling now binds, which
// is the difference from the store this replaces: that one advertised fifty chunks, disabled
// its codec's length check, and encoded whatever it was given. The check is the store's own
// now, applied to the sealed length in sealSessionData, which is what both write paths go
// through (#270).
func TestServerSideStore_ASessionPastTheStoresOwnCeilingIsRefused(t *testing.T) {
	backend := newFakeBackend()
	store := newTestStore(backend, false)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	session, err := store.New(req, storeTestName)
	require.NoError(t, err)
	session.Values["payload"] = strings.Repeat("x", MaxSessionDataBytes+1)

	require.Error(t, store.Save(req, w, session))
	assert.Zero(t, backend.creates, "nothing oversized reaches storage")
	assert.Empty(t, w.Result().Cookies(), "and the browser is told nothing about a session that was not written")
}
