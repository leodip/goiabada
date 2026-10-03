package usersession

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"errors"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/authserver/internal/useragent"
	"github.com/leodip/goiabada/authserver/internal/uuid/uuidtest"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
)

// =============================================================================
// Tests for StartNewUserSession
//
// This is what creates the SSO session row and writes its identifier into the
// browser cookie after a successful login. Everything downstream (idle timeout,
// max lifetime, ACR step-up) reads the fields it sets here.
// =============================================================================

// txSentinel is the transaction the shared stub hands the body. It is non-nil and the mock
// database never dereferences it, which is the whole of what it has to be: an expectation
// written against txSentinel matches a call the body made and no call made before or after the
// transaction, where the manager passes nil. A nil here -- which is what the BeginTransaction stubs
// it replaced handed over, and what this package's own copy of the stub handed over until #198
// -- makes those two indistinguishable, so a sweep moved back outside the transaction would
// pass on call count alone. mocks_data.ExpectRunInTransaction now refuses a nil outright, so
// what was this package's convention is the shared stub's rule (#422).
var txSentinel = &sql.Tx{}

const testSessionName = "test-session"

// chromeUserAgent is a desktop UA string, so the device fields are populated
// rather than empty.
const chromeUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// firefoxUserAgent is the second device of the sweep table: a different browser on a different OS,
// so the raw header differs from chromeUserAgent well before its end.
const firefoxUserAgent = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"

// errLoadRefused and errCreateRefused are what armableBackend answers when armed, so a case can
// tell its own failure from any other with errors.Is through the store's wrapping.
var (
	errLoadRefused   = errors.New("the backend refused the read")
	errCreateRefused = errors.New("the backend refused the write")
)

// armableBackend is the in-memory backend with the two operations StartNewUserSession reaches
// through the store made to fail on demand, the admin console callback's pattern (#427): the
// shared MemoryBackend injects nothing, and a test that needs one failure wraps it.
//
// beforeCreate runs inside Create, which is the one point in StartNewUserSession that is after
// the commit and before the compensation: the rotation's new row is written there. The
// cancellation case needs to act exactly there and nowhere else. loads and creates count what
// reached the backend, for the case asserting nothing did.
type armableBackend struct {
	*sessiontest.MemoryBackend
	failLoad     bool
	failCreate   bool
	beforeCreate func()
	loads        int
	creates      int
}

func (b *armableBackend) Load(ctx context.Context, id string) (*sessionstore.Record, error) {
	b.loads++
	if b.failLoad {
		return nil, errLoadRefused
	}
	return b.MemoryBackend.Load(ctx, id)
}

func (b *armableBackend) Create(ctx context.Context, id string, data []byte, authenticated bool) (time.Time, error) {
	b.creates++
	if b.beforeCreate != nil {
		b.beforeCreate()
	}
	if b.failCreate {
		return time.Time{}, errCreateRefused
	}
	return b.MemoryBackend.Create(ctx, id, data, authenticated)
}

// startSessionMocks is the strict database mock and the real browser session store. The store is
// the production ServerSideStore over an in-memory backend since #431: the manager's port names
// Regenerate, which the generated sessionstore mock does not have, so what the sign-in wrote to
// the browser is read back through the store with the cookies a browser would hold.
type startSessionMocks struct {
	t       *testing.T
	db      *mocks_data.Database
	backend *armableBackend
	store   *sessionstore.ServerSideStore
	manager *Manager
}

func newStartSessionMocks(t *testing.T) *startSessionMocks {
	t.Helper()
	db := mocks_data.NewDatabase(t)
	backend := &armableBackend{MemoryBackend: sessiontest.NewMemoryBackend()}
	store, err := sessionstore.NewServerSideStore(backend, sessionkeys.SessionIdentifier, false,
		sessionstore.PersistentCookie, sessionstore.KeyPair{
			AuthenticationKey: []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
			EncryptionKey:     []byte("0123456789abcdef0123456789abcdef"),
		}, nil)
	require.NoError(t, err)
	return &startSessionMocks{
		t:       t,
		db:      db,
		backend: backend,
		store:   store,
		manager: &Manager{
			database:     db,
			sessionStore: store,
			sessionName:  testSessionName,
		},
	}
}

// seed stores values as the browser's pre-sign-in session and returns the cookies naming it.
func (m *startSessionMocks) seed(values map[string]any) []*http.Cookie {
	m.t.Helper()
	req := httptest.NewRequest("GET", "/", nil)
	sess, err := m.store.Get(req, testSessionName)
	require.NoError(m.t, err)
	for k, v := range values {
		sess.Values[k] = v
	}
	rr := httptest.NewRecorder()
	require.NoError(m.t, m.store.Save(req, rr, sess))
	cookies := rr.Result().Cookies()
	require.Len(m.t, cookies, 1)
	return cookies
}

// readBack loads the session cookies name, through the store's own Get, as the browser's next
// request would.
func (m *startSessionMocks) readBack(cookies []*http.Cookie) *sessionstore.Session {
	m.t.Helper()
	req := httptest.NewRequest("GET", "/", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	sess, err := m.store.Get(req, testSessionName)
	require.NoError(m.t, err)
	return sess
}

// identifier is the browser session identifier a cookie names, which the store alone can read:
// every seal draws a fresh nonce, so comparing cookie values proves nothing.
func (m *startSessionMocks) identifier(cookie *http.Cookie) string {
	m.t.Helper()
	id, err := m.store.OpenCookie(testSessionName, cookie.Value)
	require.NoError(m.t, err)
	return id
}

func withCookies(req *http.Request, cookies []*http.Cookie) *http.Request {
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

// someCredentialInstant is the captured credential instant for the tests that are not about
// AuthTime. StartNewUserSession refuses nil and zero, so every legitimate call carries one; a
// fixed offset into the past rather than now, so no assertion in those tests can lean on
// AuthTime coinciding with the clock.
func someCredentialInstant() *time.Time {
	instant := time.Now().UTC().Add(-5 * time.Minute)
	return &instant
}

func newSessionRequest(remoteAddr string, userAgent string) *http.Request {
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = remoteAddr
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	return req
}

// expectPersistThroughCommit sets up everything up to and including the commit: the transaction,
// the session row, its client association and the sibling read the sweep runs on. The
// browser-session read before it and the rotation after it are the real store's, and a case
// testing either one's failure arms the backend instead.
//
// The sibling read is matched on txSentinel rather than mock.Anything, so it is an assertion
// and not just a stub: a read moved back outside the transaction arrives with a nil tx and the
// strict mock fails it as unexpected.
//
// The returned pointer receives the session that was handed to CreateUserSession.
func (m *startSessionMocks) expectPersistThroughCommit(userId int64, existingSessions []record.UserSession) **record.UserSession {
	captured := new(*record.UserSession)

	mocks_data.ExpectRunInTransaction(m.db, txSentinel)
	m.db.On("CreateUserSession", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		created := args.Get(2).(*record.UserSession)
		created.Id = 99 // stand in for the generated primary key
		*captured = created
	}).Return(nil).Once()
	m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	m.db.On("GetUserSessionsByUserId", mock.Anything, txSentinel, userId).Return(existingSessions, nil).Once()

	return captured
}

func TestStartNewUserSession_PopulatesSessionFields(t *testing.T) {
	m := newStartSessionMocks(t)
	req := newSessionRequest("192.168.1.50:54321", chromeUserAgent)
	recorder := httptest.NewRecorder()

	captured := m.expectPersistThroughCommit(123, nil)
	credentialAcceptedAt := someCredentialInstant()

	before := time.Now().UTC()
	result, _, err := m.manager.StartNewUserSession(recorder, req, 123, 7, "pwd otp", record.AcrLevel2Mandatory, 0, nil, credentialAcceptedAt, "192.168.1.50", nil)
	after := time.Now().UTC()

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Same(t, *captured, result, "the persisted session must be the one returned")

	assert.Equal(t, int64(123), result.UserId)
	assert.Equal(t, "pwd otp", result.AuthMethods)
	assert.Equal(t, record.AcrLevel2Mandatory, result.AcrLevel)
	assert.Equal(t, "192.168.1.50", result.IpAddress, "the address is the one the caller passed")

	// The identifier must be a fresh UUID, since it is what the browser cookie
	// carries and what every later lookup keys on.
	parsed, parseErr := uuidtest.Parse(result.SessionIdentifier)
	assert.NoError(t, parseErr, "the session identifier must be a valid UUID")
	// uuidtest.Parse accepts the nil UUID, so "non-empty" would pass against a hard-coded
	// one. Compare against the nil spelling itself.
	assert.NotEqual(t, "00000000-0000-0000-0000-000000000000", parsed)

	// Started and LastAccessed are stamped with the same UTC now: they measure the session's
	// own life. AuthTime is the captured credential instant, never this call's clock;
	// TestStartNewUserSession_AuthTimeIsTheCapturedCredentialInstant pins the distance
	// between the two, and TestStartNewUserSession_RefusesAMissingCredentialInstant that no
	// call runs without one.
	for name, value := range map[string]time.Time{
		"Started":      result.Started,
		"LastAccessed": result.LastAccessed,
	} {
		assert.False(t, value.Before(before), "%s must not predate the call", name)
		assert.False(t, value.After(after), "%s must not postdate the call", name)
		assert.Equal(t, time.UTC, value.Location(), "%s must be stored in UTC", name)
	}
	assert.Equal(t, result.Started, result.LastAccessed)
	assert.True(t, result.AuthTime.Equal(*credentialAcceptedAt), "AuthTime must be the captured instant")
	assert.Equal(t, time.UTC, result.AuthTime.Location(), "AuthTime must be stored in UTC")

	assert.EqualValues(t, 0, result.OtpConfigGeneration,
		"a nil capture must land the session at generation 0, which is the fail-closed value: "+
			"it owes a level 2 re-prompt as soon as the user's counter is above 0")

	// The three display labels are whatever useragent.Labels derives from this request, and
	// the exhaustive table for that lives at useragent's own seam. Thin here on purpose: what
	// this asserts is that the manager stores what Labels answered, not what Labels answers.
	wantName, wantType, wantOS := useragent.Labels(req)
	assert.Equal(t, wantName, result.DeviceName)
	assert.Equal(t, wantType, result.DeviceType)
	assert.Equal(t, wantOS, result.DeviceOS)
	assert.NotEmpty(t, result.DeviceName)

	// The raw header is stored beside them, and it is what the sweep below keys on. Unlike the
	// three labels it is the string the browser sent, not a parse of it.
	assert.Equal(t, chromeUserAgent, result.UserAgent)
}

// The header reaches the row through useragent.BoundRaw, so a browser sending more than the column
// holds cannot make the insert fail. 600 bytes rather than 513, so a cut at the wrong width shows
// up in the assertion rather than being off by one.
func TestStartNewUserSession_BoundsTheUserAgentToTheColumnWidth(t *testing.T) {
	m := newStartSessionMocks(t)
	overlong := strings.Repeat("a", 600)
	req := newSessionRequest("192.168.1.50:54321", overlong)

	captured := m.expectPersistThroughCommit(123, nil)

	result, _, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), req, 123, 7, "pwd", record.AcrLevel1, 0, nil, someCredentialInstant(), "192.168.1.50", nil)

	assert.NoError(t, err)
	assert.Same(t, *captured, result)
	assert.Len(t, result.UserAgent, 512, "the persisted header must be cut to the column width")
	assert.True(t, strings.HasPrefix(overlong, result.UserAgent),
		"the cut must keep the start of the header the browser sent, not rewrite it")
}

func TestStartNewUserSession_RecordsTheClient(t *testing.T) {
	m := newStartSessionMocks(t)
	req := newSessionRequest("10.0.0.1:1234", chromeUserAgent)

	var capturedClient *record.UserSessionClient
	mocks_data.ExpectRunInTransaction(m.db, txSentinel)
	m.db.On("CreateUserSession", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		args.Get(2).(*record.UserSession).Id = 99
	}).Return(nil).Once()
	m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		capturedClient = args.Get(2).(*record.UserSessionClient)
	}).Return(nil).Once()
	m.db.On("GetUserSessionsByUserId", mock.Anything, txSentinel, int64(123)).Return(nil, nil).Once()

	result, _, err := m.manager.StartNewUserSession(httptest.NewRecorder(), req, 123, 7, "pwd", record.AcrLevel1, 0, nil, someCredentialInstant(), "192.168.1.50", nil)

	assert.NoError(t, err)
	assert.Len(t, result.Clients, 1)
	assert.Equal(t, int64(7), result.Clients[0].ClientId)

	assert.NotNil(t, capturedClient)
	assert.Equal(t, int64(7), capturedClient.ClientId)
	assert.Equal(t, int64(99), capturedClient.UserSessionId,
		"the client row must point at the session's generated id")
	assert.Equal(t, result.Started, capturedClient.Started)
	assert.Equal(t, result.Started, capturedClient.LastAccessed)
}

// The session identifier is written into the browser session, which is how the
// browser is tied back to the database row. Read back through the store with the
// cookie the sign-in wrote, as the browser's next request would.
func TestStartNewUserSession_WritesIdentifierIntoTheCookieSession(t *testing.T) {
	m := newStartSessionMocks(t)
	req := newSessionRequest("10.0.0.1:1234", chromeUserAgent)
	rr := httptest.NewRecorder()

	m.expectPersistThroughCommit(123, nil)

	result, _, err := m.manager.StartNewUserSession(rr, req, 123, 7, "pwd", record.AcrLevel1, 0, nil, someCredentialInstant(), "192.168.1.50", nil)

	require.NoError(t, err)
	assert.Equal(t, result.SessionIdentifier, m.readBack(rr.Result().Cookies()).Values[sessionkeys.SessionIdentifier])
}

// -----------------------------------------------------------------------------
// Superseding sessions from the same device
//
// After creating the new session, any other session for the same user on the
// same device and IP is deleted, so a re-login replaces rather than accumulates.
// -----------------------------------------------------------------------------

func TestStartNewUserSession_DeletesMatchingSessionFromSameDeviceAndIp(t *testing.T) {
	m := newStartSessionMocks(t)
	req := newSessionRequest("192.168.1.50:54321", chromeUserAgent)

	stale := record.UserSession{
		Id:                42,
		SessionIdentifier: "an-older-session",
		IpAddress:         "192.168.1.50",
		UserAgent:         chromeUserAgent,
	}

	m.expectPersistThroughCommit(123, []record.UserSession{stale})
	m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(42)).Return(nil).Once()

	_, removed, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), req, 123, 7, "pwd", record.AcrLevel1, 0, nil, someCredentialInstant(), "192.168.1.50", nil)

	assert.NoError(t, err)
	assert.Equal(t, []int64{42}, removedIds(removed), "the swept row is reported so the caller can audit it")
}

// removedIds is the ids of the rows StartNewUserSession reported removed, in order: the row id is
// what the caller's audit event names.
func removedIds(removed []record.UserSession) []int64 {
	ids := []int64{}
	for _, us := range removed {
		ids = append(ids, us.Id)
	}
	return ids
}

// The reversal, and the whole of decision 1: a row whose three labels disagree with the request on
// every one of them is still the same device when the raw header and the address match, so it is
// deleted. Under the pre-#281 key this session survived, because the sweep compared the labels.
func TestStartNewUserSession_DeletesAMatchingHeaderWhoseLabelsDiffer(t *testing.T) {
	m := newStartSessionMocks(t)
	req := newSessionRequest("192.168.1.50:54321", chromeUserAgent)

	stale := record.UserSession{
		Id:                42,
		SessionIdentifier: "an-older-session",
		IpAddress:         "192.168.1.50",
		UserAgent:         chromeUserAgent, // the header the request sends, so the device matches
		DeviceName:        "Some Other Browser",
		DeviceType:        "Mobile",
		DeviceOS:          "Linux",
	}

	m.expectPersistThroughCommit(123, []record.UserSession{stale})
	m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(42)).Return(nil).Once()

	_, _, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), req, 123, 7, "pwd", record.AcrLevel1, 0, nil, someCredentialInstant(), "192.168.1.50", nil)

	assert.NoError(t, err)
}

// Decision 7, the half that sweeps rather than the half that keeps: a header-less client matches a
// pre-upgrade row on the same address, because both read as the empty string, and the older session
// is swept exactly as it would have been before the upgrade.
func TestStartNewUserSession_AnEmptyHeaderMatchesAnEmptyHeader(t *testing.T) {
	m := newStartSessionMocks(t)
	req := newSessionRequest("192.168.1.50:54321", "")
	req.Header.Del("User-Agent")

	stale := record.UserSession{
		Id:                42,
		SessionIdentifier: "a-legacy-session",
		IpAddress:         "192.168.1.50",
		UserAgent:         "",
	}

	m.expectPersistThroughCommit(123, []record.UserSession{stale})
	m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(42)).Return(nil).Once()

	_, _, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), req, 123, 7, "pwd", record.AcrLevel1, 0, nil, someCredentialInstant(), "192.168.1.50", nil)

	assert.NoError(t, err)
}

// Anything that differs in device or IP is a separate login and must survive.
// NewDatabase(t) fails on an unexpected DeleteUserSession, which is the assertion.
func TestStartNewUserSession_KeepsSessionsFromOtherDevicesOrIps(t *testing.T) {
	// Every case below is compared against a request sending chromeUserAgent from 192.168.1.50.
	testCases := []struct {
		name    string
		session record.UserSession
	}{
		{
			name: "same header, other ip",
			session: record.UserSession{
				Id: 42, SessionIdentifier: "other", IpAddress: "10.0.0.9",
				UserAgent: chromeUserAgent,
			},
		},
		{
			name: "other header, same ip",
			session: record.UserSession{
				Id: 42, SessionIdentifier: "other", IpAddress: "192.168.1.50",
				UserAgent: firefoxUserAgent,
			},
		},
		{
			// Decision 7: a pre-upgrade row carries no header and there is nothing to backfill
			// it from, so a login that sends one does not sweep it. It expires on its own.
			name: "a legacy row with no header, against a request that sends one",
			session: record.UserSession{
				Id: 42, SessionIdentifier: "legacy", IpAddress: "192.168.1.50",
				UserAgent: "",
			},
		},
		{
			// The labels are display only from here, so matching on all three is not matching.
			name: "the three labels match but the header does not",
			session: record.UserSession{
				Id: 42, SessionIdentifier: "other", IpAddress: "192.168.1.50",
				UserAgent:  firefoxUserAgent,
				DeviceName: "Chrome 120.0.0.0", DeviceType: "Desktop", DeviceOS: "Windows 10.0",
			},
		},
		{
			// Exact-version equality is stricter than the old key, never looser: two builds of
			// one browser are two devices, where the old labels collapsed them into one.
			name: "the same browser at a different build",
			session: record.UserSession{
				Id: 42, SessionIdentifier: "other", IpAddress: "192.168.1.50",
				UserAgent: strings.Replace(chromeUserAgent, "Chrome/120.0.0.0", "Chrome/121.0.0.0", 1),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := newStartSessionMocks(t)
			m.expectPersistThroughCommit(123, []record.UserSession{tc.session})

			_, _, err := m.manager.StartNewUserSession(
				httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent),
				123, 7, "pwd", record.AcrLevel1, 0, nil, someCredentialInstant(), "192.168.1.50", nil)

			assert.NoError(t, err)
		})
	}
}

// The session just created must never delete itself, even though it matches its
// own device and IP on every other field.
func TestStartNewUserSession_DoesNotDeleteTheSessionItJustCreated(t *testing.T) {
	m := newStartSessionMocks(t)
	req := newSessionRequest("192.168.1.50:54321", chromeUserAgent)

	var newIdentifier string
	mocks_data.ExpectRunInTransaction(m.db, txSentinel)
	m.db.On("CreateUserSession", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		created := args.Get(2).(*record.UserSession)
		created.Id = 99
		newIdentifier = created.SessionIdentifier
	}).Return(nil).Once()
	m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	// Return the freshly created session as if it were already persisted. The
	// identifier is only known once CreateUserSession has run, so this is
	// resolved lazily at call time.
	m.db.On("GetUserSessionsByUserId", mock.Anything, txSentinel, int64(123)).Return(
		func(_ context.Context, _ *sql.Tx, _ int64) ([]record.UserSession, error) {
			return []record.UserSession{{
				Id:                99,
				SessionIdentifier: newIdentifier,
				IpAddress:         "192.168.1.50",
				// The new key, so this row reaches the self-identifier guard rather than
				// being skipped by a mismatch and passing vacuously.
				UserAgent: useragent.BoundRaw(req.UserAgent()),
			}}, nil
		}).Once()

	_, _, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), req, 123, 7, "pwd", record.AcrLevel1, 0, nil, someCredentialInstant(), "192.168.1.50", nil)

	assert.NoError(t, err)
}

// -----------------------------------------------------------------------------
// The session a sign-in replaces, the address it is given, and what it reports (#243)
//
// A sign-in that could not reuse the browser's own session for the same user -- expired, idle, or
// older than the max_age asked for -- replaces it, and the sweep compares one address to one
// address. Every row removed comes back once, and only when its deletion committed, because each
// is owed a deleted_user_session event after the commit.
// -----------------------------------------------------------------------------

// The address stored and swept on is the argument, not the request's RemoteAddr: the caller
// reads the browser's address through the one reader the rest of the server uses. The row at the
// RemoteAddr host is a different address from the one given, so it survives; the one at the given
// address is swept.
func TestStartNewUserSession_StoresAndSweepsOnTheAddressItIsGiven(t *testing.T) {
	m := newStartSessionMocks(t)
	req := newSessionRequest("192.168.1.50:54321", chromeUserAgent)

	captured := m.expectPersistThroughCommit(123, []record.UserSession{
		{Id: 41, SessionIdentifier: "at-the-remote-addr", IpAddress: "192.168.1.50", UserAgent: chromeUserAgent},
		{Id: 42, SessionIdentifier: "at-the-given-address", IpAddress: "203.0.113.7", UserAgent: chromeUserAgent},
	})
	m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(42)).Return(nil).Once()

	result, removed, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), req, 123, 7, "pwd", record.AcrLevel1, 0, nil, someCredentialInstant(), "203.0.113.7", nil)

	require.NoError(t, err)
	assert.Equal(t, "203.0.113.7", (*captured).IpAddress)
	assert.Equal(t, "203.0.113.7", result.IpAddress)
	assert.Equal(t, []int64{42}, removedIds(removed))
}

// Decision 17's exactness: an address that contains the new one, or that an earlier binary left as
// a comma-joined history including it, is not the same address, so the row survives. The old
// substring test swept all three of these.
func TestStartNewUserSession_TheSweepComparesWholeAddresses(t *testing.T) {
	for name, stored := range map[string]string{
		"a longer address with the given one as a prefix": "10.0.0.12",
		"a history ending in the given address":           "192.168.1.1,10.0.0.1",
		"a history starting with the given address":       "10.0.0.1,192.168.1.1",
	} {
		t.Run(name, func(t *testing.T) {
			m := newStartSessionMocks(t)
			m.expectPersistThroughCommit(123, []record.UserSession{
				{Id: 42, SessionIdentifier: "other", IpAddress: stored, UserAgent: chromeUserAgent},
			})

			_, removed, err := m.manager.StartNewUserSession(
				httptest.NewRecorder(), newSessionRequest("10.0.0.1:1234", chromeUserAgent),
				123, 7, "pwd", record.AcrLevel1, 0, nil, someCredentialInstant(), "10.0.0.1", nil)

			require.NoError(t, err)
			assert.Empty(t, removed)
		})
	}
}

// The browser's own session is removed with the new one's creation wherever it was last seen and
// whatever browser it recorded: it is the one this sign-in replaces. Before #243 it survived
// whenever its address or header differed from the sign-in's, listed and bumped by its refresh
// tokens with no browser able to reach it. The other row differs in both and is not replaced, so
// it survives.
func TestStartNewUserSession_DeletesTheSessionItReplacesWhereverItWasSeen(t *testing.T) {
	m := newStartSessionMocks(t)
	replaced := record.UserSession{
		Id: 42, SessionIdentifier: "the-cookie-named-this", UserId: 123,
		IpAddress: "198.51.100.20", UserAgent: firefoxUserAgent,
	}
	m.expectPersistThroughCommit(123, []record.UserSession{
		replaced,
		{Id: 43, SessionIdentifier: "another-device", UserId: 123, IpAddress: "198.51.100.21", UserAgent: firefoxUserAgent},
	})
	m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(42)).Return(nil).Once()

	_, removed, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent),
		123, 7, "pwd", record.AcrLevel1, 0, nil, someCredentialInstant(), "192.168.1.50", &replaced)

	require.NoError(t, err)
	assert.Equal(t, []int64{42}, removedIds(removed))
}

// A replaced session on the sign-in's own device is both reasons at once. It is deleted once and
// reported once, so the caller writes one event for it rather than two. DeleteUserSession answers
// nil for a row already gone, so a second delete would not fail: the Once is the assertion.
func TestStartNewUserSession_AReplacedSessionThatAlsoMatchesTheSweepIsRemovedOnce(t *testing.T) {
	m := newStartSessionMocks(t)
	replaced := record.UserSession{
		Id: 42, SessionIdentifier: "the-cookie-named-this", UserId: 123,
		IpAddress: "192.168.1.50", UserAgent: chromeUserAgent,
	}
	m.expectPersistThroughCommit(123, []record.UserSession{replaced})
	m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(42)).Return(nil).Once()

	_, removed, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent),
		123, 7, "pwd", record.AcrLevel1, 0, nil, someCredentialInstant(), "192.168.1.50", &replaced)

	require.NoError(t, err)
	assert.Equal(t, []int64{42}, removedIds(removed))
}

// A replaced session that is no longer there when the transaction reads -- a logout or the idle
// sweep got to it first -- is not deleted and not reported: this sign-in did not remove it, and an
// event saying so would record a deletion twice. The strict mock refuses a DeleteUserSession.
func TestStartNewUserSession_AReplacedSessionAlreadyGoneIsNotReported(t *testing.T) {
	m := newStartSessionMocks(t)
	replaced := record.UserSession{Id: 42, SessionIdentifier: "already-gone", UserId: 123, IpAddress: "198.51.100.20"}
	m.expectPersistThroughCommit(123, nil)

	_, removed, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent),
		123, 7, "pwd", record.AcrLevel1, 0, nil, someCredentialInstant(), "192.168.1.50", &replaced)

	require.NoError(t, err)
	assert.Empty(t, removed)
}

// Another user's session is not this function's to end: the cross-user handover terminates it with
// revocation before calling here, and replacing it here would delete it with nothing revoked. It is
// refused before anything is read or written.
func TestStartNewUserSession_RefusesToReplaceAnotherUsersSession(t *testing.T) {
	m := newStartSessionMocks(t)
	req := withCookies(newSessionRequest("192.168.1.50:54321", chromeUserAgent), m.seed(nil))
	loads := m.backend.loads
	foreign := record.UserSession{Id: 42, SessionIdentifier: "someone-else", UserId: 999}

	result, removed, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), req, 123, 7, "pwd", record.AcrLevel1, 0, nil, someCredentialInstant(), "192.168.1.50", &foreign)

	require.ErrorContains(t, err, "belongs to user 999")
	assert.Nil(t, result)
	assert.Nil(t, removed)
	assert.Equal(t, loads, m.backend.loads, "the browser session is not even read")
}

// RunInTransaction reruns the whole body after a deadlock abort, so what the aborted attempt
// deleted was undone. The rows reported are the committed attempt's, once each: row 41 was deleted
// by the first attempt only -- something else removed it before the rerun read -- and row 42 by
// both. A slice kept across attempts would report 41, which the database has no deletion of by this
// sign-in, and 42 twice.
func TestStartNewUserSession_ARerunReportsTheCommittedAttemptsRemovalsOnce(t *testing.T) {
	m := newStartSessionMocks(t)
	sameDevice := func(id int64) record.UserSession {
		return record.UserSession{Id: id, SessionIdentifier: fmt.Sprintf("row-%d", id), IpAddress: "192.168.1.50", UserAgent: chromeUserAgent}
	}

	mocks_data.ExpectRunInTransactionRerun(m.db, txSentinel)
	m.db.On("CreateUserSession", mock.Anything, txSentinel, mock.Anything).Run(func(args mock.Arguments) {
		args.Get(2).(*record.UserSession).Id = 99
	}).Return(nil).Twice()
	m.db.On("CreateUserSessionClient", mock.Anything, txSentinel, mock.Anything).Return(nil).Twice()
	m.db.On("GetUserSessionsByUserId", mock.Anything, txSentinel, int64(123)).
		Return([]record.UserSession{sameDevice(41), sameDevice(42)}, nil).Once()
	m.db.On("GetUserSessionsByUserId", mock.Anything, txSentinel, int64(123)).
		Return([]record.UserSession{sameDevice(42)}, nil).Once()
	m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(41)).Return(nil).Once()
	m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(42)).Return(nil).Twice()

	_, removed, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent),
		123, 7, "pwd", record.AcrLevel1, 0, nil, someCredentialInstant(), "192.168.1.50", nil)

	require.NoError(t, err)
	assert.Equal(t, []int64{42}, removedIds(removed))
}

// A transaction that does not commit reports nothing, even when the body had already deleted rows
// before it failed: the rollback undid them, and an event for each would record deletions that did
// not happen. The refused commit is the same, because the helper cannot say it landed.
func TestStartNewUserSession_AnUncommittedTransactionReportsNoRemovals(t *testing.T) {
	dbErr := errors.New("database is down")
	sweep := []record.UserSession{
		{Id: 41, SessionIdentifier: "row-41", IpAddress: "192.168.1.50", UserAgent: chromeUserAgent},
		{Id: 42, SessionIdentifier: "row-42", IpAddress: "192.168.1.50", UserAgent: chromeUserAgent},
	}

	t.Run("a later delete fails and the body rolls back", func(t *testing.T) {
		m := newStartSessionMocks(t)
		stub := mocks_data.ExpectRunInTransaction(m.db, txSentinel)
		m.db.On("CreateUserSession", mock.Anything, txSentinel, mock.Anything).Return(nil).Once()
		m.db.On("CreateUserSessionClient", mock.Anything, txSentinel, mock.Anything).Return(nil).Once()
		m.db.On("GetUserSessionsByUserId", mock.Anything, txSentinel, int64(123)).Return(sweep, nil).Once()
		m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(41)).Return(nil).Once()
		m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(42)).Return(dbErr).Once()

		result, removed, err := m.manager.StartNewUserSession(
			httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent),
			123, 7, "pwd", record.AcrLevel1, 0, nil, someCredentialInstant(), "192.168.1.50", nil)

		require.ErrorIs(t, err, dbErr)
		require.ErrorIs(t, stub.BodyErr, dbErr, "the body rolled back")
		assert.Nil(t, result)
		assert.Empty(t, removed, "row 41's deletion was rolled back with the rest")
	})

	t.Run("the commit is refused", func(t *testing.T) {
		m := newStartSessionMocks(t)
		mocks_data.ExpectRunInTransactionThenFail(m.db, txSentinel, dbErr)
		m.db.On("CreateUserSession", mock.Anything, txSentinel, mock.Anything).Return(nil).Once()
		m.db.On("CreateUserSessionClient", mock.Anything, txSentinel, mock.Anything).Return(nil).Once()
		m.db.On("GetUserSessionsByUserId", mock.Anything, txSentinel, int64(123)).Return(sweep, nil).Once()
		m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(41)).Return(nil).Once()
		m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(42)).Return(nil).Once()

		result, removed, err := m.manager.StartNewUserSession(
			httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent),
			123, 7, "pwd", record.AcrLevel1, 0, nil, someCredentialInstant(), "192.168.1.50", nil)

		require.ErrorIs(t, err, dbErr)
		assert.Nil(t, result)
		assert.Empty(t, removed)
	})
}

// The browser session write comes after the commit, so when it fails the swept rows are gone
// whatever the compensation does, and they come back beside the error for the caller to audit
// before it answers. The compensation still deletes only the new row, outside the transaction.
func TestStartNewUserSession_ARotationFailureStillReportsTheCommittedRemovals(t *testing.T) {
	m := newStartSessionMocks(t)
	req := withCookies(newSessionRequest("192.168.1.50:54321", chromeUserAgent), m.seed(nil))
	m.backend.failCreate = true

	m.expectPersistThroughCommit(123, []record.UserSession{
		{Id: 42, SessionIdentifier: "an-older-session", IpAddress: "192.168.1.50", UserAgent: chromeUserAgent},
	})
	m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(42)).Return(nil).Once()
	m.db.On("DeleteUserSession", mock.Anything, (*sql.Tx)(nil), int64(99)).Return(nil).Once()

	result, removed, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), req, 123, 7, "pwd", record.AcrLevel1, 0, nil, someCredentialInstant(), "192.168.1.50", nil)

	require.ErrorIs(t, err, errCreateRefused)
	assert.Nil(t, result)
	assert.Equal(t, []int64{42}, removedIds(removed))
}

// -----------------------------------------------------------------------------
// Failure paths
//
// Every step can fail, and none of them may return a session alongside an error.
// -----------------------------------------------------------------------------

func TestStartNewUserSession_ErrorsPropagate(t *testing.T) {
	dbErr := errors.New("database is down")

	testCases := []struct {
		name string
		// setup registers the case's expectations and returns whatever this case asserts
		// beyond "an error, and no session alongside it", or nil when the strict mocks are
		// the whole of it. A mock built with NewDatabase(t) fails the test on any call the
		// setup did not register, so what a case leaves out it is asserting did not happen.
		// The browser arrives with a pre-sign-in session in every case, as a ceremony's does.
		setup func(m *startSessionMocks) func(t *testing.T)
	}{
		{
			// #198's third window, closed rather than compensated: the browser-session read
			// runs before anything is written, so an unreadable cookie leaves no row behind.
			// The database mock is handed no expectation at all, which is the assertion.
			name: "the browser session cannot be read, and nothing is written",
			setup: func(m *startSessionMocks) func(*testing.T) {
				m.backend.failLoad = true
				return nil
			},
		},
		{
			name: "the transaction cannot be opened",
			setup: func(m *startSessionMocks) func(*testing.T) {
				mocks_data.ExpectRunInTransactionRefused(m.db, dbErr)
				return nil
			},
		},
		{
			name: "CreateUserSession fails",
			setup: func(m *startSessionMocks) func(*testing.T) {
				mocks_data.ExpectRunInTransaction(m.db, txSentinel)
				m.db.On("CreateUserSession", mock.Anything, mock.Anything, mock.Anything).Return(dbErr).Once()
				return nil
			},
		},
		{
			name: "CreateUserSessionClient fails",
			setup: func(m *startSessionMocks) func(*testing.T) {
				mocks_data.ExpectRunInTransaction(m.db, txSentinel)
				m.db.On("CreateUserSession", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything).Return(dbErr).Once()
				return nil
			},
		},
		{
			name: "the commit fails",
			setup: func(m *startSessionMocks) func(*testing.T) {
				mocks_data.ExpectRunInTransactionThenFail(m.db, txSentinel, dbErr)
				m.db.On("CreateUserSession", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("GetUserSessionsByUserId", mock.Anything, txSentinel, int64(123)).Return(nil, nil).Once()
				return nil
			},
		},
		{
			// #198's first window. The read is inside the transaction now, so its failure is
			// handed to RunInTransaction, which rolls the row back; before the fix it ran
			// after the commit and the row stayed. BodyErr is how the rollback is observed,
			// the helper rolling back exactly when the body errs.
			name: "the sibling read fails inside the transaction",
			setup: func(m *startSessionMocks) func(*testing.T) {
				stub := mocks_data.ExpectRunInTransaction(m.db, txSentinel)
				m.db.On("CreateUserSession", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("GetUserSessionsByUserId", mock.Anything, txSentinel, int64(123)).Return(nil, dbErr).Once()
				return func(t *testing.T) {
					assert.ErrorIs(t, stub.BodyErr, dbErr,
						"the body must hand its error to RunInTransaction, which is what rolls the row back")
				}
			},
		},
		{
			// #198's second window, and the same argument one call further in: the sweep is
			// in the transaction, so a delete that fails takes the new row down with it and
			// undoes the siblings it had already deleted.
			name: "a sibling delete fails inside the transaction",
			setup: func(m *startSessionMocks) func(*testing.T) {
				req := newSessionRequest("192.168.1.50:54321", chromeUserAgent)
				stub := mocks_data.ExpectRunInTransaction(m.db, txSentinel)
				m.db.On("CreateUserSession", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("GetUserSessionsByUserId", mock.Anything, txSentinel, int64(123)).Return([]record.UserSession{{
					Id:                42,
					SessionIdentifier: "an-older-session",
					IpAddress:         "192.168.1.50",
					// The new key, so the sweep still reaches the delete that fails here.
					UserAgent: useragent.BoundRaw(req.UserAgent()),
				}}, nil).Once()
				m.db.On("DeleteUserSession", mock.Anything, txSentinel, int64(42)).Return(dbErr).Once()
				return func(t *testing.T) {
					assert.ErrorIs(t, stub.BodyErr, dbErr,
						"the body must hand its error to RunInTransaction, which is what rolls the row back")
				}
			},
		},
		{
			// #198's fourth window, the one that cannot be closed: the commit has happened, so
			// the row is compensated instead. TestStartNewUserSession_DeletesTheRowWhenTheRotationFails
			// owns the detail; here it is the "no session alongside an error" contract.
			name: "the browser session cannot be rotated",
			setup: func(m *startSessionMocks) func(*testing.T) {
				m.expectPersistThroughCommit(123, nil)
				m.backend.failCreate = true
				m.db.On("DeleteUserSession", mock.Anything, (*sql.Tx)(nil), int64(99)).Return(nil).Once()
				return nil
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := newStartSessionMocks(t)
			req := withCookies(newSessionRequest("192.168.1.50:54321", chromeUserAgent), m.seed(nil))
			alsoAssert := tc.setup(m)

			result, removed, err := m.manager.StartNewUserSession(
				httptest.NewRecorder(), req,
				123, 7, "pwd", record.AcrLevel1, 0, nil, someCredentialInstant(), "192.168.1.50", nil)

			assert.Error(t, err)
			assert.Nil(t, result, "no session may be returned alongside an error")
			assert.Empty(t, removed, "no case here swept a row that committed")
			if alsoAssert != nil {
				alsoAssert(t)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// #198: what the manager leaves in the database when a step fails
//
// The four steps that used to run after the commit are now three inside the transaction
// and one after it. The three are owned by TestStartNewUserSession_ErrorsPropagate above,
// which asserts both the rollback and the transaction each call was made on. The fourth,
// the browser-store write, cannot join -- RunInTransaction reruns its body on a deadlock
// and a rerun would write Set-Cookie twice -- so it is compensated, and these are the
// tests for that.
//
// The write is the real store's Regenerate since #431, which the manager's port requires: there
// is no Save arm left to cover, and a failure is reached by arming the backend under the store.
// -----------------------------------------------------------------------------

// The control for the compensation tests below: when the rotation succeeds there is nothing to
// undo, and the strict database mock fails the test on a DeleteUserSession it was not told to
// expect. It is also the rotation itself, read back as the browser would see it: the sign-in's one
// cookie names a new identifier whose session carries the user session and what the browser held
// before, and the cookie the browser arrived with names nothing.
func TestStartNewUserSession_RotatesTheBrowserSessionIdentifierAndKeepsTheRow(t *testing.T) {
	m := newStartSessionMocks(t)
	preSignIn := m.seed(map[string]any{"pre-sign-in": "kept"})
	req := withCookies(newSessionRequest("192.168.1.50:54321", chromeUserAgent), preSignIn)
	rr := httptest.NewRecorder()

	captured := m.expectPersistThroughCommit(123, nil)

	result, _, err := m.manager.StartNewUserSession(
		rr, req, 123, 7, "pwd", record.AcrLevel1, 0, nil, someCredentialInstant(), "192.168.1.50", nil)

	require.NoError(t, err)
	assert.Same(t, *captured, result)

	signedIn := rr.Result().Cookies()
	require.Len(t, signedIn, 1,
		"the identifier is in the session before it is rotated, so the sign-in reaches the browser as one Set-Cookie")
	assert.NotEqual(t, m.identifier(preSignIn[0]), m.identifier(signedIn[0]),
		"the sign-in's cookie names a new browser session identifier")

	sess := m.readBack(signedIn)
	assert.Equal(t, result.SessionIdentifier, sess.Values[sessionkeys.SessionIdentifier])
	assert.Equal(t, "kept", sess.Values["pre-sign-in"], "the rotation keeps what the session held")

	assert.True(t, m.readBack(preSignIn).IsNew, "the pre-sign-in cookie names nothing any more")
}

// #198's fourth window: the transaction committed, the rotation failed, and the row it created is
// deleted rather than left for nobody. The delete carries a nil transaction, which is what says it
// is outside the committed one rather than part of it.
func TestStartNewUserSession_DeletesTheRowWhenTheRotationFails(t *testing.T) {
	m := newStartSessionMocks(t)
	req := withCookies(newSessionRequest("192.168.1.50:54321", chromeUserAgent), m.seed(nil))
	rr := httptest.NewRecorder()
	m.backend.failCreate = true

	m.expectPersistThroughCommit(123, nil)
	m.db.On("DeleteUserSession", mock.Anything, (*sql.Tx)(nil), int64(99)).Return(nil).Once()

	result, _, err := m.manager.StartNewUserSession(
		rr, req, 123, 7, "pwd", record.AcrLevel1, 0, nil, someCredentialInstant(), "192.168.1.50", nil)

	assert.Nil(t, result)
	require.ErrorIs(t, err, errCreateRefused, "the caller must be told why the ceremony failed, not what the cleanup did")
	assert.Contains(t, err.Error(), "unable to rotate the browser session identifier")
	assert.Empty(t, rr.Result().Cookies(), "no cookie names a session the ceremony abandoned")
}

// The compensation runs on a context of its own, because the cancellation that would stop it is
// the same event that causes the failure it is compensating for (#386, final review round 1
// finding 9).
//
// net/http cancels a request's context the moment the client disconnects, and a disconnected
// client is exactly why a browser-store write fails. So the two arrive together: Regenerate
// reports a failure, and the DeleteUserSession that undoes the committed row is handed a context
// that is already done. Before this, that left #198's orphan behind in precisely the case the
// compensation was written for -- and only in that case, which is why every other test in this
// file passed over it.
//
// The backend cancels the request inside Create, where the rotation writes its new row, rather
// than the test doing it up front, because cancelling before the call would stop
// RunInTransaction instead and never reach the window.
func TestStartNewUserSession_DeletesTheRowEvenWhenTheRequestWasCancelled(t *testing.T) {
	m := newStartSessionMocks(t)

	req := withCookies(newSessionRequest("192.168.1.50:54321", chromeUserAgent), m.seed(nil))
	ctx, cancel := context.WithCancel(req.Context())
	req = req.WithContext(ctx)
	m.backend.beforeCreate = cancel
	m.backend.failCreate = true

	m.expectPersistThroughCommit(123, nil)
	m.db.On("DeleteUserSession", aLiveSessionContext(), (*sql.Tx)(nil), int64(99)).Return(nil).Once()

	result, _, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), req,
		123, 7, "pwd", record.AcrLevel1, 0, nil, someCredentialInstant(), "192.168.1.50", nil)

	assert.Nil(t, result)
	assert.ErrorIs(t, err, errCreateRefused, "the caller is still told why the ceremony failed")
	assert.Error(t, ctx.Err(), "the request really was cancelled before the compensation ran")
	m.db.AssertExpectations(t)
}

// aLiveSessionContext matches only a context that is not done, so a compensation issued on the
// cancelled request's context matches nothing and the strict mock reports it.
func aLiveSessionContext() interface{} {
	return mock.MatchedBy(func(ctx context.Context) bool { return ctx.Err() == nil })
}

// The compensation is best effort and can itself fail, which is the one thing this fix cannot
// make impossible. When it does, the original error is still what errors.Is finds -- the caller
// answers for the reason the ceremony failed -- and the cleanup failure rides alongside it
// rather than being dropped, so the record says the row survived.
func TestStartNewUserSession_AFailedCompensationKeepsTheOriginalError(t *testing.T) {
	m := newStartSessionMocks(t)
	deleteErr := errors.New("database is down")
	m.backend.failCreate = true

	m.expectPersistThroughCommit(123, nil)
	m.db.On("DeleteUserSession", mock.Anything, (*sql.Tx)(nil), int64(99)).Return(deleteErr).Once()

	result, _, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent),
		123, 7, "pwd", record.AcrLevel1, 0, nil, someCredentialInstant(), "192.168.1.50", nil)

	assert.Nil(t, result)
	require.ErrorIs(t, err, errCreateRefused, "the original failure must survive a failed cleanup")
	assert.ErrorIs(t, err, deleteErr, "the cleanup failure must not be dropped")
	assert.Contains(t, err.Error(), "unable to delete the user session left behind by a failed browser session write")
}

// A failure to read the browser session is wrapped with context, since the store's error alone
// is hard to place.
//
// #198 moved this read above the transaction, so the database is handed no expectation here
// either: the read is the first thing the manager does, and a mock built with NewDatabase(t)
// fails on any call at all. The refusal therefore costs no row, where before the fix it came
// after one had been committed.
func TestStartNewUserSession_WrapsSessionStoreReadError(t *testing.T) {
	m := newStartSessionMocks(t)
	req := withCookies(newSessionRequest("192.168.1.50:54321", chromeUserAgent), m.seed(nil))
	m.backend.failLoad = true

	_, _, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), req,
		123, 7, "pwd", record.AcrLevel1, 0, nil, someCredentialInstant(), "192.168.1.50", nil)

	require.ErrorIs(t, err, errLoadRefused)
	assert.Contains(t, err.Error(), "unable to get the session")
}

// =============================================================================
// Tests for NewManager
// =============================================================================

func TestNewManager_StoresItsDependencies(t *testing.T) {
	m := newStartSessionMocks(t)

	manager := NewManager(m.store, "some-session", m.db)

	assert.NotNil(t, manager)
	assert.Same(t, m.db, manager.database)
	assert.Same(t, m.store, manager.sessionStore)
	assert.Equal(t, "some-session", manager.sessionName)

	// The constructor's clock is the wall clock in UTC.
	require.NotNil(t, manager.now)
	before := time.Now().UTC()
	got := manager.now()
	assert.Equal(t, time.UTC, got.Location())
	assert.False(t, got.Before(before))
}

// TestStartNewUserSession_StampsAuthStateGeneration is the session row of #106's
// persisted-state stamping table (finding 28). It asserts the generation written onto the
// model handed to CreateUserSession.
//
// The value comes from the AuthContext, which captured it when the ceremony authenticated,
// and NOT from the user's current value. A ceremony that began before a credential change
// must therefore produce a session on the superseded generation, which is then rejected,
// rather than one silently carried past the boundary that change established.
//
// 7 is deliberately nonzero: written with 0 this test would coincide with the column
// default and pass even if the assignment were missing entirely.
func TestStartNewUserSession_StampsAuthStateGeneration(t *testing.T) {
	m := newStartSessionMocks(t)
	captured := m.expectPersistThroughCommit(123, nil)

	_, _, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent),
		123, 7, "pwd", record.AcrLevel1, 7, nil, someCredentialInstant(), "192.168.1.50", nil)

	assert.NoError(t, err)
	if assert.NotNil(t, *captured, "CreateUserSession was never called") {
		assert.EqualValues(t, 7, (*captured).AuthStateGeneration,
			"the session must carry the generation the ceremony authenticated under")
	}
}

// A brand new session carries the OTP configuration generation the ceremony observed when it
// answered the level 2 question, not the user's current value and not zero. Promoting it here
// rather than later is what stops the session owing a re-prompt on the very next request
// (#242 decision 3).
//
// 9 rather than a small number, and different from the auth state generation above, so the
// two parameters cannot be confused with each other or with a zero default.
func TestStartNewUserSession_StampsOtpConfigGeneration(t *testing.T) {
	m := newStartSessionMocks(t)
	captured := m.expectPersistThroughCommit(123, nil)

	observed := int64(9)
	_, _, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent),
		123, 7, "pwd", record.AcrLevel1, 7, &observed, someCredentialInstant(), "192.168.1.50", nil)

	assert.NoError(t, err)
	if assert.NotNil(t, *captured, "CreateUserSession was never called") {
		assert.EqualValues(t, 9, (*captured).OtpConfigGeneration,
			"the session must carry the OTP configuration generation the ceremony answered against")
		assert.EqualValues(t, 7, (*captured).AuthStateGeneration,
			"the two generations must not be crossed")
	}
}

// A nil capture is what a ceremony written by an older binary produces, and it lands at 0.
// That is deliberately the fail-closed direction: a user whose counter has already moved above
// 0 owes a level 2 re-prompt on this brand new session, which costs one prompt, where the
// alternative of reading the counter live here would silently satisfy an obligation the
// ceremony never addressed.
func TestStartNewUserSession_NilOtpConfigGenerationLandsAtZero(t *testing.T) {
	m := newStartSessionMocks(t)
	captured := m.expectPersistThroughCommit(123, nil)

	_, _, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent),
		123, 7, "pwd", record.AcrLevel1, 7, nil, someCredentialInstant(), "192.168.1.50", nil)

	assert.NoError(t, err)
	if assert.NotNil(t, *captured, "CreateUserSession was never called") {
		assert.EqualValues(t, 0, (*captured).OtpConfigGeneration)
	}
}

// -----------------------------------------------------------------------------
// AuthTime: the credential's instant, not this function's clock (#252 decision 8)
// -----------------------------------------------------------------------------

// AuthTime is the auth_time claim, and OIDC Core 3.1.2.1 makes it max_age's reference point:
// "the allowable elapsed time in seconds since the last time the End-User was actively
// authenticated by the OP". The credential is accepted at /auth/pwd or /auth/otp and the
// session is created two hops later at /auth/completed, with the browser driving the gap, so
// the two instants are the same only when nobody pauses.
//
// 90 minutes is well past any max_age a relying party would send and far outside the window a
// clock read inside the call could land in, so the assertion cannot pass by coincidence.
// Started and LastAccessed must stay on now: they measure the session's own life, and pulling
// them back would shorten it against the idle timeout and the max lifetime.
func TestStartNewUserSession_AuthTimeIsTheCapturedCredentialInstant(t *testing.T) {
	m := newStartSessionMocks(t)
	captured := m.expectPersistThroughCommit(123, nil)

	credentialAcceptedAt := time.Now().UTC().Add(-90 * time.Minute)

	before := time.Now().UTC()
	result, _, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent),
		123, 7, "pwd", record.AcrLevel1, 7, nil, &credentialAcceptedAt, "192.168.1.50", nil)
	after := time.Now().UTC()

	assert.NoError(t, err)
	if assert.NotNil(t, *captured, "CreateUserSession was never called") {
		assert.True(t, (*captured).AuthTime.Equal(credentialAcceptedAt),
			"the persisted AuthTime must be the captured credential instant, got %v want %v",
			(*captured).AuthTime, credentialAcceptedAt)
	}
	assert.True(t, result.AuthTime.Equal(credentialAcceptedAt),
		"the returned session must carry it too: /auth/completed reads AuthTime back off this "+
			"row and puts it on the AuthContext, which is what the code and then the token sign")

	assert.False(t, result.Started.Before(before), "Started must stay on now")
	assert.False(t, result.Started.After(after), "Started must stay on now")
	assert.Equal(t, result.Started, result.LastAccessed)
	assert.True(t, result.AuthTime.Before(result.Started),
		"a paused ceremony produces an AuthTime older than the session it creates")
}

// A non-UTC capture is normalised rather than stored as it arrives. Nothing in the ceremony
// produces one today (both credential handlers capture time.Now().UTC()), but the column is
// read back and compared against UTC values by every session view, and a location riding along
// on the model is the kind of thing that survives until a formatter prints the wrong hour.
func TestStartNewUserSession_AuthTimeIsNormalisedToUTC(t *testing.T) {
	m := newStartSessionMocks(t)
	captured := m.expectPersistThroughCommit(123, nil)

	zone := time.FixedZone("UTC+7", 7*60*60)
	credentialAcceptedAt := time.Now().In(zone).Add(-30 * time.Minute)

	_, _, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent),
		123, 7, "pwd", record.AcrLevel1, 7, nil, &credentialAcceptedAt, "192.168.1.50", nil)

	assert.NoError(t, err)
	if assert.NotNil(t, *captured, "CreateUserSession was never called") {
		assert.Equal(t, time.UTC, (*captured).AuthTime.Location(),
			"AuthTime must be stored in UTC, like Started and LastAccessed")
		assert.True(t, (*captured).AuthTime.Equal(credentialAcceptedAt),
			"normalising the location must not move the instant")
	}
}

// Nil and zero both mean "this call captured no credential instant", and there is nothing true
// to write into AuthTime, so the call is refused before anything is touched: no transaction, no
// row, no cookie. Falling back to now here would recreate the exact defect #252 decision 8
// removed, one broken caller away -- a session claiming the user authenticated at the moment
// the redirect landed, whoever was holding the browser. The one production caller cannot reach
// this branch: /auth/completed refuses to mint a session without Level1AuthCompleted, and the
// password handler that sets it sets AuthenticatedAt beside it. The refusal is what turns that
// invariant from an argument in a comment into a check that fails closed.
func TestStartNewUserSession_RefusesAMissingCredentialInstant(t *testing.T) {
	var zeroTime time.Time
	for name, capture := range map[string]*time.Time{
		"nil":  nil,
		"zero": &zeroTime,
	} {
		t.Run(name, func(t *testing.T) {
			m := newStartSessionMocks(t)
			recorder := httptest.NewRecorder()
			// The browser brings a session, so a read of it would reach the backend: without
			// one the store answers a fresh session without consulting anything, and the
			// counts below would be zero whatever the manager did.
			req := withCookies(newSessionRequest("192.168.1.50:54321", chromeUserAgent), m.seed(nil))
			loads, creates := m.backend.loads, m.backend.creates

			result, _, err := m.manager.StartNewUserSession(
				recorder, req,
				123, 7, "pwd", record.AcrLevel1, 7, nil, capture, "192.168.1.50", nil)

			require.ErrorContains(t, err, "no credential instant captured")
			assert.Nil(t, result, "a refused call must hand back no session")

			// Nothing may have been written on either side of the refusal: the argument
			// counts below match each method's arity, because AssertNotCalled compares the
			// whole argument list and a wrong count would match nothing and assert nothing.
			m.db.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
			m.db.AssertNotCalled(t, "CreateUserSession", mock.Anything, mock.Anything, mock.Anything)
			m.db.AssertNotCalled(t, "CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything)
			m.db.AssertNotCalled(t, "GetUserSessionsByUserId", mock.Anything, mock.Anything, mock.Anything)
			m.db.AssertNotCalled(t, "DeleteUserSession", mock.Anything, mock.Anything, mock.Anything)
			assert.Equal(t, loads, m.backend.loads, "the browser session is not even read")
			assert.Equal(t, creates, m.backend.creates, "nor written")
			assert.Empty(t, recorder.Header().Values("Set-Cookie"),
				"no cookie may be written for a session that was never created")
		})
	}
}
