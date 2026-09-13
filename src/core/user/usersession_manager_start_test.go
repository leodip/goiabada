package user

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"errors"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/useragent"
	"github.com/leodip/goiabada/core/uuidutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
)

// =============================================================================
// Tests for StartNewUserSession
//
// This is what creates the SSO session row and writes its identifier into the
// browser cookie after a successful login. Everything downstream (idle timeout,
// max lifetime, ACR step-up) reads the fields it sets here.
// =============================================================================

const testSessionName = "test-session"

// chromeUserAgent is a desktop UA string, so the device fields are populated
// rather than empty.
const chromeUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// firefoxUserAgent is the second device of the sweep table: a different browser on a different OS,
// so the raw header differs from chromeUserAgent well before its end.
const firefoxUserAgent = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"

type startSessionMocks struct {
	db      *mocks_data.Database
	store   *mocks_sessionstore.Store
	manager *UserSessionManager
	session *sessionstore.Session
}

func newStartSessionMocks(t *testing.T) *startSessionMocks {
	t.Helper()
	db := mocks_data.NewDatabase(t)
	store := mocks_sessionstore.NewStore(t)
	return &startSessionMocks{
		db:    db,
		store: store,
		manager: &UserSessionManager{
			database:     db,
			sessionStore: store,
			sessionName:  testSessionName,
		},
		session: sessionstore.NewSession(store, testSessionName),
	}
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

// expectSuccessfulPersist sets up the full happy-path call sequence. The
// returned pointer receives the session that was handed to CreateUserSession.
func (m *startSessionMocks) expectSuccessfulPersist(userId int64, existingSessions []models.UserSession) **models.UserSession {
	captured := new(*models.UserSession)

	expectRunInTransaction(m.db, nil)
	m.db.On("CreateUserSession", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		created := args.Get(1).(*models.UserSession)
		created.Id = 99 // stand in for the generated primary key
		*captured = created
	}).Return(nil).Once()
	m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil).Once()
	m.db.On("GetUserSessionsByUserId", mock.Anything, userId).Return(existingSessions, nil).Once()
	m.store.On("Get", mock.Anything, testSessionName).Return(m.session, nil).Once()
	m.store.On("Save", mock.Anything, mock.Anything, m.session).Return(nil).Once()

	return captured
}

func TestStartNewUserSession_PopulatesSessionFields(t *testing.T) {
	m := newStartSessionMocks(t)
	req := newSessionRequest("192.168.1.50:54321", chromeUserAgent)
	recorder := httptest.NewRecorder()

	captured := m.expectSuccessfulPersist(123, nil)
	credentialAcceptedAt := someCredentialInstant()

	before := time.Now().UTC()
	result, err := m.manager.StartNewUserSession(recorder, req, 123, 7, "pwd otp", enums.AcrLevel2Mandatory.String(), 0, nil, credentialAcceptedAt)
	after := time.Now().UTC()

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Same(t, *captured, result, "the persisted session must be the one returned")

	assert.Equal(t, int64(123), result.UserId)
	assert.Equal(t, "pwd otp", result.AuthMethods)
	assert.Equal(t, enums.AcrLevel2Mandatory.String(), result.AcrLevel)
	assert.Equal(t, "192.168.1.50", result.IpAddress, "the port must be stripped from RemoteAddr")

	// The identifier must be a fresh UUID, since it is what the browser cookie
	// carries and what every later lookup keys on.
	parsed, parseErr := uuidutil.Parse(result.SessionIdentifier)
	assert.NoError(t, parseErr, "the session identifier must be a valid UUID")
	// uuidutil.Parse accepts the nil UUID, so "non-empty" would pass against a hard-coded
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

// The header reaches the row through useragent.Bound, so a browser sending more than the column
// holds cannot make the insert fail. 600 bytes rather than 513, so a cut at the wrong width shows
// up in the assertion rather than being off by one.
func TestStartNewUserSession_BoundsTheUserAgentToTheColumnWidth(t *testing.T) {
	m := newStartSessionMocks(t)
	overlong := strings.Repeat("a", 600)
	req := newSessionRequest("192.168.1.50:54321", overlong)

	captured := m.expectSuccessfulPersist(123, nil)

	result, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), req, 123, 7, "pwd", enums.AcrLevel1.String(), 0, nil, someCredentialInstant())

	assert.NoError(t, err)
	assert.Same(t, *captured, result)
	assert.Len(t, result.UserAgent, 512, "the persisted header must be cut to the column width")
	assert.True(t, strings.HasPrefix(overlong, result.UserAgent),
		"the cut must keep the start of the header the browser sent, not rewrite it")
}

func TestStartNewUserSession_RecordsTheClient(t *testing.T) {
	m := newStartSessionMocks(t)
	req := newSessionRequest("10.0.0.1:1234", chromeUserAgent)

	var capturedClient *models.UserSessionClient
	expectRunInTransaction(m.db, nil)
	m.db.On("CreateUserSession", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		args.Get(1).(*models.UserSession).Id = 99
	}).Return(nil).Once()
	m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		capturedClient = args.Get(1).(*models.UserSessionClient)
	}).Return(nil).Once()
	m.db.On("GetUserSessionsByUserId", mock.Anything, int64(123)).Return(nil, nil).Once()
	m.store.On("Get", mock.Anything, testSessionName).Return(m.session, nil).Once()
	m.store.On("Save", mock.Anything, mock.Anything, m.session).Return(nil).Once()

	result, err := m.manager.StartNewUserSession(httptest.NewRecorder(), req, 123, 7, "pwd", enums.AcrLevel1.String(), 0, nil, someCredentialInstant())

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

// The session identifier is written into the cookie session, which is how the
// browser is tied back to the database row.
func TestStartNewUserSession_WritesIdentifierIntoTheCookieSession(t *testing.T) {
	m := newStartSessionMocks(t)
	req := newSessionRequest("10.0.0.1:1234", chromeUserAgent)

	m.expectSuccessfulPersist(123, nil)

	result, err := m.manager.StartNewUserSession(httptest.NewRecorder(), req, 123, 7, "pwd", enums.AcrLevel1.String(), 0, nil, someCredentialInstant())

	assert.NoError(t, err)
	assert.Equal(t, result.SessionIdentifier, m.session.Values[constants.SessionKeySessionIdentifier])
}

// -----------------------------------------------------------------------------
// IP address extraction
// -----------------------------------------------------------------------------

func TestStartNewUserSession_IpAddressExtraction(t *testing.T) {
	testCases := []struct {
		name       string
		remoteAddr string
		wantIp     string
	}{
		{"ipv4 with port", "192.168.1.50:54321", "192.168.1.50"},
		{"ipv4 without port falls back to the whole value", "192.168.1.50", "192.168.1.50"},
		{"ipv6 with port", "[2001:db8::1]:8080", "2001:db8::1"},
		{"ipv6 loopback with port", "[::1]:8080", "::1"},
		{"bare ipv6 falls back to the whole value", "::1", "::1"},
		{"localhost with port", "127.0.0.1:9999", "127.0.0.1"},
		{"hostname with port", "some-host:443", "some-host"},
		{"empty remote address", "", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := newStartSessionMocks(t)
			req := newSessionRequest(tc.remoteAddr, chromeUserAgent)

			m.expectSuccessfulPersist(123, nil)

			result, err := m.manager.StartNewUserSession(
				httptest.NewRecorder(), req, 123, 7, "pwd", enums.AcrLevel1.String(), 0, nil, someCredentialInstant())

			assert.NoError(t, err)
			assert.Equal(t, tc.wantIp, result.IpAddress)
		})
	}
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

	stale := models.UserSession{
		Id:                42,
		SessionIdentifier: "an-older-session",
		IpAddress:         "192.168.1.50",
		UserAgent:         chromeUserAgent,
	}

	m.expectSuccessfulPersist(123, []models.UserSession{stale})
	m.db.On("DeleteUserSession", mock.Anything, int64(42)).Return(nil).Once()

	_, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), req, 123, 7, "pwd", enums.AcrLevel1.String(), 0, nil, someCredentialInstant())

	assert.NoError(t, err)
}

// The reversal, and the whole of decision 1: a row whose three labels disagree with the request on
// every one of them is still the same device when the raw header and the address match, so it is
// deleted. Under the pre-#281 key this session survived, because the sweep compared the labels.
func TestStartNewUserSession_DeletesAMatchingHeaderWhoseLabelsDiffer(t *testing.T) {
	m := newStartSessionMocks(t)
	req := newSessionRequest("192.168.1.50:54321", chromeUserAgent)

	stale := models.UserSession{
		Id:                42,
		SessionIdentifier: "an-older-session",
		IpAddress:         "192.168.1.50",
		UserAgent:         chromeUserAgent, // the header the request sends, so the device matches
		DeviceName:        "Some Other Browser",
		DeviceType:        "Mobile",
		DeviceOS:          "Linux",
	}

	m.expectSuccessfulPersist(123, []models.UserSession{stale})
	m.db.On("DeleteUserSession", mock.Anything, int64(42)).Return(nil).Once()

	_, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), req, 123, 7, "pwd", enums.AcrLevel1.String(), 0, nil, someCredentialInstant())

	assert.NoError(t, err)
}

// Decision 7, the half that sweeps rather than the half that keeps: a header-less client matches a
// pre-upgrade row on the same address, because both read as the empty string, and the older session
// is swept exactly as it would have been before the upgrade.
func TestStartNewUserSession_AnEmptyHeaderMatchesAnEmptyHeader(t *testing.T) {
	m := newStartSessionMocks(t)
	req := newSessionRequest("192.168.1.50:54321", "")
	req.Header.Del("User-Agent")

	stale := models.UserSession{
		Id:                42,
		SessionIdentifier: "a-legacy-session",
		IpAddress:         "192.168.1.50",
		UserAgent:         "",
	}

	m.expectSuccessfulPersist(123, []models.UserSession{stale})
	m.db.On("DeleteUserSession", mock.Anything, int64(42)).Return(nil).Once()

	_, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), req, 123, 7, "pwd", enums.AcrLevel1.String(), 0, nil, someCredentialInstant())

	assert.NoError(t, err)
}

// Anything that differs in device or IP is a separate login and must survive.
// NewDatabase(t) fails on an unexpected DeleteUserSession, which is the assertion.
func TestStartNewUserSession_KeepsSessionsFromOtherDevicesOrIps(t *testing.T) {
	// Every case below is compared against a request sending chromeUserAgent from 192.168.1.50.
	testCases := []struct {
		name    string
		session models.UserSession
	}{
		{
			name: "same header, other ip",
			session: models.UserSession{
				Id: 42, SessionIdentifier: "other", IpAddress: "10.0.0.9",
				UserAgent: chromeUserAgent,
			},
		},
		{
			name: "other header, same ip",
			session: models.UserSession{
				Id: 42, SessionIdentifier: "other", IpAddress: "192.168.1.50",
				UserAgent: firefoxUserAgent,
			},
		},
		{
			// Decision 7: a pre-upgrade row carries no header and there is nothing to backfill
			// it from, so a login that sends one does not sweep it. It expires on its own.
			name: "a legacy row with no header, against a request that sends one",
			session: models.UserSession{
				Id: 42, SessionIdentifier: "legacy", IpAddress: "192.168.1.50",
				UserAgent: "",
			},
		},
		{
			// The labels are display only from here, so matching on all three is not matching.
			name: "the three labels match but the header does not",
			session: models.UserSession{
				Id: 42, SessionIdentifier: "other", IpAddress: "192.168.1.50",
				UserAgent:  firefoxUserAgent,
				DeviceName: "Chrome 120.0.0.0", DeviceType: "Desktop", DeviceOS: "Windows 10.0",
			},
		},
		{
			// Exact-version equality is stricter than the old key, never looser: two builds of
			// one browser are two devices, where the old labels collapsed them into one.
			name: "the same browser at a different build",
			session: models.UserSession{
				Id: 42, SessionIdentifier: "other", IpAddress: "192.168.1.50",
				UserAgent: strings.Replace(chromeUserAgent, "Chrome/120.0.0.0", "Chrome/121.0.0.0", 1),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := newStartSessionMocks(t)
			m.expectSuccessfulPersist(123, []models.UserSession{tc.session})

			_, err := m.manager.StartNewUserSession(
				httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent),
				123, 7, "pwd", enums.AcrLevel1.String(), 0, nil, someCredentialInstant())

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
	expectRunInTransaction(m.db, nil)
	m.db.On("CreateUserSession", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		created := args.Get(1).(*models.UserSession)
		created.Id = 99
		newIdentifier = created.SessionIdentifier
	}).Return(nil).Once()
	m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil).Once()
	// Return the freshly created session as if it were already persisted. The
	// identifier is only known once CreateUserSession has run, so this is
	// resolved lazily at call time.
	m.db.On("GetUserSessionsByUserId", mock.Anything, int64(123)).Return(
		func(_ *sql.Tx, _ int64) ([]models.UserSession, error) {
			return []models.UserSession{{
				Id:                99,
				SessionIdentifier: newIdentifier,
				IpAddress:         "192.168.1.50",
				// The new key, so this row reaches the self-identifier guard rather than
				// being skipped by a mismatch and passing vacuously.
				UserAgent: useragent.Raw(req),
			}}, nil
		}).Once()
	m.store.On("Get", mock.Anything, testSessionName).Return(m.session, nil).Once()
	m.store.On("Save", mock.Anything, mock.Anything, m.session).Return(nil).Once()

	_, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), req, 123, 7, "pwd", enums.AcrLevel1.String(), 0, nil, someCredentialInstant())

	assert.NoError(t, err)
}

// -----------------------------------------------------------------------------
// Failure paths
//
// Every step can fail, and none of them may return a session alongside an error.
// -----------------------------------------------------------------------------

func TestStartNewUserSession_ErrorsPropagate(t *testing.T) {
	dbErr := errors.New("database is down")

	testCases := []struct {
		name  string
		setup func(m *startSessionMocks)
	}{
		{
			name: "the transaction cannot be opened",
			setup: func(m *startSessionMocks) {
				expectRunInTransactionRefused(m.db, dbErr)
			},
		},
		{
			name: "CreateUserSession fails",
			setup: func(m *startSessionMocks) {
				expectRunInTransaction(m.db, nil)
				m.db.On("CreateUserSession", mock.Anything, mock.Anything).Return(dbErr).Once()
			},
		},
		{
			name: "CreateUserSessionClient fails",
			setup: func(m *startSessionMocks) {
				expectRunInTransaction(m.db, nil)
				m.db.On("CreateUserSession", mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(dbErr).Once()
			},
		},
		{
			name: "the commit fails",
			setup: func(m *startSessionMocks) {
				expectRunInTransactionThenFail(m.db, nil, dbErr)
				m.db.On("CreateUserSession", mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil).Once()
			},
		},
		{
			name: "GetUserSessionsByUserId fails",
			setup: func(m *startSessionMocks) {
				expectRunInTransaction(m.db, nil)
				m.db.On("CreateUserSession", mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("GetUserSessionsByUserId", mock.Anything, int64(123)).Return(nil, dbErr).Once()
			},
		},
		{
			name: "DeleteUserSession fails",
			setup: func(m *startSessionMocks) {
				req := newSessionRequest("192.168.1.50:54321", chromeUserAgent)
				expectRunInTransaction(m.db, nil)
				m.db.On("CreateUserSession", mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("GetUserSessionsByUserId", mock.Anything, int64(123)).Return([]models.UserSession{{
					Id:                42,
					SessionIdentifier: "an-older-session",
					IpAddress:         "192.168.1.50",
					// The new key, so the sweep still reaches the delete that fails here.
					UserAgent: useragent.Raw(req),
				}}, nil).Once()
				m.db.On("DeleteUserSession", mock.Anything, int64(42)).Return(dbErr).Once()
			},
		},
		{
			name: "the session store cannot be read",
			setup: func(m *startSessionMocks) {
				expectRunInTransaction(m.db, nil)
				m.db.On("CreateUserSession", mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("GetUserSessionsByUserId", mock.Anything, int64(123)).Return(nil, nil).Once()
				m.store.On("Get", mock.Anything, testSessionName).Return(nil, errors.New("cookie is corrupt")).Once()
			},
		},
		{
			name: "the session store cannot be saved",
			setup: func(m *startSessionMocks) {
				expectRunInTransaction(m.db, nil)
				m.db.On("CreateUserSession", mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("GetUserSessionsByUserId", mock.Anything, int64(123)).Return(nil, nil).Once()
				m.store.On("Get", mock.Anything, testSessionName).Return(m.session, nil).Once()
				m.store.On("Save", mock.Anything, mock.Anything, m.session).Return(errors.New("cannot write cookie")).Once()
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := newStartSessionMocks(t)
			tc.setup(m)

			result, err := m.manager.StartNewUserSession(
				httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent),
				123, 7, "pwd", enums.AcrLevel1.String(), 0, nil, someCredentialInstant())

			assert.Error(t, err)
			assert.Nil(t, result, "no session may be returned alongside an error")
		})
	}
}

// A failure to read the cookie session is wrapped with context, since the raw
// gorilla error alone is hard to place.
func TestStartNewUserSession_WrapsSessionStoreReadError(t *testing.T) {
	m := newStartSessionMocks(t)

	expectRunInTransaction(m.db, nil)
	m.db.On("CreateUserSession", mock.Anything, mock.Anything).Return(nil).Once()
	m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil).Once()
	m.db.On("GetUserSessionsByUserId", mock.Anything, int64(123)).Return(nil, nil).Once()
	m.store.On("Get", mock.Anything, testSessionName).Return(nil, errors.New("cookie is corrupt")).Once()

	_, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent),
		123, 7, "pwd", enums.AcrLevel1.String(), 0, nil, someCredentialInstant())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to get the session")
	assert.Contains(t, err.Error(), "cookie is corrupt")
}

// =============================================================================
// Tests for NewUserSessionManager
// =============================================================================

func TestNewUserSessionManager_StoresItsDependencies(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	store := mocks_sessionstore.NewStore(t)

	manager := NewUserSessionManager(store, "some-session", db)

	assert.NotNil(t, manager)
	assert.Same(t, db, manager.database)
	assert.Same(t, store, manager.sessionStore)
	assert.Equal(t, "some-session", manager.sessionName)
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
	captured := m.expectSuccessfulPersist(123, nil)

	_, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent),
		123, 7, "pwd", enums.AcrLevel1.String(), 7, nil, someCredentialInstant())

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
	captured := m.expectSuccessfulPersist(123, nil)

	observed := int64(9)
	_, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent),
		123, 7, "pwd", enums.AcrLevel1.String(), 7, &observed, someCredentialInstant())

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
	captured := m.expectSuccessfulPersist(123, nil)

	_, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent),
		123, 7, "pwd", enums.AcrLevel1.String(), 7, nil, someCredentialInstant())

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
	captured := m.expectSuccessfulPersist(123, nil)

	credentialAcceptedAt := time.Now().UTC().Add(-90 * time.Minute)

	before := time.Now().UTC()
	result, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent),
		123, 7, "pwd", enums.AcrLevel1.String(), 7, nil, &credentialAcceptedAt)
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
	captured := m.expectSuccessfulPersist(123, nil)

	zone := time.FixedZone("UTC+7", 7*60*60)
	credentialAcceptedAt := time.Now().In(zone).Add(-30 * time.Minute)

	_, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent),
		123, 7, "pwd", enums.AcrLevel1.String(), 7, nil, &credentialAcceptedAt)

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

			result, err := m.manager.StartNewUserSession(
				recorder, newSessionRequest("192.168.1.50:54321", chromeUserAgent),
				123, 7, "pwd", enums.AcrLevel1.String(), 7, nil, capture)

			require.ErrorContains(t, err, "no credential instant captured")
			assert.Nil(t, result, "a refused call must hand back no session")

			// Nothing may have been written on either side of the refusal: the argument
			// counts below match each method's arity, because AssertNotCalled compares the
			// whole argument list and a wrong count would match nothing and assert nothing.
			m.db.AssertNotCalled(t, "RunInTransaction", mock.Anything)
			m.db.AssertNotCalled(t, "CreateUserSession", mock.Anything, mock.Anything)
			m.db.AssertNotCalled(t, "CreateUserSessionClient", mock.Anything, mock.Anything)
			m.db.AssertNotCalled(t, "GetUserSessionsByUserId", mock.Anything, mock.Anything)
			m.db.AssertNotCalled(t, "DeleteUserSession", mock.Anything, mock.Anything)
			m.store.AssertNotCalled(t, "Get", mock.Anything, mock.Anything)
			m.store.AssertNotCalled(t, "Save", mock.Anything, mock.Anything, mock.Anything)
			assert.Empty(t, recorder.Header().Values("Set-Cookie"),
				"no cookie may be written for a session that was never created")
		})
	}
}
