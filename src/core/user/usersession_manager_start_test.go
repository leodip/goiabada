package user

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/useragent"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

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

type startSessionMocks struct {
	db      *mocks_data.Database
	store   *mocks_sessionstore.Store
	manager *UserSessionManager
	session *sessions.Session
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
		session: sessions.NewSession(store, testSessionName),
	}
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

	m.db.On("BeginTransaction").Return(nil, nil).Once()
	m.db.On("CreateUserSession", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		created := args.Get(1).(*models.UserSession)
		created.Id = 99 // stand in for the generated primary key
		*captured = created
	}).Return(nil).Once()
	m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil).Once()
	m.db.On("CommitTransaction", mock.Anything).Return(nil).Once()
	// The deferred rollback runs even after a successful commit.
	m.db.On("RollbackTransaction", mock.Anything).Return(nil).Once()
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

	before := time.Now().UTC()
	result, err := m.manager.StartNewUserSession(recorder, req, 123, 7, "pwd otp", enums.AcrLevel2Mandatory.String(), 0, nil)
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
	parsed, parseErr := uuid.Parse(result.SessionIdentifier)
	assert.NoError(t, parseErr, "the session identifier must be a valid UUID")
	assert.NotEqual(t, uuid.Nil, parsed)

	// Started, LastAccessed and AuthTime are all stamped with the same UTC now.
	for name, value := range map[string]time.Time{
		"Started":      result.Started,
		"LastAccessed": result.LastAccessed,
		"AuthTime":     result.AuthTime,
	} {
		assert.False(t, value.Before(before), "%s must not predate the call", name)
		assert.False(t, value.After(after), "%s must not postdate the call", name)
		assert.Equal(t, time.UTC, value.Location(), "%s must be stored in UTC", name)
	}
	assert.Equal(t, result.Started, result.LastAccessed)
	assert.Equal(t, result.Started, result.AuthTime)

	assert.EqualValues(t, 0, result.OtpConfigGeneration,
		"a nil capture must land the session at generation 0, which is the fail-closed value: "+
			"it owes a level 2 re-prompt as soon as the user's counter is above 0")

	// Device fields come from the User-Agent.
	assert.Equal(t, useragent.GetDeviceName(req), result.DeviceName)
	assert.Equal(t, useragent.GetDeviceType(req), result.DeviceType)
	assert.Equal(t, useragent.GetDeviceOS(req), result.DeviceOS)
	assert.NotEmpty(t, result.DeviceName)
}

func TestStartNewUserSession_RecordsTheClient(t *testing.T) {
	m := newStartSessionMocks(t)
	req := newSessionRequest("10.0.0.1:1234", chromeUserAgent)

	var capturedClient *models.UserSessionClient
	m.db.On("BeginTransaction").Return(nil, nil).Once()
	m.db.On("CreateUserSession", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		args.Get(1).(*models.UserSession).Id = 99
	}).Return(nil).Once()
	m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		capturedClient = args.Get(1).(*models.UserSessionClient)
	}).Return(nil).Once()
	m.db.On("CommitTransaction", mock.Anything).Return(nil).Once()
	m.db.On("RollbackTransaction", mock.Anything).Return(nil).Once()
	m.db.On("GetUserSessionsByUserId", mock.Anything, int64(123)).Return(nil, nil).Once()
	m.store.On("Get", mock.Anything, testSessionName).Return(m.session, nil).Once()
	m.store.On("Save", mock.Anything, mock.Anything, m.session).Return(nil).Once()

	result, err := m.manager.StartNewUserSession(httptest.NewRecorder(), req, 123, 7, "pwd", enums.AcrLevel1.String(), 0, nil)

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

	result, err := m.manager.StartNewUserSession(httptest.NewRecorder(), req, 123, 7, "pwd", enums.AcrLevel1.String(), 0, nil)

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
				httptest.NewRecorder(), req, 123, 7, "pwd", enums.AcrLevel1.String(), 0, nil)

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
		DeviceName:        useragent.GetDeviceName(req),
		DeviceType:        useragent.GetDeviceType(req),
		DeviceOS:          useragent.GetDeviceOS(req),
	}

	m.expectSuccessfulPersist(123, []models.UserSession{stale})
	m.db.On("DeleteUserSession", mock.Anything, int64(42)).Return(nil).Once()

	_, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), req, 123, 7, "pwd", enums.AcrLevel1.String(), 0, nil)

	assert.NoError(t, err)
}

// Anything that differs in device or IP is a separate login and must survive.
// NewDatabase(t) fails on an unexpected DeleteUserSession, which is the assertion.
func TestStartNewUserSession_KeepsSessionsFromOtherDevicesOrIps(t *testing.T) {
	req := newSessionRequest("192.168.1.50:54321", chromeUserAgent)
	matchingName := useragent.GetDeviceName(req)
	matchingType := useragent.GetDeviceType(req)
	matchingOS := useragent.GetDeviceOS(req)

	testCases := []struct {
		name    string
		session models.UserSession
	}{
		{
			name: "different ip",
			session: models.UserSession{
				Id: 42, SessionIdentifier: "other", IpAddress: "10.0.0.9",
				DeviceName: matchingName, DeviceType: matchingType, DeviceOS: matchingOS,
			},
		},
		{
			name: "different device name",
			session: models.UserSession{
				Id: 42, SessionIdentifier: "other", IpAddress: "192.168.1.50",
				DeviceName: "Some Other Browser", DeviceType: matchingType, DeviceOS: matchingOS,
			},
		},
		{
			name: "different device type",
			session: models.UserSession{
				Id: 42, SessionIdentifier: "other", IpAddress: "192.168.1.50",
				DeviceName: matchingName, DeviceType: "Mobile", DeviceOS: matchingOS,
			},
		},
		{
			name: "different device os",
			session: models.UserSession{
				Id: 42, SessionIdentifier: "other", IpAddress: "192.168.1.50",
				DeviceName: matchingName, DeviceType: matchingType, DeviceOS: "Linux",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := newStartSessionMocks(t)
			m.expectSuccessfulPersist(123, []models.UserSession{tc.session})

			_, err := m.manager.StartNewUserSession(
				httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent),
				123, 7, "pwd", enums.AcrLevel1.String(), 0, nil)

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
	m.db.On("BeginTransaction").Return(nil, nil).Once()
	m.db.On("CreateUserSession", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		created := args.Get(1).(*models.UserSession)
		created.Id = 99
		newIdentifier = created.SessionIdentifier
	}).Return(nil).Once()
	m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil).Once()
	m.db.On("CommitTransaction", mock.Anything).Return(nil).Once()
	m.db.On("RollbackTransaction", mock.Anything).Return(nil).Once()
	// Return the freshly created session as if it were already persisted. The
	// identifier is only known once CreateUserSession has run, so this is
	// resolved lazily at call time.
	m.db.On("GetUserSessionsByUserId", mock.Anything, int64(123)).Return(
		func(_ *sql.Tx, _ int64) ([]models.UserSession, error) {
			return []models.UserSession{{
				Id:                99,
				SessionIdentifier: newIdentifier,
				IpAddress:         "192.168.1.50",
				DeviceName:        useragent.GetDeviceName(req),
				DeviceType:        useragent.GetDeviceType(req),
				DeviceOS:          useragent.GetDeviceOS(req),
			}}, nil
		}).Once()
	m.store.On("Get", mock.Anything, testSessionName).Return(m.session, nil).Once()
	m.store.On("Save", mock.Anything, mock.Anything, m.session).Return(nil).Once()

	_, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), req, 123, 7, "pwd", enums.AcrLevel1.String(), 0, nil)

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
			name: "BeginTransaction fails",
			setup: func(m *startSessionMocks) {
				m.db.On("BeginTransaction").Return(nil, dbErr).Once()
			},
		},
		{
			name: "CreateUserSession fails",
			setup: func(m *startSessionMocks) {
				m.db.On("BeginTransaction").Return(nil, nil).Once()
				m.db.On("CreateUserSession", mock.Anything, mock.Anything).Return(dbErr).Once()
				m.db.On("RollbackTransaction", mock.Anything).Return(nil).Once()
			},
		},
		{
			name: "CreateUserSessionClient fails",
			setup: func(m *startSessionMocks) {
				m.db.On("BeginTransaction").Return(nil, nil).Once()
				m.db.On("CreateUserSession", mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(dbErr).Once()
				m.db.On("RollbackTransaction", mock.Anything).Return(nil).Once()
			},
		},
		{
			name: "CommitTransaction fails",
			setup: func(m *startSessionMocks) {
				m.db.On("BeginTransaction").Return(nil, nil).Once()
				m.db.On("CreateUserSession", mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("CommitTransaction", mock.Anything).Return(dbErr).Once()
				m.db.On("RollbackTransaction", mock.Anything).Return(nil).Once()
			},
		},
		{
			name: "GetUserSessionsByUserId fails",
			setup: func(m *startSessionMocks) {
				m.db.On("BeginTransaction").Return(nil, nil).Once()
				m.db.On("CreateUserSession", mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("CommitTransaction", mock.Anything).Return(nil).Once()
				m.db.On("RollbackTransaction", mock.Anything).Return(nil).Once()
				m.db.On("GetUserSessionsByUserId", mock.Anything, int64(123)).Return(nil, dbErr).Once()
			},
		},
		{
			name: "DeleteUserSession fails",
			setup: func(m *startSessionMocks) {
				req := newSessionRequest("192.168.1.50:54321", chromeUserAgent)
				m.db.On("BeginTransaction").Return(nil, nil).Once()
				m.db.On("CreateUserSession", mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("CommitTransaction", mock.Anything).Return(nil).Once()
				m.db.On("RollbackTransaction", mock.Anything).Return(nil).Once()
				m.db.On("GetUserSessionsByUserId", mock.Anything, int64(123)).Return([]models.UserSession{{
					Id:                42,
					SessionIdentifier: "an-older-session",
					IpAddress:         "192.168.1.50",
					DeviceName:        useragent.GetDeviceName(req),
					DeviceType:        useragent.GetDeviceType(req),
					DeviceOS:          useragent.GetDeviceOS(req),
				}}, nil).Once()
				m.db.On("DeleteUserSession", mock.Anything, int64(42)).Return(dbErr).Once()
			},
		},
		{
			name: "the session store cannot be read",
			setup: func(m *startSessionMocks) {
				m.db.On("BeginTransaction").Return(nil, nil).Once()
				m.db.On("CreateUserSession", mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("CommitTransaction", mock.Anything).Return(nil).Once()
				m.db.On("RollbackTransaction", mock.Anything).Return(nil).Once()
				m.db.On("GetUserSessionsByUserId", mock.Anything, int64(123)).Return(nil, nil).Once()
				m.store.On("Get", mock.Anything, testSessionName).Return(nil, errors.New("cookie is corrupt")).Once()
			},
		},
		{
			name: "the session store cannot be saved",
			setup: func(m *startSessionMocks) {
				m.db.On("BeginTransaction").Return(nil, nil).Once()
				m.db.On("CreateUserSession", mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil).Once()
				m.db.On("CommitTransaction", mock.Anything).Return(nil).Once()
				m.db.On("RollbackTransaction", mock.Anything).Return(nil).Once()
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
				123, 7, "pwd", enums.AcrLevel1.String(), 0, nil)

			assert.Error(t, err)
			assert.Nil(t, result, "no session may be returned alongside an error")
		})
	}
}

// A failure to read the cookie session is wrapped with context, since the raw
// gorilla error alone is hard to place.
func TestStartNewUserSession_WrapsSessionStoreReadError(t *testing.T) {
	m := newStartSessionMocks(t)

	m.db.On("BeginTransaction").Return(nil, nil).Once()
	m.db.On("CreateUserSession", mock.Anything, mock.Anything).Return(nil).Once()
	m.db.On("CreateUserSessionClient", mock.Anything, mock.Anything).Return(nil).Once()
	m.db.On("CommitTransaction", mock.Anything).Return(nil).Once()
	m.db.On("RollbackTransaction", mock.Anything).Return(nil).Once()
	m.db.On("GetUserSessionsByUserId", mock.Anything, int64(123)).Return(nil, nil).Once()
	m.store.On("Get", mock.Anything, testSessionName).Return(nil, errors.New("cookie is corrupt")).Once()

	_, err := m.manager.StartNewUserSession(
		httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent),
		123, 7, "pwd", enums.AcrLevel1.String(), 0, nil)

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

	manager := NewUserSessionManager(nil, store, "some-session", db)

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
		123, 7, "pwd", enums.AcrLevel1.String(), 7, nil)

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
		123, 7, "pwd", enums.AcrLevel1.String(), 7, &observed)

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
		123, 7, "pwd", enums.AcrLevel1.String(), 7, nil)

	assert.NoError(t, err)
	if assert.NotNil(t, *captured, "CreateUserSession was never called") {
		assert.EqualValues(t, 0, (*captured).OtpConfigGeneration)
	}
}
