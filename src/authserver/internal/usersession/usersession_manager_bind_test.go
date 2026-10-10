package usersession

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/otpcredential"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
)

// A bump takes the session's row before it reads it, so the whole row it writes back is never a
// copy a removal of the authenticator has lowered since (#542).
func TestBumpUserSession_TakesTheRowBeforeReadingIt(t *testing.T) {
	database := datamocks.NewDatabase(t)
	manager := &Manager{database: database}

	var order []string
	datamocks.ExpectRunInTransaction(database, txSentinel)
	database.On("AcquireUserSessionRow", mock.Anything, txSentinel, bumpSessionIdentifier).Return(true, nil).
		Run(func(mock.Arguments) { order = append(order, "lock") }).Once()
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, txSentinel, bumpSessionIdentifier).Return(bumpedSession(), nil).
		Run(func(mock.Arguments) { order = append(order, "read") }).Once()
	database.On("UserSessionLoadClients", mock.Anything, txSentinel, mock.Anything).Return(nil).Once()
	database.On("UpdateUserSession", mock.Anything, txSentinel, mock.Anything).Return(nil).
		Run(func(mock.Arguments) { order = append(order, "write") }).Once()
	database.On("CreateUserSessionClient", mock.Anything, txSentinel, mock.Anything).Return(nil).Once()

	_, err := manager.BumpUserSession(context.Background(), bumpSessionIdentifier, 456, "", "", "")

	require.NoError(t, err)
	assert.Equal(t, []string{"lock", "read", "write"}, order)
}

// A sign-in claiming a code is checked on the user under the user's row, before the session's row is
// taken or anything read: the order a removal takes the two in (#542).
func TestBindUserSession_ChecksTheClaimUnderTheUserRowFirst(t *testing.T) {
	database := datamocks.NewDatabase(t)
	manager := &Manager{database: database}
	generation := int64(4)

	var order []string
	datamocks.ExpectRunInTransaction(database, txSentinel)
	database.On("AcquireUserRow", mock.Anything, txSentinel, int64(123)).Return(nil).
		Run(func(mock.Arguments) { order = append(order, "user lock") }).Once()
	database.On("GetUserById", mock.Anything, txSentinel, int64(123)).
		Return(&record.User{Id: 123, OTPEnabled: true, OtpConfigGeneration: 4}, nil).
		Run(func(mock.Arguments) { order = append(order, "user read") }).Once()
	database.On("AcquireUserSessionRow", mock.Anything, txSentinel, bumpSessionIdentifier).Return(true, nil).
		Run(func(mock.Arguments) { order = append(order, "session lock") }).Once()
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, txSentinel, bumpSessionIdentifier).Return(bumpedSession(), nil).
		Run(func(mock.Arguments) { order = append(order, "session read") }).Once()
	database.On("UserSessionLoadClients", mock.Anything, txSentinel, mock.Anything).Return(nil).Once()
	database.On("UpdateUserSession", mock.Anything, txSentinel, mock.MatchedBy(func(s *record.UserSession) bool {
		return s.AuthMethods == "pwd otp" && s.AcrLevel == record.AcrLevel2Mandatory
	})).Return(nil).Once()
	database.On("CreateUserSessionClient", mock.Anything, txSentinel, mock.Anything).Return(nil).Once()

	_, err := manager.BindUserSession(context.Background(), bumpSessionIdentifier, 456, Authentication{
		UserId: 123, AuthMethods: "pwd otp", AcrLevel: record.AcrLevel2Mandatory,
		OTPClaim: otpcredential.OTPClaim{Claimed: true, Generation: &generation},
	}, false, "")

	require.NoError(t, err)
	assert.Equal(t, []string{"user lock", "user read", "session lock", "session read"}, order)
}

// A code from an authenticator removed, or removed and replaced, since the ceremony checked it
// raises nothing: the session's row is not even taken (#542).
func TestBindUserSession_AClaimThatNoLongerStandsWritesNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		user *record.User
	}{
		{"the authenticator removed", &record.User{Id: 123, OtpConfigGeneration: 5}},
		{"the authenticator removed and another set up", &record.User{Id: 123, OTPEnabled: true, OtpConfigGeneration: 6}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			manager := &Manager{database: database}
			generation := int64(4)

			stub := datamocks.ExpectRunInTransaction(database, txSentinel)
			database.On("AcquireUserRow", mock.Anything, txSentinel, int64(123)).Return(nil).Once()
			database.On("GetUserById", mock.Anything, txSentinel, int64(123)).Return(tc.user, nil).Once()

			result, err := manager.BindUserSession(context.Background(), bumpSessionIdentifier, 456, Authentication{
				UserId: 123, AuthMethods: "pwd otp", AcrLevel: record.AcrLevel2Mandatory,
				OTPClaim: otpcredential.OTPClaim{Claimed: true, Generation: &generation},
			}, false, "")

			require.ErrorIs(t, err, otpcredential.ErrAuthenticatorRemoved)
			require.ErrorIs(t, stub.BodyErr, otpcredential.ErrAuthenticatorRemoved)
			assert.Nil(t, result)
			database.AssertNotCalled(t, "AcquireUserSessionRow", mock.Anything, mock.Anything, mock.Anything)
			database.AssertNotCalled(t, "UpdateUserSession", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// A ceremony that verified the password itself replaces the session's authentication, the password's
// instant with it, in the same write as the bump: the level, the methods and both times are the
// sign-in's, lower than the session's or not (#537, #542).
func TestBindUserSession_ReplaceWritesTheSignInsAuthentication(t *testing.T) {
	database := datamocks.NewDatabase(t)
	manager := &Manager{database: database}

	old := time.Date(2026, 10, 10, 6, 0, 0, 0, time.UTC)
	session := bumpedSession()
	session.AcrLevel, session.AuthMethods, session.AuthTime, session.PasswordAuthTime =
		record.AcrLevel2Mandatory, "pwd otp", old, old
	signedIn := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)

	datamocks.ExpectRunInTransaction(database, txSentinel)
	database.On("AcquireUserSessionRow", mock.Anything, txSentinel, bumpSessionIdentifier).Return(true, nil).Once()
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, txSentinel, bumpSessionIdentifier).Return(session, nil).Once()
	database.On("UserSessionLoadClients", mock.Anything, txSentinel, session).Return(nil).Once()
	database.On("UpdateUserSession", mock.Anything, txSentinel, mock.MatchedBy(func(s *record.UserSession) bool {
		return s.AcrLevel == record.AcrLevel1 && s.AuthMethods == "pwd" &&
			s.AuthTime.Equal(signedIn) && s.PasswordAuthTime.Equal(signedIn)
	})).Return(nil).Once()
	database.On("CreateUserSessionClient", mock.Anything, txSentinel, mock.Anything).Return(nil).Once()

	result, err := manager.BindUserSession(context.Background(), bumpSessionIdentifier, 456, Authentication{
		UserId: 123, AuthMethods: "pwd", AcrLevel: record.AcrLevel1, AuthTime: &signedIn, PasswordAuthTime: &signedIn,
	}, true, "")

	require.NoError(t, err)
	assert.Equal(t, record.AcrLevel1, result.AcrLevel)
}

// A code entered over a reused session moves auth_time and leaves the password's instant alone:
// a removal of the authenticator later lowers auth_time back to it (#542).
func TestBindUserSession_AStepUpLeavesThePasswordInstant(t *testing.T) {
	database := datamocks.NewDatabase(t)
	manager := &Manager{database: database}

	passwordAt := time.Date(2026, 10, 10, 6, 0, 0, 0, time.UTC)
	session := bumpedSession()
	session.AuthTime, session.PasswordAuthTime = passwordAt, passwordAt
	codeAt := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)

	datamocks.ExpectRunInTransaction(database, txSentinel)
	database.On("AcquireUserSessionRow", mock.Anything, txSentinel, bumpSessionIdentifier).Return(true, nil).Once()
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, txSentinel, bumpSessionIdentifier).Return(session, nil).Once()
	database.On("UserSessionLoadClients", mock.Anything, txSentinel, session).Return(nil).Once()
	database.On("UpdateUserSession", mock.Anything, txSentinel, mock.MatchedBy(func(s *record.UserSession) bool {
		return s.AuthMethods == "pwd otp" && s.AuthTime.Equal(codeAt) && s.PasswordAuthTime.Equal(passwordAt)
	})).Return(nil).Once()
	database.On("CreateUserSessionClient", mock.Anything, txSentinel, mock.Anything).Return(nil).Once()

	_, err := manager.BindUserSession(context.Background(), bumpSessionIdentifier, 456, Authentication{
		AuthMethods: "pwd otp", AcrLevel: record.AcrLevel2Optional, AuthTime: &codeAt,
	}, false, "")

	require.NoError(t, err)
}

// Replacing a session's authentication with no password instant would leave password_auth_time
// describing an older sign-in, so it is refused before a transaction opens.
func TestBindUserSession_ReplaceWithoutAPasswordInstantIsRefused(t *testing.T) {
	database := datamocks.NewDatabase(t)
	manager := &Manager{database: database}
	signedIn := time.Now().UTC()

	_, err := manager.BindUserSession(context.Background(), bumpSessionIdentifier, 456, Authentication{
		UserId: 123, AuthMethods: "pwd", AcrLevel: record.AcrLevel1, AuthTime: &signedIn,
	}, true, "")

	require.ErrorContains(t, err, "no password instant captured")
	database.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
}

// A sign-in binds only its own user's session.
func TestBindUserSession_RefusesAnotherUsersSession(t *testing.T) {
	database := datamocks.NewDatabase(t)
	manager := &Manager{database: database}

	stub := datamocks.ExpectRunInTransaction(database, txSentinel)
	database.On("AcquireUserSessionRow", mock.Anything, txSentinel, bumpSessionIdentifier).Return(true, nil).Once()
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, txSentinel, bumpSessionIdentifier).Return(bumpedSession(), nil).Once()

	_, err := manager.BindUserSession(context.Background(), bumpSessionIdentifier, 456, Authentication{
		UserId: 999, AuthMethods: "pwd", AcrLevel: record.AcrLevel1,
	}, false, "")

	require.ErrorContains(t, err, "refusing to bind user session")
	require.Error(t, stub.BodyErr)
	database.AssertNotCalled(t, "UpdateUserSession", mock.Anything, mock.Anything, mock.Anything)
}

// A new session records the password's instant beside auth_time, which a code entered after the
// password made the later of the two (#542).
func TestStartNewUserSession_RecordsThePasswordInstant(t *testing.T) {
	m := newStartSessionMocks(t)
	captured := m.expectPersistThroughCommit(123, nil)
	passwordAt := time.Now().UTC().Add(-3 * time.Minute)
	codeAt := passwordAt.Add(time.Minute)

	result, _, err := m.manager.StartNewUserSession(httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent), 7,
		Authentication{UserId: 123, AuthMethods: "pwd otp", AcrLevel: record.AcrLevel2Mandatory, AuthTime: &codeAt, PasswordAuthTime: &passwordAt},
		0, nil, "192.168.1.50", nil)

	require.NoError(t, err)
	assert.Same(t, *captured, result)
	assert.True(t, result.AuthTime.Equal(codeAt))
	assert.True(t, result.PasswordAuthTime.Equal(passwordAt))
}

// No session is created without the password's instant: it is what a removal of the authenticator
// lowers auth_time to, and there is nothing true to invent in its place.
func TestStartNewUserSession_RefusesAMissingPasswordInstant(t *testing.T) {
	m := newStartSessionMocks(t)
	at := time.Now().UTC()

	_, _, err := m.manager.StartNewUserSession(httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent), 7,
		Authentication{UserId: 123, AuthMethods: "pwd", AcrLevel: record.AcrLevel1, AuthTime: &at},
		0, nil, "192.168.1.50", nil)

	require.ErrorContains(t, err, "no password instant captured")
	m.db.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
}

// A code from an authenticator removed since the ceremony checked it creates no session: the claim
// is asked again under the user's row, first in the transaction (#542).
func TestStartNewUserSession_AClaimThatNoLongerStandsCreatesNothing(t *testing.T) {
	m := newStartSessionMocks(t)
	at := time.Now().UTC()
	generation := int64(4)

	stub := datamocks.ExpectRunInTransaction(m.db, txSentinel)
	m.db.On("AcquireUserRow", mock.Anything, txSentinel, int64(123)).Return(nil).Once()
	m.db.On("GetUserById", mock.Anything, txSentinel, int64(123)).Return(&record.User{Id: 123, OtpConfigGeneration: 5}, nil).Once()

	result, removed, err := m.manager.StartNewUserSession(httptest.NewRecorder(), newSessionRequest("192.168.1.50:54321", chromeUserAgent), 7,
		Authentication{
			UserId: 123, AuthMethods: "pwd otp", AcrLevel: record.AcrLevel2Mandatory, AuthTime: &at, PasswordAuthTime: &at,
			OTPClaim: otpcredential.OTPClaim{Claimed: true, Generation: &generation},
		},
		0, &generation, "192.168.1.50", nil)

	require.ErrorIs(t, err, otpcredential.ErrAuthenticatorRemoved)
	require.ErrorIs(t, stub.BodyErr, otpcredential.ErrAuthenticatorRemoved)
	assert.Nil(t, result)
	assert.Empty(t, removed)
	m.db.AssertNotCalled(t, "CreateUserSession", mock.Anything, mock.Anything, mock.Anything)
}
