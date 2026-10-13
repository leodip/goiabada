package usersession

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
)

// The ordering rule of the reuse arm (#538): a bind whose credential was accepted before the
// session's current auth_time writes nothing. These cases pin the two orderings the issue names,
// at the transaction the bind runs in, against the row the transaction locked.
//
// WITHOUT THE ORDERING RULE. The two writes were already one transaction (#542), so the wrong
// result each ordering produced before #538 was not a torn write but the wrong winner: the bump
// raised the session to the older step-up's level, or a prompt=login replaced it with an
// authentication earlier than the one it held. Without the rule both binds succeed and the
// session ends up describing the older sign-in, which is what these tests fail on before the fix.

// A step-up completing after a newer prompt=login wrote the session is refused: the session keeps
// the newer sign-in's level and methods, and the older step-up answers ErrStaleAuthentication
// rather than raising level 2 and "pwd otp" over what the newer authentication set. This is the
// issue's second ordering, at the write itself.
func TestBindUserSession_AnOlderStepUpDoesNotRaiseTheSessionOverANewerSignIn(t *testing.T) {
	database := datamocks.NewDatabase(t)
	manager := &Manager{database: database}

	newer := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	older := newer.Add(-2 * time.Minute)

	// The row the transaction locked already describes the newer sign-in.
	session := bumpedSession()
	session.AcrLevel, session.AuthMethods, session.AuthTime, session.PasswordAuthTime =
		record.AcrLevel1, "pwd", newer, newer

	datamocks.ExpectRunInTransaction(database, txSentinel)
	database.On("AcquireUserSessionRow", mock.Anything, txSentinel, bumpSessionIdentifier).Return(true, nil).Once()
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, txSentinel, bumpSessionIdentifier).Return(session, nil).Once()

	// The step-up ceremony accepted its code before the newer sign-in's password.
	olderInstant := older
	result, err := manager.BindUserSession(context.Background(), bumpSessionIdentifier, 456, Authentication{
		UserId: 123, AuthMethods: "pwd otp", AcrLevel: record.AcrLevel2Mandatory,
		AuthTime: &olderInstant,
	}, false, "")

	require.ErrorIs(t, err, ErrStaleAuthentication)
	assert.Nil(t, result)

	// Nothing was written: the session row, its clients and neither of the two writes ran.
	database.AssertNotCalled(t, "UserSessionLoadClients", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "UpdateUserSession", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "UpdateUserSessionClient", mock.Anything, mock.Anything, mock.Anything)
}

// A prompt=login whose password was accepted before a newer sign-in is refused too: replace is
// the arm that writes the sign-in's level and methods over the session, and an older sign-in
// must not do that over a newer one. This is the issue's first ordering, the step-up Tab B won
// being the thing Tab A's replace would have lost.
func TestBindUserSession_AnOlderReplaceDoesNotWriteOverANewerSignIn(t *testing.T) {
	database := datamocks.NewDatabase(t)
	manager := &Manager{database: database}

	newer := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	older := newer.Add(-2 * time.Minute)

	session := bumpedSession()
	session.AcrLevel, session.AuthMethods, session.AuthTime, session.PasswordAuthTime =
		record.AcrLevel2Mandatory, "pwd otp", newer, newer

	datamocks.ExpectRunInTransaction(database, txSentinel)
	database.On("AcquireUserSessionRow", mock.Anything, txSentinel, bumpSessionIdentifier).Return(true, nil).Once()
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, txSentinel, bumpSessionIdentifier).Return(session, nil).Once()

	olderInstant := older
	result, err := manager.BindUserSession(context.Background(), bumpSessionIdentifier, 456, Authentication{
		UserId: 123, AuthMethods: "pwd", AcrLevel: record.AcrLevel1,
		AuthTime: &olderInstant, PasswordAuthTime: &olderInstant,
	}, true, "")

	require.ErrorIs(t, err, ErrStaleAuthentication)
	assert.Nil(t, result)

	database.AssertNotCalled(t, "UserSessionLoadClients", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "UpdateUserSession", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "UpdateUserSessionClient", mock.Anything, mock.Anything, mock.Anything)
}

// The newer authentication of each pair takes the session: the ordering refuses the older one
// only, so the write the newer sign-in makes still happens, whichever arm it arrives on. A bind
// whose instant is exactly the session's own auth_time is current, not stale: that is the sign-in
// the session already describes, binding again, and refusing it would turn that sign-in away from
// its own session.
func TestBindUserSession_ANewerSignInStillBindsAndAnEqualInstantIsCurrent(t *testing.T) {
	older := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	newer := older.Add(2 * time.Minute)

	for _, tc := range []struct {
		name      string
		instant   time.Time
		replace   bool
		methods   string
		level     record.AcrLevel
		wantLevel record.AcrLevel
	}{
		{"a newer step-up raises the session", newer, false, "pwd otp", record.AcrLevel2Mandatory, record.AcrLevel2Mandatory},
		{"a newer replace writes its own authentication", newer, true, "pwd", record.AcrLevel1, record.AcrLevel1},
		{"an equal instant is current, not stale", older, false, "pwd", record.AcrLevel1, record.AcrLevel1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			manager := &Manager{database: database}

			session := bumpedSession()
			session.AcrLevel, session.AuthMethods, session.AuthTime, session.PasswordAuthTime =
				record.AcrLevel1, "pwd", older, older

			datamocks.ExpectRunInTransaction(database, txSentinel)
			database.On("AcquireUserSessionRow", mock.Anything, txSentinel, bumpSessionIdentifier).Return(true, nil).Once()
			database.On("GetUserSessionBySessionIdentifier", mock.Anything, txSentinel, bumpSessionIdentifier).Return(session, nil).Once()
			database.On("UserSessionLoadClients", mock.Anything, txSentinel, session).Return(nil).Once()
			database.On("UpdateUserSession", mock.Anything, txSentinel, session).Return(nil).Once()
			database.On("CreateUserSessionClient", mock.Anything, txSentinel, mock.Anything).Return(nil).Once()

			instant := tc.instant
			auth := Authentication{
				UserId: 123, AuthMethods: tc.methods, AcrLevel: tc.level,
				AuthTime: &instant,
			}
			if tc.replace {
				auth.PasswordAuthTime = &instant
			}

			result, err := manager.BindUserSession(context.Background(), bumpSessionIdentifier, 456, auth, tc.replace, "")

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, tc.wantLevel, result.AcrLevel)
			assert.Equal(t, tc.instant, result.AuthTime)
			database.AssertExpectations(t)
		})
	}
}

// A session with no auth_time yet -- a legacy row, or one no bind has stamped -- has no newer
// authentication for an arriving sign-in to be older than: the first bind that carries an instant
// takes it, however old the instant is. And a bump that carries neither an instant nor an adopted
// one -- the token endpoint's, or prompt=none's -- claims no authentication and cannot be stale:
// it writes neither auth_time nor the level of a ceremony that authenticated nothing. An SSO
// bind, which carries the instant its ceremony adopted, is the test below.
func TestBindUserSession_NoAuthTimeTakesAnyInstantAndACarrylessBumpIsNeverStale(t *testing.T) {
	staleInstant := time.Date(2026, 10, 10, 6, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name string
		auth Authentication
	}{
		{"a legacy row with no auth_time takes any instant",
			Authentication{UserId: 123, AuthMethods: "pwd otp", AcrLevel: record.AcrLevel2Mandatory, AuthTime: &staleInstant}},
		{"a carryless bump that adopted nothing is never stale",
			Authentication{UserId: 123, AuthMethods: "pwd", AcrLevel: record.AcrLevel1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			manager := &Manager{database: database}

			// The row has zero auth_time: never stamped.
			session := bumpedSession()
			require.True(t, session.AuthTime.IsZero())

			datamocks.ExpectRunInTransaction(database, txSentinel)
			database.On("AcquireUserSessionRow", mock.Anything, txSentinel, bumpSessionIdentifier).Return(true, nil).Once()
			database.On("GetUserSessionBySessionIdentifier", mock.Anything, txSentinel, bumpSessionIdentifier).Return(session, nil).Once()
			database.On("UserSessionLoadClients", mock.Anything, txSentinel, session).Return(nil).Once()
			database.On("UpdateUserSession", mock.Anything, txSentinel, session).Return(nil).Once()
			database.On("CreateUserSessionClient", mock.Anything, txSentinel, mock.Anything).Return(nil).Once()

			result, err := manager.BindUserSession(context.Background(), bumpSessionIdentifier, 456, tc.auth, false, "")

			require.NoError(t, err)
			require.NotNil(t, result)
			database.AssertExpectations(t)
		})
	}
}

// The adopted instant of #538's SSO case. A bind whose ceremony adopted the session compares the
// auth_time it adopted with the row the transaction locks, so a session a newer sign-in has
// reached since the adoption is not one the ceremony may still write: merging its adopted methods
// back would raise the session with an authentication older than the one it holds now, and the
// bind answers ErrStaleAuthentication and writes nothing. A session that still holds the adopted
// instant is exactly what the ceremony was built on, so the bind takes it and, entering no
// credential of its own, leaves auth_time where the row had it.
//
// The comparison runs whenever the adopted instant is set, so an SSO ceremony that then stepped up
// is refused on a moved session even though its own code is newer than the row's auth_time: the
// methods it would merge beside that code came from the session it adopted. And a legacy row
// adopted with no auth_time still holds that zero, so it takes the bind.
func TestBindUserSession_AnSSOBindWhoseSessionMovedIsRefused(t *testing.T) {
	adopted := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	moved := adopted.Add(2 * time.Minute)
	steppedUp := moved.Add(time.Minute)

	for _, tc := range []struct {
		name            string
		sessionAuthTime time.Time
		adopted         time.Time
		ownInstant      *time.Time
		wantStale       bool
	}{
		{"a session a newer sign-in has reached refuses the SSO bind", moved, adopted, nil, true},
		{"a session that still holds the adopted instant takes the SSO bind", adopted, adopted, nil, false},
		{"an SSO ceremony that stepped up is refused on a moved session, its newer code notwithstanding", moved, adopted, &steppedUp, true},
		{"a legacy row adopted with no auth_time takes the SSO bind", time.Time{}, time.Time{}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			manager := &Manager{database: database}

			session := bumpedSession()
			session.AcrLevel, session.AuthMethods, session.AuthTime, session.PasswordAuthTime =
				record.AcrLevel1, "pwd", tc.sessionAuthTime, tc.sessionAuthTime

			datamocks.ExpectRunInTransaction(database, txSentinel)
			database.On("AcquireUserSessionRow", mock.Anything, txSentinel, bumpSessionIdentifier).Return(true, nil).Once()
			database.On("GetUserSessionBySessionIdentifier", mock.Anything, txSentinel, bumpSessionIdentifier).Return(session, nil).Once()

			if !tc.wantStale {
				database.On("UserSessionLoadClients", mock.Anything, txSentinel, session).Return(nil).Once()
				database.On("UpdateUserSession", mock.Anything, txSentinel, session).Return(nil).Once()
				database.On("CreateUserSessionClient", mock.Anything, txSentinel, mock.Anything).Return(nil).Once()
			}

			// The SSO bind: the methods and level its ceremony adopted from the session, and the
			// instant it adopted them at, with the instant of a code it entered when it stepped up.
			adoptedInstant := tc.adopted
			result, err := manager.BindUserSession(context.Background(), bumpSessionIdentifier, 456,
				Authentication{UserId: 123, AuthMethods: "pwd otp", AcrLevel: record.AcrLevel2Mandatory,
					AuthTime: tc.ownInstant, AdoptedAuthTime: &adoptedInstant}, false, "")

			if tc.wantStale {
				require.ErrorIs(t, err, ErrStaleAuthentication)
				assert.Nil(t, result)
				database.AssertNotCalled(t, "UserSessionLoadClients", mock.Anything, mock.Anything, mock.Anything)
				database.AssertNotCalled(t, "UpdateUserSession", mock.Anything, mock.Anything, mock.Anything)
				database.AssertNotCalled(t, "CreateUserSessionClient", mock.Anything, mock.Anything, mock.Anything)
				database.AssertNotCalled(t, "UpdateUserSessionClient", mock.Anything, mock.Anything, mock.Anything)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Truef(t, result.AuthTime.Equal(tc.sessionAuthTime),
					"a bind that entered no credential leaves auth_time where the row had it: %v", result.AuthTime)
				database.AssertExpectations(t)
			}
		})
	}
}

// A ceremony's instants and the row it wrote are equal at the auth_time column's precision, a
// microsecond, and never exactly: the ceremony carries the clock's nanoseconds, and the row what
// the engine kept, truncated or rounded. And a ceremony that adopted the session and then entered a
// code moved auth_time to that code with its own first bind, so its second bind, a reload of
// /auth/completed after a step that failed once the bind had committed, finds its own instant there
// rather than the adopted one. Both are the authentication the session already describes, and
// neither is stale; an instant a microsecond away, or one belonging to someone else, still is.
func TestStaleAuthentication_TheCeremonysOwnInstantAtTheColumnsPrecision(t *testing.T) {
	adopted := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	// A code instant with nanoseconds the column does not keep.
	code := adopted.Add(time.Minute + 1600*time.Nanosecond)
	truncated := code.Truncate(time.Microsecond)
	roundedUp := truncated.Add(time.Microsecond)
	someoneElse := code.Add(time.Minute)

	ptr := func(at time.Time) *time.Time { return &at }

	for _, tc := range []struct {
		name      string
		row       time.Time
		adopted   *time.Time
		own       *time.Time
		wantStale bool
	}{
		{"an SSO step-up binds again over its own first bind, truncated", truncated, ptr(adopted), ptr(code), false},
		{"an SSO step-up binds again over its own first bind, rounded up", roundedUp, ptr(adopted), ptr(code), false},
		{"an SSO step-up whose row moved to another sign-in is refused", someoneElse, ptr(adopted), ptr(code), true},
		{"a credential's retry over the row it truncated is current", truncated, nil, ptr(code), false},
		{"a credential's retry over the row it rounded up is current", roundedUp, nil, ptr(code), false},
		{"a credential a microsecond older than the row is refused", code.Add(time.Microsecond), nil, ptr(code), true},
		{"an adopted instant read back from the row matches it", adopted, ptr(adopted), nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := bumpedSession()
			session.AuthTime = tc.row

			stale := staleAuthentication(session, Authentication{AuthTime: tc.own, AdoptedAuthTime: tc.adopted})

			assert.Equal(t, tc.wantStale, stale)
		})
	}
}

// AuthenticationIsStale is the ordering rule asked of the session row as it is now, with no lock
// and no write, which /auth/completed asks before it rotates the browser session's identifier. A
// session that is gone is not stale here, since the bind answers that itself, and a failed read is
// returned rather than read as either answer.
func TestAuthenticationIsStale_AsksTheRuleOfTheRowAsItIsNow(t *testing.T) {
	adopted := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	moved := adopted.Add(2 * time.Minute)
	readFailure := errors.New("read failed")

	for _, tc := range []struct {
		name      string
		row       *record.UserSession
		readErr   error
		wantStale bool
	}{
		{"a row a newer sign-in has reached is stale", &record.UserSession{UserId: 123, AuthTime: moved}, nil, true},
		{"a row that still holds the adopted instant is not", &record.UserSession{UserId: 123, AuthTime: adopted}, nil, false},
		{"a session that is gone is not stale here", nil, nil, false},
		{"a failed read is returned", nil, readFailure, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			manager := &Manager{database: database}

			database.On("GetUserSessionBySessionIdentifier", mock.Anything, (*sql.Tx)(nil), bumpSessionIdentifier).
				Return(tc.row, tc.readErr).Once()

			adoptedInstant := adopted
			stale, err := manager.AuthenticationIsStale(context.Background(), bumpSessionIdentifier,
				Authentication{UserId: 123, AuthMethods: "pwd otp", AdoptedAuthTime: &adoptedInstant})

			if tc.readErr != nil {
				require.ErrorIs(t, err, readFailure)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.wantStale, stale)

			// It writes nothing and locks nothing.
			database.AssertNotCalled(t, "AcquireUserSessionRow", mock.Anything, mock.Anything, mock.Anything)
			database.AssertNotCalled(t, "UpdateUserSession", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}
