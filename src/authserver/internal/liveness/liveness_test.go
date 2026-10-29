package liveness

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The instant every row is judged at, and the bounds it is judged against: an hour idle, a day in
// all.
var (
	checkedAt = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	settings  = &record.Settings{
		UserSessionIdleTimeoutInSeconds: 3600,
		UserSessionMaxLifetimeInSeconds: 86400,
	}
)

const sid = "sid-1"

// liveSession is a session of user 1 on generation gen, started an hour ago and used five minutes
// ago: within both bounds at checkedAt.
func liveSession(gen int64) *record.UserSession {
	return &record.UserSession{
		Id:                  9,
		SessionIdentifier:   sid,
		UserId:              1,
		Started:             checkedAt.Add(-1 * time.Hour),
		LastAccessed:        checkedAt.Add(-5 * time.Minute),
		AuthStateGeneration: gen,
	}
}

func TestAccessToken(t *testing.T) {
	enabledUser := &record.User{Id: 1, Subject: "user-1", Enabled: true}

	expiredSession := liveSession(0)
	expiredSession.LastAccessed = checkedAt.Add(-2 * time.Hour)

	pastMaxLifetime := liveSession(0)
	pastMaxLifetime.Started = checkedAt.Add(-25 * time.Hour)

	foreignSession := liveSession(0)
	foreignSession.UserId = 2

	tests := []struct {
		label  string
		claims map[string]interface{}
		// nil user and session mean the row never reads that far; noUser means the read finds none.
		user        *record.User
		noUser      bool
		session     *record.UserSession
		noSession   bool
		wantRefusal Refusal
	}{
		// A token without auth_time is a client's, from the client credentials grant: there is no
		// user to check, and nothing is read.
		{
			label:       "client token",
			claims:      map[string]interface{}{"sub": "client-1"},
			wantRefusal: Live,
		},

		{
			label:       "blank subject",
			claims:      map[string]interface{}{"auth_time": float64(1), "sub": "  "},
			wantRefusal: BlankSubject,
		},
		{
			label:       "subject names no user",
			claims:      map[string]interface{}{"auth_time": float64(1), "sub": "user-1"},
			noUser:      true,
			wantRefusal: UserNotFound,
		},
		{
			label:       "disabled user, sid-less",
			claims:      map[string]interface{}{"auth_time": float64(1), "sub": "user-1"},
			user:        &record.User{Id: 1, Subject: "user-1", Enabled: false},
			wantRefusal: UserDisabled,
		},
		{
			label:       "disabled user, session-bound",
			claims:      map[string]interface{}{"auth_time": float64(1), "sub": "user-1", "sid": sid},
			user:        &record.User{Id: 1, Subject: "user-1", Enabled: false},
			wantRefusal: UserDisabled,
		},

		// Without sid, the token's own generation decides; an absent claim is generation 0.
		{
			label:       "sid-less, claim matches",
			claims:      map[string]interface{}{"auth_time": float64(1), "sub": "user-1", "auth_state_generation": float64(3)},
			user:        &record.User{Id: 1, Subject: "user-1", Enabled: true, AuthStateGeneration: 3},
			wantRefusal: Live,
		},
		{
			label:       "sid-less, claim behind",
			claims:      map[string]interface{}{"auth_time": float64(1), "sub": "user-1", "auth_state_generation": float64(2)},
			user:        &record.User{Id: 1, Subject: "user-1", Enabled: true, AuthStateGeneration: 3},
			wantRefusal: TokenGenerationSuperseded,
		},
		{
			label:       "sid-less, absent claim while the user is at 0",
			claims:      map[string]interface{}{"auth_time": float64(1), "sub": "user-1"},
			user:        enabledUser,
			wantRefusal: Live,
		},
		{
			label:       "sid-less, absent claim once the user has advanced",
			claims:      map[string]interface{}{"auth_time": float64(1), "sub": "user-1"},
			user:        &record.User{Id: 1, Subject: "user-1", Enabled: true, AuthStateGeneration: 1},
			wantRefusal: TokenGenerationSuperseded,
		},
		// A malformed claim is never read as 0, or it would inherit the absent claim's pass.
		{
			label:       "sid-less, malformed claim while the user is at 0",
			claims:      map[string]interface{}{"auth_time": float64(1), "sub": "user-1", "auth_state_generation": "0"},
			user:        enabledUser,
			wantRefusal: TokenGenerationSuperseded,
		},
		{
			label:       "sid-less, malformed claim against a stored -1",
			claims:      map[string]interface{}{"auth_time": float64(1), "sub": "user-1", "auth_state_generation": "-1"},
			user:        &record.User{Id: 1, Subject: "user-1", Enabled: true, AuthStateGeneration: -1},
			wantRefusal: TokenGenerationSuperseded,
		},

		// With sid, the session decides, and the token's own generation claim is not read.
		{
			label:       "session-bound, everything current",
			claims:      map[string]interface{}{"auth_time": float64(1), "sub": "user-1", "sid": sid},
			user:        enabledUser,
			session:     liveSession(0),
			wantRefusal: Live,
		},
		{
			label:       "session-bound, stale token claim ignored",
			claims:      map[string]interface{}{"auth_time": float64(1), "sub": "user-1", "sid": sid, "auth_state_generation": float64(0)},
			user:        &record.User{Id: 1, Subject: "user-1", Enabled: true, AuthStateGeneration: 1},
			session:     liveSession(1),
			wantRefusal: Live,
		},
		{
			label:       "session terminated",
			claims:      map[string]interface{}{"auth_time": float64(1), "sub": "user-1", "sid": sid},
			user:        enabledUser,
			noSession:   true,
			wantRefusal: SessionNotFound,
		},
		{
			label:       "session of another user",
			claims:      map[string]interface{}{"auth_time": float64(1), "sub": "user-1", "sid": sid},
			user:        enabledUser,
			session:     foreignSession,
			wantRefusal: SessionOfAnotherUser,
		},
		{
			label:       "session past its idle timeout",
			claims:      map[string]interface{}{"auth_time": float64(1), "sub": "user-1", "sid": sid},
			user:        enabledUser,
			session:     expiredSession,
			wantRefusal: SessionExpired,
		},
		{
			label:       "session past its maximum lifetime",
			claims:      map[string]interface{}{"auth_time": float64(1), "sub": "user-1", "sid": sid},
			user:        enabledUser,
			session:     pastMaxLifetime,
			wantRefusal: SessionExpired,
		},
		{
			label:       "session on a superseded generation",
			claims:      map[string]interface{}{"auth_time": float64(1), "sub": "user-1", "sid": sid},
			user:        &record.User{Id: 1, Subject: "user-1", Enabled: true, AuthStateGeneration: 1},
			session:     liveSession(0),
			wantRefusal: SessionGenerationSuperseded,
		},
	}

	for _, tc := range tests {
		t.Run(tc.label, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			switch {
			case tc.noUser:
				database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), "user-1").Return(nil, nil).Once()
			case tc.user != nil:
				database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), "user-1").Return(tc.user, nil).Once()
			}
			switch {
			case tc.noSession:
				database.On("GetUserSessionBySessionIdentifier", mock.Anything, (*sql.Tx)(nil), sid).Return(nil, nil).Once()
			case tc.session != nil:
				database.On("GetUserSessionBySessionIdentifier", mock.Anything, (*sql.Tx)(nil), sid).Return(tc.session, nil).Once()
			}

			verdict, err := AccessToken(context.Background(), database, oauth.JwtToken{Claims: tc.claims}, settings, checkedAt)

			require.NoError(t, err)
			assert.Equal(t, tc.wantRefusal, verdict.Refusal, "refusal")
			assert.Equal(t, tc.wantRefusal == Live, verdict.Live(), "live")
			if tc.user == nil {
				assert.Nil(t, verdict.User, "no user read")
			} else {
				assert.Same(t, tc.user, verdict.User, "the user read")
			}
			if tc.session == nil {
				assert.Nil(t, verdict.Session, "no session read")
			} else {
				assert.Same(t, tc.session, verdict.Session, "the session read")
			}
		})
	}
}

// The session identifier the verdict carries is the token's sid once the check reached the
// session, and empty before: a caller logs it beside a refusal or a fault.
func TestAccessToken_SessionIdentifier(t *testing.T) {
	enabledUser := &record.User{Id: 1, Subject: "user-1", Enabled: true}

	t.Run("a session-bound token's verdict names its session", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetUserBySubject", mock.Anything, mock.Anything, "user-1").Return(enabledUser, nil)
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sid).Return(nil, nil)

		verdict, err := AccessToken(context.Background(), database,
			oauth.JwtToken{Claims: map[string]interface{}{"auth_time": float64(1), "sub": "user-1", "sid": sid}},
			settings, checkedAt)

		require.NoError(t, err)
		assert.Equal(t, sid, verdict.SessionIdentifier)
	})

	t.Run("a refusal before the session names none", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetUserBySubject", mock.Anything, mock.Anything, "user-1").
			Return(&record.User{Id: 1, Subject: "user-1", Enabled: false}, nil)

		verdict, err := AccessToken(context.Background(), database,
			oauth.JwtToken{Claims: map[string]interface{}{"auth_time": float64(1), "sub": "user-1", "sid": sid}},
			settings, checkedAt)

		require.NoError(t, err)
		assert.Equal(t, UserDisabled, verdict.Refusal)
		assert.Empty(t, verdict.SessionIdentifier)
	})
}

// A fault is an error and never a refusal: a caller must not answer a database failure as a dead
// token.
func TestAccessToken_Faults(t *testing.T) {
	sessionBound := oauth.JwtToken{Claims: map[string]interface{}{"auth_time": float64(1), "sub": "user-1", "sid": sid}}
	enabledUser := &record.User{Id: 1, Subject: "user-1", Enabled: true}

	t.Run("reading the user fails", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetUserBySubject", mock.Anything, mock.Anything, "user-1").Return(nil, errors.New("the database is down"))

		verdict, err := AccessToken(context.Background(), database, sessionBound, settings, checkedAt)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "the database is down")
		assert.False(t, verdict.Live())
		assert.Empty(t, verdict.SessionIdentifier, "the user's read names no session")
	})

	t.Run("reading the session fails", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetUserBySubject", mock.Anything, mock.Anything, "user-1").Return(enabledUser, nil)
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sid).Return(nil, errors.New("the database is down"))

		verdict, err := AccessToken(context.Background(), database, sessionBound, settings, checkedAt)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "the database is down")
		assert.False(t, verdict.Live())
		assert.Equal(t, sid, verdict.SessionIdentifier)
	})

	t.Run("no settings to measure the session against", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetUserBySubject", mock.Anything, mock.Anything, "user-1").Return(enabledUser, nil)
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sid).Return(liveSession(0), nil)

		verdict, err := AccessToken(context.Background(), database, sessionBound, nil, checkedAt)

		require.ErrorIs(t, err, ErrNoSettings)
		assert.False(t, verdict.Live())
		assert.Equal(t, sid, verdict.SessionIdentifier)
	})

	// Settings are needed only for the bounds, so a refusal decided before them stands without.
	t.Run("a session of another user is refused without settings", func(t *testing.T) {
		foreign := liveSession(0)
		foreign.UserId = 2
		database := datamocks.NewDatabase(t)
		database.On("GetUserBySubject", mock.Anything, mock.Anything, "user-1").Return(enabledUser, nil)
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sid).Return(foreign, nil)

		verdict, err := AccessToken(context.Background(), database, sessionBound, nil, checkedAt)

		require.NoError(t, err)
		assert.Equal(t, SessionOfAnotherUser, verdict.Refusal)
	})

	t.Run("a sid-less token needs no settings", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetUserBySubject", mock.Anything, mock.Anything, "user-1").Return(enabledUser, nil)

		verdict, err := AccessToken(context.Background(), database,
			oauth.JwtToken{Claims: map[string]interface{}{"auth_time": float64(1), "sub": "user-1"}}, nil, checkedAt)

		require.NoError(t, err)
		assert.True(t, verdict.Live())
	})
}

// The subject is read trimmed, and a blank one is none, so a subject with surrounding whitespace
// names the same user to the check as to reqctx's readers.
func TestSubject(t *testing.T) {
	for _, sub := range []string{"user-1", " user-1", "user-1\t", "\n user-1 "} {
		subject, ok := Subject(oauth.JwtToken{Claims: map[string]interface{}{"sub": sub}})
		assert.Truef(t, ok, "sub %q", sub)
		assert.Equalf(t, "user-1", subject, "sub %q", sub)
	}

	for _, claims := range []map[string]interface{}{{}, {"sub": ""}, {"sub": " \t "}, {"sub": 42}} {
		subject, ok := Subject(oauth.JwtToken{Claims: claims})
		assert.Falsef(t, ok, "claims %v", claims)
		assert.Emptyf(t, subject, "claims %v", claims)
	}
}
