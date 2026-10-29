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
		Issuer:                          testIssuer,
		UserSessionIdleTimeoutInSeconds: 3600,
		UserSessionMaxLifetimeInSeconds: 86400,
	}
)

const (
	sid = "sid-1"
	// testIssuer is the configured issuer every token in these tests names, unless a row says
	// otherwise.
	testIssuer = "https://auth.example.com"
	// clientIdentifier is the client every token in these tests was issued to.
	clientIdentifier = "client-1"
)

// enabledClient is the client every token names: it exists and is enabled.
var enabledClient = &record.Client{Id: 7, ClientIdentifier: clientIdentifier, Enabled: true}

// accessToken is an access token as issuance mints it since #676: the at+jwt header, the configured
// issuer and the client it was issued to, with claims on top, which may replace any of the three.
func accessToken(claims map[string]interface{}) oauth.JwtToken {
	all := map[string]interface{}{"iss": testIssuer, "client_id": clientIdentifier}
	for name, value := range claims {
		all[name] = value
	}
	return oauth.JwtToken{Header: map[string]interface{}{"alg": "RS256", "typ": "at+jwt"}, Claims: all}
}

// expectEnabledClient has the client lookup find enabledClient, once.
func expectEnabledClient(database *datamocks.Database) {
	database.On("GetClientByClientIdentifier", mock.Anything, (*sql.Tx)(nil), clientIdentifier).Return(enabledClient, nil).Once()
}

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
			expectEnabledClient(database)
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

			verdict, err := AccessToken(context.Background(), database, accessToken(tc.claims), settings, checkedAt)

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

// The token's own RFC 9068 checks (#676 decisions 2, 4 and 6): the at+jwt header, the configured
// issuer exactly, and a client that exists and is enabled. Each applies to a client's token as much
// as to a user's, and a refusal on the header or the issuer reads nothing.
func TestAccessToken_RFC9068(t *testing.T) {
	enabledUser := &record.User{Id: 1, Subject: "user-1", Enabled: true}
	disabledClient := &record.Client{Id: 7, ClientIdentifier: clientIdentifier, Enabled: false}
	userToken := map[string]interface{}{"auth_time": float64(1), "sub": "user-1"}
	clientToken := map[string]interface{}{"sub": clientIdentifier}

	type lookup int
	const (
		notRead lookup = iota
		finds
		findsNone
		findsDisabled
	)

	tests := []struct {
		label string
		// header replaces the token's when set; noHeader leaves it nil.
		header   map[string]interface{}
		noHeader bool
		claims   map[string]interface{}
		// without lists claims the token does not carry.
		without     []string
		client      lookup
		readsUser   bool
		wantRefusal Refusal
	}{
		{label: "a user's token as issued", claims: userToken, client: finds, readsUser: true, wantRefusal: Live},
		{label: "a client's token as issued", claims: clientToken, client: finds, wantRefusal: Live},

		// RFC 9068 section 4: the header is at+jwt or application/at+jwt, and a media type is
		// compared without regard to case (RFC 7515 section 4.1.9).
		{label: "the header's typ spelled as a media type", header: map[string]interface{}{"alg": "RS256", "typ": "application/at+jwt"},
			claims: userToken, client: finds, readsUser: true, wantRefusal: Live},
		{label: "the header's typ in capitals", header: map[string]interface{}{"alg": "RS256", "typ": "AT+JWT"},
			claims: userToken, client: finds, readsUser: true, wantRefusal: Live},
		// A token issued before the upgrade (#676 decision 4).
		{label: "a JWT header", header: map[string]interface{}{"alg": "RS256", "typ": "JWT"},
			claims: userToken, wantRefusal: NotAnAccessTokenHeader},
		{label: "a JWT header on a client's token", header: map[string]interface{}{"alg": "RS256", "typ": "JWT"},
			claims: clientToken, wantRefusal: NotAnAccessTokenHeader},
		{label: "a header without typ", header: map[string]interface{}{"alg": "RS256"},
			claims: userToken, wantRefusal: NotAnAccessTokenHeader},
		{label: "no header read", noHeader: true, claims: userToken, wantRefusal: NotAnAccessTokenHeader},
		{label: "a typ that is not a string", header: map[string]interface{}{"alg": "RS256", "typ": 1},
			claims: userToken, wantRefusal: NotAnAccessTokenHeader},

		// The issuer exactly as configured: no trailing slash, no case folding.
		{label: "another issuer", claims: map[string]interface{}{"auth_time": float64(1), "sub": "user-1", "iss": "https://other.example.com"},
			wantRefusal: ForeignIssuer},
		{label: "the issuer with a trailing slash", claims: map[string]interface{}{"auth_time": float64(1), "sub": "user-1", "iss": testIssuer + "/"},
			wantRefusal: ForeignIssuer},
		{label: "the issuer in capitals", claims: map[string]interface{}{"sub": clientIdentifier, "iss": "HTTPS://AUTH.EXAMPLE.COM"},
			wantRefusal: ForeignIssuer},
		{label: "no issuer", claims: userToken, without: []string{"iss"}, wantRefusal: ForeignIssuer},

		// The client the token names (decision 6).
		{label: "no client_id", claims: userToken, without: []string{"client_id"}, wantRefusal: ClientNotFound},
		{label: "a client that is gone", claims: userToken, client: findsNone, wantRefusal: ClientNotFound},
		{label: "a disabled client, a user's token", claims: userToken, client: findsDisabled, wantRefusal: ClientDisabled},
		{label: "a disabled client, a client's token", claims: clientToken, client: findsDisabled, wantRefusal: ClientDisabled},
	}

	for _, tc := range tests {
		t.Run(tc.label, func(t *testing.T) {
			token := accessToken(tc.claims)
			switch {
			case tc.noHeader:
				token.Header = nil
			case tc.header != nil:
				token.Header = tc.header
			}
			for _, name := range tc.without {
				delete(token.Claims, name)
			}

			database := datamocks.NewDatabase(t)
			var wantClient *record.Client
			switch tc.client {
			case finds:
				expectEnabledClient(database)
				wantClient = enabledClient
			case findsNone:
				database.On("GetClientByClientIdentifier", mock.Anything, (*sql.Tx)(nil), clientIdentifier).Return(nil, nil).Once()
			case findsDisabled:
				database.On("GetClientByClientIdentifier", mock.Anything, (*sql.Tx)(nil), clientIdentifier).Return(disabledClient, nil).Once()
				wantClient = disabledClient
			}
			if tc.readsUser {
				database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), "user-1").Return(enabledUser, nil).Once()
			}

			verdict, err := AccessToken(context.Background(), database, token, settings, checkedAt)

			require.NoError(t, err)
			assert.Equal(t, tc.wantRefusal, verdict.Refusal, "refusal")
			assert.Equal(t, tc.wantRefusal == Live, verdict.Live(), "live")
			if wantClient == nil {
				assert.Nil(t, verdict.Client, "no client read")
			} else {
				assert.Same(t, wantClient, verdict.Client, "the client read")
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
		expectEnabledClient(database)
		database.On("GetUserBySubject", mock.Anything, mock.Anything, "user-1").Return(enabledUser, nil)
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sid).Return(nil, nil)

		verdict, err := AccessToken(context.Background(), database,
			accessToken(map[string]interface{}{"auth_time": float64(1), "sub": "user-1", "sid": sid}),
			settings, checkedAt)

		require.NoError(t, err)
		assert.Equal(t, sid, verdict.SessionIdentifier)
	})

	t.Run("a refusal before the session names none", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		expectEnabledClient(database)
		database.On("GetUserBySubject", mock.Anything, mock.Anything, "user-1").
			Return(&record.User{Id: 1, Subject: "user-1", Enabled: false}, nil)

		verdict, err := AccessToken(context.Background(), database,
			accessToken(map[string]interface{}{"auth_time": float64(1), "sub": "user-1", "sid": sid}),
			settings, checkedAt)

		require.NoError(t, err)
		assert.Equal(t, UserDisabled, verdict.Refusal)
		assert.Empty(t, verdict.SessionIdentifier)
	})
}

// A fault is an error and never a refusal: a caller must not answer a database failure as a dead
// token.
func TestAccessToken_Faults(t *testing.T) {
	sessionBound := accessToken(map[string]interface{}{"auth_time": float64(1), "sub": "user-1", "sid": sid})
	enabledUser := &record.User{Id: 1, Subject: "user-1", Enabled: true}

	t.Run("reading the user fails", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		expectEnabledClient(database)
		database.On("GetUserBySubject", mock.Anything, mock.Anything, "user-1").Return(nil, errors.New("the database is down"))

		verdict, err := AccessToken(context.Background(), database, sessionBound, settings, checkedAt)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "the database is down")
		assert.False(t, verdict.Live())
		assert.Empty(t, verdict.SessionIdentifier, "the user's read names no session")
	})

	t.Run("reading the session fails", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		expectEnabledClient(database)
		database.On("GetUserBySubject", mock.Anything, mock.Anything, "user-1").Return(enabledUser, nil)
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sid).Return(nil, errors.New("the database is down"))

		verdict, err := AccessToken(context.Background(), database, sessionBound, settings, checkedAt)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "the database is down")
		assert.False(t, verdict.Live())
		assert.Equal(t, sid, verdict.SessionIdentifier)
	})

	t.Run("reading the client fails", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, clientIdentifier).
			Return(nil, errors.New("the database is down"))

		verdict, err := AccessToken(context.Background(), database, sessionBound, settings, checkedAt)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "the database is down")
		assert.False(t, verdict.Live())
	})

	// The issuer is checked against the settings before anything is read, so a token of any kind
	// is a fault without them. Only the header, which needs none, is refused first.
	t.Run("no settings to check the issuer against", func(t *testing.T) {
		for label, token := range map[string]oauth.JwtToken{
			"session-bound": sessionBound,
			"sid-less":      accessToken(map[string]interface{}{"auth_time": float64(1), "sub": "user-1"}),
			"a client's":    accessToken(map[string]interface{}{"sub": clientIdentifier}),
		} {
			verdict, err := AccessToken(context.Background(), datamocks.NewDatabase(t), token, nil, checkedAt)

			require.ErrorIs(t, err, ErrNoSettings, label)
			assert.False(t, verdict.Live(), label)
		}
	})

	t.Run("a header that is not at+jwt is refused without settings", func(t *testing.T) {
		token := sessionBound
		token.Header = map[string]interface{}{"alg": "RS256", "typ": "JWT"}

		verdict, err := AccessToken(context.Background(), datamocks.NewDatabase(t), token, nil, checkedAt)

		require.NoError(t, err)
		assert.Equal(t, NotAnAccessTokenHeader, verdict.Refusal)
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
