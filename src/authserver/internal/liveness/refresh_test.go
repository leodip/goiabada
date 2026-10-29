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

const familyJti = "family-1"

func TestFindRefreshToken(t *testing.T) {
	t.Run("a code-descended token names its code's user, client and scope", func(t *testing.T) {
		row := &record.RefreshToken{RefreshTokenJti: "jti-1", CodeId: sql.NullInt64{Int64: 11, Valid: true}}
		database := datamocks.NewDatabase(t)
		database.On("GetRefreshTokenByJti", mock.Anything, (*sql.Tx)(nil), "jti-1").Return(row, nil).Once()
		database.On("RefreshTokenLoadCode", mock.Anything, (*sql.Tx)(nil), row).Return(nil).Once().
			Run(func(args mock.Arguments) {
				args.Get(2).(*record.RefreshToken).Code = record.Code{Id: 11, ClientId: 4, UserId: 1, Scope: "openid email"}
			})
		database.On("CodeLoadUser", mock.Anything, (*sql.Tx)(nil), &row.Code).Return(nil).Once().
			Run(func(args mock.Arguments) {
				args.Get(2).(*record.Code).User = record.User{Id: 1, Subject: "user-1", Enabled: true}
			})

		stored, err := FindRefreshToken(context.Background(), database, oauth.JwtToken{Claims: map[string]interface{}{"jti": "jti-1"}})

		require.NoError(t, err)
		require.NotNil(t, stored)
		assert.Same(t, row, stored.Row)
		assert.False(t, stored.IsROPC)
		assert.Equal(t, int64(4), stored.ClientId)
		assert.Equal(t, int64(1), stored.UserId)
		assert.Equal(t, "openid email", stored.Scope)
		require.NotNil(t, stored.User)
		assert.Equal(t, "user-1", stored.User.Subject)
	})

	t.Run("a password grant's token names the user, client and scope on its own row", func(t *testing.T) {
		row := &record.RefreshToken{
			RefreshTokenJti: "jti-1",
			UserId:          sql.NullInt64{Int64: 2, Valid: true},
			ClientId:        sql.NullInt64{Int64: 5, Valid: true},
			Scope:           "openid profile",
		}
		database := datamocks.NewDatabase(t)
		database.On("GetRefreshTokenByJti", mock.Anything, (*sql.Tx)(nil), "jti-1").Return(row, nil).Once()
		database.On("RefreshTokenLoadUser", mock.Anything, (*sql.Tx)(nil), row).Return(nil).Once().
			Run(func(args mock.Arguments) {
				args.Get(2).(*record.RefreshToken).User = record.User{Id: 2, Subject: "user-2", Enabled: true}
			})
		database.On("RefreshTokenLoadClient", mock.Anything, (*sql.Tx)(nil), row).Return(nil).Once()

		stored, err := FindRefreshToken(context.Background(), database, oauth.JwtToken{Claims: map[string]interface{}{"jti": "jti-1"}})

		require.NoError(t, err)
		require.NotNil(t, stored)
		assert.Same(t, row, stored.Row)
		assert.True(t, stored.IsROPC)
		assert.Equal(t, int64(5), stored.ClientId)
		assert.Equal(t, int64(2), stored.UserId)
		assert.Equal(t, "openid profile", stored.Scope)
		require.NotNil(t, stored.User)
		assert.Equal(t, "user-2", stored.User.Subject)
	})

	t.Run("a jti with no row is no token, and nothing more is read", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetRefreshTokenByJti", mock.Anything, (*sql.Tx)(nil), "jti-1").Return(nil, nil).Once()

		stored, err := FindRefreshToken(context.Background(), database, oauth.JwtToken{Claims: map[string]interface{}{"jti": "jti-1"}})

		require.NoError(t, err)
		assert.Nil(t, stored)
	})

	t.Run("a token without jti is a fault, read nowhere", func(t *testing.T) {
		database := datamocks.NewDatabase(t)

		stored, err := FindRefreshToken(context.Background(), database, oauth.JwtToken{Claims: map[string]interface{}{"typ": "Refresh"}})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not contain a jti claim")
		assert.Nil(t, stored)
	})

	down := errors.New("the database is down")
	faults := []struct {
		label  string
		ropc   bool
		failOn string
	}{
		{label: "reading the row fails", failOn: "GetRefreshTokenByJti"},
		{label: "loading the code fails", failOn: "RefreshTokenLoadCode"},
		{label: "loading the code's user fails", failOn: "CodeLoadUser"},
		{label: "loading a password grant's user fails", ropc: true, failOn: "RefreshTokenLoadUser"},
		{label: "loading a password grant's client fails", ropc: true, failOn: "RefreshTokenLoadClient"},
	}
	for _, f := range faults {
		t.Run(f.label, func(t *testing.T) {
			row := &record.RefreshToken{RefreshTokenJti: "jti-1", CodeId: sql.NullInt64{Int64: 11, Valid: true}}
			calls := []string{"GetRefreshTokenByJti", "RefreshTokenLoadCode", "CodeLoadUser"}
			if f.ropc {
				row = &record.RefreshToken{RefreshTokenJti: "jti-1",
					UserId: sql.NullInt64{Int64: 2, Valid: true}, ClientId: sql.NullInt64{Int64: 5, Valid: true}}
				calls = []string{"GetRefreshTokenByJti", "RefreshTokenLoadUser", "RefreshTokenLoadClient"}
			}
			database := datamocks.NewDatabase(t)
			for _, call := range calls {
				var err error
				if call == f.failOn {
					err = down
				}
				switch call {
				case "GetRefreshTokenByJti":
					if err != nil {
						database.On(call, mock.Anything, mock.Anything, "jti-1").Return(nil, err).Once()
					} else {
						database.On(call, mock.Anything, mock.Anything, "jti-1").Return(row, nil).Once()
					}
				default:
					database.On(call, mock.Anything, mock.Anything, mock.Anything).Return(err).Once()
				}
				if call == f.failOn {
					break
				}
			}

			stored, err := FindRefreshToken(context.Background(), database, oauth.JwtToken{Claims: map[string]interface{}{"jti": "jti-1"}})

			require.ErrorIs(t, err, down)
			assert.Nil(t, stored)
		})
	}
}

// codeDescended is a live session-bound token of user 1, descended from code 11 of client 4 through
// session sid, everything on generation 2.
func codeDescended() *StoredRefreshToken {
	user := &record.User{Id: 1, Subject: "user-1", Enabled: true, AuthStateGeneration: 2}
	return &StoredRefreshToken{
		Row: &record.RefreshToken{
			RefreshTokenJti:      "jti-1",
			FirstRefreshTokenJti: familyJti,
			CodeId:               sql.NullInt64{Int64: 11, Valid: true},
			Code: record.Code{Id: 11, ClientId: 4, UserId: 1, SessionIdentifier: sid,
				CodeChallenge: sql.NullString{String: "challenge", Valid: true}, AuthStateGeneration: 2},
			SessionIdentifier:   sid,
			AuthStateGeneration: 2,
		},
		ClientId: 4,
		UserId:   1,
		User:     user,
		Scope:    "openid",
	}
}

// passwordGrant is a live token of user 1 from the password grant of client 4: offline, on no code
// and no session.
func passwordGrant() *StoredRefreshToken {
	return &StoredRefreshToken{
		Row: &record.RefreshToken{
			RefreshTokenJti:      "jti-1",
			FirstRefreshTokenJti: familyJti,
			UserId:               sql.NullInt64{Int64: 1, Valid: true},
			ClientId:             sql.NullInt64{Int64: 4, Valid: true},
			AuthenticatedAt:      sql.NullTime{Time: checkedAt.Add(-time.Hour), Valid: true},
			AuthStateGeneration:  2,
		},
		IsROPC:   true,
		ClientId: 4,
		UserId:   1,
		User:     &record.User{Id: 1, Subject: "user-1", Enabled: true, AuthStateGeneration: 2},
		Scope:    "openid",
	}
}

func sessionBoundClaims() map[string]interface{} {
	return map[string]interface{}{"jti": "jti-1", "typ": "Refresh"}
}

// offlineClaims is an offline token whose maximum lifetime ends at maxLifetime.
func offlineClaims(maxLifetime time.Time) map[string]interface{} {
	return map[string]interface{}{"jti": "jti-1", "typ": "Offline", "offline_access_max_lifetime": float64(maxLifetime.Unix())}
}

func TestRefreshToken(t *testing.T) {
	inAnHour := checkedAt.Add(time.Hour)

	sessionOfUser := func(userId int64) *record.UserSession {
		session := liveSession(2)
		session.UserId = userId
		return session
	}
	idleSession := liveSession(2)
	idleSession.LastAccessed = checkedAt.Add(-2 * time.Hour)
	pastMaxLifetime := liveSession(2)
	pastMaxLifetime.Started = checkedAt.Add(-25 * time.Hour)

	recorded, notRecorded := true, false

	tests := []struct {
		label  string
		stored func() *StoredRefreshToken
		claims map[string]interface{}
		// family is what the family's revocation record answers; nil means it is never read.
		family *bool
		// readsSession names the session the check looks up, "" for none; session is what it finds.
		readsSession string
		session      *record.UserSession
		want         RefreshRefusal
	}{
		{
			label:  "a live session-bound token",
			stored: codeDescended, claims: sessionBoundClaims(),
			family: &notRecorded, readsSession: sid, session: liveSession(2),
			want: RefreshLive,
		},
		{
			label:  "a live offline token whose session is gone",
			stored: codeDescended, claims: offlineClaims(inAnHour),
			family: &notRecorded, readsSession: sid,
			want: RefreshLive,
		},
		{
			label:  "a live offline token whose session is its user's",
			stored: codeDescended, claims: offlineClaims(inAnHour),
			family: &notRecorded, readsSession: sid, session: sessionOfUser(1),
			want: RefreshLive,
		},
		{
			// An offline token's own row carries no session: the code's is the grant's.
			label: "an offline token's session is its code's",
			stored: func() *StoredRefreshToken {
				s := codeDescended()
				s.Row.SessionIdentifier = ""
				s.Row.Code.SessionIdentifier = "code-sid"
				return s
			},
			claims: offlineClaims(inAnHour),
			family: &notRecorded, readsSession: "code-sid", session: sessionOfUser(2),
			want: RefreshSessionOfAnotherUser,
		},
		{
			label: "an offline token whose code names no session reads none",
			stored: func() *StoredRefreshToken {
				s := codeDescended()
				s.Row.Code.SessionIdentifier = ""
				return s
			},
			claims: offlineClaims(inAnHour),
			family: &notRecorded,
			want:   RefreshLive,
		},
		{
			label:  "a live password grant token reads no session",
			stored: passwordGrant, claims: offlineClaims(inAnHour),
			family: &notRecorded,
			want:   RefreshLive,
		},

		// The user, the generation, the authentication instant and the code are read off what was
		// loaded with the row, and refuse before anything else is read.
		{
			label: "a disabled user",
			stored: func() *StoredRefreshToken {
				s := codeDescended()
				s.User.Enabled = false
				return s
			},
			claims: sessionBoundClaims(),
			want:   RefreshUserDisabled,
		},
		{
			// A user row that is gone loads as the zero user, who is not enabled.
			label: "a user that is gone",
			stored: func() *StoredRefreshToken {
				s := codeDescended()
				s.User = &record.User{}
				return s
			},
			claims: sessionBoundClaims(),
			want:   RefreshUserDisabled,
		},
		{
			label: "a password grant's disabled user",
			stored: func() *StoredRefreshToken {
				s := passwordGrant()
				s.User.Enabled = false
				return s
			},
			claims: offlineClaims(inAnHour),
			want:   RefreshUserDisabled,
		},
		{
			label: "the user's generation has moved past the token's",
			stored: func() *StoredRefreshToken {
				s := codeDescended()
				s.User.AuthStateGeneration = 3
				return s
			},
			claims: sessionBoundClaims(),
			want:   RefreshGenerationSuperseded,
		},
		{
			label: "the token's generation is ahead of the user's",
			stored: func() *StoredRefreshToken {
				s := passwordGrant()
				s.Row.AuthStateGeneration = 3
				return s
			},
			claims: offlineClaims(inAnHour),
			want:   RefreshGenerationSuperseded,
		},
		{
			// A password change promotes the preserved session's tokens while their codes stay
			// behind: the row's generation decides, never the code's.
			label: "a promoted token whose code is on the old generation",
			stored: func() *StoredRefreshToken {
				s := codeDescended()
				s.Row.Code.AuthStateGeneration = 1
				return s
			},
			claims: sessionBoundClaims(),
			family: &notRecorded, readsSession: sid, session: liveSession(2),
			want: RefreshLive,
		},
		{
			label: "a password grant token with no authentication instant",
			stored: func() *StoredRefreshToken {
				s := passwordGrant()
				s.Row.AuthenticatedAt = sql.NullTime{}
				return s
			},
			claims: offlineClaims(inAnHour),
			want:   RefreshNoAuthenticationInstant,
		},
		{
			// The instant of a code-descended token is on its code, so its row needs none.
			label:  "a code-descended token with no instant on its row",
			stored: codeDescended, claims: sessionBoundClaims(),
			family: &notRecorded, readsSession: sid, session: liveSession(2),
			want: RefreshLive,
		},
		{
			label: "a revoked code",
			stored: func() *StoredRefreshToken {
				s := codeDescended()
				s.Row.Code.Revoked = true
				return s
			},
			claims: offlineClaims(inAnHour),
			want:   RefreshCodeRevoked,
		},
		{
			label: "a disabled user's token of a revoked code",
			stored: func() *StoredRefreshToken {
				s := codeDescended()
				s.User.Enabled = false
				s.Row.Code.Revoked = true
				return s
			},
			claims: sessionBoundClaims(),
			want:   RefreshUserDisabled,
		},

		// The family's revocation record, then the session or the offline bounds.
		{
			label:  "a family recorded as revoked",
			stored: codeDescended, claims: sessionBoundClaims(),
			family: &recorded,
			want:   RefreshFamilyRevoked,
		},
		{
			label:  "a password grant family recorded as revoked",
			stored: passwordGrant, claims: offlineClaims(inAnHour),
			family: &recorded,
			want:   RefreshFamilyRevoked,
		},
		{
			label:  "a session that is gone",
			stored: codeDescended, claims: sessionBoundClaims(),
			family: &notRecorded, readsSession: sid,
			want: RefreshSessionNotFound,
		},
		{
			label:  "a session past its idle timeout",
			stored: codeDescended, claims: sessionBoundClaims(),
			family: &notRecorded, readsSession: sid, session: idleSession,
			want: RefreshSessionExpired,
		},
		{
			label:  "a session past its maximum lifetime",
			stored: codeDescended, claims: sessionBoundClaims(),
			family: &notRecorded, readsSession: sid, session: pastMaxLifetime,
			want: RefreshSessionExpired,
		},
		{
			label:  "a session of another user",
			stored: codeDescended, claims: sessionBoundClaims(),
			family: &notRecorded, readsSession: sid, session: sessionOfUser(2),
			want: RefreshSessionOfAnotherUser,
		},
		{
			// A session-bound token's session is its own row's.
			label: "a session-bound token's session is its row's",
			stored: func() *StoredRefreshToken {
				s := codeDescended()
				s.Row.SessionIdentifier = "row-sid"
				return s
			},
			claims: sessionBoundClaims(),
			family: &notRecorded, readsSession: "row-sid",
			want: RefreshSessionNotFound,
		},
		{
			label:  "an offline token past its maximum lifetime reads no session",
			stored: codeDescended, claims: offlineClaims(checkedAt.Add(-time.Second)),
			family: &notRecorded,
			want:   RefreshOfflineExpired,
		},
		{
			label:  "an offline token at the last second of its maximum lifetime",
			stored: codeDescended, claims: offlineClaims(checkedAt),
			family: &notRecorded, readsSession: sid,
			want: RefreshLive,
		},
		{
			label:  "an offline token whose code's session is another user's",
			stored: codeDescended, claims: offlineClaims(inAnHour),
			family: &notRecorded, readsSession: sid, session: sessionOfUser(2),
			want: RefreshSessionOfAnotherUser,
		},

		// A revoked row is refused last, and its family's record is not read: below every other
		// refusal, so the refresh grant can tell a replay of an otherwise intact grant from the rest.
		{
			label: "a revoked token of an intact grant",
			stored: func() *StoredRefreshToken {
				s := codeDescended()
				s.Row.Revoked = true
				return s
			},
			claims: sessionBoundClaims(), readsSession: sid, session: liveSession(2),
			want: RefreshTokenRevoked,
		},
		{
			label: "a revoked password grant token",
			stored: func() *StoredRefreshToken {
				s := passwordGrant()
				s.Row.Revoked = true
				return s
			},
			claims: offlineClaims(inAnHour),
			want:   RefreshTokenRevoked,
		},
		{
			label: "a revoked token whose session is gone",
			stored: func() *StoredRefreshToken {
				s := codeDescended()
				s.Row.Revoked = true
				return s
			},
			claims: sessionBoundClaims(), readsSession: sid,
			want: RefreshSessionNotFound,
		},
		{
			label: "a revoked token of a disabled user",
			stored: func() *StoredRefreshToken {
				s := codeDescended()
				s.Row.Revoked = true
				s.User.Enabled = false
				return s
			},
			claims: sessionBoundClaims(),
			want:   RefreshUserDisabled,
		},
	}

	for _, tc := range tests {
		t.Run(tc.label, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			if tc.family != nil {
				database.On("IsRefreshTokenFamilyRevoked", mock.Anything, (*sql.Tx)(nil), familyJti).Return(*tc.family, nil).Once()
			}
			if tc.readsSession != "" {
				if tc.session == nil {
					database.On("GetUserSessionBySessionIdentifier", mock.Anything, (*sql.Tx)(nil), tc.readsSession).Return(nil, nil).Once()
				} else {
					database.On("GetUserSessionBySessionIdentifier", mock.Anything, (*sql.Tx)(nil), tc.readsSession).Return(tc.session, nil).Once()
				}
			}

			refusal, err := RefreshToken(context.Background(), database, tc.stored(), oauth.JwtToken{Claims: tc.claims}, settings, checkedAt)

			require.NoError(t, err)
			assert.Equal(t, tc.want, refusal)
		})
	}
}

// A fault is an error and never a refusal, and the refusal that comes with it is not live.
func TestRefreshToken_Faults(t *testing.T) {
	down := errors.New("the database is down")
	inAnHour := checkedAt.Add(time.Hour)

	t.Run("reading the family's record fails", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, familyJti).Return(false, down)

		refusal, err := RefreshToken(context.Background(), database, codeDescended(),
			oauth.JwtToken{Claims: sessionBoundClaims()}, settings, checkedAt)

		require.ErrorIs(t, err, down)
		assert.NotEqual(t, RefreshLive, refusal)
	})

	t.Run("reading the session fails", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, familyJti).Return(false, nil)
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sid).Return(nil, down)

		refusal, err := RefreshToken(context.Background(), database, codeDescended(),
			oauth.JwtToken{Claims: sessionBoundClaims()}, settings, checkedAt)

		require.ErrorIs(t, err, down)
		assert.NotEqual(t, RefreshLive, refusal)
	})

	t.Run("reading an offline token's session fails", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, familyJti).Return(false, nil)
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sid).Return(nil, down)

		refusal, err := RefreshToken(context.Background(), database, codeDescended(),
			oauth.JwtToken{Claims: offlineClaims(inAnHour)}, settings, checkedAt)

		require.ErrorIs(t, err, down)
		assert.NotEqual(t, RefreshLive, refusal)
	})

	t.Run("an offline token without its maximum lifetime", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, familyJti).Return(false, nil)

		refusal, err := RefreshToken(context.Background(), database, codeDescended(),
			oauth.JwtToken{Claims: map[string]interface{}{"jti": "jti-1", "typ": "Offline"}}, settings, checkedAt)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not contain an offline_access_max_lifetime claim")
		assert.NotEqual(t, RefreshLive, refusal)
	})

	for _, typ := range []interface{}{nil, "", "Bearer", "ID", "refresh"} {
		claims := map[string]interface{}{"jti": "jti-1"}
		if typ != nil {
			claims["typ"] = typ
		}
		t.Run("a token typed neither Refresh nor Offline", func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, familyJti).Return(false, nil)

			refusal, err := RefreshToken(context.Background(), database, codeDescended(),
				oauth.JwtToken{Claims: claims}, settings, checkedAt)

			require.Errorf(t, err, "typ %v", typ)
			assert.Contains(t, err.Error(), "does not contain a valid typ claim")
			assert.NotEqual(t, RefreshLive, refusal)
		})
	}

	t.Run("no settings to measure the session against", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, familyJti).Return(false, nil)
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, sid).Return(liveSession(2), nil)

		refusal, err := RefreshToken(context.Background(), database, codeDescended(),
			oauth.JwtToken{Claims: sessionBoundClaims()}, nil, checkedAt)

		require.ErrorIs(t, err, ErrNoSettings)
		assert.NotEqual(t, RefreshLive, refusal)
	})

	// Settings are needed only for a session's bounds.
	t.Run("an offline token needs no settings", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("IsRefreshTokenFamilyRevoked", mock.Anything, mock.Anything, familyJti).Return(false, nil)

		refusal, err := RefreshToken(context.Background(), database, passwordGrant(),
			oauth.JwtToken{Claims: offlineClaims(inAnHour)}, nil, checkedAt)

		require.NoError(t, err)
		assert.Equal(t, RefreshLive, refusal)
	})
}
