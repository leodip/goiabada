package datatests

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/otpcredential"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/usersession"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A removal of the authenticator lowers each of the user's sessions to what the password alone
// reached: amr "pwd", level 2 optional at most, and auth_time back to the time the password was
// entered. A session that already claims no more than that is not touched, and neither is another
// user's (#542).
func TestLowerUserSessionsToPassword_LowersWhatClaimsMoreThanAPassword(t *testing.T) {
	ctx := context.Background()
	passwordAt := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Microsecond)
	codeAt := passwordAt.Add(90 * time.Minute)
	otherAt := passwordAt.Add(30 * time.Minute)

	user := createTestUser(t)
	someoneElse := createTestUser(t)
	seed := func(userId int64, acr record.AcrLevel, methods string, authTime time.Time) *record.UserSession {
		session := createTestUserSession(t, userId)
		session.AcrLevel, session.AuthMethods, session.AuthTime, session.PasswordAuthTime = acr, methods, authTime, passwordAt
		require.NoError(t, database.UpdateUserSession(ctx, nil, session))
		return session
	}

	stepUpToLevel3 := seed(user.Id, record.AcrLevel2Mandatory, "pwd otp", codeAt)
	codeAtLevel2 := seed(user.Id, record.AcrLevel2Optional, "pwd otp", codeAt)
	// auth_time differs from the password's only so a write to it would show.
	passwordOnly := seed(user.Id, record.AcrLevel2Optional, "pwd", otherAt)
	levelOne := seed(user.Id, record.AcrLevel1, "pwd", otherAt)
	notThisUser := seed(someoneElse.Id, record.AcrLevel2Mandatory, "pwd otp", codeAt)

	require.NoError(t, database.RunInTransaction(ctx, func(tx *sql.Tx) error {
		return database.LowerUserSessionsToPassword(ctx, tx, user.Id, "pwd")
	}))

	for _, tc := range []struct {
		name     string
		session  *record.UserSession
		acr      record.AcrLevel
		methods  string
		authTime time.Time
	}{
		{"a level 3 session that stepped up with a code", stepUpToLevel3, record.AcrLevel2Optional, "pwd", passwordAt},
		{"a level 2 session that entered a code", codeAtLevel2, record.AcrLevel2Optional, "pwd", passwordAt},
		{"a session that claims only the password", passwordOnly, record.AcrLevel2Optional, "pwd", otherAt},
		{"a level 1 session", levelOne, record.AcrLevel1, "pwd", otherAt},
		{"another user's session", notThisUser, record.AcrLevel2Mandatory, "pwd otp", codeAt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read, err := database.GetUserSessionById(ctx, nil, tc.session.Id)
			require.NoError(t, err)
			assert.Equal(t, tc.acr, read.AcrLevel)
			assert.Equal(t, tc.methods, read.AuthMethods)
			assert.Truef(t, read.AuthTime.Equal(tc.authTime), "auth_time %v, want %v", read.AuthTime, tc.authTime)
			assert.True(t, read.PasswordAuthTime.Equal(passwordAt), "the password's instant never moves")
		})
	}
}

// A sign-in binding a code to the session holds the user's row, as its claim check takes it, and the
// session's, with the step-up written and not yet committed, when the authenticator is removed. The
// removal takes the user's row first, so it waits, and then lowers what the sign-in wrote rather than
// running past it. The session's row alone would not do: the session claimed no code until the
// sign-in's write commits, so PostgreSQL's UPDATE does not even wait for a row it would not have
// lowered as committed (#542).
func TestRemove_WaitsForABindHoldingTheUserRowAndLowersWhatItWrote(t *testing.T) {
	ctx := context.Background()
	other := secondDatabase(t)
	passwordAt := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	codeAt := passwordAt.Add(30 * time.Minute)

	user := createTestUser(t)
	user.OTPEnabled = true
	user.OTPSecretEncrypted = []byte("the authenticator's seed")
	require.NoError(t, database.UpdateUser(ctx, nil, user))
	user, err := database.GetUserById(ctx, nil, user.Id)
	require.NoError(t, err)

	session := createTestUserSession(t, user.Id)
	session.AcrLevel, session.AuthMethods, session.AuthTime, session.PasswordAuthTime = record.AcrLevel1, "pwd", passwordAt, passwordAt
	require.NoError(t, database.UpdateUserSession(ctx, nil, session))

	tx, err := database.BeginTransaction(ctx)
	require.NoError(t, err)
	defer func() { _ = database.RollbackTransaction(ctx, tx) }()

	// The bind's statements, in BindUserSession's order: the user's row for the claim check, the
	// session's row, the read, and the step-up written whole.
	require.NoError(t, database.AcquireUserRow(ctx, tx, user.Id))
	live, err := database.AcquireUserSessionRow(ctx, tx, session.SessionIdentifier)
	require.NoError(t, err)
	require.True(t, live)
	bound, err := database.GetUserSessionBySessionIdentifier(ctx, tx, session.SessionIdentifier)
	require.NoError(t, err)
	bound.AcrLevel, bound.AuthMethods, bound.AuthTime = record.AcrLevel2Mandatory, "pwd otp", codeAt
	require.NoError(t, database.UpdateUserSession(ctx, tx, bound))

	removal := goBlocked(t, "the removal", tx, func(reached func()) error {
		reached()
		removed, removeErr := otpcredential.Remove(ctx, other, user)
		if removeErr == nil && !removed {
			return errors.New("the removal matched no authenticator")
		}
		return removeErr
	})
	removal.requireBlocked(t)
	removal.requireStillWaiting(t)
	require.NoError(t, database.CommitTransaction(ctx, tx))
	require.NoError(t, removal.await(t), "the removal waits for the bind and then commits")

	read, err := database.GetUserSessionById(ctx, nil, session.Id)
	require.NoError(t, err)
	assert.Equal(t, record.AcrLevel2Optional, read.AcrLevel, "the bind's level 3 is lowered")
	assert.Equal(t, "pwd", read.AuthMethods, "the bind's otp is lowered")
	assert.True(t, read.AuthTime.Equal(passwordAt), "auth_time is the password's again")
}

// The other order, which is finding 3 of #542's review: the removal has lowered the session and not
// committed when a bump arrives. The bump takes the row before it reads it, so it waits and then
// writes the whole row back from the lowered one; reading first, it wrote back the otp and the
// level 3 the removal had just taken away.
func TestBumpUserSession_WaitsForALoweringHoldingTheRow(t *testing.T) {
	ctx := context.Background()
	other := secondDatabase(t)
	passwordAt := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	codeAt := passwordAt.Add(30 * time.Minute)

	client := createTestClient(t)
	user := createTestUser(t)
	session := createTestUserSession(t, user.Id)
	session.AcrLevel, session.AuthMethods, session.AuthTime, session.PasswordAuthTime = record.AcrLevel2Mandatory, "pwd otp", codeAt, passwordAt
	require.NoError(t, database.UpdateUserSession(ctx, nil, session))

	tx, err := database.BeginTransaction(ctx)
	require.NoError(t, err)
	defer func() { _ = database.RollbackTransaction(ctx, tx) }()
	require.NoError(t, database.LowerUserSessionsToPassword(ctx, tx, user.Id, "pwd"))

	manager := usersession.NewManager(nil, "", other)
	bump := goBlocked(t, "the bump", tx, func(reached func()) error {
		reached()
		_, bumpErr := manager.BumpUserSession(ctx, session.SessionIdentifier, client.Id, "", "", "")
		return bumpErr
	})
	bump.requireBlocked(t)
	bump.requireStillWaiting(t)
	require.NoError(t, database.CommitTransaction(ctx, tx))
	require.NoError(t, bump.await(t))

	read, err := database.GetUserSessionById(ctx, nil, session.Id)
	require.NoError(t, err)
	assert.Equal(t, record.AcrLevel2Optional, read.AcrLevel, "the bump does not put level 3 back")
	assert.Equal(t, "pwd", read.AuthMethods, "the bump does not put otp back")
	assert.True(t, read.AuthTime.Equal(passwordAt), "the bump does not put the code's auth_time back")
}
