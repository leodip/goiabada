package datatests

import (
	"database/sql"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #139: THE FOREIGN KEYS OF A REFRESH TOKEN AND OF AN ASSOCIATION ROW ARE NEVER REWRITTEN.
//
// These two tags are not hygiene, and the reason they are load-bearing is invisible from the row
// state they protect. SQL Server re-checks a foreign key whenever its column appears in an
// UPDATE's SET list, unchanged value or not, by taking a shared lock on the parent row.
// UpdateRefreshToken and UpdateUserSessionClient are both full-row updates through sqlbuilder, so
// every column not tagged is in that list.
//
// What that cost. revokeRefreshTokens calls UpdateRefreshToken, and it is what EVERY session-side
// transaction on this branch ends with: the credential sweep, the two other revocation paths and
// the auth-code replay response. So each of them took a shared clients lock at its grant sweep,
// after it already held the session row and, through the session's cascade, that session's
// association rows. Against DeleteClient, which holds the clients row exclusively and is waiting
// to read those association rows, that closes a cycle, and the credential operation is the victim:
// the password does not change, the session it was ending survives, and the token it was revoking
// stays valid. BumpUserSession is the second instance, because it writes EVERY association the
// session has rather than only the one the ceremony is for, so a bump running for client A asks
// for client B's parent lock while a deletion of B is waiting for that session.
//
// The remedy removes the lock rather than ordering it, because a lock no statement names is one no
// reader of that code can be expected to order. Nothing anywhere reassigns any of these five
// columns: rotation constructs a new refresh token and copies them, which is what makes the family
// chain a chain, and an association is created when a session first reaches a client and deleted
// with the session.
//
// These tests fail on every engine when a tag is removed, rather than only on the one where the
// missing tag costs a deadlock. That is the point of them: the deadlock is measured in
// lock_order_client_delete_test.go, and this is what stops the tag being deleted as surplus by
// somebody reading the model alone.

func TestUpdateRefreshToken_TheKeysAreNotRewritten(t *testing.T) {
	original := createTestRefreshToken(t)

	otherClient := createTestClient(t)
	otherUser := createTestUser(t)
	otherCode := createTestCode(t, otherClient.Id, otherUser.Id)

	require.True(t, original.CodeId.Valid, "the fixture's token descends from a code")
	require.True(t, original.UserId.Valid, "the fixture's token names a user")
	require.True(t, original.ClientId.Valid, "the fixture's token names a client")
	require.NotEqual(t, original.CodeId.Int64, otherCode.Id, "the reassignment has to be a change")
	require.NotEqual(t, original.UserId.Int64, otherUser.Id, "the reassignment has to be a change")
	require.NotEqual(t, original.ClientId.Int64, otherClient.Id, "the reassignment has to be a change")

	wasCodeId, wasUserId, wasClientId := original.CodeId, original.UserId, original.ClientId

	original.CodeId = sql.NullInt64{Int64: otherCode.Id, Valid: true}
	original.UserId = sql.NullInt64{Int64: otherUser.Id, Valid: true}
	original.ClientId = sql.NullInt64{Int64: otherClient.Id, Valid: true}
	original.Scope = "rewritten_" + gofakeit.LetterN(6)
	original.Revoked = true

	require.NoError(t, database.UpdateRefreshToken(nil, original))

	stored, err := database.GetRefreshTokenById(nil, original.Id)
	require.NoError(t, err)
	require.NotNil(t, stored)

	assert.Equal(t, wasCodeId, stored.CodeId, "code_id must not be in the update set")
	assert.Equal(t, wasUserId, stored.UserId, "user_id must not be in the update set")
	assert.Equal(t, wasClientId, stored.ClientId, "client_id must not be in the update set")

	// And the ordinary columns still are, which is what makes the three above a targeted exclusion
	// rather than an update that quietly stopped writing anything.
	assert.Equal(t, original.Scope, stored.Scope, "the untagged columns must still be written")
	assert.True(t, stored.Revoked, "revocation is the write this statement exists for and must land")
}

func TestUpdateUserSessionClient_TheKeysAreNotRewritten(t *testing.T) {
	client := createTestClient(t)
	otherClient := createTestClient(t)
	user := createTestUser(t)
	session := createTestUserSession(t, user.Id)
	otherSession := createTestUserSession(t, user.Id)

	association := createTestUserSessionClientWithIds(t, session.Id, client.Id)

	moved := time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
	association.ClientId = otherClient.Id
	association.UserSessionId = otherSession.Id
	association.LastAccessed = moved

	require.NoError(t, database.UpdateUserSessionClient(nil, association))

	stored, err := database.GetUserSessionClientById(nil, association.Id)
	require.NoError(t, err)
	require.NotNil(t, stored)

	assert.Equal(t, client.Id, stored.ClientId, "client_id must not be in the update set")
	assert.Equal(t, session.Id, stored.UserSessionId, "user_session_id must not be in the update set")
	assert.WithinDuration(t, moved, stored.LastAccessed, time.Second,
		"the untagged columns must still be written: last_accessed is the whole reason a bump updates this row")
}
