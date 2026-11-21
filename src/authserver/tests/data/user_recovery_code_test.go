package datatests

import (
	"context"
	"database/sql"
	"sync"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A user's recovery codes (#257 decision 3): one row per code of the user's current set, stored as
// the code's SHA-256 in hex, and marked used rather than deleted. The data tier stores hashes and
// never sees a code, so these tests hand it hashes of their own.

// recoveryCodeHashes returns n distinct hashes in the stored form, 64 lowercase hex digits.
func recoveryCodeHashes(n int) []string {
	hashes := make([]string, n)
	for i := range hashes {
		hashes[i] = hashutil.HashString(fake.UUID())
	}
	return hashes
}

// replaceRecoveryCodes stores hashes as userID's set, in a transaction as the method requires.
func replaceRecoveryCodes(t *testing.T, userID int64, hashes []string) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, database.RunInTransaction(ctx, func(tx *sql.Tx) error {
		return database.ReplaceUserRecoveryCodes(ctx, tx, userID, hashes)
	}), "ReplaceUserRecoveryCodes")
}

func unusedRecoveryCodes(t *testing.T, userID int64) int {
	t.Helper()
	n, err := database.CountUnusedUserRecoveryCodes(context.Background(), nil, userID)
	require.NoError(t, err, "CountUnusedUserRecoveryCodes")
	return n
}

func useRecoveryCode(t *testing.T, userID int64, hash string) bool {
	t.Helper()
	used, err := database.TryUseUserRecoveryCode(context.Background(), nil, userID, hash)
	require.NoError(t, err, "TryUseUserRecoveryCode")
	return used
}

func TestReplaceUserRecoveryCodes_StoresTheSetUnused(t *testing.T) {
	user := createTestUser(t)
	other := createTestUser(t)
	hashes := recoveryCodeHashes(10)

	replaceRecoveryCodes(t, user.ID, hashes)

	assert.Equal(t, 10, unusedRecoveryCodes(t, user.ID), "every code of a new set is unused")
	assert.Equal(t, 0, unusedRecoveryCodes(t, other.ID), "another user has none")
	for _, hash := range hashes {
		assert.True(t, useRecoveryCode(t, user.ID, hash), "each stored hash is a code of the set")
	}
	assert.Equal(t, 0, unusedRecoveryCodes(t, user.ID))
}

// A new set replaces the old one whole: the old codes stop working at once, used or not, and the
// count is the new set's (#257 decisions 1 and 8).
func TestReplaceUserRecoveryCodes_ReplacesTheOldSet(t *testing.T) {
	user := createTestUser(t)
	old := recoveryCodeHashes(10)
	replaceRecoveryCodes(t, user.ID, old)
	require.True(t, useRecoveryCode(t, user.ID, old[0]))

	replacement := recoveryCodeHashes(10)
	replaceRecoveryCodes(t, user.ID, replacement)

	assert.Equal(t, 10, unusedRecoveryCodes(t, user.ID), "the new set's ten, and none of the old")
	for _, hash := range old[1:] {
		assert.False(t, useRecoveryCode(t, user.ID, hash), "an unused code of the old set is gone")
	}
	assert.True(t, useRecoveryCode(t, user.ID, replacement[3]), "the new set's codes work")
}

// The replacement leaves every other user's set as it was.
func TestReplaceUserRecoveryCodes_LeavesOtherUsersAlone(t *testing.T) {
	user := createTestUser(t)
	other := createTestUser(t)
	theirs := recoveryCodeHashes(10)
	replaceRecoveryCodes(t, other.ID, theirs)

	replaceRecoveryCodes(t, user.ID, recoveryCodeHashes(10))

	assert.Equal(t, 10, unusedRecoveryCodes(t, other.ID))
	assert.True(t, useRecoveryCode(t, other.ID, theirs[0]))
}

// The delete and the inserts are one replacement only inside a transaction: autocommitted, a
// failure between them would leave the user with no set, or with old and new together.
func TestReplaceUserRecoveryCodes_RequiresATransaction(t *testing.T) {
	user := createTestUser(t)
	hashes := recoveryCodeHashes(10)

	err := database.ReplaceUserRecoveryCodes(context.Background(), nil, user.ID, hashes)

	require.Error(t, err)
	assert.Equal(t, 0, unusedRecoveryCodes(t, user.ID), "and nothing was written")
}

// A set that cannot all be stored stores none of it: the same code twice is the key's refusal, and
// the transaction rolls back the old set's deletion with it.
func TestReplaceUserRecoveryCodes_ARefusedCodeRollsTheReplacementBack(t *testing.T) {
	user := createTestUser(t)
	old := recoveryCodeHashes(10)
	replaceRecoveryCodes(t, user.ID, old)

	duplicated := recoveryCodeHashes(9)
	duplicated = append(duplicated, duplicated[0])
	ctx := context.Background()
	err := database.RunInTransaction(ctx, func(tx *sql.Tx) error {
		return database.ReplaceUserRecoveryCodes(ctx, tx, user.ID, duplicated)
	})

	require.Error(t, err)
	assert.Equal(t, 10, unusedRecoveryCodes(t, user.ID), "the old set stands")
	assert.True(t, useRecoveryCode(t, user.ID, old[5]))
	assert.False(t, useRecoveryCode(t, user.ID, duplicated[1]))
}

func TestReplaceUserRecoveryCodes_RefusesAZeroUserID(t *testing.T) {
	ctx := context.Background()
	err := database.RunInTransaction(ctx, func(tx *sql.Tx) error {
		return database.ReplaceUserRecoveryCodes(ctx, tx, 0, recoveryCodeHashes(10))
	})
	require.Error(t, err)
}

// An empty hash would be stored as a code nobody can type and claimed by a caller that hashed
// nothing, so it is refused.
func TestReplaceUserRecoveryCodes_RefusesAnEmptyHash(t *testing.T) {
	user := createTestUser(t)
	hashes := recoveryCodeHashes(9)
	hashes = append(hashes, "")

	ctx := context.Background()
	err := database.RunInTransaction(ctx, func(tx *sql.Tx) error {
		return database.ReplaceUserRecoveryCodes(ctx, tx, user.ID, hashes)
	})

	require.Error(t, err)
	assert.Equal(t, 0, unusedRecoveryCodes(t, user.ID))
}

// Using a code is one conditional write: the first use claims it, every later one is refused, and
// the count drops by the one code (#257 decision 3).
func TestTryUseUserRecoveryCode_ClaimsACodeOnce(t *testing.T) {
	user := createTestUser(t)
	hashes := recoveryCodeHashes(10)
	replaceRecoveryCodes(t, user.ID, hashes)

	assert.True(t, useRecoveryCode(t, user.ID, hashes[2]), "the first use claims it")
	assert.Equal(t, 9, unusedRecoveryCodes(t, user.ID))
	assert.False(t, useRecoveryCode(t, user.ID, hashes[2]), "the second use is refused")
	assert.Equal(t, 9, unusedRecoveryCodes(t, user.ID), "and changes nothing")
}

// A hash the user's set does not hold claims nothing: one of no set, and one of another user's set.
func TestTryUseUserRecoveryCode_RefusesACodeNotInTheUsersSet(t *testing.T) {
	user := createTestUser(t)
	other := createTestUser(t)
	replaceRecoveryCodes(t, user.ID, recoveryCodeHashes(10))
	theirs := recoveryCodeHashes(10)
	replaceRecoveryCodes(t, other.ID, theirs)

	assert.False(t, useRecoveryCode(t, user.ID, hashutil.HashString(fake.UUID())), "a code of no set")
	assert.False(t, useRecoveryCode(t, user.ID, theirs[0]), "another user's code")
	assert.Equal(t, 10, unusedRecoveryCodes(t, user.ID))
	assert.Equal(t, 10, unusedRecoveryCodes(t, other.ID), "the other user's code is still unused")
}

// The hash is compared exactly: the stored form is lowercase hex, and the same digits in upper
// case are another value, so the comparison is the engine's case-sensitive one (#283).
func TestTryUseUserRecoveryCode_ComparesTheHashCaseSensitively(t *testing.T) {
	user := createTestUser(t)
	hash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	replaceRecoveryCodes(t, user.ID, []string{hash})

	assert.False(t, useRecoveryCode(t, user.ID, "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"))
	assert.True(t, useRecoveryCode(t, user.ID, hash))
}

func TestTryUseUserRecoveryCode_RefusesAnEmptyHashOrAZeroUserID(t *testing.T) {
	user := createTestUser(t)
	replaceRecoveryCodes(t, user.ID, recoveryCodeHashes(10))

	_, err := database.TryUseUserRecoveryCode(context.Background(), nil, user.ID, "")
	require.Error(t, err)
	_, err = database.TryUseUserRecoveryCode(context.Background(), nil, 0, hashutil.HashString(fake.UUID()))
	require.Error(t, err)
	assert.Equal(t, 10, unusedRecoveryCodes(t, user.ID))
}

// Two submissions of one code, at once: exactly one claims it. Single use is a property of the one
// conditional write, which only a real engine shows (#257 decision 3).
func TestTryUseUserRecoveryCode_OfTwoConcurrentUsesExactlyOneClaims(t *testing.T) {
	user := createTestUser(t)
	hashes := recoveryCodeHashes(10)
	replaceRecoveryCodes(t, user.ID, hashes)

	const attempts = 8
	results := make([]bool, attempts)
	failures := make([]error, attempts)
	var start, done sync.WaitGroup
	start.Add(1)
	for i := 0; i < attempts; i++ {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			start.Wait()
			results[i], failures[i] = database.TryUseUserRecoveryCode(context.Background(), nil, user.ID, hashes[7])
		}(i)
	}
	start.Done()
	done.Wait()

	claimed := 0
	for i := 0; i < attempts; i++ {
		require.NoError(t, failures[i], "attempt %d", i)
		if results[i] {
			claimed++
		}
	}
	assert.Equal(t, 1, claimed, "one code, one use")
	assert.Equal(t, 9, unusedRecoveryCodes(t, user.ID))
}

// Removing the authenticator deletes the user's whole set, used codes too, and no one else's.
func TestDeleteUserRecoveryCodes(t *testing.T) {
	user := createTestUser(t)
	other := createTestUser(t)
	hashes := recoveryCodeHashes(10)
	replaceRecoveryCodes(t, user.ID, hashes)
	replaceRecoveryCodes(t, other.ID, recoveryCodeHashes(10))
	require.True(t, useRecoveryCode(t, user.ID, hashes[0]))

	require.NoError(t, database.DeleteUserRecoveryCodes(context.Background(), nil, user.ID))

	assert.Equal(t, 0, unusedRecoveryCodes(t, user.ID))
	for _, hash := range hashes[1:] {
		assert.False(t, useRecoveryCode(t, user.ID, hash), "a deleted code no longer works")
	}
	// A new set after the deletion holds only itself: the used code deleted with the old one does
	// not linger as a used row of the new set.
	replaceRecoveryCodes(t, user.ID, []string{hashes[0]})
	assert.Equal(t, 1, unusedRecoveryCodes(t, user.ID))
	assert.Equal(t, 10, unusedRecoveryCodes(t, other.ID), "another user's set stays")

	require.NoError(t, database.DeleteUserRecoveryCodes(context.Background(), nil, createTestUser(t).ID),
		"a user with no codes is no error")
}

// The codes go with their user, as every table hanging off a user does.
func TestUserRecoveryCodes_GoWithTheirUser(t *testing.T) {
	user := createTestUser(t)
	hashes := recoveryCodeHashes(10)
	replaceRecoveryCodes(t, user.ID, hashes)

	require.NoError(t, database.DeleteUser(context.Background(), nil, user.ID))

	assert.Equal(t, 0, unusedRecoveryCodes(t, user.ID))
	assert.False(t, useRecoveryCode(t, user.ID, hashes[0]))
}

// UserRecoveryCodeExists tells a used code of the user's current set, which the sign-in audits as
// a replay, from a code the set never held or one of a replaced set, whose rows are gone (#257
// decision 10). It reads the set, used codes and unused alike, and only the user's own.
func TestUserRecoveryCodeExists(t *testing.T) {
	ctx := context.Background()
	user := createTestUser(t)
	other := createTestUser(t)
	old := recoveryCodeHashes(10)
	replaceRecoveryCodes(t, user.ID, old)
	current := recoveryCodeHashes(10)
	replaceRecoveryCodes(t, user.ID, current)
	require.True(t, useRecoveryCode(t, user.ID, current[0]))

	exists := func(userID int64, hash string) bool {
		t.Helper()
		found, err := database.UserRecoveryCodeExists(ctx, nil, userID, hash)
		require.NoError(t, err, "UserRecoveryCodeExists")
		return found
	}

	assert.True(t, exists(user.ID, current[0]), "a used code of the current set")
	assert.True(t, exists(user.ID, current[1]), "an unused code of the current set")
	assert.False(t, exists(user.ID, old[0]), "a code of the replaced set is gone")
	assert.False(t, exists(user.ID, recoveryCodeHashes(1)[0]), "a code the set never held")
	assert.False(t, exists(other.ID, current[0]), "another user's set holds none of this user's codes")

	_, err := database.UserRecoveryCodeExists(ctx, nil, 0, current[0])
	require.Error(t, err, "a zero user id is a caller bug")
	_, err = database.UserRecoveryCodeExists(ctx, nil, user.ID, "")
	require.Error(t, err, "an empty hash is a caller bug")
}
