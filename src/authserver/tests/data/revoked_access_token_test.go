package datatests

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Seam of #676 decision 1's stored jtis, against the real engines: an access token without a grant,
// of the client credentials grant or the implicit flow, is revoked by storing its jti with its
// expiry. A second revocation stores nothing, the access-token check asks whether a jti is stored,
// and the cleanup job deletes a stored jti once its token has expired.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>

// newAccessTokenJti is a jti of the shape the auth server signs, a UUID, with a lower-case letter in
// front so its upper-case spelling is another string.
func newAccessTokenJti() string {
	return "at-" + fake.UUID()
}

// accessTokenIsRevoked asks the lookup under test, through the pool.
func accessTokenIsRevoked(t *testing.T, jti string) bool {
	t.Helper()
	revoked, err := database.IsAccessTokenRevoked(context.Background(), nil, jti)
	require.NoError(t, err, "IsAccessTokenRevoked")
	return revoked
}

// recordAccessTokenRevoked stores jti through the method under test, through the pool, and returns
// whether this call stored it.
func recordAccessTokenRevoked(t *testing.T, jti string, expiresAt time.Time) bool {
	t.Helper()
	stored, err := database.RecordAccessTokenRevoked(context.Background(), nil, jti, expiresAt)
	require.NoError(t, err, "RecordAccessTokenRevoked")
	return stored
}

// storedAccessTokenExpiry reads the stored row's expires_at, and how many rows hold the jti, straight
// from the table, so what the method wrote is checked apart from the lookup also under test. The jti
// is inlined rather than bound, so the query needs no per-engine placeholder syntax; it is a value
// the test drew, not caller input.
func storedAccessTokenExpiry(t *testing.T, jti string) (time.Time, int) {
	t.Helper()
	var count int
	require.NoError(t, rawSQLHandle(t).QueryRowContext(context.Background(), fmt.Sprintf(
		"SELECT COUNT(*) FROM revoked_access_tokens WHERE jti = '%s'", jti)).Scan(&count))
	if count == 0 {
		return time.Time{}, 0
	}
	var expiresAt time.Time
	require.NoError(t, rawSQLHandle(t).QueryRowContext(context.Background(), fmt.Sprintf(
		"SELECT expires_at FROM revoked_access_tokens WHERE jti = '%s'", jti)).Scan(&expiresAt))
	return expiresAt, count
}

// A jti is stored once, with the token's expiry, and the lookup then finds it. Revoking the same
// token again stores nothing, reports so, and leaves the first expiry as it was.
func TestRecordAccessTokenRevoked(t *testing.T) {
	jti := newAccessTokenJti()
	expiresAt := time.Date(2031, 4, 5, 6, 7, 8, 0, time.UTC)
	require.False(t, accessTokenIsRevoked(t, jti), "a jti nobody revoked is not stored")

	assert.True(t, recordAccessTokenRevoked(t, jti, expiresAt), "the first revocation stores the jti")
	assert.True(t, accessTokenIsRevoked(t, jti))
	stored, count := storedAccessTokenExpiry(t, jti)
	require.Equal(t, 1, count)
	assert.True(t, expiresAt.Equal(stored.UTC()), "the token's expiry is stored: got %v", stored)

	assert.False(t, recordAccessTokenRevoked(t, jti, expiresAt.Add(time.Hour)),
		"a second revocation of the same token stores nothing")
	stored, count = storedAccessTokenExpiry(t, jti)
	assert.Equal(t, 1, count, "still one row")
	assert.True(t, expiresAt.Equal(stored.UTC()), "and the first expiry stays: got %v", stored)
	assert.True(t, accessTokenIsRevoked(t, jti))
}

// One token's revocation answers for no other token.
func TestIsAccessTokenRevoked_OneTokenDoesNotAnswerForAnother(t *testing.T) {
	revoked := newAccessTokenJti()
	bystander := newAccessTokenJti()
	recordAccessTokenRevoked(t, revoked, time.Now().UTC().Add(time.Hour))

	assert.True(t, accessTokenIsRevoked(t, revoked))
	assert.False(t, accessTokenIsRevoked(t, bystander))
}

// Another spelling of a stored jti is another token, so the lookup compares the identifier exactly:
// SQL Server pads for `=`, so a trailing space would otherwise find the token without one, and a
// collation that folds case would find the other case (#283). Each spelling is then stored as a
// token of its own.
func TestIsAccessTokenRevoked_ComparesTheIdentifierExactly(t *testing.T) {
	jti := newAccessTokenJti()
	recordAccessTokenRevoked(t, jti, time.Now().UTC().Add(time.Hour))

	for name, asked := range map[string]string{
		"upper case":     strings.ToUpper(jti),
		"trailing space": jti + " ",
		"leading space":  " " + jti,
	} {
		t.Run(name, func(t *testing.T) {
			require.NotEqual(t, jti, asked)

			assert.False(t, accessTokenIsRevoked(t, asked), "another spelling is another token")
		})
	}

	upper := strings.ToUpper(jti)
	assert.True(t, recordAccessTokenRevoked(t, upper, time.Now().UTC().Add(time.Hour)),
		"the jti in another case is another token, stored on its own")
	assert.True(t, accessTokenIsRevoked(t, upper))
}

// An empty jti is an error, never an answer: the auth server signs none, so it can only be a caller
// bug, and answering "not revoked" would let a token through that no row could ever refuse.
func TestRevokedAccessToken_RefusesAnEmptyJti(t *testing.T) {
	_, err := database.IsAccessTokenRevoked(context.Background(), nil, "")
	require.Error(t, err)

	stored, err := database.RecordAccessTokenRevoked(context.Background(), nil, "", time.Now().UTC().Add(time.Hour))
	require.Error(t, err)
	assert.False(t, stored)
}

// The cleanup job deletes a stored jti once its token has expired, and no sooner: a row whose
// expiry is the sweep's moment is kept for the next sweep, and an unexpired token stays revoked.
func TestDeleteExpiredRevokedAccessTokens(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	expired := newAccessTokenJti()
	atTheBoundary := newAccessTokenJti()
	live := newAccessTokenJti()
	recordAccessTokenRevoked(t, expired, now.Add(-time.Minute))
	recordAccessTokenRevoked(t, atTheBoundary, now)
	recordAccessTokenRevoked(t, live, now.Add(time.Hour))

	require.NoError(t, database.DeleteExpiredRevokedAccessTokens(context.Background(), nil, now))

	assert.False(t, accessTokenIsRevoked(t, expired), "an expired token's jti is deleted")
	assert.True(t, accessTokenIsRevoked(t, atTheBoundary), "a token expiring at the sweep's moment is kept")
	assert.True(t, accessTokenIsRevoked(t, live), "an unexpired token stays revoked")

	require.NoError(t, database.DeleteExpiredRevokedAccessTokens(context.Background(), nil, now.Add(time.Microsecond)))
	assert.False(t, accessTokenIsRevoked(t, atTheBoundary))
	assert.True(t, accessTokenIsRevoked(t, live))

	// Sweeping nothing is not an error.
	require.NoError(t, database.DeleteExpiredRevokedAccessTokens(context.Background(), nil, now))
}

// The methods run on the transaction they are handed: a jti stored in a transaction that rolls back
// is not stored.
func TestRevokedAccessToken_EnlistsInTheCallersTransaction(t *testing.T) {
	jti := newAccessTokenJti()
	tx, err := database.BeginTransaction(context.Background())
	require.NoError(t, err)
	// A failing assertion must not leave the transaction open: SQLite has one connection, and every
	// later test in the tier would wait for it.
	defer func() { _ = database.RollbackTransaction(context.Background(), tx) }()

	stored, err := database.RecordAccessTokenRevoked(context.Background(), tx, jti, time.Now().UTC().Add(time.Hour))
	require.NoError(t, err)
	require.True(t, stored)
	revoked, err := database.IsAccessTokenRevoked(context.Background(), tx, jti)
	require.NoError(t, err)
	assert.True(t, revoked, "the transaction sees its own write")
	require.NoError(t, database.RollbackTransaction(context.Background(), tx))

	assert.False(t, accessTokenIsRevoked(t, jti), "a rolled back revocation stored nothing")
}
