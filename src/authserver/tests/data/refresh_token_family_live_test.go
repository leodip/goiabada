package datatests

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Seam of #676 decision 1: the query that says whether a grant is live, against the real engines.
// An access token carrying grant_id lives only while its refresh token family has no revocation
// record and still has a member that is not revoked. Every revocation path either writes the record
// or revokes every member, so the one rule covers them all, and a rotation keeps the grant live
// because it revokes the parent and inserts the child in one transaction.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>

// familyIsLive asks the query under test, through the pool.
func familyIsLive(t *testing.T, family string) bool {
	t.Helper()
	live, err := database.IsRefreshTokenFamilyLive(context.Background(), nil, family)
	require.NoError(t, err, "IsRefreshTokenFamilyLive")
	return live
}

// Each case varies one family's members and record, and nothing else.
func TestIsRefreshTokenFamilyLive(t *testing.T) {
	for _, tc := range []struct {
		name string
		// members lists each member's revoked flag, in the order they are written.
		members  []bool
		recorded bool
		want     bool
	}{
		{name: "one live member and no record", members: []bool{false}, want: true},
		{name: "a rotated family: a revoked parent and a live child", members: []bool{true, false}, want: true},
		{name: "a forked family with two live children", members: []bool{true, false, false}, want: true},
		{name: "every member revoked and no record", members: []bool{true, true}, want: false},
		{name: "a live member under a record", members: []bool{false}, recorded: true, want: false},
		{name: "a rotated family under a record", members: []bool{true, false}, recorded: true, want: false},
		{name: "every member revoked under a record", members: []bool{true}, recorded: true, want: false},
		{name: "a record and no member", recorded: true, want: false},
		{name: "no member and no record", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			family := newFamilyJti()
			if len(tc.members) > 0 {
				seedFamilyMembers(t, family, tc.members...)
			}
			if tc.recorded {
				recordFamily(t, family)
			}

			assert.Equal(t, tc.want, familyIsLive(t, family))
		})
	}
}

// A family is live by its own members and record, and no other family's.
func TestIsRefreshTokenFamilyLive_OneFamilyDoesNotAnswerForAnother(t *testing.T) {
	t.Run("another family's live member", func(t *testing.T) {
		family := newFamilyJti()
		bystander := newFamilyJti()
		seedFamilyMembers(t, family, true)
		seedFamilyMembers(t, bystander, false)

		assert.False(t, familyIsLive(t, family), "this family's only member is revoked")
		assert.True(t, familyIsLive(t, bystander))
	})

	t.Run("another family's record", func(t *testing.T) {
		family := newFamilyJti()
		recorded := newFamilyJti()
		seedFamilyMembers(t, family, false)
		seedFamilyMembers(t, recorded, false)
		recordFamily(t, recorded)

		assert.True(t, familyIsLive(t, family), "the record names another family")
		assert.False(t, familyIsLive(t, recorded))
	})
}

// The query compares the identifier as exactly what it is, for the reason
// TestRefreshTokenFamilyRevocation_TheLookupComparesTheJtiExactly states: SQL Server pads for `=`
// under every collation, so a trailing space would otherwise find the live member of the family
// without one. The control is the exact identifier.
func TestIsRefreshTokenFamilyLive_ComparesTheIdentifierExactly(t *testing.T) {
	family := newFamilyJti()
	seedFamilyMembers(t, family, false)
	require.True(t, familyIsLive(t, family), "control: the exact identifier finds the live member")

	for name, asked := range map[string]string{
		"upper case":     strings.ToUpper(family),
		"trailing space": family + " ",
		"leading space":  " " + family,
	} {
		t.Run(name, func(t *testing.T) {
			require.NotEqual(t, family, asked)

			live, err := database.IsRefreshTokenFamilyLive(context.Background(), nil, asked)

			require.NoError(t, err, "a different spelling is a family with no member, not a fault")
			assert.False(t, live, "and it must not read as the live one")
		})
	}
}

// An empty identifier is an error, never an answer: false would refuse the token as a dead grant
// when the fault is the caller's, and the two must not be confused.
func TestIsRefreshTokenFamilyLive_RefusesAnEmptyIdentifier(t *testing.T) {
	live, err := database.IsRefreshTokenFamilyLive(context.Background(), nil, "")

	require.Error(t, err)
	assert.False(t, live)
}

// The query runs on the transaction it is handed, so it sees what that transaction wrote, and a
// revocation that rolls back leaves the grant live. Everything inside a body goes through its
// transaction: SQLite has one connection.
func TestIsRefreshTokenFamilyLive_EnlistsInTheCallersTransaction(t *testing.T) {
	ctx := context.Background()

	t.Run("a revocation in the same transaction ends the grant there", func(t *testing.T) {
		family := newFamilyJti()
		seedFamilyMembers(t, family, false)

		err := database.RunInTransaction(ctx, func(tx *sql.Tx) error {
			before, err := database.IsRefreshTokenFamilyLive(ctx, tx, family)
			require.NoError(t, err)
			require.True(t, before, "control: live before the revocation")

			_, err = database.RevokeRefreshTokenFamily(ctx, tx, family)
			require.NoError(t, err)

			after, err := database.IsRefreshTokenFamilyLive(ctx, tx, family)
			require.NoError(t, err)
			assert.False(t, after, "the transaction sees its own revocation")
			return nil
		})

		require.NoError(t, err)
		assert.False(t, familyIsLive(t, family), "and the committed revocation ends the grant")
	})

	t.Run("a revocation that rolls back leaves the grant live", func(t *testing.T) {
		family := newFamilyJti()
		seedFamilyMembers(t, family, false)
		refused := errors.New("the revocation decided against it")

		err := database.RunInTransaction(ctx, func(tx *sql.Tx) error {
			_, err := database.RevokeRefreshTokenFamily(ctx, tx, family)
			require.NoError(t, err)
			_, err = database.RecordRefreshTokenFamilyRevoked(ctx, tx, family, familyRevocationReason)
			require.NoError(t, err)
			return refused
		})

		require.ErrorIs(t, err, refused)
		assert.True(t, familyIsLive(t, family), "nothing the rolled back transaction wrote is seen")
	})
}
