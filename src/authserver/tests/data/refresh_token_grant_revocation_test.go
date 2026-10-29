package datatests

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/revocation"
)

// Seam of #676 decision 1's sixth revocation operation, against the real engines: a client revoking
// one grant at /auth/revoke ends every member of its refresh token family and records the family
// revoked under client_revoked, in one transaction, and reports the jtis it moved from live to
// revoked. The family's members are read by the identifier they share.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>

// jtisOf lists the members' jtis, sorted, so two lists compare whatever order the engine answered in.
func jtisOf(tokens []*record.RefreshToken) []string {
	jtis := make([]string, 0, len(tokens))
	for _, rt := range tokens {
		jtis = append(jtis, rt.RefreshTokenJti)
	}
	sort.Strings(jtis)
	return jtis
}

// Every member of the family, live and revoked, and no member of another.
func TestGetRefreshTokensByFirstRefreshTokenJti(t *testing.T) {
	ctx := context.Background()
	family := newFamilyJti()
	members := seedFamilyMembers(t, family, true, false, false)
	seedFamilyMembers(t, newFamilyJti(), false)

	got, err := database.GetRefreshTokensByFirstRefreshTokenJti(ctx, nil, family)

	require.NoError(t, err)
	assert.Equal(t, jtisOf(members), jtisOf(got))
	for _, rt := range got {
		assert.Equal(t, family, rt.FirstRefreshTokenJti)
	}
}

// A family with no member left answers no member, and no error.
func TestGetRefreshTokensByFirstRefreshTokenJti_NoMember(t *testing.T) {
	got, err := database.GetRefreshTokensByFirstRefreshTokenJti(context.Background(), nil, newFamilyJti())

	require.NoError(t, err)
	assert.Empty(t, got)
}

// The members are compared with the identifier as exactly what it is, for the reason
// TestIsRefreshTokenFamilyLive_ComparesTheIdentifierExactly states (#283): SQL Server pads for `=`,
// so a trailing space would otherwise find the family without one, and a revocation of a grant
// nobody holds would end one somebody does.
func TestGetRefreshTokensByFirstRefreshTokenJti_ComparesTheIdentifierExactly(t *testing.T) {
	family := newFamilyJti()
	seedFamilyMembers(t, family, false)

	for name, asked := range map[string]string{
		"upper case":     strings.ToUpper(family),
		"trailing space": family + " ",
		"leading space":  " " + family,
	} {
		t.Run(name, func(t *testing.T) {
			require.NotEqual(t, family, asked)

			got, err := database.GetRefreshTokensByFirstRefreshTokenJti(context.Background(), nil, asked)

			require.NoError(t, err)
			assert.Empty(t, got, "another spelling is another family")
		})
	}
}

// An empty identifier is an error, for the reason RevokeRefreshTokenFamily states: on a revocation
// path it can only be a caller bug, and answering it would sweep every row with an empty family.
func TestGetRefreshTokensByFirstRefreshTokenJti_RefusesAnEmptyIdentifier(t *testing.T) {
	got, err := database.GetRefreshTokensByFirstRefreshTokenJti(context.Background(), nil, "")

	require.Error(t, err)
	assert.Empty(t, got)
}

// The operation revokes every member of the grant's family, reports the ones it moved, records the
// family under client_revoked, and leaves another family alone.
func TestRevokeGrantTx(t *testing.T) {
	ctx := context.Background()
	family := newFamilyJti()
	members := seedFamilyMembers(t, family, true, false, false)
	bystander := newFamilyJti()
	seedFamilyMembers(t, bystander, false)
	require.True(t, familyIsLive(t, family), "control: the grant is live before it is revoked")

	result, err := revocation.RevokeGrantTx(ctx, database, family)

	require.NoError(t, err)
	assert.ElementsMatch(t, []string{members[1].RefreshTokenJti, members[2].RefreshTokenJti},
		result.RevokedRefreshTokenJtis, "the two live members, and not the one rotated before")

	stored, err := database.GetRefreshTokensByFirstRefreshTokenJti(ctx, nil, family)
	require.NoError(t, err)
	require.Len(t, stored, 3)
	for _, rt := range stored {
		assert.True(t, rt.Revoked, "member %s is revoked", rt.RefreshTokenJti)
	}
	reason, _, found := familyRevocationRow(t, family)
	require.True(t, found, "the family is recorded")
	assert.Equal(t, "client_revoked", reason)
	assert.False(t, familyIsLive(t, family), "the grant is no longer live")

	assert.True(t, familyIsLive(t, bystander), "another grant stays live")
	_, _, bystanderRecorded := familyRevocationRow(t, bystander)
	assert.False(t, bystanderRecorded)
}

// A second revocation of the same grant moves nothing and reports an empty list, never null, and a
// family another path recorded first keeps that path's reason.
func TestRevokeGrantTx_AGrantAlreadyRevoked(t *testing.T) {
	ctx := context.Background()

	t.Run("revoked twice by the client", func(t *testing.T) {
		family := newFamilyJti()
		seedFamilyMembers(t, family, false)
		_, err := revocation.RevokeGrantTx(ctx, database, family)
		require.NoError(t, err)

		result, err := revocation.RevokeGrantTx(ctx, database, family)

		require.NoError(t, err)
		require.NotNil(t, result.RevokedRefreshTokenJtis)
		assert.Empty(t, result.RevokedRefreshTokenJtis)
		reason, _, found := familyRevocationRow(t, family)
		require.True(t, found)
		assert.Equal(t, "client_revoked", reason)
	})

	t.Run("recorded by another path first", func(t *testing.T) {
		family := newFamilyJti()
		seedFamilyMembers(t, family, false)
		recordFamily(t, family)

		result, err := revocation.RevokeGrantTx(ctx, database, family)

		require.NoError(t, err)
		assert.Len(t, result.RevokedRefreshTokenJtis, 1, "the live member is still swept")
		reason, _, found := familyRevocationRow(t, family)
		require.True(t, found)
		assert.Equal(t, familyRevocationReason, reason, "the first record stays as it was")
	})
}
