package revocation

import (
	"context"
	"database/sql"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 3 for the revoked-family record a client's revocation writes (#259, #437). The sweep reaches
// the refresh tokens that exist when its transaction reads them, and a rotation that claimed its
// parent and has not inserted its child holds no live row: the child then commits live into a family
// the operator believes is revoked. The record is written in the same transaction, for every family
// the client holds a token of, and is what the validator and the rotation's own transaction refuse
// that child with. What an engine then does with two writers of one key is the data tier's.

// expectClientFamilyRecords expects one record per family, on the revoking transaction, carrying the
// reason a client's revocation gives.
func expectClientFamilyRecords(db *mocks_data.Database, families ...string) {
	for _, family := range families {
		db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, family, ReasonClientBecamePublic).
			Return(true, nil).Once()
	}
}

// A family is recorded although every one of its members is already revoked: the sibling that is
// mid-rotation is the one a sweep cannot see, and the family is what its child will be born into.
// Two members of one family are one record, and a token with no family identifier is skipped, since
// no issuer writes one and recording an empty jti is refused as a caller bug.
func TestRevokeClientGrants_RecordsEachFamilyOnceWhateverItsMembersState(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	tokens := []*models.RefreshToken{
		{Id: 1, RefreshTokenJti: "a-1", FirstRefreshTokenJti: "fam-all-revoked", Revoked: true},
		{Id: 2, RefreshTokenJti: "a-2", FirstRefreshTokenJti: "fam-all-revoked", Revoked: true},
		{Id: 3, RefreshTokenJti: "b-1", FirstRefreshTokenJti: "fam-live"},
		{Id: 4, RefreshTokenJti: "no-family"},
	}
	db.On("RevokeCodesByClientId", mock.Anything, revokeTx, revokeClientId).Return(int64(0), nil).Once()
	db.On("GetRefreshTokensByClientId", mock.Anything, revokeTx, revokeClientId).Return(tokens, nil).Once()
	expectClientFamilyRecords(db, "fam-all-revoked", "fam-live")
	db.On("UpdateRefreshToken", mock.Anything, revokeTx, tokens[2]).Return(nil).Once()
	db.On("UpdateRefreshToken", mock.Anything, revokeTx, tokens[3]).Return(nil).Once()

	result, err := RevokeClientGrants(context.Background(), db, revokeTx, revokeClientId)

	require.NoError(t, err)
	assert.Equal(t, []string{"b-1", "no-family"}, result.RevokedRefreshTokenJtis,
		"the record changes what is swept by nothing: only the live tokens are revoked and reported")
	db.AssertNumberOfCalls(t, "RecordRefreshTokenFamilyRevoked", 2)
}

// A record that cannot be written leaves the revocation as an error, with no token swept: the
// transaction rolls back, so a caller never audits a revocation that did not happen.
func TestRevokeClientGrants_AFailedRecordSweepsNothing(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	tokens := clientGrantFixture()
	boom := errs.New("connection refused")
	db.On("RevokeCodesByClientId", mock.Anything, revokeTx, revokeClientId).Return(int64(1), nil).Once()
	db.On("GetRefreshTokensByClientId", mock.Anything, revokeTx, revokeClientId).Return(tokens, nil).Once()
	db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-session", ReasonClientBecamePublic).
		Return(false, boom).Once()

	result, err := RevokeClientGrants(context.Background(), db, revokeTx, revokeClientId)

	require.ErrorIs(t, err, boom)
	assert.Equal(t, ClientGrantRevocationResult{}, result)
	assertNotAttempted(t, db, "UpdateRefreshToken")
}

// A containment of the same family can win the key while the flip's transaction holds its read. The
// write loses as a unique violation, which on PostgreSQL aborts the transaction, so the flip runs
// its body once more and reads the record the containment committed (#259, #437). The second
// attempt's result is the one that commits.
func TestRevokeClientGrantsTx_ALostKeyRunsTheRevocationOnceMore(t *testing.T) {
	lostTheKey := errs.Errorf("%w: a containment recorded the family first", data.ErrUniqueViolation)

	t.Run("the second attempt commits", func(t *testing.T) {
		db := mocks_data.NewDatabase(t)
		first := mocks_data.ExpectRunInTransaction(db, revokeTx)
		second := mocks_data.ExpectRunInTransaction(db, revokeTx)
		db.On("RevokeCodesByClientId", mock.Anything, revokeTx, revokeClientId).Return(int64(1), nil).Twice()
		token := &models.RefreshToken{Id: 1, RefreshTokenJti: "rt-1", FirstRefreshTokenJti: "fam-1"}
		db.On("GetRefreshTokensByClientId", mock.Anything, revokeTx, revokeClientId).
			Return([]*models.RefreshToken{token}, nil).Twice()
		db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-1", ReasonClientBecamePublic).
			Return(false, lostTheKey).Once()
		db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-1", ReasonClientBecamePublic).
			Return(false, nil).Once()
		db.On("UpdateRefreshToken", mock.Anything, revokeTx, token).Return(nil).Once()

		writes := 0
		result, err := RevokeClientGrantsTx(context.Background(), db, revokeClientId, func(tx *sql.Tx) (bool, error) {
			writes++
			return true, nil
		})

		require.NoError(t, err)
		assert.Equal(t, 2, writes, "the client write is part of the body that reran")
		assert.ErrorIs(t, first.BodyErr, data.ErrUniqueViolation)
		assert.NoError(t, second.BodyErr)
		assert.Equal(t, []string{"rt-1"}, result.RevokedRefreshTokenJtis)
		assert.Equal(t, int64(1), result.RevokedCodeCount)
	})

	t.Run("a second loss is an error with the zero result", func(t *testing.T) {
		db := mocks_data.NewDatabase(t)
		mocks_data.ExpectRunInTransaction(db, revokeTx)
		mocks_data.ExpectRunInTransaction(db, revokeTx)
		db.On("RevokeCodesByClientId", mock.Anything, revokeTx, revokeClientId).Return(int64(1), nil).Twice()
		db.On("GetRefreshTokensByClientId", mock.Anything, revokeTx, revokeClientId).
			Return([]*models.RefreshToken{{Id: 1, RefreshTokenJti: "rt-1", FirstRefreshTokenJti: "fam-1"}}, nil).Twice()
		db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-1", ReasonClientBecamePublic).
			Return(false, lostTheKey).Twice()

		result, err := RevokeClientGrantsTx(context.Background(), db, revokeClientId, func(tx *sql.Tx) (bool, error) {
			return true, nil
		})

		require.ErrorIs(t, err, data.ErrUniqueViolation)
		assert.Equal(t, ClientGrantRevocationResult{}, result)
	})
}
