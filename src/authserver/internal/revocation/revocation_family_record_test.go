package revocation

import (
	"context"
	"database/sql"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
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
func expectClientFamilyRecords(db *datamocks.Database, families ...string) {
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
	db := datamocks.NewDatabase(t)
	tokens := []*record.RefreshToken{
		{ID: 1, RefreshTokenJTI: "a-1", FirstRefreshTokenJTI: "fam-all-revoked", Revoked: true},
		{ID: 2, RefreshTokenJTI: "a-2", FirstRefreshTokenJTI: "fam-all-revoked", Revoked: true},
		{ID: 3, RefreshTokenJTI: "b-1", FirstRefreshTokenJTI: "fam-live"},
		{ID: 4, RefreshTokenJTI: "no-family"},
	}
	db.On("RevokeCodesByClientID", mock.Anything, revokeTx, revokeClientID).Return(int64(0), nil).Once()
	db.On("GetRefreshTokensByClientID", mock.Anything, revokeTx, revokeClientID).Return(tokens, nil).Once()
	expectClientFamilyRecords(db, "fam-all-revoked", "fam-live")
	db.On("UpdateRefreshToken", mock.Anything, revokeTx, tokens[2]).Return(nil).Once()
	db.On("UpdateRefreshToken", mock.Anything, revokeTx, tokens[3]).Return(nil).Once()

	result, err := RevokeClientGrants(context.Background(), db, revokeTx, revokeClientID, ReasonClientBecamePublic)

	require.NoError(t, err)
	assert.Equal(t, []string{"b-1", "no-family"}, result.RevokedRefreshTokenJTIs,
		"the record changes what is swept by nothing: only the live tokens are revoked and reported")
	db.AssertNumberOfCalls(t, "RecordRefreshTokenFamilyRevoked", 2)
}

// The sweep stores the reason its caller gives on each family it records, so a rename's families say
// client_identifier_changed and a switch to public's say client_became_public (#710 decision 5).
func TestRevokeClientGrants_RecordsTheFamiliesUnderTheCallersReason(t *testing.T) {
	for _, reason := range []string{"client_identifier_changed", "client_became_public"} {
		t.Run(reason, func(t *testing.T) {
			db := datamocks.NewDatabase(t)
			tokens := []*record.RefreshToken{
				{ID: 1, RefreshTokenJTI: "a-1", FirstRefreshTokenJTI: "fam-a"},
				{ID: 2, RefreshTokenJTI: "b-1", FirstRefreshTokenJTI: "fam-b"},
			}
			db.On("RevokeCodesByClientID", mock.Anything, revokeTx, revokeClientID).Return(int64(0), nil).Once()
			db.On("GetRefreshTokensByClientID", mock.Anything, revokeTx, revokeClientID).Return(tokens, nil).Once()
			db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-a", reason).Return(true, nil).Once()
			db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-b", reason).Return(true, nil).Once()
			db.On("UpdateRefreshToken", mock.Anything, revokeTx, tokens[0]).Return(nil).Once()
			db.On("UpdateRefreshToken", mock.Anything, revokeTx, tokens[1]).Return(nil).Once()

			result, err := RevokeClientGrants(context.Background(), db, revokeTx, revokeClientID, reason)

			require.NoError(t, err)
			assert.Equal(t, []string{"a-1", "b-1"}, result.RevokedRefreshTokenJTIs)
		})
	}
}

// RevokeClientGrantsTx hands its caller's reason to the sweep.
func TestRevokeClientGrantsTx_RecordsTheFamiliesUnderTheCallersReason(t *testing.T) {
	db := datamocks.NewDatabase(t)
	datamocks.ExpectRunInTransaction(db, revokeTx)
	token := &record.RefreshToken{ID: 1, RefreshTokenJTI: "rt-1", FirstRefreshTokenJTI: "fam-1"}
	db.On("RevokeCodesByClientID", mock.Anything, revokeTx, revokeClientID).Return(int64(2), nil).Once()
	db.On("GetRefreshTokensByClientID", mock.Anything, revokeTx, revokeClientID).
		Return([]*record.RefreshToken{token}, nil).Once()
	db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-1", "client_identifier_changed").
		Return(true, nil).Once()
	db.On("UpdateRefreshToken", mock.Anything, revokeTx, token).Return(nil).Once()

	result, err := RevokeClientGrantsTx(context.Background(), db, revokeClientID, ReasonClientIdentifierChanged,
		func(tx *sql.Tx) (bool, error) { return true, nil })

	require.NoError(t, err)
	assert.Equal(t, int64(2), result.RevokedCodeCount)
	assert.Equal(t, []string{"rt-1"}, result.RevokedRefreshTokenJTIs)
}

// A record that cannot be written leaves the revocation as an error, with no token swept: the
// transaction rolls back, so a caller never audits a revocation that did not happen.
func TestRevokeClientGrants_AFailedRecordSweepsNothing(t *testing.T) {
	db := datamocks.NewDatabase(t)
	tokens := clientGrantFixture()
	boom := errs.New("connection refused")
	db.On("RevokeCodesByClientID", mock.Anything, revokeTx, revokeClientID).Return(int64(1), nil).Once()
	db.On("GetRefreshTokensByClientID", mock.Anything, revokeTx, revokeClientID).Return(tokens, nil).Once()
	db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-session", ReasonClientBecamePublic).
		Return(false, boom).Once()

	result, err := RevokeClientGrants(context.Background(), db, revokeTx, revokeClientID, ReasonClientBecamePublic)

	require.ErrorIs(t, err, boom)
	assert.Equal(t, ClientGrantResult{}, result)
	assertNotAttempted(t, db, "UpdateRefreshToken")
}

// A containment of the same family can win the key while the flip's transaction holds its read. The
// write loses as a unique violation, which on PostgreSQL aborts the transaction, so the flip runs
// its body once more and reads the record the containment committed (#259, #437). The second
// attempt's result is the one that commits.
func TestRevokeClientGrantsTx_ALostKeyRunsTheRevocationOnceMore(t *testing.T) {
	lostTheKey := errs.Errorf("%w: a containment recorded the family first", data.ErrUniqueViolation)

	t.Run("the second attempt commits", func(t *testing.T) {
		db := datamocks.NewDatabase(t)
		first := datamocks.ExpectRunInTransaction(db, revokeTx)
		second := datamocks.ExpectRunInTransaction(db, revokeTx)
		db.On("RevokeCodesByClientID", mock.Anything, revokeTx, revokeClientID).Return(int64(1), nil).Twice()
		token := &record.RefreshToken{ID: 1, RefreshTokenJTI: "rt-1", FirstRefreshTokenJTI: "fam-1"}
		db.On("GetRefreshTokensByClientID", mock.Anything, revokeTx, revokeClientID).
			Return([]*record.RefreshToken{token}, nil).Twice()
		db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-1", ReasonClientBecamePublic).
			Return(false, lostTheKey).Once()
		db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-1", ReasonClientBecamePublic).
			Return(false, nil).Once()
		db.On("UpdateRefreshToken", mock.Anything, revokeTx, token).Return(nil).Once()

		writes := 0
		result, err := RevokeClientGrantsTx(context.Background(), db, revokeClientID, ReasonClientBecamePublic, func(tx *sql.Tx) (bool, error) {
			writes++
			return true, nil
		})

		require.NoError(t, err)
		assert.Equal(t, 2, writes, "the client write is part of the body that reran")
		require.ErrorIs(t, first.BodyErr, data.ErrUniqueViolation)
		require.NoError(t, second.BodyErr)
		assert.Equal(t, []string{"rt-1"}, result.RevokedRefreshTokenJTIs)
		assert.Equal(t, int64(1), result.RevokedCodeCount)
	})

	t.Run("a second loss is an error with the zero result", func(t *testing.T) {
		db := datamocks.NewDatabase(t)
		datamocks.ExpectRunInTransaction(db, revokeTx)
		datamocks.ExpectRunInTransaction(db, revokeTx)
		db.On("RevokeCodesByClientID", mock.Anything, revokeTx, revokeClientID).Return(int64(1), nil).Twice()
		db.On("GetRefreshTokensByClientID", mock.Anything, revokeTx, revokeClientID).
			Return([]*record.RefreshToken{{ID: 1, RefreshTokenJTI: "rt-1", FirstRefreshTokenJTI: "fam-1"}}, nil).Twice()
		db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-1", ReasonClientBecamePublic).
			Return(false, lostTheKey).Twice()

		result, err := RevokeClientGrantsTx(context.Background(), db, revokeClientID, ReasonClientBecamePublic, func(tx *sql.Tx) (bool, error) {
			return true, nil
		})

		require.ErrorIs(t, err, data.ErrUniqueViolation)
		assert.Equal(t, ClientGrantResult{}, result)
	})
}

// The disconnect writes the same family records, so it loses the same key to the same containment,
// and reruns its body once for the same reason (#622, #135). The consent deletion and the code mark
// are part of the body that reruns, and the second attempt's result is the one that commits: the
// family the containment recorded first is not counted as this call's.
func TestDisconnectClientTx_ALostKeyRunsTheDisconnectOnceMore(t *testing.T) {
	lostTheKey := errs.Errorf("%w: a containment recorded the family first", data.ErrUniqueViolation)

	t.Run("the second attempt commits", func(t *testing.T) {
		db := datamocks.NewDatabase(t)
		first := datamocks.ExpectRunInTransaction(db, revokeTx)
		second := datamocks.ExpectRunInTransaction(db, revokeTx)
		expectClientWithoutLogoutURI(db)
		token := &record.RefreshToken{ID: 1, RefreshTokenJTI: "rt-1", FirstRefreshTokenJTI: "fam-1"}
		// The first attempt's mark rolled back with it, so the second makes it again and reports it.
		db.On("RevokeUnusedCodesByUserIDAndClientID", mock.Anything, revokeTx, disconnectUserID, disconnectClientID).
			Return(int64(1), nil).Twice()
		db.On("GetRefreshTokensByUserIDAndClientID", mock.Anything, revokeTx, disconnectUserID, disconnectClientID).
			Return([]*record.RefreshToken{token}, nil).Twice()
		db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-1", ReasonClientDisconnected).
			Return(false, lostTheKey).Once()
		db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-1", ReasonClientDisconnected).
			Return(false, nil).Once()
		db.On("MarkRefreshTokenAsRevoked", mock.Anything, revokeTx, token.ID).Return(true, nil).Once()

		deletions := 0
		result, err := DisconnectClientTx(context.Background(), db, disconnectUserID, disconnectClientID, nil,
			func(tx *sql.Tx) (bool, error) {
				deletions++
				return true, nil
			})

		require.NoError(t, err)
		assert.Equal(t, 2, deletions, "the consent deletion is part of the body that reran")
		require.ErrorIs(t, first.BodyErr, data.ErrUniqueViolation)
		require.NoError(t, second.BodyErr)
		assert.Equal(t, DisconnectResult{
			ConsentDeleted:          true,
			RevokedCodeCount:        1,
			RevokedRefreshTokenJTIs: []string{"rt-1"},
		}, result)
	})

	t.Run("a second loss is an error with the zero result", func(t *testing.T) {
		db := datamocks.NewDatabase(t)
		datamocks.ExpectRunInTransaction(db, revokeTx)
		datamocks.ExpectRunInTransaction(db, revokeTx)
		expectClientWithoutLogoutURI(db)
		db.On("RevokeUnusedCodesByUserIDAndClientID", mock.Anything, revokeTx, disconnectUserID, disconnectClientID).
			Return(int64(1), nil).Twice()
		db.On("GetRefreshTokensByUserIDAndClientID", mock.Anything, revokeTx, disconnectUserID, disconnectClientID).
			Return([]*record.RefreshToken{{ID: 1, RefreshTokenJTI: "rt-1", FirstRefreshTokenJTI: "fam-1"}}, nil).Twice()
		db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-1", ReasonClientDisconnected).
			Return(false, lostTheKey).Twice()

		result, err := DisconnectClientTx(context.Background(), db, disconnectUserID, disconnectClientID, nil,
			deletesTheConsent)

		require.ErrorIs(t, err, data.ErrUniqueViolation)
		assert.Equal(t, DisconnectResult{}, result)
		assertNotAttempted(t, db, "UpdateRefreshToken")
	})
}

// expectTerminationFamilyRecords expects one record per family, on the terminating transaction,
// carrying the reason a session's termination gives.
func expectTerminationFamilyRecords(db *datamocks.Database, families ...string) {
	for _, family := range families {
		db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, family, ReasonSessionTerminated).
			Return(true, nil).Once()
	}
}

// A termination and the response to a reused code sweep the tokens their transaction read, so a
// rotation that claimed its parent before the read inserts a child neither reaches. The revoked code
// refuses that child at the refresh grant, but the access token the rotation minted names only its
// grant, so each records every family it read: that is what the access-token check refuses the
// token by (#676 decision 1). A losing record leaves both to run once more, as a client's revocation
// does.
func TestTerminateUserSessionTx_ALostKeyRunsTheTerminationOnceMore(t *testing.T) {
	lostTheKey := errs.Errorf("%w: a containment recorded the family first", data.ErrUniqueViolation)
	db := datamocks.NewDatabase(t)
	first := datamocks.ExpectRunInTransaction(db, revokeTx)
	second := datamocks.ExpectRunInTransaction(db, revokeTx)
	token := &record.RefreshToken{ID: 1, RefreshTokenJTI: "rt-1", FirstRefreshTokenJTI: "fam-1"}
	db.On("DeleteUserSession", mock.Anything, revokeTx, terminateSessionID).Return(nil).Twice()
	db.On("RevokeCodesBySessionIdentifier", mock.Anything, revokeTx, terminateSid).Return(int64(1), nil).Twice()
	db.On("GetRefreshTokensBySessionIdentifier", mock.Anything, revokeTx, terminateSid).
		Return([]*record.RefreshToken{token}, nil).Twice()
	db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-1", ReasonSessionTerminated).
		Return(false, lostTheKey).Once()
	db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-1", ReasonSessionTerminated).
		Return(false, nil).Once()
	db.On("UpdateRefreshToken", mock.Anything, revokeTx, token).Return(nil).Once()

	result, err := TerminateUserSessionTx(context.Background(), db, terminatedSession(), false)

	require.NoError(t, err)
	require.ErrorIs(t, first.BodyErr, data.ErrUniqueViolation)
	require.NoError(t, second.BodyErr)
	assert.Equal(t, []string{"rt-1"}, result.RevokedRefreshTokenJTIs)
	assert.Equal(t, int64(1), result.RevokedCodeCount)
}

func TestRevokeOnAuthCodeReuse_RecordsEveryFamilyItSweeps(t *testing.T) {
	t.Run("each family once, a revoked member's included", func(t *testing.T) {
		db := datamocks.NewDatabase(t)
		tokens := []*record.RefreshToken{
			{ID: 1, RefreshTokenJTI: "a-1", FirstRefreshTokenJTI: "fam-a", Revoked: true},
			{ID: 2, RefreshTokenJTI: "a-2", FirstRefreshTokenJTI: "fam-a"},
			{ID: 3, RefreshTokenJTI: "b-1", FirstRefreshTokenJTI: "fam-b", Revoked: true},
		}
		datamocks.ExpectRunInTransaction(db, revokeTx)
		db.On("AcquireUserSessionRow", mock.Anything, revokeTx, reuseSid).Return(true, nil).Once()
		db.On("GetRefreshTokensBySessionIdentifier", mock.Anything, revokeTx, reuseSid).Return(tokens, nil).Once()
		db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-a", ReasonAuthCodeReuse).
			Return(true, nil).Once()
		db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-b", ReasonAuthCodeReuse).
			Return(true, nil).Once()
		db.On("UpdateRefreshToken", mock.Anything, revokeTx, tokens[1]).Return(nil).Once()
		db.On("GetUserSessionBySessionIdentifier", mock.Anything, revokeTx, reuseSid).Return(nil, nil).Once()

		result, err := RevokeOnAuthCodeReuseTx(context.Background(), db, &record.Code{ID: 42, SessionIdentifier: reuseSid}, nil)

		require.NoError(t, err)
		assert.Equal(t, []string{"a-2"}, result.RevokedRefreshTokenJTIs)
		db.AssertNumberOfCalls(t, "RecordRefreshTokenFamilyRevoked", 2)
	})

	t.Run("a failed record sweeps nothing", func(t *testing.T) {
		db := datamocks.NewDatabase(t)
		boom := errs.New("connection refused")
		token := &record.RefreshToken{ID: 1, RefreshTokenJTI: "rt-1", FirstRefreshTokenJTI: "fam-1"}
		datamocks.ExpectRunInTransaction(db, revokeTx)
		db.On("AcquireUserSessionRow", mock.Anything, revokeTx, reuseSid).Return(true, nil).Once()
		db.On("GetRefreshTokensBySessionIdentifier", mock.Anything, revokeTx, reuseSid).
			Return([]*record.RefreshToken{token}, nil).Once()
		db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-1", ReasonAuthCodeReuse).
			Return(false, boom).Once()

		result, err := RevokeOnAuthCodeReuseTx(context.Background(), db, &record.Code{ID: 42, SessionIdentifier: reuseSid}, nil)

		require.ErrorIs(t, err, boom)
		assert.Equal(t, AuthCodeReuseResult{}, result)
		assertNotAttempted(t, db, "UpdateRefreshToken", "DeleteUserSession")
	})

	t.Run("a lost key runs the response once more", func(t *testing.T) {
		lostTheKey := errs.Errorf("%w: a containment recorded the family first", data.ErrUniqueViolation)
		db := datamocks.NewDatabase(t)
		first := datamocks.ExpectRunInTransaction(db, revokeTx)
		second := datamocks.ExpectRunInTransaction(db, revokeTx)
		token := &record.RefreshToken{ID: 1, RefreshTokenJTI: "rt-1", FirstRefreshTokenJTI: "fam-1"}
		db.On("AcquireUserSessionRow", mock.Anything, revokeTx, reuseSid).Return(true, nil).Twice()
		db.On("GetRefreshTokensBySessionIdentifier", mock.Anything, revokeTx, reuseSid).
			Return([]*record.RefreshToken{token}, nil).Twice()
		db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-1", ReasonAuthCodeReuse).
			Return(false, lostTheKey).Once()
		db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-1", ReasonAuthCodeReuse).
			Return(false, nil).Once()
		db.On("UpdateRefreshToken", mock.Anything, revokeTx, token).Return(nil).Once()
		db.On("GetUserSessionBySessionIdentifier", mock.Anything, revokeTx, reuseSid).Return(nil, nil).Once()

		result, err := RevokeOnAuthCodeReuseTx(context.Background(), db, &record.Code{ID: 42, SessionIdentifier: reuseSid}, nil)

		require.NoError(t, err)
		require.ErrorIs(t, first.BodyErr, data.ErrUniqueViolation)
		require.NoError(t, second.BodyErr)
		assert.Equal(t, []string{"rt-1"}, result.RevokedRefreshTokenJTIs)
	})
}
