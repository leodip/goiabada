package revocation

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The user and client of a consent withdrawal (#622). Ids of their own, so an expectation copied
// from another fixture in this package cannot match here by accident.
const (
	withdrawUserId   = int64(31)
	withdrawClientId = int64(5151)
)

// withdrawalFixture is one family with a live member and an already-rotated one, and a second
// family whose only member is live: two records, two tokens swept.
func withdrawalFixture() []*record.RefreshToken {
	return []*record.RefreshToken{
		{Id: 1, RefreshTokenJti: "rt-rotated", FirstRefreshTokenJti: "fam-a", Revoked: true},
		{Id: 2, RefreshTokenJti: "rt-live-a", FirstRefreshTokenJti: "fam-a"},
		{Id: 3, RefreshTokenJti: "rt-live-b", FirstRefreshTokenJti: "fam-b"},
	}
}

// The withdrawal deletes the consent first, then marks the user's unused codes with that client
// revoked, reads the user's tokens with that client, records each family once under the
// withdrawal's reason, and sweeps only the live tokens. The codes it marked and the tokens it
// swept are what it reports for the audit record.
func TestRevokeOnConsentWithdrawalTx_WithdrawsRecordsAndSweeps(t *testing.T) {
	db := datamocks.NewDatabase(t)
	tokens := withdrawalFixture()
	var order []string
	datamocks.ExpectRunInTransaction(db, revokeTx)
	db.On("RevokeUnusedCodesByUserIdAndClientId", mock.Anything, revokeTx, withdrawUserId, withdrawClientId).
		Run(func(mock.Arguments) { order = append(order, "mark codes") }).
		Return(int64(2), nil).Once()
	db.On("GetRefreshTokensByUserIdAndClientId", mock.Anything, revokeTx, withdrawUserId, withdrawClientId).
		Run(func(mock.Arguments) { order = append(order, "enumerate") }).
		Return(tokens, nil).Once()
	db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-a", ReasonConsentWithdrawn).
		Run(func(mock.Arguments) { order = append(order, "record") }).
		Return(true, nil).Once()
	db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-b", ReasonConsentWithdrawn).
		Run(func(mock.Arguments) { order = append(order, "record") }).
		Return(true, nil).Once()
	db.On("UpdateRefreshToken", mock.Anything, revokeTx, tokens[1]).
		Run(func(mock.Arguments) { order = append(order, "sweep") }).
		Return(nil).Once()
	db.On("UpdateRefreshToken", mock.Anything, revokeTx, tokens[2]).
		Run(func(mock.Arguments) { order = append(order, "sweep") }).
		Return(nil).Once()

	result, err := RevokeOnConsentWithdrawalTx(context.Background(), db, withdrawUserId, withdrawClientId,
		func(tx *sql.Tx) error {
			assert.Same(t, revokeTx, tx, "the withdrawal runs on the revocation's own transaction")
			order = append(order, "withdraw")
			return nil
		})

	require.NoError(t, err)
	assert.Equal(t, []string{"rt-live-a", "rt-live-b"}, result.RevokedRefreshTokenJtis,
		"only the tokens this call moved from live to revoked are reported")
	assert.Equal(t, int64(2), result.RevokedCodeCount, "the codes the mark transitioned are reported")
	assert.Equal(t, []string{"withdraw", "mark codes", "enumerate", "record", "record", "sweep", "sweep"}, order)
}

// A withdrawal that finds nothing to mark or sweep still commits, and reports a zero count and an
// empty list rather than null, so the audit record carries [].
func TestRevokeOnConsentWithdrawalTx_NothingToSweepReportsAnEmptyList(t *testing.T) {
	db := datamocks.NewDatabase(t)
	datamocks.ExpectRunInTransaction(db, revokeTx)
	db.On("RevokeUnusedCodesByUserIdAndClientId", mock.Anything, revokeTx, withdrawUserId, withdrawClientId).
		Return(int64(0), nil).Once()
	db.On("GetRefreshTokensByUserIdAndClientId", mock.Anything, revokeTx, withdrawUserId, withdrawClientId).
		Return([]*record.RefreshToken{}, nil).Once()

	result, err := RevokeOnConsentWithdrawalTx(context.Background(), db, withdrawUserId, withdrawClientId,
		func(tx *sql.Tx) error { return nil })

	require.NoError(t, err)
	require.NotNil(t, result.RevokedRefreshTokenJtis)
	assert.Empty(t, result.RevokedRefreshTokenJtis)
	assert.Equal(t, int64(0), result.RevokedCodeCount)
}

// No withdrawal, no transaction: a sweep without the deletion that asked for it is refused before
// anything is opened.
func TestRevokeOnConsentWithdrawalTx_RefusesANilWithdrawal(t *testing.T) {
	db := datamocks.NewDatabase(t)

	result, err := RevokeOnConsentWithdrawalTx(context.Background(), db, withdrawUserId, withdrawClientId, nil)

	require.Error(t, err)
	assert.Equal(t, ConsentWithdrawalResult{}, result)
	assertNotAttempted(t, db, "RunInTransaction")
}

// TestRevokeOnConsentWithdrawalTx_AnyFailureYieldsTheZeroResult walks every failure point, as
// TestTerminateUserSessionTx_AnyFailureYieldsTheZeroResult does: the error reaches the caller, the
// result is the zero value, and nothing after the failure is attempted. The enumeration row is the
// one that names the defect #622 fixed: a withdrawal swallowing that error would commit the
// deletion with no family record and no sweep, leaving the grant standing.
//
// Each row registers only the calls its path reaches, and the strict mock fails an unexpected call
// or an unmet expectation.
func TestRevokeOnConsentWithdrawalTx_AnyFailureYieldsTheZeroResult(t *testing.T) {
	boom := errors.New("connection refused")

	cases := []struct {
		name         string
		withdrawErr  error
		setup        func(db *datamocks.Database)
		notAttempted []string
	}{
		{
			name: "the transaction cannot be opened",
			setup: func(db *datamocks.Database) {
				datamocks.ExpectRunInTransactionRefused(db, boom)
			},
			notAttempted: []string{"RevokeUnusedCodesByUserIdAndClientId", "GetRefreshTokensByUserIdAndClientId"},
		},
		{
			name:        "the deletion fails",
			withdrawErr: boom,
			setup: func(db *datamocks.Database) {
				datamocks.ExpectRunInTransaction(db, revokeTx)
			},
			notAttempted: []string{"RevokeUnusedCodesByUserIdAndClientId", "GetRefreshTokensByUserIdAndClientId",
				"RecordRefreshTokenFamilyRevoked", "UpdateRefreshToken"},
		},
		{
			// A withdrawal that committed without its code mark would leave a code issued before
			// it redeemable for a grant the sweep never saw.
			name: "the code mark fails",
			setup: func(db *datamocks.Database) {
				datamocks.ExpectRunInTransaction(db, revokeTx)
				db.On("RevokeUnusedCodesByUserIdAndClientId", mock.Anything, revokeTx, withdrawUserId, withdrawClientId).
					Return(int64(0), boom).Once()
			},
			notAttempted: []string{"GetRefreshTokensByUserIdAndClientId", "RecordRefreshTokenFamilyRevoked",
				"UpdateRefreshToken"},
		},
		{
			name: "the enumeration fails",
			setup: func(db *datamocks.Database) {
				datamocks.ExpectRunInTransaction(db, revokeTx)
				db.On("RevokeUnusedCodesByUserIdAndClientId", mock.Anything, revokeTx, withdrawUserId, withdrawClientId).
					Return(int64(1), nil).Once()
				db.On("GetRefreshTokensByUserIdAndClientId", mock.Anything, revokeTx, withdrawUserId, withdrawClientId).
					Return(nil, boom).Once()
			},
			notAttempted: []string{"RecordRefreshTokenFamilyRevoked", "UpdateRefreshToken"},
		},
		{
			name: "a family record fails",
			setup: func(db *datamocks.Database) {
				datamocks.ExpectRunInTransaction(db, revokeTx)
				db.On("RevokeUnusedCodesByUserIdAndClientId", mock.Anything, revokeTx, withdrawUserId, withdrawClientId).
					Return(int64(1), nil).Once()
				db.On("GetRefreshTokensByUserIdAndClientId", mock.Anything, revokeTx, withdrawUserId, withdrawClientId).
					Return(withdrawalFixture(), nil).Once()
				db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-a", ReasonConsentWithdrawn).
					Return(false, boom).Once()
			},
			notAttempted: []string{"UpdateRefreshToken"},
		},
		{
			// The first live token's write fails, so the second is never written.
			name: "a token write fails",
			setup: func(db *datamocks.Database) {
				tokens := withdrawalFixture()
				datamocks.ExpectRunInTransaction(db, revokeTx)
				db.On("RevokeUnusedCodesByUserIdAndClientId", mock.Anything, revokeTx, withdrawUserId, withdrawClientId).
					Return(int64(1), nil).Once()
				db.On("GetRefreshTokensByUserIdAndClientId", mock.Anything, revokeTx, withdrawUserId, withdrawClientId).
					Return(tokens, nil).Once()
				db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, mock.Anything, ReasonConsentWithdrawn).
					Return(true, nil).Twice()
				db.On("UpdateRefreshToken", mock.Anything, revokeTx, tokens[1]).Return(boom).Once()
			},
		},
		{
			// A commit that reports an error may in fact have applied, and the caller still gets
			// the zero result and must not audit.
			name: "the commit fails",
			setup: func(db *datamocks.Database) {
				tokens := withdrawalFixture()
				datamocks.ExpectRunInTransactionThenFail(db, revokeTx, boom)
				db.On("RevokeUnusedCodesByUserIdAndClientId", mock.Anything, revokeTx, withdrawUserId, withdrawClientId).
					Return(int64(1), nil).Once()
				db.On("GetRefreshTokensByUserIdAndClientId", mock.Anything, revokeTx, withdrawUserId, withdrawClientId).
					Return(tokens, nil).Once()
				db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, mock.Anything, ReasonConsentWithdrawn).
					Return(true, nil).Twice()
				db.On("UpdateRefreshToken", mock.Anything, revokeTx, mock.Anything).Return(nil).Twice()
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := datamocks.NewDatabase(t)
			tc.setup(db)

			result, err := RevokeOnConsentWithdrawalTx(context.Background(), db, withdrawUserId, withdrawClientId,
				func(tx *sql.Tx) error { return tc.withdrawErr })

			require.ErrorIs(t, err, boom)
			assert.Equal(t, ConsentWithdrawalResult{}, result)
			assert.Nil(t, result.RevokedRefreshTokenJtis,
				"the error path returns the zero value, and a caller must not audit it")
			assert.Equal(t, int64(0), result.RevokedCodeCount,
				"a rolled-back mark is not reported")
			assertNotAttempted(t, db, tc.notAttempted...)
		})
	}
}

// TestLogRevokedConsentGrants_Payload pins the revoked_consent_grants payload field by field: both
// withdrawal endpoints write it through this one helper (#622).
func TestLogRevokedConsentGrants_Payload(t *testing.T) {
	recorder := &reuseAuditRecorder{}

	LogRevokedConsentGrants(context.Background(), recorder, withdrawUserId, withdrawClientId, "the-caller",
		ConsentWithdrawalResult{RevokedCodeCount: 2, RevokedRefreshTokenJtis: []string{"rt-1"}})

	require.Equal(t, 1, recorder.calls)
	assert.Equal(t, audit.EventRevokedConsentGrants, recorder.event)
	assert.Equal(t, map[string]interface{}{
		"user_id":                    withdrawUserId,
		"client_id":                  withdrawClientId,
		"logged_in_user":             "the-caller",
		"revoked_code_count":         int64(2),
		"revoked_refresh_token_jtis": []string{"rt-1"},
	}, recorder.details)
}
