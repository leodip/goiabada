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

// The user and client of a disconnect (#622, #135). Ids of their own, so an expectation copied
// from another fixture in this package cannot match here by accident.
const (
	disconnectUserID   = int64(31)
	disconnectClientID = int64(5151)
)

// disconnectFixture is one family with a live member and an already-rotated one, and a second
// family whose only member is live: two records, two tokens swept.
func disconnectFixture() []*record.RefreshToken {
	return []*record.RefreshToken{
		{ID: 1, RefreshTokenJTI: "rt-rotated", FirstRefreshTokenJTI: "fam-a", Revoked: true},
		{ID: 2, RefreshTokenJTI: "rt-live-a", FirstRefreshTokenJTI: "fam-a"},
		{ID: 3, RefreshTokenJTI: "rt-live-b", FirstRefreshTokenJTI: "fam-b"},
	}
}

// expectClientWithoutLogoutURI registers the disconnect's first read, the client, which registered no
// back-channel logout URI, so the disconnect tells nobody and reads nothing more for it.
func expectClientWithoutLogoutURI(db *datamocks.Database) {
	db.On("GetClientsByIDs", mock.Anything, revokeTx, []int64{disconnectClientID}).
		Return([]record.Client{{ID: disconnectClientID, ClientIdentifier: "no-logout-uri"}}, nil)
}

// deletesTheConsent is a consent deletion that reports it deleted the row.
func deletesTheConsent(*sql.Tx) (bool, error) { return true, nil }

// The disconnect deletes the consent first, then marks the user's unused codes with that client
// revoked, reads the user's tokens with that client, records each family once under
// client_disconnected, and sweeps only the live tokens. It reports each of those changes: the
// consent deleted, the codes marked, the tokens moved from live to revoked and the families it
// newly recorded.
func TestDisconnectClientTx_DeletesTheConsentRecordsAndSweeps(t *testing.T) {
	db := datamocks.NewDatabase(t)
	tokens := disconnectFixture()
	var order []string
	datamocks.ExpectRunInTransaction(db, revokeTx)
	expectClientWithoutLogoutURI(db)
	db.On("RevokeUnusedCodesByUserIDAndClientID", mock.Anything, revokeTx, disconnectUserID, disconnectClientID).
		Run(func(mock.Arguments) { order = append(order, "mark codes") }).
		Return(int64(2), nil).Once()
	db.On("GetRefreshTokensByUserIDAndClientID", mock.Anything, revokeTx, disconnectUserID, disconnectClientID).
		Run(func(mock.Arguments) { order = append(order, "enumerate") }).
		Return(tokens, nil).Once()
	db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-a", "client_disconnected").
		Run(func(mock.Arguments) { order = append(order, "record") }).
		Return(true, nil).Once()
	db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-b", "client_disconnected").
		Run(func(mock.Arguments) { order = append(order, "record") }).
		Return(true, nil).Once()
	db.On("MarkRefreshTokenAsRevoked", mock.Anything, revokeTx, tokens[1].ID).
		Run(func(mock.Arguments) { order = append(order, "sweep") }).
		Return(true, nil).Once()
	db.On("MarkRefreshTokenAsRevoked", mock.Anything, revokeTx, tokens[2].ID).
		Run(func(mock.Arguments) { order = append(order, "sweep") }).
		Return(true, nil).Once()

	result, err := DisconnectClientTx(context.Background(), db, disconnectUserID, disconnectClientID, nil,
		func(tx *sql.Tx) (bool, error) {
			assert.Same(t, revokeTx, tx, "the consent deletion runs on the disconnect's own transaction")
			order = append(order, "delete consent")
			return true, nil
		})

	require.NoError(t, err)
	assert.Equal(t, DisconnectResult{
		ConsentDeleted:          true,
		RevokedCodeCount:        2,
		RevokedRefreshTokenJTIs: []string{"rt-live-a", "rt-live-b"},
		RecordedFamilyCount:     2,
	}, result, "only what this call changed is reported")
	assert.True(t, result.Changed())
	assert.Equal(t, []string{"delete consent", "mark codes", "enumerate", "record", "record", "sweep", "sweep"}, order)
}

// The consent deletion is optional: a disconnect of a client the user holds no consent with runs
// the same sweep and reports no consent deleted.
func TestDisconnectClientTx_WithoutAConsentDeletion(t *testing.T) {
	db := datamocks.NewDatabase(t)
	tokens := []*record.RefreshToken{{ID: 4, RefreshTokenJTI: "rt-ropc", FirstRefreshTokenJTI: "fam-ropc"}}
	datamocks.ExpectRunInTransaction(db, revokeTx)
	expectClientWithoutLogoutURI(db)
	db.On("RevokeUnusedCodesByUserIDAndClientID", mock.Anything, revokeTx, disconnectUserID, disconnectClientID).
		Return(int64(0), nil).Once()
	db.On("GetRefreshTokensByUserIDAndClientID", mock.Anything, revokeTx, disconnectUserID, disconnectClientID).
		Return(tokens, nil).Once()
	db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-ropc", "client_disconnected").
		Return(true, nil).Once()
	db.On("MarkRefreshTokenAsRevoked", mock.Anything, revokeTx, tokens[0].ID).Return(true, nil).Once()

	result, err := DisconnectClientTx(context.Background(), db, disconnectUserID, disconnectClientID, nil, nil)

	require.NoError(t, err)
	assert.Equal(t, DisconnectResult{
		RevokedRefreshTokenJTIs: []string{"rt-ropc"},
		RecordedFamilyCount:     1,
	}, result)
	assert.True(t, result.Changed())
}

// A consent another request deleted first, no code to mark, and only tokens already revoked whose
// family is already recorded: the call changed nothing, and says so, with an empty list rather
// than null.
func TestDisconnectClientTx_NothingToEndReportsNoChange(t *testing.T) {
	db := datamocks.NewDatabase(t)
	datamocks.ExpectRunInTransaction(db, revokeTx)
	expectClientWithoutLogoutURI(db)
	db.On("RevokeUnusedCodesByUserIDAndClientID", mock.Anything, revokeTx, disconnectUserID, disconnectClientID).
		Return(int64(0), nil).Once()
	db.On("GetRefreshTokensByUserIDAndClientID", mock.Anything, revokeTx, disconnectUserID, disconnectClientID).
		Return([]*record.RefreshToken{
			{ID: 5, RefreshTokenJTI: "rt-gone", FirstRefreshTokenJTI: "fam-gone", Revoked: true},
		}, nil).Once()
	db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-gone", "client_disconnected").
		Return(false, nil).Once()

	result, err := DisconnectClientTx(context.Background(), db, disconnectUserID, disconnectClientID, nil,
		func(*sql.Tx) (bool, error) { return false, nil })

	require.NoError(t, err)
	require.NotNil(t, result.RevokedRefreshTokenJTIs)
	assert.Equal(t, DisconnectResult{RevokedRefreshTokenJTIs: []string{}}, result)
	assert.False(t, result.Changed(), "a call that deleted, marked, revoked and recorded nothing changed nothing")
}

// A token read live that an overlapping disconnect revoked and committed before this one's write
// reached it is not reported: the conditional write matches no live row, and the family that call
// recorded is found already recorded. The call changed nothing, so its caller answers 404 and
// audits nothing, and the token is audited once, by the call that revoked it (#135 decision 2).
func TestDisconnectClientTx_ATokenAnOverlappingCallRevokedFirstIsNotReported(t *testing.T) {
	db := datamocks.NewDatabase(t)
	datamocks.ExpectRunInTransaction(db, revokeTx)
	expectClientWithoutLogoutURI(db)
	db.On("RevokeUnusedCodesByUserIDAndClientID", mock.Anything, revokeTx, disconnectUserID, disconnectClientID).
		Return(int64(0), nil).Once()
	db.On("GetRefreshTokensByUserIDAndClientID", mock.Anything, revokeTx, disconnectUserID, disconnectClientID).
		Return([]*record.RefreshToken{
			{ID: 7, RefreshTokenJTI: "rt-read-live", FirstRefreshTokenJTI: "fam-overlap"},
		}, nil).Once()
	db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-overlap", "client_disconnected").
		Return(false, nil).Once()
	db.On("MarkRefreshTokenAsRevoked", mock.Anything, revokeTx, int64(7)).Return(false, nil).Once()

	result, err := DisconnectClientTx(context.Background(), db, disconnectUserID, disconnectClientID, nil,
		func(*sql.Tx) (bool, error) { return false, nil })

	require.NoError(t, err)
	assert.Equal(t, DisconnectResult{RevokedRefreshTokenJTIs: []string{}}, result)
	assert.False(t, result.Changed(), "the overlapping call made every change this one would have")
}

// A family whose members were all revoked already, by a rotation's parent claim for instance, and
// that has no record yet is still a change: the record is what refuses a child a rotation in
// flight inserts after the commit (#259).
func TestDisconnectClientTx_ANewlyRecordedFamilyAloneIsAChange(t *testing.T) {
	db := datamocks.NewDatabase(t)
	datamocks.ExpectRunInTransaction(db, revokeTx)
	expectClientWithoutLogoutURI(db)
	db.On("RevokeUnusedCodesByUserIDAndClientID", mock.Anything, revokeTx, disconnectUserID, disconnectClientID).
		Return(int64(0), nil).Once()
	db.On("GetRefreshTokensByUserIDAndClientID", mock.Anything, revokeTx, disconnectUserID, disconnectClientID).
		Return([]*record.RefreshToken{
			{ID: 6, RefreshTokenJTI: "rt-claimed", FirstRefreshTokenJTI: "fam-in-flight", Revoked: true},
		}, nil).Once()
	db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-in-flight", "client_disconnected").
		Return(true, nil).Once()

	result, err := DisconnectClientTx(context.Background(), db, disconnectUserID, disconnectClientID, nil, nil)

	require.NoError(t, err)
	assert.Equal(t, DisconnectResult{RevokedRefreshTokenJTIs: []string{}, RecordedFamilyCount: 1}, result)
	assert.True(t, result.Changed())
}

// Each of the four changes on its own makes the call a change; none of them is a no-op.
func TestDisconnectResult_Changed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result DisconnectResult
		want   bool
	}{
		{"nothing", DisconnectResult{RevokedRefreshTokenJTIs: []string{}}, false},
		{"the zero value", DisconnectResult{}, false},
		{"the consent deleted", DisconnectResult{ConsentDeleted: true}, true},
		{"one code marked", DisconnectResult{RevokedCodeCount: 1}, true},
		{"one token revoked", DisconnectResult{RevokedRefreshTokenJTIs: []string{"rt"}}, true},
		{"one family recorded", DisconnectResult{RecordedFamilyCount: 1}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.result.Changed())
		})
	}
}

// TestDisconnectClientTx_AnyFailureYieldsTheZeroResult walks every failure point, as
// TestTerminateUserSessionTx_AnyFailureYieldsTheZeroResult does: the error reaches the caller, the
// result is the zero value, and nothing after the failure is attempted. The enumeration row is the
// one that names the defect #622 fixed: a disconnect swallowing that error would commit the
// deletion with no family record and no sweep, leaving the grant standing.
//
// Each row registers only the calls its path reaches, and the strict mock fails an unexpected call
// or an unmet expectation.
func TestDisconnectClientTx_AnyFailureYieldsTheZeroResult(t *testing.T) {
	boom := errors.New("connection refused")

	cases := []struct {
		name         string
		deleteErr    error
		setup        func(db *datamocks.Database)
		notAttempted []string
	}{
		{
			name: "the transaction cannot be opened",
			setup: func(db *datamocks.Database) {
				datamocks.ExpectRunInTransactionRefused(db, boom)
			},
			notAttempted: []string{"RevokeUnusedCodesByUserIDAndClientID", "GetRefreshTokensByUserIDAndClientID"},
		},
		{
			name:      "the consent deletion fails",
			deleteErr: boom,
			setup: func(db *datamocks.Database) {
				datamocks.ExpectRunInTransaction(db, revokeTx)
				expectClientWithoutLogoutURI(db)
			},
			notAttempted: []string{"RevokeUnusedCodesByUserIDAndClientID", "GetRefreshTokensByUserIDAndClientID",
				"RecordRefreshTokenFamilyRevoked", "MarkRefreshTokenAsRevoked"},
		},
		{
			// A disconnect that committed without its code mark would leave a code issued before
			// it redeemable for a grant the sweep never saw.
			name: "the code mark fails",
			setup: func(db *datamocks.Database) {
				datamocks.ExpectRunInTransaction(db, revokeTx)
				expectClientWithoutLogoutURI(db)
				db.On("RevokeUnusedCodesByUserIDAndClientID", mock.Anything, revokeTx, disconnectUserID, disconnectClientID).
					Return(int64(0), boom).Once()
			},
			notAttempted: []string{"GetRefreshTokensByUserIDAndClientID", "RecordRefreshTokenFamilyRevoked",
				"MarkRefreshTokenAsRevoked"},
		},
		{
			name: "the enumeration fails",
			setup: func(db *datamocks.Database) {
				datamocks.ExpectRunInTransaction(db, revokeTx)
				expectClientWithoutLogoutURI(db)
				db.On("RevokeUnusedCodesByUserIDAndClientID", mock.Anything, revokeTx, disconnectUserID, disconnectClientID).
					Return(int64(1), nil).Once()
				db.On("GetRefreshTokensByUserIDAndClientID", mock.Anything, revokeTx, disconnectUserID, disconnectClientID).
					Return(nil, boom).Once()
			},
			notAttempted: []string{"RecordRefreshTokenFamilyRevoked", "MarkRefreshTokenAsRevoked"},
		},
		{
			name: "a family record fails",
			setup: func(db *datamocks.Database) {
				datamocks.ExpectRunInTransaction(db, revokeTx)
				expectClientWithoutLogoutURI(db)
				db.On("RevokeUnusedCodesByUserIDAndClientID", mock.Anything, revokeTx, disconnectUserID, disconnectClientID).
					Return(int64(1), nil).Once()
				db.On("GetRefreshTokensByUserIDAndClientID", mock.Anything, revokeTx, disconnectUserID, disconnectClientID).
					Return(disconnectFixture(), nil).Once()
				db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, "fam-a", ReasonClientDisconnected).
					Return(false, boom).Once()
			},
			notAttempted: []string{"MarkRefreshTokenAsRevoked"},
		},
		{
			// The first live token's write fails, so the second is never written.
			name: "a token write fails",
			setup: func(db *datamocks.Database) {
				tokens := disconnectFixture()
				datamocks.ExpectRunInTransaction(db, revokeTx)
				expectClientWithoutLogoutURI(db)
				db.On("RevokeUnusedCodesByUserIDAndClientID", mock.Anything, revokeTx, disconnectUserID, disconnectClientID).
					Return(int64(1), nil).Once()
				db.On("GetRefreshTokensByUserIDAndClientID", mock.Anything, revokeTx, disconnectUserID, disconnectClientID).
					Return(tokens, nil).Once()
				db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, mock.Anything, ReasonClientDisconnected).
					Return(true, nil).Twice()
				db.On("MarkRefreshTokenAsRevoked", mock.Anything, revokeTx, tokens[1].ID).Return(false, boom).Once()
			},
		},
		{
			// A commit that reports an error may in fact have applied, and the caller still gets
			// the zero result and must not audit.
			name: "the commit fails",
			setup: func(db *datamocks.Database) {
				tokens := disconnectFixture()
				datamocks.ExpectRunInTransactionThenFail(db, revokeTx, boom)
				expectClientWithoutLogoutURI(db)
				db.On("RevokeUnusedCodesByUserIDAndClientID", mock.Anything, revokeTx, disconnectUserID, disconnectClientID).
					Return(int64(1), nil).Once()
				db.On("GetRefreshTokensByUserIDAndClientID", mock.Anything, revokeTx, disconnectUserID, disconnectClientID).
					Return(tokens, nil).Once()
				db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, mock.Anything, ReasonClientDisconnected).
					Return(true, nil).Twice()
				db.On("MarkRefreshTokenAsRevoked", mock.Anything, revokeTx, mock.Anything).Return(true, nil).Twice()
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := datamocks.NewDatabase(t)
			tc.setup(db)

			result, err := DisconnectClientTx(context.Background(), db, disconnectUserID, disconnectClientID, nil,
				func(tx *sql.Tx) (bool, error) { return tc.deleteErr == nil, tc.deleteErr })

			require.ErrorIs(t, err, boom)
			assert.Equal(t, DisconnectResult{}, result,
				"the error path returns the zero value, and a caller must not audit it")
			assert.False(t, result.Changed(), "a rolled-back disconnect reports no change")
			assertNotAttempted(t, db, tc.notAttempted...)
		})
	}
}

// TestLogDisconnectedClient_Payload pins the disconnected_client payload field by field: every
// endpoint that disconnects a client writes it through this one helper (#135 decision 6), with
// the fields revoked_consent_grants carried.
func TestLogDisconnectedClient_Payload(t *testing.T) {
	recorder := &reuseAuditRecorder{}

	LogDisconnectedClient(context.Background(), recorder, disconnectUserID, disconnectClientID, "the-caller",
		DisconnectResult{ConsentDeleted: true, RevokedCodeCount: 2, RevokedRefreshTokenJTIs: []string{"rt-1"},
			RecordedFamilyCount: 1})

	require.Equal(t, 1, recorder.calls)
	assert.Equal(t, "disconnected_client", recorder.event)
	assert.Equal(t, audit.EventDisconnectedClient, recorder.event)
	assert.Equal(t, map[string]interface{}{
		"user_id":                    disconnectUserID,
		"client_id":                  disconnectClientID,
		"logged_in_user":             "the-caller",
		"revoked_code_count":         int64(2),
		"revoked_refresh_token_jtis": []string{"rt-1"},
	}, recorder.details)
}
