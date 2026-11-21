package revocation

import (
	"context"
	"errors"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The grant a client revokes at /auth/revoke (#676 decision 1), and the two clients of its audit
// records. Values of their own, so an expectation copied from another fixture in this package cannot
// match here by accident.
const (
	revokedGrantID     = "fam-revoked-grant"
	grantUserID        = int64(61)
	grantClientID      = int64(6161)
	grantOtherClientID = int64(6262)
)

// grantFixture is one family rotated twice: its first two members revoked by the rotations, the
// last live, and a fork's second live child.
func grantFixture() []*record.RefreshToken {
	return []*record.RefreshToken{
		{ID: 1, RefreshTokenJTI: "rt-first", FirstRefreshTokenJTI: revokedGrantID, Revoked: true},
		{ID: 2, RefreshTokenJTI: "rt-second", FirstRefreshTokenJTI: revokedGrantID, Revoked: true},
		{ID: 3, RefreshTokenJTI: "rt-live", FirstRefreshTokenJTI: revokedGrantID},
		{ID: 4, RefreshTokenJTI: "rt-fork", FirstRefreshTokenJTI: revokedGrantID},
	}
}

// The revocation records the family under client_revoked first, then reads its members and sweeps
// the live ones, all in one transaction, and reports the members it moved.
func TestRevokeGrantTx_RecordsAndSweepsTheFamily(t *testing.T) {
	db := datamocks.NewDatabase(t)
	tokens := grantFixture()
	var order []string
	datamocks.ExpectRunInTransaction(db, revokeTx)
	db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, revokedGrantID, "client_revoked").
		Run(func(mock.Arguments) { order = append(order, "record") }).
		Return(true, nil).Once()
	db.On("GetRefreshTokensByFirstRefreshTokenJTI", mock.Anything, revokeTx, revokedGrantID).
		Run(func(mock.Arguments) { order = append(order, "enumerate") }).
		Return(tokens, nil).Once()
	db.On("UpdateRefreshToken", mock.Anything, revokeTx, tokens[2]).
		Run(func(mock.Arguments) { order = append(order, "sweep") }).
		Return(nil).Once()
	db.On("UpdateRefreshToken", mock.Anything, revokeTx, tokens[3]).
		Run(func(mock.Arguments) { order = append(order, "sweep") }).
		Return(nil).Once()

	result, err := RevokeGrantTx(context.Background(), db, revokedGrantID)

	require.NoError(t, err)
	assert.Equal(t, []string{"rt-live", "rt-fork"}, result.RevokedRefreshTokenJTIs,
		"only the members this call moved from live to revoked are reported")
	assert.Equal(t, []string{"record", "enumerate", "sweep", "sweep"}, order)
	for _, rt := range tokens {
		assert.True(t, rt.Revoked, "member %s is revoked", rt.RefreshTokenJTI)
	}
}

// A grant already revoked commits, records nothing new and reports an empty list rather than null,
// so the audit record carries [].
func TestRevokeGrantTx_NothingLeftReportsAnEmptyList(t *testing.T) {
	db := datamocks.NewDatabase(t)
	datamocks.ExpectRunInTransaction(db, revokeTx)
	db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, revokedGrantID, "client_revoked").
		Return(false, nil).Once()
	db.On("GetRefreshTokensByFirstRefreshTokenJTI", mock.Anything, revokeTx, revokedGrantID).
		Return([]*record.RefreshToken{{ID: 1, RefreshTokenJTI: "rt-first", Revoked: true}}, nil).Once()

	result, err := RevokeGrantTx(context.Background(), db, revokedGrantID)

	require.NoError(t, err)
	require.NotNil(t, result.RevokedRefreshTokenJTIs)
	assert.Empty(t, result.RevokedRefreshTokenJTIs)
}

// No grant, no transaction: an empty identifier is a caller bug, refused before anything is opened.
func TestRevokeGrantTx_RefusesAnEmptyGrant(t *testing.T) {
	db := datamocks.NewDatabase(t)

	result, err := RevokeGrantTx(context.Background(), db, "")

	require.Error(t, err)
	assert.Equal(t, GrantRevocationResult{}, result)
	assertNotAttempted(t, db, "RunInTransaction")
}

// Every failure reaches the caller with the zero result, and nothing after it is attempted, so a
// caller cannot audit a revocation that rolled back.
func TestRevokeGrantTx_AnyFailureYieldsTheZeroResult(t *testing.T) {
	boom := errors.New("connection refused")

	cases := []struct {
		name         string
		setup        func(db *datamocks.Database)
		notAttempted []string
	}{
		{
			name: "the transaction cannot be opened",
			setup: func(db *datamocks.Database) {
				datamocks.ExpectRunInTransactionRefused(db, boom)
			},
			notAttempted: []string{"RecordRefreshTokenFamilyRevoked", "GetRefreshTokensByFirstRefreshTokenJTI"},
		},
		{
			name: "the record fails",
			setup: func(db *datamocks.Database) {
				datamocks.ExpectRunInTransaction(db, revokeTx)
				db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, revokedGrantID, "client_revoked").
					Return(false, boom).Once()
			},
			notAttempted: []string{"GetRefreshTokensByFirstRefreshTokenJTI", "UpdateRefreshToken"},
		},
		{
			name: "the members cannot be read",
			setup: func(db *datamocks.Database) {
				datamocks.ExpectRunInTransaction(db, revokeTx)
				db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, revokedGrantID, "client_revoked").
					Return(true, nil).Once()
				db.On("GetRefreshTokensByFirstRefreshTokenJTI", mock.Anything, revokeTx, revokedGrantID).
					Return(nil, boom).Once()
			},
			notAttempted: []string{"UpdateRefreshToken"},
		},
		{
			name: "the sweep fails",
			setup: func(db *datamocks.Database) {
				datamocks.ExpectRunInTransaction(db, revokeTx)
				db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, revokedGrantID, "client_revoked").
					Return(true, nil).Once()
				db.On("GetRefreshTokensByFirstRefreshTokenJTI", mock.Anything, revokeTx, revokedGrantID).
					Return(grantFixture(), nil).Once()
				db.On("UpdateRefreshToken", mock.Anything, revokeTx, mock.Anything).Return(boom).Once()
			},
		},
		{
			name: "the commit fails",
			setup: func(db *datamocks.Database) {
				datamocks.ExpectRunInTransactionThenFail(db, revokeTx, boom)
				db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, revokedGrantID, "client_revoked").
					Return(true, nil).Once()
				db.On("GetRefreshTokensByFirstRefreshTokenJTI", mock.Anything, revokeTx, revokedGrantID).
					Return(grantFixture(), nil).Once()
				db.On("UpdateRefreshToken", mock.Anything, revokeTx, mock.Anything).Return(nil).Twice()
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := datamocks.NewDatabase(t)
			tc.setup(db)

			result, err := RevokeGrantTx(context.Background(), db, revokedGrantID)

			require.ErrorIs(t, err, boom)
			assert.Equal(t, GrantRevocationResult{}, result)
			assertNotAttempted(t, db, tc.notAttempted...)
		})
	}
}

// revoked_grant carries the client that revoked, the grant's user, the grant, the type of token
// sent and the jtis the call moved, always a list.
func TestLogRevokedGrant_Payload(t *testing.T) {
	for _, tc := range []struct {
		name      string
		tokenType string
		result    GrantRevocationResult
		wantJTIs  []string
	}{
		{"by its refresh token", "refresh_token", GrantRevocationResult{RevokedRefreshTokenJTIs: []string{"rt-live"}}, []string{"rt-live"}},
		{"by an access token", "access_token", GrantRevocationResult{RevokedRefreshTokenJTIs: []string{}}, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := &reuseAuditRecorder{}

			LogRevokedGrant(context.Background(), recorder, grantClientID, grantUserID, revokedGrantID, tc.tokenType, tc.result)

			require.Equal(t, 1, recorder.calls)
			assert.Equal(t, audit.EventRevokedGrant, recorder.event)
			assert.Equal(t, "revoked_grant", recorder.event)
			assert.Equal(t, map[string]interface{}{
				"client_id":                  grantClientID,
				"user_id":                    grantUserID,
				"grant_id":                   revokedGrantID,
				"token_type":                 tc.tokenType,
				"revoked_refresh_token_jtis": tc.wantJTIs,
			}, recorder.details)
		})
	}
}

// token_revocation_refused carries the client that called, the client the token was issued to and
// the type of token sent.
func TestLogTokenRevocationRefused_Payload(t *testing.T) {
	recorder := &reuseAuditRecorder{}

	LogTokenRevocationRefused(context.Background(), recorder, grantOtherClientID, grantClientID, "access_token")

	require.Equal(t, 1, recorder.calls)
	assert.Equal(t, audit.EventTokenRevocationRefused, recorder.event)
	assert.Equal(t, "token_revocation_refused", recorder.event)
	assert.Equal(t, map[string]interface{}{
		"client_id":       grantOtherClientID,
		"token_client_id": grantClientID,
		"token_type":      "access_token",
	}, recorder.details)
}
