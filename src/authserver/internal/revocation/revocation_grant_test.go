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
	revokedGrantId     = "fam-revoked-grant"
	grantUserId        = int64(61)
	grantClientId      = int64(6161)
	grantOtherClientId = int64(6262)
)

// grantFixture is one family rotated twice: its first two members revoked by the rotations, the
// last live, and a fork's second live child.
func grantFixture() []*record.RefreshToken {
	return []*record.RefreshToken{
		{Id: 1, RefreshTokenJti: "rt-first", FirstRefreshTokenJti: revokedGrantId, Revoked: true},
		{Id: 2, RefreshTokenJti: "rt-second", FirstRefreshTokenJti: revokedGrantId, Revoked: true},
		{Id: 3, RefreshTokenJti: "rt-live", FirstRefreshTokenJti: revokedGrantId},
		{Id: 4, RefreshTokenJti: "rt-fork", FirstRefreshTokenJti: revokedGrantId},
	}
}

// The revocation records the family under client_revoked first, then reads its members and sweeps
// the live ones, all in one transaction, and reports the members it moved.
func TestRevokeGrantTx_RecordsAndSweepsTheFamily(t *testing.T) {
	db := datamocks.NewDatabase(t)
	tokens := grantFixture()
	var order []string
	datamocks.ExpectRunInTransaction(db, revokeTx)
	db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, revokedGrantId, "client_revoked").
		Run(func(mock.Arguments) { order = append(order, "record") }).
		Return(true, nil).Once()
	db.On("GetRefreshTokensByFirstRefreshTokenJti", mock.Anything, revokeTx, revokedGrantId).
		Run(func(mock.Arguments) { order = append(order, "enumerate") }).
		Return(tokens, nil).Once()
	db.On("UpdateRefreshToken", mock.Anything, revokeTx, tokens[2]).
		Run(func(mock.Arguments) { order = append(order, "sweep") }).
		Return(nil).Once()
	db.On("UpdateRefreshToken", mock.Anything, revokeTx, tokens[3]).
		Run(func(mock.Arguments) { order = append(order, "sweep") }).
		Return(nil).Once()

	result, err := RevokeGrantTx(context.Background(), db, revokedGrantId)

	require.NoError(t, err)
	assert.Equal(t, []string{"rt-live", "rt-fork"}, result.RevokedRefreshTokenJtis,
		"only the members this call moved from live to revoked are reported")
	assert.Equal(t, []string{"record", "enumerate", "sweep", "sweep"}, order)
	for _, rt := range tokens {
		assert.True(t, rt.Revoked, "member %s is revoked", rt.RefreshTokenJti)
	}
}

// A grant already revoked commits, records nothing new and reports an empty list rather than null,
// so the audit record carries [].
func TestRevokeGrantTx_NothingLeftReportsAnEmptyList(t *testing.T) {
	db := datamocks.NewDatabase(t)
	datamocks.ExpectRunInTransaction(db, revokeTx)
	db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, revokedGrantId, "client_revoked").
		Return(false, nil).Once()
	db.On("GetRefreshTokensByFirstRefreshTokenJti", mock.Anything, revokeTx, revokedGrantId).
		Return([]*record.RefreshToken{{Id: 1, RefreshTokenJti: "rt-first", Revoked: true}}, nil).Once()

	result, err := RevokeGrantTx(context.Background(), db, revokedGrantId)

	require.NoError(t, err)
	require.NotNil(t, result.RevokedRefreshTokenJtis)
	assert.Empty(t, result.RevokedRefreshTokenJtis)
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
			notAttempted: []string{"RecordRefreshTokenFamilyRevoked", "GetRefreshTokensByFirstRefreshTokenJti"},
		},
		{
			name: "the record fails",
			setup: func(db *datamocks.Database) {
				datamocks.ExpectRunInTransaction(db, revokeTx)
				db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, revokedGrantId, "client_revoked").
					Return(false, boom).Once()
			},
			notAttempted: []string{"GetRefreshTokensByFirstRefreshTokenJti", "UpdateRefreshToken"},
		},
		{
			name: "the members cannot be read",
			setup: func(db *datamocks.Database) {
				datamocks.ExpectRunInTransaction(db, revokeTx)
				db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, revokedGrantId, "client_revoked").
					Return(true, nil).Once()
				db.On("GetRefreshTokensByFirstRefreshTokenJti", mock.Anything, revokeTx, revokedGrantId).
					Return(nil, boom).Once()
			},
			notAttempted: []string{"UpdateRefreshToken"},
		},
		{
			name: "the sweep fails",
			setup: func(db *datamocks.Database) {
				datamocks.ExpectRunInTransaction(db, revokeTx)
				db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, revokedGrantId, "client_revoked").
					Return(true, nil).Once()
				db.On("GetRefreshTokensByFirstRefreshTokenJti", mock.Anything, revokeTx, revokedGrantId).
					Return(grantFixture(), nil).Once()
				db.On("UpdateRefreshToken", mock.Anything, revokeTx, mock.Anything).Return(boom).Once()
			},
		},
		{
			name: "the commit fails",
			setup: func(db *datamocks.Database) {
				datamocks.ExpectRunInTransactionThenFail(db, revokeTx, boom)
				db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, revokeTx, revokedGrantId, "client_revoked").
					Return(true, nil).Once()
				db.On("GetRefreshTokensByFirstRefreshTokenJti", mock.Anything, revokeTx, revokedGrantId).
					Return(grantFixture(), nil).Once()
				db.On("UpdateRefreshToken", mock.Anything, revokeTx, mock.Anything).Return(nil).Twice()
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := datamocks.NewDatabase(t)
			tc.setup(db)

			result, err := RevokeGrantTx(context.Background(), db, revokedGrantId)

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
		wantJtis  []string
	}{
		{"by its refresh token", "refresh_token", GrantRevocationResult{RevokedRefreshTokenJtis: []string{"rt-live"}}, []string{"rt-live"}},
		{"by an access token", "access_token", GrantRevocationResult{RevokedRefreshTokenJtis: []string{}}, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := &reuseAuditRecorder{}

			LogRevokedGrant(context.Background(), recorder, grantClientId, grantUserId, revokedGrantId, tc.tokenType, tc.result)

			require.Equal(t, 1, recorder.calls)
			assert.Equal(t, audit.EventRevokedGrant, recorder.event)
			assert.Equal(t, "revoked_grant", recorder.event)
			assert.Equal(t, map[string]interface{}{
				"client_id":                  grantClientId,
				"user_id":                    grantUserId,
				"grant_id":                   revokedGrantId,
				"token_type":                 tc.tokenType,
				"revoked_refresh_token_jtis": tc.wantJtis,
			}, recorder.details)
		})
	}
}

// token_revocation_refused carries the client that called, the client the token was issued to and
// the type of token sent.
func TestLogTokenRevocationRefused_Payload(t *testing.T) {
	recorder := &reuseAuditRecorder{}

	LogTokenRevocationRefused(context.Background(), recorder, grantOtherClientId, grantClientId, "access_token")

	require.Equal(t, 1, recorder.calls)
	assert.Equal(t, audit.EventTokenRevocationRefused, recorder.event)
	assert.Equal(t, "token_revocation_refused", recorder.event)
	assert.Equal(t, map[string]interface{}{
		"client_id":       grantOtherClientId,
		"token_client_id": grantClientId,
		"token_type":      "access_token",
	}, recorder.details)
}
