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

// A sign-out with a confirmed id_token_hint ends the departing client's part of the session and, in
// the same transaction, revokes that client's session-bound grants from the session (#135 decision 9).
// The data tier holds what the sweep reaches on every engine; these hold the transaction's shape.

const (
	signOutSid      = "sign-out-sid"
	signOutClientID = int64(6161)
)

var signOutTx = &sql.Tx{}

// signOutSession is a session two clients share, the departing one first.
func signOutSession() *record.UserSession {
	return &record.UserSession{ID: 71, UserID: 17, SessionIdentifier: signOutSid}
}

func signOutSessionClients() []record.UserSessionClient {
	return []record.UserSessionClient{
		{ID: 1, ClientID: signOutClientID, Client: record.Client{ID: signOutClientID, ClientIdentifier: "departing"}},
		{ID: 2, ClientID: 6262, Client: record.Client{ID: 6262, ClientIdentifier: "staying"}},
	}
}

// expectClientPartRemoval stubs the end's reads under the session's row and the removal of the
// departing client's row.
func expectClientPartRemoval(db *datamocks.Database) {
	db.On("GetUserSessionBySessionIdentifier", mock.Anything, (*sql.Tx)(nil), signOutSid).Return(signOutSession(), nil)
	datamocks.ExpectRunInTransaction(db, signOutTx)
	db.On("AcquireUserSessionRow", mock.Anything, signOutTx, signOutSid).Return(true, nil)
	db.On("GetCommittedUserSessionClients", mock.Anything, signOutTx, int64(71)).Return(signOutSessionClients(), nil)
	db.On("DeleteUserSessionClient", mock.Anything, signOutTx, int64(1)).Return(nil)
}

// TestEndClientPartTx_RevokesInTheSameTransaction: the codes and the session-bound tokens of the
// departing client are revoked on the end's own transaction, each family recorded under
// client_signed_out before its tokens are flipped, and the result reports what was transitioned.
func TestEndClientPartTx_RevokesInTheSameTransaction(t *testing.T) {
	db := datamocks.NewDatabase(t)
	expectClientPartRemoval(db)
	tokens := []*record.RefreshToken{
		{ID: 1, RefreshTokenJTI: "rt-rotated", FirstRefreshTokenJTI: "fam-a", Revoked: true},
		{ID: 2, RefreshTokenJTI: "rt-live", FirstRefreshTokenJTI: "fam-a"},
	}
	db.On("RevokeUnusedCodesBySessionIdentifierAndClientID", mock.Anything, signOutTx, signOutSid, signOutClientID).
		Return(int64(3), nil).Once()
	db.On("GetSessionBoundRefreshTokensBySessionIdentifierAndClientID", mock.Anything, signOutTx, signOutSid,
		signOutClientID).Return(tokens, nil).Once()
	recorded := db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, signOutTx, "fam-a", "client_signed_out").
		Return(true, nil).Once()
	db.On("MarkRefreshTokenAsRevoked", mock.Anything, signOutTx, tokens[1].ID).Return(true, nil).Once().NotBefore(recorded)

	end, err := EndClientPartTx(context.Background(), db, signOutSid, "departing")

	require.NoError(t, err)
	require.NotNil(t, end.Ended)
	assert.Equal(t, signOutClientID, end.Ended.Client.ID)
	assert.False(t, end.SessionDeleted)
	assert.Equal(t, int64(3), end.RevokedCodeCount)
	assert.Equal(t, []string{"rt-live"}, end.RevokedRefreshTokenJTIs)
}

// TestEndClientPartTx_NothingToRevokeReportsAnEmptyList: a client with no grant on the session still
// ends its part, and reports [] rather than null for its audit payload.
func TestEndClientPartTx_NothingToRevokeReportsAnEmptyList(t *testing.T) {
	db := datamocks.NewDatabase(t)
	expectClientPartRemoval(db)
	db.On("RevokeUnusedCodesBySessionIdentifierAndClientID", mock.Anything, signOutTx, signOutSid, signOutClientID).
		Return(int64(0), nil).Once()
	db.On("GetSessionBoundRefreshTokensBySessionIdentifierAndClientID", mock.Anything, signOutTx, signOutSid,
		signOutClientID).Return([]*record.RefreshToken(nil), nil).Once()

	end, err := EndClientPartTx(context.Background(), db, signOutSid, "departing")

	require.NoError(t, err)
	require.NotNil(t, end.Ended)
	assert.NotNil(t, end.RevokedRefreshTokenJTIs)
	assert.Empty(t, end.RevokedRefreshTokenJTIs)
}

// TestEndClientPartTx_ATokenRevokedMeanwhileIsNotReported: a session-bound token read live that
// another revocation committed first is not reported by the sign-out, whose conditional write
// matches no live row, so revoked_sign_out_grants never lists a token this call did not revoke
// (#135 decision 2's accounting, which the sign-out's sweep shares).
func TestEndClientPartTx_ATokenRevokedMeanwhileIsNotReported(t *testing.T) {
	db := datamocks.NewDatabase(t)
	expectClientPartRemoval(db)
	db.On("RevokeUnusedCodesBySessionIdentifierAndClientID", mock.Anything, signOutTx, signOutSid, signOutClientID).
		Return(int64(0), nil).Once()
	db.On("GetSessionBoundRefreshTokensBySessionIdentifierAndClientID", mock.Anything, signOutTx, signOutSid,
		signOutClientID).Return([]*record.RefreshToken{
		{ID: 3, RefreshTokenJTI: "rt-revoked-meanwhile", FirstRefreshTokenJTI: "fam-b"},
		{ID: 4, RefreshTokenJTI: "rt-live", FirstRefreshTokenJTI: "fam-b"},
	}, nil).Once()
	db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, signOutTx, "fam-b", ReasonClientSignedOut).
		Return(false, nil).Once()
	db.On("MarkRefreshTokenAsRevoked", mock.Anything, signOutTx, int64(3)).Return(false, nil).Once()
	db.On("MarkRefreshTokenAsRevoked", mock.Anything, signOutTx, int64(4)).Return(true, nil).Once()

	end, err := EndClientPartTx(context.Background(), db, signOutSid, "departing")

	require.NoError(t, err)
	require.NotNil(t, end.Ended)
	assert.Equal(t, []string{"rt-live"}, end.RevokedRefreshTokenJTIs)
}

// TestEndClientPartTx_ASweepFailureYieldsTheZeroResult: a failure of the revocation fails the whole
// end, so the caller neither audits a part that rolled back nor tells the client.
func TestEndClientPartTx_ASweepFailureYieldsTheZeroResult(t *testing.T) {
	boom := errors.New("sweep failed")
	for _, tc := range []struct {
		name   string
		expect func(db *datamocks.Database)
	}{
		{"the code mark", func(db *datamocks.Database) {
			db.On("RevokeUnusedCodesBySessionIdentifierAndClientID", mock.Anything, signOutTx, signOutSid,
				signOutClientID).Return(int64(0), boom).Once()
		}},
		{"the token read", func(db *datamocks.Database) {
			db.On("RevokeUnusedCodesBySessionIdentifierAndClientID", mock.Anything, signOutTx, signOutSid,
				signOutClientID).Return(int64(1), nil).Once()
			db.On("GetSessionBoundRefreshTokensBySessionIdentifierAndClientID", mock.Anything, signOutTx, signOutSid,
				signOutClientID).Return([]*record.RefreshToken(nil), boom).Once()
		}},
		{"the family record", func(db *datamocks.Database) {
			db.On("RevokeUnusedCodesBySessionIdentifierAndClientID", mock.Anything, signOutTx, signOutSid,
				signOutClientID).Return(int64(1), nil).Once()
			db.On("GetSessionBoundRefreshTokensBySessionIdentifierAndClientID", mock.Anything, signOutTx, signOutSid,
				signOutClientID).Return([]*record.RefreshToken{{ID: 2, RefreshTokenJTI: "rt", FirstRefreshTokenJTI: "fam"}}, nil).Once()
			db.On("RecordRefreshTokenFamilyRevoked", mock.Anything, signOutTx, "fam", ReasonClientSignedOut).
				Return(false, boom).Once()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := datamocks.NewDatabase(t)
			expectClientPartRemoval(db)
			tc.expect(db)

			end, err := EndClientPartTx(context.Background(), db, signOutSid, "departing")

			require.ErrorIs(t, err, boom)
			assert.Equal(t, ClientPartEnd{}, end)
		})
	}
}

// TestLogRevokedSignOutGrants_Payload pins the revoked_sign_out_grants payload field by field.
func TestLogRevokedSignOutGrants_Payload(t *testing.T) {
	recorder := &reuseAuditRecorder{}
	clients := signOutSessionClients()

	LogRevokedSignOutGrants(context.Background(), recorder, ClientPartEnd{
		Session: signOutSession(), Ended: &clients[0],
		RevokedCodeCount: 2, RevokedRefreshTokenJTIs: []string{"rt-1"},
	})

	require.Equal(t, 1, recorder.calls)
	assert.Equal(t, "revoked_sign_out_grants", recorder.event)
	assert.Equal(t, audit.EventRevokedSignOutGrants, recorder.event)
	assert.Equal(t, map[string]interface{}{
		"user_id":                    int64(17),
		"client_id":                  signOutClientID,
		"user_session_id":            int64(71),
		"session_identifier":         signOutSid,
		"logged_in_user":             "",
		"revoked_code_count":         int64(2),
		"revoked_refresh_token_jtis": []string{"rt-1"},
	}, recorder.details)
}
