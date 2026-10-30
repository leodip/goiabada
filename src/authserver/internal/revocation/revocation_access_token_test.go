package revocation

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The access token without a grant a client revokes at /auth/revoke (#676 decision 1), and its
// audit record. Values of their own, so an expectation copied from another fixture in this package
// cannot match here by accident.
const (
	revokedAccessJti    = "at-revoked"
	accessTokenUserId   = int64(71)
	accessTokenClientId = int64(7171)
)

var revokedAccessExpiry = time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC)

// The jti is stored with the token's expiry, on no transaction, and the call reports that it stored
// it.
func TestRevokeAccessToken_StoresTheJti(t *testing.T) {
	db := datamocks.NewDatabase(t)
	db.On("RecordAccessTokenRevoked", mock.Anything, (*sql.Tx)(nil), revokedAccessJti, revokedAccessExpiry).Return(true, nil).Once()

	stored, err := RevokeAccessToken(context.Background(), db, revokedAccessJti, revokedAccessExpiry)

	require.NoError(t, err)
	assert.True(t, stored)
}

// A token whose jti another revocation stored first is not stored again, and the call says so, so
// its caller records nothing: nothing happened.
func TestRevokeAccessToken_AJtiStoredAlready(t *testing.T) {
	db := datamocks.NewDatabase(t)
	db.On("RecordAccessTokenRevoked", mock.Anything, (*sql.Tx)(nil), revokedAccessJti, revokedAccessExpiry).Return(false, nil).Once()

	stored, err := RevokeAccessToken(context.Background(), db, revokedAccessJti, revokedAccessExpiry)

	require.NoError(t, err)
	assert.False(t, stored)
}

// A fault storing the jti is an error, never "stored": the client must not be told its token was
// revoked when it was not.
func TestRevokeAccessToken_AFaultIsAnError(t *testing.T) {
	db := datamocks.NewDatabase(t)
	db.On("RecordAccessTokenRevoked", mock.Anything, (*sql.Tx)(nil), revokedAccessJti, revokedAccessExpiry).
		Return(false, errors.New("connection refused")).Once()

	stored, err := RevokeAccessToken(context.Background(), db, revokedAccessJti, revokedAccessExpiry)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")
	assert.False(t, stored)
}

// A token without a jti or an expiry is one the auth server never signs, so revoking it can only be
// a caller bug: an error, with nothing stored.
func TestRevokeAccessToken_RefusesATokenItCannotStore(t *testing.T) {
	for name, tc := range map[string]struct {
		jti       string
		expiresAt time.Time
	}{
		"no jti":    {"", revokedAccessExpiry},
		"no expiry": {revokedAccessJti, time.Time{}},
	} {
		t.Run(name, func(t *testing.T) {
			db := datamocks.NewDatabase(t)

			stored, err := RevokeAccessToken(context.Background(), db, tc.jti, tc.expiresAt)

			require.Error(t, err)
			assert.False(t, stored)
		})
	}
}

// The revoked_access_token payload, field by field: the client, the jti, and the user only when
// the token has one, a token of the implicit flow; a client credentials token names none.
func TestLogRevokedAccessToken_Payload(t *testing.T) {
	t.Run("a user's token, of the implicit flow", func(t *testing.T) {
		recorder := &reuseAuditRecorder{}

		LogRevokedAccessToken(context.Background(), recorder, accessTokenClientId, accessTokenUserId, revokedAccessJti)

		require.Equal(t, 1, recorder.calls)
		assert.Equal(t, audit.EventRevokedAccessToken, recorder.event)
		assert.Equal(t, "revoked_access_token", recorder.event)
		assert.Equal(t, map[string]interface{}{
			"client_id": accessTokenClientId,
			"user_id":   accessTokenUserId,
			"jti":       revokedAccessJti,
		}, recorder.details)
	})

	t.Run("a client's token, of the client credentials grant", func(t *testing.T) {
		recorder := &reuseAuditRecorder{}

		LogRevokedAccessToken(context.Background(), recorder, accessTokenClientId, 0, revokedAccessJti)

		require.Equal(t, 1, recorder.calls)
		assert.Equal(t, "revoked_access_token", recorder.event)
		assert.Equal(t, map[string]interface{}{
			"client_id": accessTokenClientId,
			"jti":       revokedAccessJti,
		}, recorder.details)
	})
}
