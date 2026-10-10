package otpcredential

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// A claim to a code stands only for the authenticator it came from: one removed, and one removed and
// replaced, both stand for nothing, and so does a claim whose generation was never recorded (#542).
func TestOTPClaim_StandsFor(t *testing.T) {
	generation := func(g int64) *int64 { return &g }
	enrolledAt := func(g int64) *record.User { return &record.User{OTPEnabled: true, OtpConfigGeneration: g} }

	testCases := []struct {
		name  string
		claim OTPClaim
		user  *record.User
		want  bool
	}{
		{"no code claimed stands for any user", OTPClaim{}, &record.User{OtpConfigGeneration: 3}, true},
		{"no code claimed stands with no user", OTPClaim{}, nil, true},
		{"the authenticator the code came from", OTPClaim{Claimed: true, Generation: generation(3)}, enrolledAt(3), true},
		{"the authenticator removed", OTPClaim{Claimed: true, Generation: generation(3)}, &record.User{OtpConfigGeneration: 4}, false},
		{"the authenticator removed and another set up", OTPClaim{Claimed: true, Generation: generation(3)}, enrolledAt(5), false},
		{"no generation recorded", OTPClaim{Claimed: true}, enrolledAt(3), false},
		{"the user gone", OTPClaim{Claimed: true, Generation: generation(3)}, nil, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.claim.StandsFor(tc.user))
		})
	}
}

// Recheck reads the user only after taking the user's row, in the caller's transaction, and takes
// nothing for a claim to no code (#542).
func TestOTPClaim_Recheck(t *testing.T) {
	tx := &sql.Tx{}
	generation := int64(3)
	claim := OTPClaim{Claimed: true, Generation: &generation}

	t.Run("no code claimed takes nothing", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		require.NoError(t, OTPClaim{}.Recheck(context.Background(), database, tx, 7))
	})

	t.Run("the authenticator the code came from", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		var order []string
		database.On("AcquireUserRow", mock.Anything, tx, int64(7)).Return(nil).Run(func(mock.Arguments) { order = append(order, "lock") }).Once()
		database.On("GetUserById", mock.Anything, tx, int64(7)).Return(&record.User{Id: 7, OTPEnabled: true, OtpConfigGeneration: 3}, nil).
			Run(func(mock.Arguments) { order = append(order, "read") }).Once()
		require.NoError(t, claim.Recheck(context.Background(), database, tx, 7))
		assert.Equal(t, []string{"lock", "read"}, order, "the user is read under its row lock")
	})

	t.Run("the authenticator removed and another set up", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("AcquireUserRow", mock.Anything, tx, int64(7)).Return(nil).Once()
		database.On("GetUserById", mock.Anything, tx, int64(7)).Return(&record.User{Id: 7, OTPEnabled: true, OtpConfigGeneration: 5}, nil).Once()
		require.ErrorIs(t, claim.Recheck(context.Background(), database, tx, 7), ErrAuthenticatorRemoved)
	})

	t.Run("a lock that fails reads nothing", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		fault := assert.AnError
		database.On("AcquireUserRow", mock.Anything, tx, int64(7)).Return(fault).Once()
		require.ErrorIs(t, claim.Recheck(context.Background(), database, tx, 7), fault)
		database.AssertNotCalled(t, "GetUserById", mock.Anything, mock.Anything, mock.Anything)
	})
}
