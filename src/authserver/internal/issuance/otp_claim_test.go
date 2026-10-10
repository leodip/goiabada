package issuance

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/otpcredential"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
)

// A code naming a one-time code is checked on the user under the user's row, first in the
// transaction, before the session's row is taken and the code written: a removal of the
// authenticator takes the user's row first, so it either waits for this code or is seen here (#542).
func TestIssueAuthCodeTx_ChecksTheOTPClaimUnderTheUserRowFirst(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	generation := int64(4)
	input := issueCodeInput()
	input.AuthMethods = "pwd otp"
	input.OTPClaim = otpcredential.OTPClaim{Claimed: true, Generation: &generation}

	var order []string
	note := func(what string) func(mock.Arguments) {
		return func(mock.Arguments) { order = append(order, what) }
	}
	datamocks.ExpectRunInTransaction(mockDB, issueTx, func(edge string) { order = append(order, edge) })
	mockDB.On("AcquireUserRow", mock.Anything, issueTx, int64(123)).Run(note("user row")).Return(nil).Once()
	mockDB.On("GetUserById", mock.Anything, issueTx, int64(123)).Run(note("user")).
		Return(&record.User{Id: 123, OTPEnabled: true, OtpConfigGeneration: 4}, nil).Once()
	mockDB.On("AcquireUserSessionRow", mock.Anything, issueTx, issueSid).Run(note("session row")).Return(true, nil).Once()
	mockDB.On("GetClientByClientIdentifier", mock.Anything, issueTx, "test-client").Run(note("client")).
		Return(&record.Client{Id: 1, ClientIdentifier: "test-client"}, nil).Once()
	mockDB.On("CreateCode", mock.Anything, issueTx, mock.AnythingOfType("*record.Code")).Run(note("insert")).
		Return(nil).Once()

	code, err := NewCodeIssuer(mockDB).IssueAuthCodeTx(context.Background(), input)

	require.NoError(t, err)
	assert.Equal(t, "pwd otp", code.AuthMethods)
	assert.Equal(t, []string{"begin", "user row", "user", "session row", "client", "insert", "commit"}, order)
}

// A code from an authenticator removed, or removed and replaced, since /auth/issue checked it writes
// no code, and the refusal reaches the caller after the rollback, as the gone session's does (#542).
func TestIssueAuthCodeTx_AClaimThatNoLongerStandsWritesNoCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		user *record.User
	}{
		{"the authenticator removed", &record.User{Id: 123, OtpConfigGeneration: 5}},
		{"the authenticator removed and another set up", &record.User{Id: 123, OTPEnabled: true, OtpConfigGeneration: 6}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := datamocks.NewDatabase(t)
			generation := int64(4)
			input := issueCodeInput()
			input.AuthMethods = "pwd otp"
			input.OTPClaim = otpcredential.OTPClaim{Claimed: true, Generation: &generation}

			var order []string
			stub := datamocks.ExpectRunInTransaction(mockDB, issueTx, func(edge string) { order = append(order, edge) })
			mockDB.On("AcquireUserRow", mock.Anything, issueTx, int64(123)).Return(nil).Once()
			mockDB.On("GetUserById", mock.Anything, issueTx, int64(123)).Return(tc.user, nil).Once()

			code, err := NewCodeIssuer(mockDB).IssueAuthCodeTx(context.Background(), input)
			order = append(order, "returned")

			require.ErrorIs(t, err, otpcredential.ErrAuthenticatorRemoved)
			require.ErrorIs(t, stub.BodyErr, otpcredential.ErrAuthenticatorRemoved)
			assert.Nil(t, code)
			assert.Equal(t, []string{"begin", "rollback", "returned"}, order)
			mockDB.AssertNotCalled(t, "AcquireUserSessionRow", mock.Anything, mock.Anything, mock.Anything)
			mockDB.AssertNotCalled(t, "CreateCode", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// The implicit grant's tokens are checked the same way, before the session's row and before
// anything is signed (#542).
func TestIssueImplicitTx_AClaimThatNoLongerStandsSignsNothing(t *testing.T) {
	f := newImplicitFixture(t)
	generation := int64(4)
	f.input.AuthMethods = "pwd otp"
	f.input.OTPClaim = otpcredential.OTPClaim{Claimed: true, Generation: &generation}

	stub := datamocks.ExpectRunInTransaction(f.mockDB, issueTx)
	f.mockDB.On("AcquireUserRow", mock.Anything, issueTx, f.input.User.Id).Return(nil).Once()
	f.mockDB.On("GetUserById", mock.Anything, issueTx, f.input.User.Id).
		Return(&record.User{Id: f.input.User.Id, OtpConfigGeneration: 5}, nil).Once()

	response, err := f.issuer.IssueImplicitTx(context.Background(), f.settings, f.input, true, true)

	require.ErrorIs(t, err, otpcredential.ErrAuthenticatorRemoved)
	require.ErrorIs(t, stub.BodyErr, otpcredential.ErrAuthenticatorRemoved)
	assert.Nil(t, response)
	f.mockDB.AssertNotCalled(t, "AcquireUserSessionRow", mock.Anything, mock.Anything, mock.Anything)
	f.mockDB.AssertNotCalled(t, "GetCurrentSigningKey", mock.Anything, mock.Anything)
}

// And with the authenticator the code came from, the user's row comes first and the tokens are
// signed as before.
func TestIssueImplicitTx_ChecksTheOTPClaimUnderTheUserRowFirst(t *testing.T) {
	f := newImplicitFixture(t)
	generation := int64(4)
	f.input.AuthMethods = "pwd otp"
	f.input.OTPClaim = otpcredential.OTPClaim{Claimed: true, Generation: &generation}

	var order []string
	datamocks.ExpectRunInTransaction(f.mockDB, issueTx, func(edge string) { order = append(order, edge) })
	f.mockDB.On("AcquireUserRow", mock.Anything, issueTx, f.input.User.Id).
		Run(func(mock.Arguments) { order = append(order, "user row") }).Return(nil).Once()
	f.mockDB.On("GetUserById", mock.Anything, issueTx, f.input.User.Id).
		Run(func(mock.Arguments) { order = append(order, "user") }).
		Return(&record.User{Id: f.input.User.Id, OTPEnabled: true, OtpConfigGeneration: 4}, nil).Once()
	f.mockDB.On("AcquireUserSessionRow", mock.Anything, issueTx, "sid-implicit").
		Run(func(mock.Arguments) { order = append(order, "session row") }).Return(true, nil).Once()
	f.expectEveryRead(&order, true)

	response, err := f.issuer.IssueImplicitTx(context.Background(), f.settings, f.input, true, true)

	require.NoError(t, err)
	require.NotNil(t, response)
	assert.Equal(t, []string{"begin", "user row", "user", "session row"}, order[:4])
}
