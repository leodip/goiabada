package recovery

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/audit"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
)

// The behaviour a real database shows, every action on every engine and the reads made under the
// user's row, is the data tier's tests/data/recovery_test.go. What is here is what no real database
// reaches: under the user's row a compare-and-set cannot lose, so the refusal written for one that
// does is driven through the double.

var recoveryTx = &sql.Tx{}

// auditRecorder records the events Run writes.
type auditRecorder struct{ events []string }

func (r *auditRecorder) Log(_ context.Context, auditEvent string, _ map[string]interface{}) {
	r.events = append(r.events, auditEvent)
}

// expectTheUserUnderItsRow stubs Run up to the read under the user's row: the read before the
// transaction answers before, and the read under the row answers under.
func expectTheUserUnderItsRow(database *datamocks.Database, before, under *record.User) *datamocks.RunInTransactionStub {
	database.On("GetUserByEmail", mock.Anything, (*sql.Tx)(nil), "admin@example.com").Return(before, nil)
	stub := datamocks.ExpectRunInTransaction(database, recoveryTx)
	database.On("AcquireUserRow", mock.Anything, recoveryTx, before.Id).Return(nil)
	database.On("GetUserById", mock.Anything, recoveryTx, before.Id).Return(under, nil)
	return stub
}

// TestRun_ARemovalThatLosesItsCompareAndSetCommitsNothing: RemoveTx answers false both when nothing
// was enrolled and when its compare-and-set lost to a change of the authenticator. With one still
// enrolled the recovery is refused, so nothing commits, no audit event is written, and the operator
// is not told that no authenticator was enrolled (#498 review F5).
func TestRun_ARemovalThatLosesItsCompareAndSetCommitsNothing(t *testing.T) {
	database := datamocks.NewDatabase(t)
	user := &record.User{Id: 7, Email: "admin@example.com", Enabled: true, OTPEnabled: true, OtpConfigGeneration: 3}
	stub := expectTheUserUnderItsRow(database, user, user)
	database.On("TryRemoveUserOTP", mock.Anything, recoveryTx, int64(7), int64(3)).Return(false, nil)
	recorder := &auditRecorder{}

	_, err := Run(context.Background(), database, recorder, Request{Email: "admin@example.com", RemoveOTP: true})

	var refusal *RefusedError
	require.ErrorAs(t, err, &refusal)
	assert.Contains(t, refusal.Reason, "changed while the command ran, so nothing was written")
	require.Error(t, stub.BodyErr, "the body asked the helper to roll back")
	assert.Empty(t, recorder.events, "a refusal writes no audit event")
}

// TestRun_ARemovalWithNothingEnrolledIsNoRefusal: the other false, from a user with no
// authenticator, is a removal with nothing to remove, and the recovery carries on.
func TestRun_ARemovalWithNothingEnrolledIsNoRefusal(t *testing.T) {
	database := datamocks.NewDatabase(t)
	user := &record.User{Id: 7, Email: "admin@example.com", Enabled: true, OTPEnabled: false, OtpConfigGeneration: 3}
	stub := expectTheUserUnderItsRow(database, user, user)
	database.On("TryRemoveUserOTP", mock.Anything, recoveryTx, int64(7), int64(3)).Return(false, nil)
	// The sweep follows the write; failing its first statement ends the run there, which is as far
	// as this test needs to see.
	sweepErr := errors.New("the sweep's read")
	database.On("IncrementUserAuthStateGeneration", mock.Anything, recoveryTx, int64(7)).Return(int64(0), sweepErr)

	_, err := Run(context.Background(), database, &auditRecorder{}, Request{Email: "admin@example.com", RemoveOTP: true})

	require.ErrorIs(t, err, sweepErr, "the removal with nothing to remove went on to the sweep")
	var refusal *RefusedError
	assert.NotErrorAs(t, err, &refusal)
	require.Error(t, stub.BodyErr)
}

// TestRun_TheUserIsDecidedOnUnderItsRow: what the transaction finds under the user's row is what
// the recovery acts on, so a user deleted or disabled after the read before it is refused there,
// with nothing written.
func TestRun_TheUserIsDecidedOnUnderItsRow(t *testing.T) {
	user := &record.User{Id: 7, Email: "admin@example.com", Enabled: true}

	for _, tc := range []struct {
		name  string
		under *record.User
		want  string
	}{
		{"deleted", nil, "was deleted while the command ran"},
		{"disabled", &record.User{Id: 7, Email: "admin@example.com", Enabled: false}, "was disabled while the command ran"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			stub := expectTheUserUnderItsRow(database, user, tc.under)
			recorder := &auditRecorder{}

			_, err := Run(context.Background(), database, recorder, Request{Email: "admin@example.com", RemoveOTP: true})

			var refusal *RefusedError
			require.ErrorAs(t, err, &refusal)
			assert.Contains(t, refusal.Reason, tc.want)
			require.Error(t, stub.BodyErr)
			assert.Empty(t, recorder.events)
		})
	}
}

// TestRun_ADeadlockRerunReportsOnlyTheCommittingAttempt: the first attempt finds no manage held and
// grants it, then the engine aborts it as a deadlock victim, which undoes the grant; the rerun finds
// manage held, granted meanwhile by someone else, and grants nothing. The outcome and the audit
// records are the committing attempt's, so the recovery neither says nor records a grant it did not
// make (#301, #498 round 2 F3).
func TestRun_ADeadlockRerunReportsOnlyTheCommittingAttempt(t *testing.T) {
	database := datamocks.NewDatabase(t)
	user := &record.User{Id: 7, Email: "admin@example.com", Enabled: true}
	const manageId = int64(11)
	database.On("GetUserByEmail", mock.Anything, (*sql.Tx)(nil), "admin@example.com").Return(user, nil)
	database.On("GetResourceByResourceIdentifier", mock.Anything, (*sql.Tx)(nil), builtin.AuthServerResourceIdentifier).
		Return(&record.Resource{Id: 3, ResourceIdentifier: builtin.AuthServerResourceIdentifier}, nil)
	database.On("GetPermissionsByResourceId", mock.Anything, (*sql.Tx)(nil), int64(3)).
		Return([]record.Permission{{Id: manageId, PermissionIdentifier: builtin.ManagePermissionIdentifier, ResourceId: 3}}, nil)
	stub := datamocks.ExpectRunInTransactionRerun(database, recoveryTx)
	database.On("AcquireManagePermissionRow", mock.Anything, recoveryTx).Return(manageId, nil).Twice()
	database.On("AcquireUserRow", mock.Anything, recoveryTx, int64(7)).Return(nil).Twice()
	database.On("GetUserById", mock.Anything, recoveryTx, int64(7)).Return(user, nil).Twice()
	database.On("GetUserPermissionsByUserId", mock.Anything, recoveryTx, int64(7)).
		Return([]record.UserPermission{}, nil).Once()
	database.On("GetUserPermissionsByUserId", mock.Anything, recoveryTx, int64(7)).
		Return([]record.UserPermission{{Id: 21, UserId: 7, PermissionId: manageId}}, nil).Once()
	database.On("CreateUserPermission", mock.Anything, recoveryTx, mock.Anything).Return(nil).Once()
	database.On("IncrementUserAuthStateGeneration", mock.Anything, recoveryTx, int64(7)).Return(int64(4), nil).Twice()
	database.On("GetUserSessionsByUserId", mock.Anything, recoveryTx, int64(7)).Return([]record.UserSession{}, nil).Twice()
	database.On("GetRefreshTokensByUserId", mock.Anything, recoveryTx, int64(7)).Return([]*record.RefreshToken{}, nil).Twice()
	database.On("PromoteRefreshTokenGenerations", mock.Anything, recoveryTx, []int64{}, int64(4)).Return(nil).Twice()
	recorder := &auditRecorder{}

	outcome, err := Run(context.Background(), database, recorder, Request{Email: "admin@example.com", GrantManage: true})

	require.NoError(t, err)
	require.NoError(t, stub.BodyErr)
	assert.False(t, outcome.ManageGranted, "the grant the aborted attempt made was undone with it")
	assert.Equal(t, []string{audit.EventRevokedUserAuthState}, recorder.events,
		"no grant is recorded: the committing attempt made none")
}
