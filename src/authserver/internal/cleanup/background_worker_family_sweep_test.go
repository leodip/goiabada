package cleanup

import (
	"context"
	"errors"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// The records of revoked refresh token families are swept by the claimed task, after the expired
// tokens that make a family's last member go (#132, #259, #437). A record with no member has
// nothing left to refuse, and a record with one is what refuses a child born into a revoked
// family, so the sweep must never run before the tokens it follows or be skipped by a failure.

// The sweep runs after the refresh token sweep and before the code sweep.
func TestWorker_PerformTask_SweepsFamilyRevocationsAfterTheTokens(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	worker := New(mockDB)

	var order []string
	recordStep := func(step string) func(mock.Arguments) {
		return func(mock.Arguments) { order = append(order, step) }
	}
	mockDB.On("DeleteExpiredRefreshTokens", mock.Anything, mock.Anything).
		Run(recordStep("tokens")).Return(nil).Once()
	mockDB.On("DeleteOrphanedRefreshTokenFamilyRevocations", mock.Anything, mock.Anything).
		Run(recordStep("families")).Return(nil).Once()
	mockDB.On("DeleteCodesWithoutRefreshTokens", mock.Anything, mock.Anything, mock.Anything).
		Run(recordStep("codes")).Return(nil).Once()
	mockDB.On("DeleteDeadPreRegistrations", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).Return(nil, nil).Once()

	worker.performTask(context.Background())

	assert.Equal(t, []string{"tokens", "families", "codes"}, order)
	mockDB.AssertExpectations(t)
}

// One failing sweep must not stop the next: the families step failing still leaves the code sweep
// and the session sweeps to run, as the token step failing already does.
func TestWorker_PerformTask_ContinuesAfterTheFamilySweepFails(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	worker := New(mockDB)

	mockDB.On("DeleteExpiredRefreshTokens", mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteOrphanedRefreshTokenFamilyRevocations", mock.Anything, mock.Anything).
		Return(errors.New("delete failed")).Once()
	mockDB.On("DeleteCodesWithoutRefreshTokens", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteDeadPreRegistrations", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).Return(&record.Settings{
		UserSessionIdleTimeoutInSeconds: 3600,
		UserSessionMaxLifetimeInSeconds: 86400,
	}, nil).Once()
	mockDB.On("DeleteIdleSessions", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteExpiredSessions", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

	worker.performTask(context.Background())

	mockDB.AssertExpectations(t)
}

// A shutdown during the family sweep stops the run before the code sweep: the cancellation check
// sits between the two steps, as between every other pair.
func TestWorker_PerformTask_StopsAfterTheFamilySweepWhenCancelled(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	worker := New(mockDB)

	ctx, cancel := context.WithCancel(context.Background())

	mockDB.On("DeleteExpiredRefreshTokens", mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteOrphanedRefreshTokenFamilyRevocations", mock.Anything, mock.Anything).
		Run(func(mock.Arguments) { cancel() }).Return(nil).Once()

	worker.performTask(ctx)

	mockDB.AssertNumberOfCalls(t, "DeleteCodesWithoutRefreshTokens", 0)
	mockDB.AssertNumberOfCalls(t, "GetSettingsById", 0)
	mockDB.AssertExpectations(t)
}
