package cleanup

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// The jtis of revoked access tokens without a grant are swept by the claimed task once their tokens
// have expired (#676 decision 1). Past its expiry a token is refused for that alone, so its row has
// nothing left to refuse; before it, the row is what refuses the token, so the sweep deletes by the
// run's own moment and no later one.

// The sweep runs after the family sweep and before the code sweep, at the moment the run reads.
func TestWorker_PerformTask_SweepsRevokedAccessTokensAtTheRunsMoment(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	worker := New(mockDB, metrics.NewRegistry())

	var order []string
	recordStep := func(step string) func(mock.Arguments) {
		return func(mock.Arguments) { order = append(order, step) }
	}
	var sweptAt time.Time
	mockDB.On("DeleteExpiredRefreshTokens", mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteOrphanedRefreshTokenFamilyRevocations", mock.Anything, mock.Anything).
		Run(recordStep("families")).Return(nil).Once()
	mockDB.On("DeleteExpiredRevokedAccessTokens", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			order = append(order, "access tokens")
			sweptAt = args.Get(2).(time.Time)
		}).Return(nil).Once()
	mockDB.On("DeleteCodesWithoutRefreshTokens", mock.Anything, mock.Anything, mock.Anything).
		Run(recordStep("codes")).Return(nil).Once()
	mockDB.On("DeleteDeadPreRegistrations", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).Return(nil, nil).Once()

	before := time.Now().UTC()
	worker.performTask(context.Background())
	after := time.Now().UTC()

	assert.Equal(t, []string{"families", "access tokens", "codes"}, order)
	assert.Equal(t, time.UTC, sweptAt.Location(), "the moment is read in UTC, as expires_at is written")
	assert.False(t, sweptAt.Before(before) || sweptAt.After(after),
		"the sweep deletes by the run's own moment, %v, not by one before or after the run (%v to %v)", sweptAt, before, after)
	mockDB.AssertExpectations(t)
}

// One failing sweep must not stop the next: the access-token step failing still leaves the code
// sweep and the session sweeps to run, and the run is failed.
func TestWorker_PerformTask_ContinuesAfterTheRevokedAccessTokenSweepFails(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	worker := New(mockDB, metrics.NewRegistry())

	mockDB.On("DeleteExpiredRefreshTokens", mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteOrphanedRefreshTokenFamilyRevocations", mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteExpiredRevokedAccessTokens", mock.Anything, mock.Anything, mock.Anything).
		Return(errors.New("delete failed")).Once()
	mockDB.On("DeleteCodesWithoutRefreshTokens", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteDeadPreRegistrations", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).Return(&record.Settings{
		UserSessionIdleTimeoutInSeconds: 3600,
		UserSessionMaxLifetimeInSeconds: 86400,
	}, nil).Once()
	mockDB.On("DeleteIdleSessions", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteExpiredSessions", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

	ranEveryStep, stepFailed := worker.sweep(context.Background())

	assert.True(t, ranEveryStep, "every later step still ran")
	assert.True(t, stepFailed, "and the run is reported failed")
	mockDB.AssertExpectations(t)
}

// A shutdown during the access-token sweep stops the run before the code sweep: the cancellation
// check sits between the two steps, as between every other pair.
func TestWorker_PerformTask_StopsAfterTheRevokedAccessTokenSweepWhenCancelled(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	worker := New(mockDB, metrics.NewRegistry())

	ctx, cancel := context.WithCancel(context.Background())

	mockDB.On("DeleteExpiredRefreshTokens", mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteOrphanedRefreshTokenFamilyRevocations", mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteExpiredRevokedAccessTokens", mock.Anything, mock.Anything, mock.Anything).
		Run(func(mock.Arguments) { cancel() }).Return(nil).Once()

	worker.performTask(ctx)

	mockDB.AssertNumberOfCalls(t, "DeleteCodesWithoutRefreshTokens", 0)
	mockDB.AssertNumberOfCalls(t, "GetSettingsById", 0)
	mockDB.AssertExpectations(t)
}
