package cleanup

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Pending registrations that can no longer complete are swept by the claimed task (#207 decision
// 7). A pending registration can complete until ten minutes after its link was sent, the code's
// five minutes and then the link marker's five, so the sweep's cutoff is ten minutes before the
// run: a row issued after it may still be activated and must be left alone. The data tier holds
// what the delete does with the cutoff.

// The sweep is handed a cutoff ten minutes in the past, after the code sweep and before the
// settings row is read, since it needs nothing from settings.
func TestWorker_PerformTask_SweepsDeadPreRegistrationsTenMinutesBack(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	worker := New(mockDB)

	var order []string
	recordStep := func(step string) func(mock.Arguments) {
		return func(mock.Arguments) { order = append(order, step) }
	}
	var deadBefore time.Time
	mockDB.On("DeleteExpiredRefreshTokens", mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteOrphanedRefreshTokenFamilyRevocations", mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteCodesWithoutRefreshTokens", mock.Anything, mock.Anything, mock.Anything).
		Run(recordStep("codes")).Return(nil).Once()
	mockDB.On("DeleteDeadPreRegistrations", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			order = append(order, "pre-registrations")
			deadBefore = args.Get(2).(time.Time)
		}).Return(nil).Once()
	mockDB.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).
		Run(recordStep("settings")).Return(nil, nil).Once()

	before := time.Now().UTC()
	worker.performTask(context.Background())
	after := time.Now().UTC()

	mockDB.AssertExpectations(t)
	assert.Equal(t, []string{"codes", "pre-registrations", "settings"}, order)
	assert.False(t, deadBefore.Before(before.Add(-10*time.Minute)),
		"cutoff %v is further back than ten minutes from the start of the run", deadBefore)
	assert.False(t, deadBefore.After(after.Add(-10*time.Minute)),
		"cutoff %v is less than ten minutes behind the end of the run, so it would sweep a pending "+
			"registration that can still complete", deadBefore)
}

// A failing sweep is logged and every step after it still runs: the settings read, the two session
// sweeps and the audit log sweep.
func TestWorker_PerformTask_ContinuesAfterThePreRegistrationSweepFails(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	worker := New(mockDB)

	mockDB.On("DeleteExpiredRefreshTokens", mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteOrphanedRefreshTokenFamilyRevocations", mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteCodesWithoutRefreshTokens", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteDeadPreRegistrations", mock.Anything, mock.Anything, mock.Anything).
		Return(errors.New("delete failed")).Once()
	mockDB.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).Return(&record.Settings{
		UserSessionIdleTimeoutInSeconds: 3600,
		UserSessionMaxLifetimeInSeconds: 86400,
		AuditLogRetentionDays:           30,
	}, nil).Once()
	mockDB.On("DeleteIdleSessions", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteExpiredSessions", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteOldAuditLogs", mock.Anything, mock.Anything, mock.Anything, auditLogDeleteBatchSize).
		Return(0, nil).Once()

	worker.performTask(context.Background())

	mockDB.AssertExpectations(t)
}

// A failing code sweep before it does not stop it either.
func TestWorker_PerformTask_SweepsPreRegistrationsAfterTheCodeSweepFails(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	worker := New(mockDB)

	mockDB.On("DeleteExpiredRefreshTokens", mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteOrphanedRefreshTokenFamilyRevocations", mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteCodesWithoutRefreshTokens", mock.Anything, mock.Anything, mock.Anything).
		Return(errors.New("delete failed")).Once()
	mockDB.On("DeleteDeadPreRegistrations", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("GetSettingsById", mock.Anything, mock.Anything, int64(1)).Return(nil, nil).Once()

	worker.performTask(context.Background())

	mockDB.AssertExpectations(t)
}

// A shutdown during the code sweep stops the run before this one, and a shutdown during this one
// stops it before the settings read: the cancellation check sits between every pair of steps.
func TestWorker_PerformTask_StopsAroundThePreRegistrationSweepWhenCancelled(t *testing.T) {
	t.Run("cancelled during the code sweep", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		worker := New(mockDB)
		ctx, cancel := context.WithCancel(context.Background())

		mockDB.On("DeleteExpiredRefreshTokens", mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("DeleteOrphanedRefreshTokenFamilyRevocations", mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("DeleteCodesWithoutRefreshTokens", mock.Anything, mock.Anything, mock.Anything).
			Run(func(mock.Arguments) { cancel() }).Return(nil).Once()

		worker.performTask(ctx)

		mockDB.AssertNotCalled(t, "DeleteDeadPreRegistrations", mock.Anything, mock.Anything, mock.Anything)
		mockDB.AssertExpectations(t)
	})

	t.Run("cancelled during this sweep", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		worker := New(mockDB)
		ctx, cancel := context.WithCancel(context.Background())

		mockDB.On("DeleteExpiredRefreshTokens", mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("DeleteOrphanedRefreshTokenFamilyRevocations", mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("DeleteCodesWithoutRefreshTokens", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockDB.On("DeleteDeadPreRegistrations", mock.Anything, mock.Anything, mock.Anything).
			Run(func(mock.Arguments) { cancel() }).Return(nil).Once()

		worker.performTask(ctx)

		mockDB.AssertNotCalled(t, "GetSettingsById", mock.Anything, mock.Anything, mock.Anything)
		mockDB.AssertExpectations(t)
	})
}
