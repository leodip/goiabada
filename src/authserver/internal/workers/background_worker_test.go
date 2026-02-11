package workers

import (
	"testing"
	"time"

	mocks "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestWorker_AuditLogRetention_Enabled(t *testing.T) {
	// Setup
	mockDB := mocks.NewDatabase(t)

	// Worker reads retention from settings (30 days)
	worker := NewWorker(mockDB)

	// Mock GetSettingsById with retention enabled
	settings := &models.Settings{
		UserSessionIdleTimeoutInSeconds: 3600,
		UserSessionMaxLifetimeInSeconds: 86400,
		AuditLogRetentionDays:           30,
	}
	mockDB.On("GetSettingsById", mock.Anything, int64(1)).Return(settings, nil).Maybe()

	// Mock other worker cleanup operations (they should still run)
	mockDB.On("DeleteExpiredOrRevokedRefreshTokens", mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteUsedCodesWithoutRefreshTokens", mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteIdleSessions", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteExpiredSessions", mock.Anything, mock.Anything).Return(nil).Maybe()

	// Expect DeleteOldAuditLogs to be called with correct cutoff
	expectedCutoff := time.Now().UTC().Add(-30 * 24 * time.Hour)
	mockDB.On("DeleteOldAuditLogs", mock.Anything, mock.MatchedBy(func(cutoff time.Time) bool {
		// Allow 5 second tolerance for test execution time
		return cutoff.Sub(expectedCutoff) < 5*time.Second && cutoff.Sub(expectedCutoff) > -5*time.Second
	}), 1000).Return(100, nil).Once()

	// Execute worker task
	worker.performTask()

	// Verify DeleteOldAuditLogs was called
	mockDB.AssertExpectations(t)
}

func TestWorker_AuditLogRetention_Disabled(t *testing.T) {
	// Setup
	mockDB := mocks.NewDatabase(t)

	// Worker reads retention from settings (0 = infinite retention = disabled)
	worker := NewWorker(mockDB)

	// Mock GetSettingsById with retention disabled
	settings := &models.Settings{
		UserSessionIdleTimeoutInSeconds: 3600,
		UserSessionMaxLifetimeInSeconds: 86400,
		AuditLogRetentionDays:           0,
	}
	mockDB.On("GetSettingsById", mock.Anything, int64(1)).Return(settings, nil).Maybe()

	// Mock other worker cleanup operations
	mockDB.On("DeleteExpiredOrRevokedRefreshTokens", mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteUsedCodesWithoutRefreshTokens", mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteIdleSessions", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteExpiredSessions", mock.Anything, mock.Anything).Return(nil).Maybe()

	// DeleteOldAuditLogs should NOT be called when retention is 0

	// Execute worker task
	worker.performTask()

	// Verify DeleteOldAuditLogs was not called
	mockDB.AssertNotCalled(t, "DeleteOldAuditLogs", mock.Anything, mock.Anything, mock.Anything)
}

func TestWorker_AuditLogRetention_BatchDeletion(t *testing.T) {
	// Setup
	mockDB := mocks.NewDatabase(t)

	// Worker reads retention from settings (90 days)
	worker := NewWorker(mockDB)

	// Mock GetSettingsById with retention enabled
	settings := &models.Settings{
		UserSessionIdleTimeoutInSeconds: 3600,
		UserSessionMaxLifetimeInSeconds: 86400,
		AuditLogRetentionDays:           90,
	}
	mockDB.On("GetSettingsById", mock.Anything, int64(1)).Return(settings, nil).Maybe()

	// Mock other worker cleanup operations
	mockDB.On("DeleteExpiredOrRevokedRefreshTokens", mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteUsedCodesWithoutRefreshTokens", mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteIdleSessions", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteExpiredSessions", mock.Anything, mock.Anything).Return(nil).Maybe()

	// Simulate batched deletion: first batch deletes 1000, second batch deletes 500 (done)
	mockDB.On("DeleteOldAuditLogs", mock.Anything, mock.Anything, 1000).Return(1000, nil).Once()
	mockDB.On("DeleteOldAuditLogs", mock.Anything, mock.Anything, 1000).Return(500, nil).Once()

	// Execute worker task
	worker.performTask()

	// Verify DeleteOldAuditLogs was called twice (batched)
	mockDB.AssertNumberOfCalls(t, "DeleteOldAuditLogs", 2)
}

func TestWorker_AuditLogRetention_MaxBatches(t *testing.T) {
	// Setup
	mockDB := mocks.NewDatabase(t)

	// Worker reads retention from settings (60 days)
	worker := NewWorker(mockDB)

	// Mock GetSettingsById with retention enabled
	settings := &models.Settings{
		UserSessionIdleTimeoutInSeconds: 3600,
		UserSessionMaxLifetimeInSeconds: 86400,
		AuditLogRetentionDays:           60,
	}
	mockDB.On("GetSettingsById", mock.Anything, int64(1)).Return(settings, nil).Maybe()

	// Mock other worker cleanup operations
	mockDB.On("DeleteExpiredOrRevokedRefreshTokens", mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteUsedCodesWithoutRefreshTokens", mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteIdleSessions", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteExpiredSessions", mock.Anything, mock.Anything).Return(nil).Maybe()

	// Simulate scenario where each batch deletes 1000 rows (would continue forever)
	// But we have max 100 batches, so it should stop at 100
	mockDB.On("DeleteOldAuditLogs", mock.Anything, mock.Anything, 1000).Return(1000, nil).Times(100)

	// Execute worker task
	worker.performTask()

	// Verify DeleteOldAuditLogs was called exactly 100 times (max batches limit)
	mockDB.AssertNumberOfCalls(t, "DeleteOldAuditLogs", 100)
}

func TestWorker_AuditLogRetention_Error(t *testing.T) {
	// Setup
	mockDB := mocks.NewDatabase(t)

	// Worker reads retention from settings (45 days)
	worker := NewWorker(mockDB)

	// Mock GetSettingsById with retention enabled
	settings := &models.Settings{
		UserSessionIdleTimeoutInSeconds: 3600,
		UserSessionMaxLifetimeInSeconds: 86400,
		AuditLogRetentionDays:           45,
	}
	mockDB.On("GetSettingsById", mock.Anything, int64(1)).Return(settings, nil).Maybe()

	// Mock other worker cleanup operations
	mockDB.On("DeleteExpiredOrRevokedRefreshTokens", mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteUsedCodesWithoutRefreshTokens", mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteIdleSessions", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteExpiredSessions", mock.Anything, mock.Anything).Return(nil).Maybe()

	// Simulate error on first batch
	mockDB.On("DeleteOldAuditLogs", mock.Anything, mock.Anything, 1000).Return(0, assert.AnError).Once()

	// Execute worker task (should not panic despite error)
	assert.NotPanics(t, func() {
		worker.performTask()
	})

	// Verify DeleteOldAuditLogs was called once (stopped after error)
	mockDB.AssertNumberOfCalls(t, "DeleteOldAuditLogs", 1)
}

func TestWorker_AuditLogRetention_NoDeletion(t *testing.T) {
	// Setup
	mockDB := mocks.NewDatabase(t)

	// Worker reads retention from settings (180 days)
	worker := NewWorker(mockDB)

	// Mock GetSettingsById with retention enabled
	settings := &models.Settings{
		UserSessionIdleTimeoutInSeconds: 3600,
		UserSessionMaxLifetimeInSeconds: 86400,
		AuditLogRetentionDays:           180,
	}
	mockDB.On("GetSettingsById", mock.Anything, int64(1)).Return(settings, nil).Maybe()

	// Mock other worker cleanup operations
	mockDB.On("DeleteExpiredOrRevokedRefreshTokens", mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteUsedCodesWithoutRefreshTokens", mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteIdleSessions", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteExpiredSessions", mock.Anything, mock.Anything).Return(nil).Maybe()

	// Simulate scenario where no logs are old enough (0 deleted)
	mockDB.On("DeleteOldAuditLogs", mock.Anything, mock.Anything, 1000).Return(0, nil).Once()

	// Execute worker task
	worker.performTask()

	// Verify DeleteOldAuditLogs was called once (and stopped because nothing to delete)
	mockDB.AssertNumberOfCalls(t, "DeleteOldAuditLogs", 1)
}

func TestNewWorker(t *testing.T) {
	mockDB := mocks.NewDatabase(t)

	t.Run("Create worker", func(t *testing.T) {
		worker := NewWorker(mockDB)
		assert.NotNil(t, worker)
		assert.Equal(t, mockDB, worker.database)
		assert.NotNil(t, worker.stopChan)
	})
}
