package workers

import (
	"context"
	"errors"
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
	mockDB.On("DeleteExpiredRefreshTokens", mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteUsedCodesWithoutRefreshTokens", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteIdleSessions", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteExpiredSessions", mock.Anything, mock.Anything).Return(nil).Maybe()

	// Expect DeleteOldAuditLogs to be called with correct cutoff
	expectedCutoff := time.Now().UTC().Add(-30 * 24 * time.Hour)
	mockDB.On("DeleteOldAuditLogs", mock.Anything, mock.MatchedBy(func(cutoff time.Time) bool {
		// Allow 5 second tolerance for test execution time
		return cutoff.Sub(expectedCutoff) < 5*time.Second && cutoff.Sub(expectedCutoff) > -5*time.Second
	}), 1000).Return(100, nil).Once()

	// Execute worker task
	worker.performTask(context.Background())

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
	mockDB.On("DeleteExpiredRefreshTokens", mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteUsedCodesWithoutRefreshTokens", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteIdleSessions", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteExpiredSessions", mock.Anything, mock.Anything).Return(nil).Maybe()

	// DeleteOldAuditLogs should NOT be called when retention is 0

	// Execute worker task
	worker.performTask(context.Background())

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
	mockDB.On("DeleteExpiredRefreshTokens", mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteUsedCodesWithoutRefreshTokens", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteIdleSessions", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteExpiredSessions", mock.Anything, mock.Anything).Return(nil).Maybe()

	// Simulate batched deletion: first batch deletes 1000, second batch deletes 500 (done)
	mockDB.On("DeleteOldAuditLogs", mock.Anything, mock.Anything, 1000).Return(1000, nil).Once()
	mockDB.On("DeleteOldAuditLogs", mock.Anything, mock.Anything, 1000).Return(500, nil).Once()

	// Execute worker task
	worker.performTask(context.Background())

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
	mockDB.On("DeleteExpiredRefreshTokens", mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteUsedCodesWithoutRefreshTokens", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteIdleSessions", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteExpiredSessions", mock.Anything, mock.Anything).Return(nil).Maybe()

	// Simulate scenario where each batch deletes 1000 rows (would continue forever)
	// But we have max 100 batches, so it should stop at 100
	mockDB.On("DeleteOldAuditLogs", mock.Anything, mock.Anything, 1000).Return(1000, nil).Times(100)

	// Execute worker task
	worker.performTask(context.Background())

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
	mockDB.On("DeleteExpiredRefreshTokens", mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteUsedCodesWithoutRefreshTokens", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteIdleSessions", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteExpiredSessions", mock.Anything, mock.Anything).Return(nil).Maybe()

	// Simulate error on first batch
	mockDB.On("DeleteOldAuditLogs", mock.Anything, mock.Anything, 1000).Return(0, assert.AnError).Once()

	// Execute worker task (should not panic despite error)
	assert.NotPanics(t, func() {
		worker.performTask(context.Background())
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
	mockDB.On("DeleteExpiredRefreshTokens", mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteUsedCodesWithoutRefreshTokens", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteIdleSessions", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteExpiredSessions", mock.Anything, mock.Anything).Return(nil).Maybe()

	// Simulate scenario where no logs are old enough (0 deleted)
	mockDB.On("DeleteOldAuditLogs", mock.Anything, mock.Anything, 1000).Return(0, nil).Once()

	// Execute worker task
	worker.performTask(context.Background())

	// Verify DeleteOldAuditLogs was called once (and stopped because nothing to delete)
	mockDB.AssertNumberOfCalls(t, "DeleteOldAuditLogs", 1)
}

func TestNewWorker(t *testing.T) {
	mockDB := mocks.NewDatabase(t)

	t.Run("Create worker", func(t *testing.T) {
		worker := NewWorker(mockDB)
		assert.NotNil(t, worker)
		assert.Equal(t, mockDB, worker.database)
		// cancel and done are created by Start, so a fresh worker has neither.
		assert.Nil(t, worker.cancel)
		assert.Nil(t, worker.done)
	})
}

// Stop cancels the worker's context and waits for run to finish, bounded by a
// timeout. On a worker that was never started there is nothing to cancel, so it
// returns immediately instead of blocking or panicking on a nil cancel func.
func TestWorker_StopBeforeStartIsANoOp(t *testing.T) {
	mockDB := mocks.NewDatabase(t)
	worker := NewWorker(mockDB)

	done := make(chan struct{})
	go func() {
		worker.Stop(5 * time.Second)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop must return immediately when the worker was never started")
	}
}

// Stop must be safe to call more than once. The previous implementation closed a
// channel directly, so a second call panicked with "close of closed channel".
func TestWorker_StopIsIdempotent(t *testing.T) {
	mockDB := mocks.NewDatabase(t)
	worker := NewWorker(mockDB)

	worker.cancel = func() {}
	worker.done = make(chan struct{})
	close(worker.done)

	assert.NotPanics(t, func() {
		worker.Stop(time.Second)
		worker.Stop(time.Second)
	})
}

// Stop returns once run has finished, which run signals by closing done.
func TestWorker_StopWaitsForTheRunLoop(t *testing.T) {
	mockDB := mocks.NewDatabase(t)
	worker := NewWorker(mockDB)

	ctx, cancel := context.WithCancel(context.Background())
	worker.cancel = cancel
	worker.done = make(chan struct{})

	// Stand in for run: returns only once the context is cancelled.
	go func() {
		defer close(worker.done)
		<-ctx.Done()
	}()

	finished := make(chan struct{})
	go func() {
		worker.Stop(5 * time.Second)
		close(finished)
	}()

	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop did not return after the run loop finished")
	}
}

// The wait is bounded: a run loop that never finishes must not hold shutdown open
// indefinitely, because a database call already in flight cannot be interrupted.
func TestWorker_StopGivesUpAfterTheTimeout(t *testing.T) {
	mockDB := mocks.NewDatabase(t)
	worker := NewWorker(mockDB)

	worker.cancel = func() {}
	worker.done = make(chan struct{}) // never closed

	start := time.Now()
	worker.Stop(200 * time.Millisecond)
	elapsed := time.Since(start)

	assert.GreaterOrEqual(t, elapsed, 200*time.Millisecond, "Stop must wait for the timeout")
	assert.Less(t, elapsed, 3*time.Second, "Stop must not wait past the timeout")
}

// waitOrDone is what makes the startup delay interruptible; the previous
// implementation used a plain time.Sleep that a shutdown could not cut short.
func TestWaitOrDone(t *testing.T) {
	t.Run("returns true when the wait completes", func(t *testing.T) {
		assert.True(t, waitOrDone(context.Background(), time.Millisecond))
	})

	t.Run("returns false as soon as the context is cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		start := time.Now()
		completed := waitOrDone(ctx, 30*time.Second)

		assert.False(t, completed)
		assert.Less(t, time.Since(start), 2*time.Second,
			"an already-cancelled context must not wait out the duration")
	})
}

func TestJitter(t *testing.T) {
	t.Run("stays within the bound", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			d := jitter(time.Second)
			assert.GreaterOrEqual(t, d, time.Duration(0))
			assert.Less(t, d, time.Second)
		}
	})

	t.Run("zero and negative bounds yield no delay", func(t *testing.T) {
		assert.Equal(t, time.Duration(0), jitter(0))
		assert.Equal(t, time.Duration(0), jitter(-time.Second))
	})
}

// =============================================================================
// runIfClaimed
//
// Every instance polls, but the cleanup must run on at most one of them per
// interval. That is decided by the conditional update on settings.last_cleanup_at
// behind TryClaimCleanupRun, so these tests pin that the work is gated on the
// claim rather than on a local timer.
// =============================================================================

// expectFullCleanup allows every call performTask makes, so a test can assert on
// whether the task ran at all rather than on its internals.
func expectFullCleanup(mockDB *mocks.Database) {
	mockDB.On("DeleteExpiredRefreshTokens", mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteUsedCodesWithoutRefreshTokens", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockDB.On("GetSettingsById", mock.Anything, int64(1)).Return(&models.Settings{
		UserSessionIdleTimeoutInSeconds: 3600,
		UserSessionMaxLifetimeInSeconds: 86400,
	}, nil).Maybe()
	mockDB.On("DeleteIdleSessions", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockDB.On("DeleteExpiredSessions", mock.Anything, mock.Anything).Return(nil).Maybe()
}

func TestWorker_RunIfClaimed_RunsWhenTheClaimIsWon(t *testing.T) {
	mockDB := mocks.NewDatabase(t)
	worker := NewWorker(mockDB)

	mockDB.On("TryClaimCleanupRun", mock.Anything, mock.Anything, mock.Anything).
		Return(true, nil).Once()
	// The task ran if it reached its first step.
	mockDB.On("DeleteExpiredRefreshTokens", mock.Anything).Return(nil).Once()
	expectFullCleanup(mockDB)

	worker.runIfClaimed(context.Background())

	mockDB.AssertExpectations(t)
	mockDB.AssertNumberOfCalls(t, "DeleteExpiredRefreshTokens", 1)
}

// Losing the claim means another instance is handling this interval, or it is not
// due yet. Either way nothing else may happen: NewDatabase(t) fails on any
// unexpected call, so the lack of further expectations is the assertion.
func TestWorker_RunIfClaimed_DoesNothingWhenTheClaimIsLost(t *testing.T) {
	mockDB := mocks.NewDatabase(t)
	worker := NewWorker(mockDB)

	mockDB.On("TryClaimCleanupRun", mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Once()

	worker.runIfClaimed(context.Background())

	mockDB.AssertExpectations(t)
	mockDB.AssertNumberOfCalls(t, "DeleteExpiredRefreshTokens", 0)
}

// A failure to claim must not fall through into running the cleanup: that would
// defeat the single-flight guarantee exactly when the database is unhappy.
func TestWorker_RunIfClaimed_DoesNothingWhenTheClaimErrors(t *testing.T) {
	mockDB := mocks.NewDatabase(t)
	worker := NewWorker(mockDB)

	mockDB.On("TryClaimCleanupRun", mock.Anything, mock.Anything, mock.Anything).
		Return(false, errors.New("database is down")).Once()

	worker.runIfClaimed(context.Background())

	mockDB.AssertExpectations(t)
	mockDB.AssertNumberOfCalls(t, "DeleteExpiredRefreshTokens", 0)
}

// The claim cutoff is "now minus the interval", which is what makes the schedule
// wall-clock based rather than tied to this process's uptime.
func TestWorker_RunIfClaimed_PassesTheIntervalCutoff(t *testing.T) {
	mockDB := mocks.NewDatabase(t)
	worker := NewWorker(mockDB)

	var gotNow, gotClaimableBefore time.Time
	mockDB.On("TryClaimCleanupRun", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			gotNow = args.Get(1).(time.Time)
			gotClaimableBefore = args.Get(2).(time.Time)
		}).Return(false, nil).Once()

	before := time.Now().UTC()
	worker.runIfClaimed(context.Background())
	after := time.Now().UTC()

	assert.False(t, gotNow.Before(before))
	assert.False(t, gotNow.After(after))
	assert.Equal(t, gotNow.Add(-cleanupInterval), gotClaimableBefore,
		"the cutoff must be exactly one interval before now")
}

// =============================================================================
// performTask guards
// =============================================================================

// GetSettingsById returns (nil, nil) when the row is absent. The steps after it
// all read a value from settings, so there is nothing to salvage, but it must not
// be dereferenced.
func TestWorker_PerformTask_MissingSettingsRowDoesNotPanic(t *testing.T) {
	mockDB := mocks.NewDatabase(t)
	worker := NewWorker(mockDB)

	mockDB.On("DeleteExpiredRefreshTokens", mock.Anything).Return(nil).Once()
	mockDB.On("DeleteUsedCodesWithoutRefreshTokens", mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("GetSettingsById", mock.Anything, int64(1)).Return(nil, nil).Once()

	assert.NotPanics(t, func() {
		worker.performTask(context.Background())
	})

	// The steps that need settings must not have been attempted.
	mockDB.AssertNumberOfCalls(t, "DeleteIdleSessions", 0)
	mockDB.AssertNumberOfCalls(t, "DeleteExpiredSessions", 0)
}

// One failing step must not stop the others: this is housekeeping, so the run
// should get through as much as it can.
func TestWorker_PerformTask_ContinuesAfterAStepFails(t *testing.T) {
	mockDB := mocks.NewDatabase(t)
	worker := NewWorker(mockDB)

	mockDB.On("DeleteExpiredRefreshTokens", mock.Anything).
		Return(errors.New("delete failed")).Once()
	mockDB.On("DeleteUsedCodesWithoutRefreshTokens", mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("GetSettingsById", mock.Anything, int64(1)).Return(&models.Settings{
		UserSessionIdleTimeoutInSeconds: 3600,
		UserSessionMaxLifetimeInSeconds: 86400,
	}, nil).Once()
	mockDB.On("DeleteIdleSessions", mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteExpiredSessions", mock.Anything, mock.Anything).Return(nil).Once()

	worker.performTask(context.Background())

	mockDB.AssertExpectations(t)
}

// Cancellation is observed between steps, so a shutdown truncates the run instead
// of having to wait it out.
func TestWorker_PerformTask_StopsEarlyWhenCancelled(t *testing.T) {
	mockDB := mocks.NewDatabase(t)
	worker := NewWorker(mockDB)

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel during the very first step.
	mockDB.On("DeleteExpiredRefreshTokens", mock.Anything).
		Run(func(args mock.Arguments) { cancel() }).Return(nil).Once()

	worker.performTask(ctx)

	// Nothing after the first step may have run.
	mockDB.AssertNumberOfCalls(t, "DeleteUsedCodesWithoutRefreshTokens", 0)
	mockDB.AssertNumberOfCalls(t, "GetSettingsById", 0)
	mockDB.AssertExpectations(t)
}

// The audit-log loop is the longest running part, so it checks cancellation per
// batch rather than only once per task.
func TestWorker_DeleteOldAuditLogs_StopsBetweenBatchesWhenCancelled(t *testing.T) {
	mockDB := mocks.NewDatabase(t)
	worker := NewWorker(mockDB)

	ctx, cancel := context.WithCancel(context.Background())

	// A full batch would normally cause another iteration; cancelling during the
	// first one must end the loop instead.
	mockDB.On("DeleteOldAuditLogs", mock.Anything, mock.Anything, auditLogDeleteBatchSize).
		Run(func(args mock.Arguments) { cancel() }).
		Return(auditLogDeleteBatchSize, nil).Once()

	worker.deleteOldAuditLogs(ctx, 30)

	mockDB.AssertNumberOfCalls(t, "DeleteOldAuditLogs", 1)
	mockDB.AssertExpectations(t)
}

func TestWorker_DeleteOldAuditLogs_SkippedWhenRetentionIsUnlimited(t *testing.T) {
	for _, days := range []int{0, -1} {
		mockDB := mocks.NewDatabase(t)
		worker := NewWorker(mockDB)

		// No expectations: nothing may be deleted when retention is unlimited.
		worker.deleteOldAuditLogs(context.Background(), days)

		mockDB.AssertNumberOfCalls(t, "DeleteOldAuditLogs", 0)
	}
}
