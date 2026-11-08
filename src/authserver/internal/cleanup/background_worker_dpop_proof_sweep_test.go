package cleanup

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// The replay store's records of DPoP proofs are swept on every poll, on every instance, outside the
// claim (#42 decision 9). Every DPoP request that succeeds writes one, at the rate DPoP clients make
// them, and a record has nothing left to refuse once its proof could no longer be accepted, ten
// minutes at most: behind the twelve-hour claim the table would hold 72 times its live rows.

// The sweep runs even when the claim is lost, which is every poll but one in thousands.
// datamocks.NewDatabase(t) fails on a call nobody expected, so the absence of a
// DeleteExpiredRefreshTokens expectation is the assertion that the claim really was lost.
func TestWorker_Poll_ReapsDPoPProofsEvenWhenTheClaimIsLost(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	worker := New(mockDB, metrics.NewRegistry())

	expectPollReaps(mockDB)
	mockDB.On("TryClaimCleanupRun", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Once()

	worker.poll(context.Background())

	mockDB.AssertExpectations(t)
	mockDB.AssertNumberOfCalls(t, "DeleteExpiredDPoPProofs", 1)
}

// A record expires against the instant of the poll, in UTC, as expires_at is written.
func TestWorker_Poll_ReapsDPoPProofsWithACurrentTimestamp(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	worker := New(mockDB, metrics.NewRegistry())

	var gotNow time.Time
	mockDB.On("DeleteExpiredBrowserSessions", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteExpiredAuthorizeRequests", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteExpiredRateLimitCounters", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteExpiredDPoPProofs", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { gotNow = args.Get(2).(time.Time) }).Return(nil).Once()
	mockDB.On("TryClaimCleanupRun", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Once()

	before := time.Now().UTC()
	worker.poll(context.Background())
	after := time.Now().UTC()

	assert.Equal(t, time.UTC, gotNow.Location())
	assert.False(t, gotNow.Before(before))
	assert.False(t, gotNow.After(after))
}

// The sweep is housekeeping like the others: its failure is logged, and the other sweeps and the
// claim still run.
func TestWorker_Poll_DPoPProofReapFailureStopsNothingElse(t *testing.T) {
	logs := logtest.CaptureSlog(t)
	mockDB := datamocks.NewDatabase(t)
	worker := New(mockDB, metrics.NewRegistry())

	mockDB.On("DeleteExpiredBrowserSessions", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteExpiredAuthorizeRequests", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteExpiredRateLimitCounters", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteExpiredDPoPProofs", mock.Anything, mock.Anything, mock.Anything).
		Return(errors.New("database is down")).Once()
	mockDB.On("TryClaimCleanupRun", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Once()

	worker.poll(context.Background())

	mockDB.AssertExpectations(t)
	var errorMessages []string
	for _, record := range logs.Records() {
		if record.Level == slog.LevelError {
			errorMessages = append(errorMessages, record.Message)
		}
	}
	assert.Equal(t, []string{"unable to delete expired dpop proofs"}, errorMessages)
}

// expectPollReaps expects each of the poll's four sweeps once, each succeeding.
func expectPollReaps(mockDB *datamocks.Database) {
	mockDB.On("DeleteExpiredBrowserSessions", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteExpiredAuthorizeRequests", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteExpiredRateLimitCounters", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("DeleteExpiredDPoPProofs", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
}
