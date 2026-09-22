package workers

import (
	"context"
	"testing"

	mocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/stretchr/testify/mock"
)

// Seam 4 of #386 for the worker, and thin for the reason section 5 gives: what the sweep's query
// does with a context belongs to the data tier.
//
// The worker is the one caller in this tree that is NOT below a request boundary, so the context
// it must pass is its own lifecycle context -- the one Stop cancels -- and not a fresh
// context.Background(). reapBrowserSessions had no parameter at all before this stage and so
// could not be stopped; the accept arm is what says it can be now.

type workerCtxKey struct{}

// theWorkersContext matches only the lifecycle context handed to poll, so a sweep that invented
// its own matches nothing and the strict mock reports an unexpected call.
func theWorkersContext() interface{} {
	return mock.MatchedBy(func(ctx context.Context) bool {
		return ctx.Value(workerCtxKey{}) == "lifecycle"
	})
}

func lifecycleContext() context.Context {
	return context.WithValue(context.Background(), workerCtxKey{}, "lifecycle")
}

// Stage 8 tightens two of the stubs below from mock.Anything to theWorkersContext(), because
// TryClaimCleanupRun and GetSettingsById only took a context from that stage onward, and adds the
// audit-log batch loop, which is the one sweep whose statement runs up to a hundred times.

// The accept arm: the browser-session reap runs on the poll's own context. It is the sweep that
// runs outside the claim, every five minutes, and the one whose DELETE grows with an
// unauthenticated caller's request rate (#266 decision 19) -- so it is the sweep most worth being
// able to abandon when the process is shutting down.
func TestWorker_Poll_ReapsUnderTheWorkersContext(t *testing.T) {
	mockDB := mocks.NewDatabase(t)
	worker := NewWorker(mockDB)

	mockDB.On("DeleteExpiredBrowserSessions", theWorkersContext(), mock.Anything, mock.Anything).
		Return(nil).Once()
	mockDB.On("TryClaimCleanupRun", theWorkersContext(), mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Once()

	worker.poll(lifecycleContext())

	mockDB.AssertExpectations(t)
}

// The reject arm: losing the claim stops the poll before performTask, so none of the sweeps
// inside it is reached and there is no context to get wrong. Without it the accept arm would also
// pass on a worker that swept unconditionally.
func TestWorker_Poll_LostClaimReachesNoSweepPort(t *testing.T) {
	mockDB := mocks.NewDatabase(t)
	worker := NewWorker(mockDB)

	mockDB.On("DeleteExpiredBrowserSessions", theWorkersContext(), mock.Anything, mock.Anything).
		Return(nil).Once()
	mockDB.On("TryClaimCleanupRun", theWorkersContext(), mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Once()

	worker.poll(lifecycleContext())

	mockDB.AssertNotCalled(t, "DeleteExpiredRefreshTokens", mock.Anything, mock.Anything)
	mockDB.AssertNotCalled(t, "DeleteUsedCodesWithoutRefreshTokens", mock.Anything, mock.Anything, mock.Anything)
	mockDB.AssertNotCalled(t, "DeleteIdleSessions", mock.Anything, mock.Anything, mock.Anything)
	mockDB.AssertNotCalled(t, "DeleteExpiredSessions", mock.Anything, mock.Anything, mock.Anything)
}

// performTask's own sweeps run on the context runIfClaimed was given, which is the same lifecycle
// context: the claim does not mint a new one. Asserted here rather than left to the poll cases,
// because these four are the sweeps that run inside the twelve-hour claim and a shutdown that
// cannot interrupt them waits for the slowest DELETE in the schema.
func TestWorker_PerformTask_SweepsUnderTheWorkersContext(t *testing.T) {
	mockDB := mocks.NewDatabase(t)
	worker := NewWorker(mockDB)

	mockDB.On("DeleteExpiredRefreshTokens", theWorkersContext(), mock.Anything).Return(nil).Once()
	mockDB.On("DeleteUsedCodesWithoutRefreshTokens", theWorkersContext(), mock.Anything, mock.Anything).
		Return(nil).Once()
	// The settings row is absent, which stops the task before the two session sweeps. That keeps
	// this case about the context and not about the sweep order, which its own tests own.
	mockDB.On("GetSettingsById", theWorkersContext(), mock.Anything, int64(1)).Return(nil, nil).Once()

	worker.performTask(lifecycleContext())

	mockDB.AssertExpectations(t)
}

// The audit-log sweep is the last of performTask's, and the one worth its own case: it is a loop
// that issues up to auditLogDeleteMaxBatches deletes, so it is the sweep a shutdown is most
// likely to land in the middle of, and every iteration has to be issued under the context that
// shutdown cancels rather than under one the loop invented.
func TestWorker_DeleteOldAuditLogs_SweepsUnderTheWorkersContext(t *testing.T) {
	mockDB := mocks.NewDatabase(t)
	worker := NewWorker(mockDB)

	// One short batch, which is what ends the loop after a single statement.
	mockDB.On("DeleteOldAuditLogs", theWorkersContext(), mock.Anything, mock.Anything, auditLogDeleteBatchSize).
		Return(1, nil).Once()

	worker.deleteOldAuditLogs(lifecycleContext(), 30)

	mockDB.AssertExpectations(t)
}
