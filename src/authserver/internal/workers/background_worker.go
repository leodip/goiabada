package workers

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/leodip/goiabada/core/data"
)

const (
	// cleanupInterval is how often the cleanup task should run, in wall-clock
	// terms. It is enforced through the settings.last_cleanup_at claim rather than
	// by a process-local timer, so restarts no longer reset the schedule and
	// several instances do not each run their own copy of it.
	cleanupInterval = 12 * time.Hour

	// pollInterval is how often an instance checks whether the next run is
	// claimable. It must be well under cleanupInterval so a due run is picked up
	// promptly, and short enough that an instance restarted just after a run does
	// not leave the next one late.
	pollInterval = 5 * time.Minute

	// usedCodeCleanupGrace keeps the used-code sweep away from codes that are still
	// being redeemed. The token endpoint marks a code used and only then inserts the
	// refresh token referencing it, so during token generation a healthy code looks
	// exactly like a dead one to that sweep, and deleting it makes the insert fail on
	// fk_refresh_tokens_code. The client gets a 500 instead of its tokens.
	//
	// Codes expire after 60 seconds (token_validator.go), so anything older than that
	// can never be redeemed and can never gain a refresh token. Five minutes is that
	// bound with generous room for clock skew and slow signing.
	//
	// The same cutoff also bounds the second class that sweep reaps, codes revoked
	// while still unredeemed when a session was ended (#129). There the reason is only
	// the 60 second lifetime rather than the foreign key race, so this value is already
	// past what that class needs.
	usedCodeCleanupGrace = 5 * time.Minute

	// startupDelay holds the first poll back so the server can finish coming up
	// first. Unlike the unconditional sleep this replaces, it is interruptible.
	startupDelay = 10 * time.Second

	// maxStartupJitter spreads the first poll out across instances, so replicas
	// started together do not all contend for the claim in the same instant.
	maxStartupJitter = 30 * time.Second

	// auditLogDeleteBatchSize and auditLogDeleteMaxBatches bound how much audit
	// history one run will delete, so a long-neglected table does not turn into a
	// single enormous statement.
	auditLogDeleteBatchSize  = 1000
	auditLogDeleteMaxBatches = 100
)

type Worker struct {
	database data.Database

	// cancel and done are created by Start. cancel being nil means the worker was
	// never started, which Stop treats as a no-op.
	cancel context.CancelFunc
	done   chan struct{}
}

func NewWorker(database data.Database) *Worker {
	return &Worker{
		database: database,
	}
}

func (w *Worker) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	w.done = make(chan struct{})

	go w.run(ctx)
	slog.Info("background worker service started")
}

// Stop signals the worker and waits, up to timeout, for it to finish.
//
// The wait is bounded on purpose. data.Database takes no context, so a delete
// already in flight cannot be interrupted; without a timeout, shutdown would be
// hostage to however long the current statement takes. Stop is also safe to call
// more than once, and safe to call on a worker that was never started.
func (w *Worker) Stop(timeout time.Duration) {
	if w.cancel == nil {
		return
	}

	w.cancel()

	select {
	case <-w.done:
		slog.Info("background worker service stopped")
	case <-time.After(timeout):
		slog.Warn(fmt.Sprintf("background worker did not stop within %v; continuing shutdown", timeout))
	}
}

func (w *Worker) run(ctx context.Context) {
	defer close(w.done)

	if !waitOrDone(ctx, startupDelay+jitter(maxStartupJitter)) {
		return
	}

	w.runIfClaimed(ctx)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			w.runIfClaimed(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// runIfClaimed performs the cleanup only if this instance wins the claim for the
// current interval. Every instance polls; at most one runs.
func (w *Worker) runIfClaimed(ctx context.Context) {
	now := time.Now().UTC()

	claimed, err := w.database.TryClaimCleanupRun(nil, now, now.Add(-cleanupInterval))
	if err != nil {
		slog.Error(fmt.Sprintf("error claiming the cleanup run: %v", err))
		return
	}
	if !claimed {
		// Either another instance is running it, or it is not due yet.
		return
	}

	w.performTask(ctx)
}

// waitOrDone waits for d, or returns false as soon as ctx is cancelled.
func waitOrDone(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// jitter returns a random duration in [0, max).
func jitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(max)))
}

// performTask executes the main worker task.
//
// Each step logs its own failure and the next one still runs: this is
// housekeeping, so one failing delete should not block the others. Cancellation
// is checked between steps, which is the granularity shutdown gets given that the
// individual database calls cannot be interrupted.
func (w *Worker) performTask(ctx context.Context) {
	slog.Info("worker task started")

	// Revoked rows are deliberately NOT swept here. They are the replay-detection
	// signal, retained until the token itself expires (#128).
	err := w.database.DeleteExpiredRefreshTokens(nil)
	if err != nil {
		slog.Error(fmt.Sprintf("error deleting expired refresh tokens: %v", err))
	} else {
		slog.Info("deleted expired refresh tokens")
	}

	if cancelled(ctx) {
		return
	}

	err = w.database.DeleteUsedCodesWithoutRefreshTokens(nil, time.Now().UTC().Add(-usedCodeCleanupGrace))
	if err != nil {
		slog.Error(fmt.Sprintf("error deleting used codes without refresh tokens: %v", err))
	} else {
		slog.Info("deleted used codes without refresh tokens")
	}

	if cancelled(ctx) {
		return
	}

	settings, err := w.database.GetSettingsById(nil, 1)
	if err != nil {
		slog.Error(fmt.Sprintf("error getting settings: %v", err))
		return
	}
	// GetSettingsById returns (nil, nil) when the row is absent. Every remaining
	// step reads a value from settings, so there is nothing to salvage here, but
	// it must not be dereferenced.
	if settings == nil {
		slog.Error("settings row not found; skipping the cleanup steps that need it")
		return
	}

	err = w.database.DeleteIdleSessions(nil, time.Duration(settings.UserSessionIdleTimeoutInSeconds)*time.Second)
	if err != nil {
		slog.Error(fmt.Sprintf("error deleting idle sessions: %v", err))
	} else {
		slog.Info(fmt.Sprintf("deleted idle sessions (idle timeout: %d seconds)", settings.UserSessionIdleTimeoutInSeconds))
	}

	if cancelled(ctx) {
		return
	}

	err = w.database.DeleteExpiredSessions(nil, time.Duration(settings.UserSessionMaxLifetimeInSeconds)*time.Second)
	if err != nil {
		slog.Error(fmt.Sprintf("error deleting expired sessions: %v", err))
	} else {
		slog.Info(fmt.Sprintf("deleted expired sessions (max lifetime: %d seconds)", settings.UserSessionMaxLifetimeInSeconds))
	}

	if cancelled(ctx) {
		return
	}

	w.deleteOldAuditLogs(ctx, settings.AuditLogRetentionDays)

	slog.Info("worker task completed")
}

// deleteOldAuditLogs removes audit history past the retention window, in batches.
// Zero days means retain forever.
func (w *Worker) deleteOldAuditLogs(ctx context.Context, retentionDays int) {
	if retentionDays <= 0 {
		return
	}

	cutoff := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	totalDeleted := 0

	for i := 0; i < auditLogDeleteMaxBatches; i++ {
		// Checked per batch, not just per task: this loop is the longest running
		// part of the cleanup, so it is where a shutdown is most likely to land.
		if cancelled(ctx) {
			break
		}

		deleted, err := w.database.DeleteOldAuditLogs(nil, cutoff, auditLogDeleteBatchSize)
		if err != nil {
			slog.Error(fmt.Sprintf("error deleting old audit logs: %v", err))
			break
		}

		totalDeleted += deleted
		if deleted < auditLogDeleteBatchSize {
			break
		}
	}

	if totalDeleted > 0 {
		slog.Info(fmt.Sprintf("deleted %d audit logs older than %d days", totalDeleted, retentionDays))
	}
}

// cancelled reports whether the worker has been asked to stop, logging once so a
// truncated task run is visible in the log rather than looking like it silently
// did less work.
func cancelled(ctx context.Context) bool {
	if ctx.Err() != nil {
		slog.Info("worker task interrupted by shutdown")
		return true
	}
	return false
}
