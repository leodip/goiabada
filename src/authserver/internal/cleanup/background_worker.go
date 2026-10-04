package cleanup

import (
	"context"
	"database/sql"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/leodip/goiabada/authserver/internal/emaillinks"
	"github.com/leodip/goiabada/authserver/internal/record"
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

	// codeCleanupGrace keeps the code sweep away from codes that are still being
	// redeemed. The token endpoint marks a code used and only then inserts the refresh
	// token referencing it, so during token generation a healthy code looks exactly
	// like a dead one to that sweep, and deleting it makes the insert fail on
	// fk_refresh_tokens_code. The client gets a 500 instead of its tokens.
	//
	// Codes expire after 60 seconds (token_grant_authorization_code.go), so anything older than that
	// can never be redeemed and can never gain a refresh token. Five minutes is that
	// bound with generous room for clock skew and slow signing. It bounds every class
	// the sweep reaps, used, revoked or never redeemed (#129, #436): past the lifetime
	// each of them is dead for the same reason.
	codeCleanupGrace = 5 * time.Minute

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

// backgroundWorkerDatabase is what the cleanup worker needs: the claim that makes one instance
// the sweeper, and the nine deletes it sweeps with.
type backgroundWorkerDatabase interface {
	DeleteExpiredAuthorizeRequests(ctx context.Context, tx *sql.Tx, now time.Time) error
	DeleteExpiredBrowserSessions(ctx context.Context, tx *sql.Tx, now time.Time) error
	DeleteExpiredRefreshTokens(ctx context.Context, tx *sql.Tx) error
	DeleteExpiredSessions(ctx context.Context, tx *sql.Tx, maxLifetime time.Duration) error
	DeleteOrphanedRefreshTokenFamilyRevocations(ctx context.Context, tx *sql.Tx) error
	DeleteIdleSessions(ctx context.Context, tx *sql.Tx, idleTimeout time.Duration) error
	DeleteOldAuditLogs(ctx context.Context, tx *sql.Tx, cutoff time.Time, maxDeletions int) (int, error)
	DeleteCodesWithoutRefreshTokens(ctx context.Context, tx *sql.Tx, createdBefore time.Time) error
	DeleteDeadPreRegistrations(ctx context.Context, tx *sql.Tx, deadBefore time.Time) error
	GetSettingsById(ctx context.Context, tx *sql.Tx, settingsId int64) (*record.Settings, error)
	TryClaimCleanupRun(ctx context.Context, tx *sql.Tx, now time.Time, claimableBefore time.Time) (bool, error)
}

type Worker struct {
	database backgroundWorkerDatabase

	// cancel and done are created by Start. cancel being nil means the worker was
	// never started, which Stop treats as a no-op.
	cancel context.CancelFunc
	done   chan struct{}
}

func New(database backgroundWorkerDatabase) *Worker {
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
// Cancelling now reaches the statement itself: every database call this worker makes is
// issued under the context Start opened, so a sweep already in flight is abandoned rather than
// waited out (#386). The wait stays bounded anyway, because what the driver does with a
// cancellation is the driver's to decide and shutdown is not the place to find out. Stop is also
// safe to call more than once, and safe to call on a worker that was never started.
func (w *Worker) Stop(timeout time.Duration) {
	if w.cancel == nil {
		return
	}

	w.cancel()

	select {
	case <-w.done:
		slog.Info("background worker service stopped")
	case <-time.After(timeout):
		slog.Warn("the background worker did not stop within the timeout, continuing shutdown",
			"timeout", timeout)
	}
}

func (w *Worker) run(ctx context.Context) {
	defer close(w.done)

	if !waitOrDone(ctx, startupDelay+jitter(maxStartupJitter)) {
		return
	}

	w.poll(ctx)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			w.poll(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// poll is what one tick of the worker does, and the two halves are deliberately unequal.
//
// The browser session reap and the parked authorization request reap run on every instance every
// time, outside the claim. The rest of the cleanup runs on at most one instance every
// cleanupInterval, behind the claim. The calls live here rather than inline in run so the pairing
// is one thing a test can exercise without waiting out the startup delay (#266 decision 19, #437).
func (w *Worker) poll(ctx context.Context) {
	w.reapBrowserSessions(ctx)
	w.reapAuthorizeRequests(ctx)
	w.runIfClaimed(ctx)
}

// reapAuthorizeRequests deletes parked authorization requests whose expires_at has passed.
//
// It is the second sweep that runs outside the claim, for the reason the first one does. A POST to
// /auth/authorize writes a row after checking the client and redirect URI and before anything else,
// and the endpoint is not rate limited, so an unauthenticated caller can produce rows as fast as it
// can send requests, each as large as the request it sent. A request stops being consumable after
// five minutes (authorizerequest.Lifetime), and on the twelve hour claim the row would go on
// EXISTING for up to twelve. Every five minutes keeps the physical bound within one poll of the
// logical one, the relationship #266 decision 19 argued for browser sessions.
//
// Single-flight is given up on the same terms: the delete is idempotent and keyed on an indexed
// column. Do not move this call into performTask (#437).
func (w *Worker) reapAuthorizeRequests(ctx context.Context) {
	if err := w.database.DeleteExpiredAuthorizeRequests(ctx, nil, time.Now().UTC()); err != nil {
		slog.ErrorContext(ctx, "unable to delete expired authorize requests", "error", err)
	}
}

// reapBrowserSessions deletes browser sessions whose expires_at has passed.
//
// It runs on the poll, outside the claim, which is the one sweep in this worker that does.
// The reason is a rate the others do not face: /auth/authorize writes a browser session
// before it validates anything and is not rate limited, so an unauthenticated caller can
// produce rows as fast as it can send requests. A pre-authentication session stops being
// usable after thirty minutes, but on the twelve hour claim it would go on EXISTING for up
// to twelve, and a sustained hundred requests a second would leave about 4.3 million rows
// waiting for one enormous DELETE. Every five minutes puts the physical bound below the
// logical one, which is the relationship the thirty minute lifetime was argued on, and
// each sweep then deletes five minutes of accumulation rather than half a day's.
//
// Giving up single-flight is affordable here and is not affordable for the sweeps inside
// performTask. This delete is idempotent and keyed on an indexed column, so two instances
// running it in the same instant do the same harmless thing; the code sweep beside it
// races the token endpoint's foreign key, which is what codeCleanupGrace exists for.
// Do not move this call into performTask (#266 decision 19).
func (w *Worker) reapBrowserSessions(ctx context.Context) {
	if err := w.database.DeleteExpiredBrowserSessions(ctx, nil, time.Now().UTC()); err != nil {
		slog.ErrorContext(ctx, "unable to delete expired browser sessions", "error", err)
	}
}

// runIfClaimed performs the cleanup only if this instance wins the claim for the
// current interval. Every instance polls; at most one runs.
func (w *Worker) runIfClaimed(ctx context.Context) {
	now := time.Now().UTC()

	claimed, err := w.database.TryClaimCleanupRun(ctx, nil, now, now.Add(-cleanupInterval))
	if err != nil {
		slog.ErrorContext(ctx, "unable to claim the cleanup run", "error", err)
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

// jitter returns a random duration in [0, limit).
func jitter(limit time.Duration) time.Duration {
	if limit <= 0 {
		return 0
	}
	//nolint:gosec // G404: scheduling jitter, not a secret
	return time.Duration(rand.Int64N(int64(limit)))
}

// performTask executes the main worker task.
//
// Each step logs its own failure and the next one still runs: this is
// housekeeping, so one failing delete should not block the others. Cancellation is checked
// between steps AND reaches into each of them, since every call below is issued under this
// context (#386): the check between steps is what stops the next delete from starting, and the
// context is what abandons the one already running.
func (w *Worker) performTask(ctx context.Context) {
	slog.InfoContext(ctx, "worker task started")

	// Revoked rows are deliberately NOT swept here. They are the replay-detection
	// signal, retained until the token itself expires (#128).
	err := w.database.DeleteExpiredRefreshTokens(ctx, nil)
	if err != nil {
		slog.ErrorContext(ctx, "unable to delete expired refresh tokens", "error", err)
	} else {
		slog.InfoContext(ctx, "deleted expired refresh tokens")
	}

	if cancelled(ctx) {
		return
	}

	// After the tokens, since a family's record is removed when its last token is. A record whose
	// family still has a member, live or revoked, stays: it is what refuses a child born into a
	// revoked family (#132, #259).
	err = w.database.DeleteOrphanedRefreshTokenFamilyRevocations(ctx, nil)
	if err != nil {
		slog.ErrorContext(ctx, "unable to delete orphaned refresh token family revocations", "error", err)
	} else {
		slog.InfoContext(ctx, "deleted orphaned refresh token family revocations")
	}

	if cancelled(ctx) {
		return
	}

	err = w.database.DeleteCodesWithoutRefreshTokens(ctx, nil, time.Now().UTC().Add(-codeCleanupGrace))
	if err != nil {
		slog.ErrorContext(ctx, "unable to delete codes without refresh tokens", "error", err)
	} else {
		slog.InfoContext(ctx, "deleted codes without refresh tokens")
	}

	if cancelled(ctx) {
		return
	}

	// Before the settings read, since it needs nothing from settings. The cutoff is the one
	// definition of a pending registration that can no longer complete, the one the registration's
	// replacement of a dead row reads, so this never deletes a row that could still be activated
	// (#207 decision 7). On the claim rather than the poll: registration writes at most one row per
	// address, and only after a well-formed submission at the cost of a sent mail.
	err = w.database.DeleteDeadPreRegistrations(ctx, nil, emaillinks.PreRegistrationDeadBefore(time.Now().UTC()))
	if err != nil {
		slog.ErrorContext(ctx, "unable to delete dead pre-registrations", "error", err)
	} else {
		slog.InfoContext(ctx, "deleted dead pre-registrations")
	}

	if cancelled(ctx) {
		return
	}

	settings, err := w.database.GetSettingsById(ctx, nil, 1)
	if err != nil {
		slog.ErrorContext(ctx, "unable to read the settings row", "error", err)
		return
	}
	// GetSettingsById returns (nil, nil) when the row is absent. Every remaining
	// step reads a value from settings, so there is nothing to salvage here, but
	// it must not be dereferenced.
	if settings == nil {
		slog.ErrorContext(ctx, "settings row not found, skipping the cleanup steps that need it")
		return
	}

	err = w.database.DeleteIdleSessions(ctx, nil, time.Duration(settings.UserSessionIdleTimeoutInSeconds)*time.Second)
	if err != nil {
		slog.ErrorContext(ctx, "unable to delete idle sessions", "error", err)
	} else {
		slog.InfoContext(ctx, "deleted idle sessions",
			"idle_timeout_seconds", settings.UserSessionIdleTimeoutInSeconds)
	}

	if cancelled(ctx) {
		return
	}

	err = w.database.DeleteExpiredSessions(ctx, nil, time.Duration(settings.UserSessionMaxLifetimeInSeconds)*time.Second)
	if err != nil {
		slog.ErrorContext(ctx, "unable to delete expired sessions", "error", err)
	} else {
		slog.InfoContext(ctx, "deleted expired sessions",
			"max_lifetime_seconds", settings.UserSessionMaxLifetimeInSeconds)
	}

	if cancelled(ctx) {
		return
	}

	w.deleteOldAuditLogs(ctx, settings.AuditLogRetentionDays)

	slog.InfoContext(ctx, "worker task completed")
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

		deleted, err := w.database.DeleteOldAuditLogs(ctx, nil, cutoff, auditLogDeleteBatchSize)
		if err != nil {
			slog.ErrorContext(ctx, "unable to delete old audit logs", "error", err)
			break
		}

		totalDeleted += deleted
		if deleted < auditLogDeleteBatchSize {
			break
		}
	}

	if totalDeleted > 0 {
		slog.InfoContext(ctx, "deleted old audit logs",
			"deleted", totalDeleted,
			"retention_days", retentionDays)
	}
}

// cancelled reports whether the worker has been asked to stop, logging once so a
// truncated task run is visible in the log rather than looking like it silently
// did less work.
func cancelled(ctx context.Context) bool {
	if ctx.Err() != nil {
		slog.InfoContext(ctx, "worker task interrupted by shutdown")
		return true
	}
	return false
}
