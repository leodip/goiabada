package commondb

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// A rate-limit counter is one shared tier's hits for one key digest in one window, the row every
// replica's credential limiter reads and charges (#394). The row is keyed by (key_hash,
// window_start); a window's row is created by its first reservation and swept two windows after
// it began. An empty key hash is an error in every method below: no row carries one, so it can
// only be a caller bug, and counting under it would put every such caller in one bucket.

// errNoRateLimitCounter is a charge that found no row for its window, or no row for the window
// before it: the reservation creates what is missing and charges again. It never leaves this file.
var errNoRateLimitCounter = errors.New("no rate limit counter for this window")

// errRateLimitRefused is admit refusing under the rows' locks, which rolls the charge back. It
// never leaves this file.
var errRateLimitRefused = errors.New("rate limit refused")

// lockRateLimitCounter assigns hits to itself on one window's row, which takes the row and changes
// nothing, as AcquireUserRow does.
var lockRateLimitCounter = statement{
	sqlite:   "UPDATE rate_limit_counters SET hits = hits WHERE key_hash = ? AND window_start = ?",
	mysql:    "UPDATE rate_limit_counters SET hits = hits WHERE key_hash = ? AND window_start = ?",
	postgres: "UPDATE rate_limit_counters SET hits = hits WHERE key_hash = $1 AND window_start = $2",
	mssql:    "UPDATE rate_limit_counters SET hits = hits WHERE key_hash = @p1 AND window_start = @p2",
}

var chargeRateLimitCounter = statement{
	sqlite:   "UPDATE rate_limit_counters SET hits = hits + 1 WHERE key_hash = ? AND window_start = ?",
	mysql:    "UPDATE rate_limit_counters SET hits = hits + 1 WHERE key_hash = ? AND window_start = ?",
	postgres: "UPDATE rate_limit_counters SET hits = hits + 1 WHERE key_hash = $1 AND window_start = $2",
	mssql:    "UPDATE rate_limit_counters SET hits = hits + 1 WHERE key_hash = @p1 AND window_start = @p2",
}

// refundRateLimitCounter's hits > 0 term keeps a count from going below zero.
var refundRateLimitCounter = statement{
	sqlite:   "UPDATE rate_limit_counters SET hits = hits - 1 WHERE key_hash = ? AND window_start = ? AND hits > 0",
	mysql:    "UPDATE rate_limit_counters SET hits = hits - 1 WHERE key_hash = ? AND window_start = ? AND hits > 0",
	postgres: "UPDATE rate_limit_counters SET hits = hits - 1 WHERE key_hash = $1 AND window_start = $2 AND hits > 0",
	mssql:    "UPDATE rate_limit_counters SET hits = hits - 1 WHERE key_hash = @p1 AND window_start = @p2 AND hits > 0",
}

// insertRateLimitCounter creates a window's row at zero hits.
var insertRateLimitCounter = statement{
	sqlite:   "INSERT INTO rate_limit_counters (key_hash, window_start, hits, expires_at) VALUES (?, ?, 0, ?)",
	mysql:    "INSERT INTO rate_limit_counters (key_hash, window_start, hits, expires_at) VALUES (?, ?, 0, ?)",
	postgres: "INSERT INTO rate_limit_counters (key_hash, window_start, hits, expires_at) VALUES ($1, $2, 0, $3)",
	mssql:    "INSERT INTO rate_limit_counters (key_hash, window_start, hits, expires_at) VALUES (@p1, @p2, 0, @p3)",
}

// selectRateLimitCounters is the key's rows from a window on.
var selectRateLimitCounters = statement{
	sqlite:   "SELECT key_hash, window_start, hits FROM rate_limit_counters WHERE key_hash = ? AND window_start >= ?",
	mysql:    "SELECT key_hash, window_start, hits FROM rate_limit_counters WHERE key_hash = ? AND window_start >= ?",
	postgres: "SELECT key_hash, window_start, hits FROM rate_limit_counters WHERE key_hash = $1 AND window_start >= $2",
	mssql:    "SELECT key_hash, window_start, hits FROM rate_limit_counters WHERE key_hash = @p1 AND window_start >= @p2",
}

var deleteExpiredRateLimitCounters = statement{
	sqlite:   "DELETE FROM rate_limit_counters WHERE expires_at < ?",
	mysql:    "DELETE FROM rate_limit_counters WHERE expires_at < ?",
	postgres: "DELETE FROM rate_limit_counters WHERE expires_at < $1",
	mssql:    "DELETE FROM rate_limit_counters WHERE expires_at < @p1",
}

// ReserveRateLimitHit charges one hit to keyHash's current window when admit allows it, and
// reports whether it did.
//
// ATOMIC ACROSS HANDLES, which is the whole of its job: two pods reading the same count and both
// taking the last slot is the multiplied budget the table exists to end. The charge runs in a
// transaction that first takes the previous window's row, with an UPDATE assigning hits to
// itself, then charges the current window's row, and holds both locks until the commit; the
// counts are read again under them and admit asked again, with the hit just charged taken back
// out of the current count, and a refusal there rolls the charge back. Any other reservation of
// the same key in the same window waits on the current row, and one in the next window waits on
// this one's current row, which is its previous; either then reads what this one committed, on
// every engine: an UPDATE takes the latest committed row on PostgreSQL, MySQL and SQL Server
// alike, MySQL's read after it opens its snapshot only then, and SQLite has one writer at a time.
// Locking only the current row would leave a reservation in a window that has just begun reading
// the window that has just ended while a reservation still placed there charges it, and both
// would take the last slot (#394, review round 1). Every reservation takes its two rows in
// ascending order of window, so two reservations cannot deadlock on each other; a deadlock with
// anything else is RunInTransaction's to rerun.
//
// A WINDOW THAT HAS MOVED ON IS NOT CHARGED. A reservation can be placed in a window that ends
// before its transaction runs: it read the clock just before the boundary, or waited on the lock
// across it. If the key has a row for a later window, a pod has opened it, and may have admitted
// against this window's count as its previous; a charge here now would raise that count after the
// admission was decided. So the reservation charges nothing and answers
// data.ErrRateLimitWindowMoved, and the limiter places it again in the later window. The row is
// read under the locks, so a later reservation that took this window's row first is seen.
//
// The read before the transaction is the cheap refusal: a key past its budget is refused without
// a write, so a flood against one account is a read per request rather than a write and a
// rollback. Counts only fall between that read and the charge by a refund, so a refusal it
// answers is one the transaction would have answered a moment earlier.
//
// THE ROWS ARE CREATED OUTSIDE THE TRANSACTION. A row can only be locked once it exists, so both
// windows' rows are created at zero hits when the read before the transaction finds either
// missing. A window's first reservations can all find no row, and all of them insert it; every
// insert but one loses on the primary key, which on PostgreSQL aborts the transaction it ran in.
// So the insert runs on its own, a lost race on the key being the row existing, and a
// transaction that finds a row missing anyway rolls back, has it created, and charges again. A
// row lives until two windows after it began, so the second charge finds it.
func (d *Database) ReserveRateLimitHit(ctx context.Context, keyHash string, current, previous, expiresAt time.Time,
	admit func(curr, prev int) bool) (bool, error) {

	if keyHash == "" {
		return false, errs.New("can't reserve a rate limit hit with an empty key hash")
	}
	if admit == nil {
		return false, errs.New("can't reserve a rate limit hit without an admission rule")
	}
	if !previous.Before(current) {
		return false, errs.New("can't reserve a rate limit hit with a previous window that does not precede the current one")
	}
	if !expiresAt.After(current) {
		return false, errs.New("can't reserve a rate limit hit in a counter that has already expired")
	}
	current, previous, expiresAt = current.UTC(), previous.UTC(), expiresAt.UTC()

	rows, err := d.readRateLimitRows(ctx, nil, keyHash, current, previous)
	if err != nil {
		return false, err
	}
	if rows.later {
		return false, errs.WithStack(data.ErrRateLimitWindowMoved)
	}
	if !admit(rows.curr, rows.prev) {
		return false, nil
	}

	for attempt := 1; attempt <= 2; attempt++ {
		if err := d.createMissingRateLimitCounters(ctx, keyHash, current, previous, expiresAt, rows); err != nil {
			return false, err
		}
		admitted, found, err := d.chargeRateLimitHit(ctx, keyHash, current, previous, admit)
		if !errors.Is(err, errNoRateLimitCounter) {
			return admitted, err
		}
		rows = found
	}
	return false, errs.New("a rate limit counter for this reservation was gone again after it was created")
}

// chargeRateLimitHit is one transaction of ReserveRateLimitHit: take the previous window's row,
// charge the current window's, read the key's rows under both locks, and keep the charge only if
// no later window has been opened and admit, shown the counts before it, allows it. A missing row
// is errNoRateLimitCounter, with the rows that were found.
func (d *Database) chargeRateLimitHit(ctx context.Context, keyHash string, current, previous time.Time,
	admit func(curr, prev int) bool) (bool, rateLimitRows, error) {

	var found rateLimitRows
	err := d.RunInTransaction(ctx, func(tx *sql.Tx) error {
		// The previous row first. Assigning a column to itself is the same text on every engine and
		// locks the row on each, as AcquireUserRow does; whether the row exists is the read below's
		// to say, since MySQL counts a row whose columns did not change as unaffected.
		if _, err := d.ExecSQL(ctx, tx, lockRateLimitCounter.text(d.Dialect), keyHash, previous); err != nil {
			return errs.Wrap(err, "unable to lock the previous rate limit counter")
		}

		if _, err := d.ExecSQL(ctx, tx, chargeRateLimitCounter.text(d.Dialect), keyHash, current); err != nil {
			return errs.Wrap(err, "unable to charge rate limit counter")
		}

		rows, err := d.readRateLimitRows(ctx, tx, keyHash, current, previous)
		if err != nil {
			return err
		}
		found = rows
		if !rows.hasCurr || !rows.hasPrev {
			return errNoRateLimitCounter
		}
		if rows.later {
			return errs.WithStack(data.ErrRateLimitWindowMoved)
		}
		if !admit(rows.curr-1, rows.prev) {
			return errRateLimitRefused
		}
		return nil
	})
	if errors.Is(err, errRateLimitRefused) {
		return false, found, nil
	}
	if err != nil {
		return false, found, err
	}
	return true, found, nil
}

// createMissingRateLimitCounters inserts at zero hits whichever of the two windows' rows rows did
// not find. The previous row expires two windows after it began, as every row does, which is one
// window after the current one began.
func (d *Database) createMissingRateLimitCounters(ctx context.Context, keyHash string,
	current, previous, expiresAt time.Time, rows rateLimitRows) error {

	if !rows.hasPrev {
		if err := d.createRateLimitCounter(ctx, keyHash, previous, current.Add(current.Sub(previous))); err != nil {
			return err
		}
	}
	if !rows.hasCurr {
		if err := d.createRateLimitCounter(ctx, keyHash, current, expiresAt); err != nil {
			return err
		}
	}
	return nil
}

// createRateLimitCounter inserts a window's row at zero hits, on no transaction. A row already
// there is what a lost race on the key means, and is no error.
func (d *Database) createRateLimitCounter(ctx context.Context, keyHash string, windowStart, expiresAt time.Time) error {
	_, err := d.ExecSQL(ctx, nil, insertRateLimitCounter.text(d.Dialect), keyHash, windowStart, expiresAt)
	if err != nil && !errors.Is(err, data.ErrUniqueViolation) {
		return errs.Wrap(err, "unable to create rate limit counter")
	}
	return nil
}

// RefundRateLimitHit takes one hit back from the window it was charged in, never below zero. A row
// that is gone, swept or never written, is nothing to refund.
func (d *Database) RefundRateLimitHit(ctx context.Context, tx *sql.Tx, keyHash string, windowStart time.Time) error {

	if keyHash == "" {
		return errs.New("can't refund a rate limit hit with an empty key hash")
	}

	if _, err := d.ExecSQL(ctx, tx, refundRateLimitCounter.text(d.Dialect), keyHash, windowStart.UTC()); err != nil {
		return errs.Wrap(err, "unable to refund rate limit counter")
	}
	return nil
}

// GetRateLimitCounts reports keyHash's hits in the current and the previous window.
func (d *Database) GetRateLimitCounts(ctx context.Context, tx *sql.Tx, keyHash string,
	current, previous time.Time) (int, int, error) {

	rows, err := d.readRateLimitRows(ctx, tx, keyHash, current.UTC(), previous.UTC())
	if err != nil {
		return 0, 0, err
	}
	return rows.curr, rows.prev, nil
}

// rateLimitRows is what one read of a key's rows found, from the previous window on.
type rateLimitRows struct {
	curr, prev       int
	hasCurr, hasPrev bool
	// later is a row for a window after the current one: some pod has opened it.
	later bool
}

// readRateLimitRows reads keyHash's rows from the previous window on, in one range over the
// key's windows. Windows are aligned, so nothing lies between the previous and the current one,
// and a row is told apart by whether it began before, at or after the current window rather than
// by comparing the instant read back with the one asked for.
//
// The digest each row carries is compared with the one asked for in Go, for the reason
// GetAuthorizeRequestByHandleHash states: SQL Server pads for `=` under every collation.
func (d *Database) readRateLimitRows(ctx context.Context, tx *sql.Tx, keyHash string,
	current, previous time.Time) (rateLimitRows, error) {

	if keyHash == "" {
		return rateLimitRows{}, errs.New("can't read rate limit counts with an empty key hash")
	}

	rows, err := d.QuerySQL(ctx, tx, selectRateLimitCounters.text(d.Dialect), keyHash, previous)
	if err != nil {
		return rateLimitRows{}, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var found rateLimitRows
	for rows.Next() {
		var counter record.RateLimitCounter
		if err := rows.Scan(&counter.KeyHash, &counter.WindowStart, &counter.Hits); err != nil {
			return rateLimitRows{}, errs.Wrap(err, "unable to scan rate limit counter")
		}
		if engineFoldedTheMatch(counter.KeyHash, keyHash) {
			continue
		}
		switch {
		case counter.WindowStart.Before(current):
			found.prev, found.hasPrev = counter.Hits, true
		case counter.WindowStart.After(current):
			found.later = true
		default:
			found.curr, found.hasCurr = counter.Hits, true
		}
	}
	if err := rows.Err(); err != nil {
		return rateLimitRows{}, errs.Wrap(err, "unable to read query results")
	}

	return found, nil
}

// DeleteExpiredRateLimitCounters reaps on expires_at alone: a row is no use once both windows
// that read it are over. An unauthenticated caller creates rows, so the sweep is what bounds the
// table.
func (d *Database) DeleteExpiredRateLimitCounters(ctx context.Context, tx *sql.Tx, now time.Time) error {

	if _, err := d.ExecSQL(ctx, tx, deleteExpiredRateLimitCounters.text(d.Dialect), now.UTC()); err != nil {
		return errs.Wrap(err, "unable to delete expired rate limit counters")
	}
	return nil
}
