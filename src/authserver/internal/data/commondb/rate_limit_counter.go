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

// errNoRateLimitCounter is a charge that found no row for its window: the reservation creates the
// row and charges again. It never leaves this file.
var errNoRateLimitCounter = errors.New("no rate limit counter for this window")

// errRateLimitRefused is admit refusing under the row's lock, which rolls the charge back. It
// never leaves this file.
var errRateLimitRefused = errors.New("rate limit refused")

// ReserveRateLimitHit charges one hit to keyHash's current window when admit allows it, and
// reports whether it did.
//
// ATOMIC ACROSS HANDLES, which is the whole of its job: two pods reading the same count and both
// taking the last slot is the multiplied budget the table exists to end. The charge is an UPDATE
// of the window's row inside a transaction, so it holds the row's lock from that statement until
// the commit; the counts are read again under that lock and admit asked again, with the hit just
// charged taken back out of the current count, and a refusal there rolls the charge back. Any
// other reservation of the same key waits on that lock and then reads what this one committed,
// on every engine: the UPDATE takes the latest committed row on PostgreSQL and MySQL alike, and
// SQLite has one writer at a time. Only the current window's row is locked, so two reservations
// cannot deadlock on each other; a deadlock with anything else is RunInTransaction's to rerun.
//
// The read before the transaction is the cheap refusal: a key past its budget is refused without
// a write, so a flood against one account is a read per request rather than a write and a
// rollback. Counts only fall between that read and the charge by a refund, so a refusal it
// answers is one the transaction would have answered a moment earlier.
//
// THE ROW IS CREATED OUTSIDE THE TRANSACTION. A window's first reservations can all find no row
// to charge, and all of them insert it; every insert but one loses on the primary key, which on
// PostgreSQL aborts the transaction it ran in. So the charge that finds no row rolls back, the
// row is inserted at zero hits on its own, a lost race on the key being the row existing, and the
// charge runs again. A row lives until two windows after it began, so the second charge finds it.
func (d *Database) ReserveRateLimitHit(ctx context.Context, keyHash string, current, previous, expiresAt time.Time,
	admit func(curr, prev int) bool) (bool, error) {

	if keyHash == "" {
		return false, errs.New("can't reserve a rate limit hit with an empty key hash")
	}
	if admit == nil {
		return false, errs.New("can't reserve a rate limit hit without an admission rule")
	}
	if !expiresAt.After(current) {
		return false, errs.New("can't reserve a rate limit hit in a counter that has already expired")
	}
	current, previous, expiresAt = current.UTC(), previous.UTC(), expiresAt.UTC()

	curr, prev, err := d.GetRateLimitCounts(ctx, nil, keyHash, current, previous)
	if err != nil {
		return false, err
	}
	if !admit(curr, prev) {
		return false, nil
	}

	for attempt := 1; attempt <= 2; attempt++ {
		admitted, err := d.chargeRateLimitHit(ctx, keyHash, current, previous, admit)
		if !errors.Is(err, errNoRateLimitCounter) {
			return admitted, err
		}
		if attempt == 2 {
			break
		}
		if err := d.createRateLimitCounter(ctx, keyHash, current, expiresAt); err != nil {
			return false, err
		}
	}
	return false, errs.New("the rate limit counter for this window was gone again after it was created")
}

// chargeRateLimitHit is one transaction of ReserveRateLimitHit: charge the window's row, read the
// counts under its lock, and keep the charge only if admit, shown the counts before it, allows it.
func (d *Database) chargeRateLimitHit(ctx context.Context, keyHash string, current, previous time.Time,
	admit func(curr, prev int) bool) (bool, error) {

	err := d.RunInTransaction(ctx, func(tx *sql.Tx) error {
		updateBuilder := d.Flavor.NewUpdateBuilder()
		updateBuilder.Update("rate_limit_counters")
		updateBuilder.Set(updateBuilder.Incr("hits"))
		updateBuilder.Where(
			updateBuilder.Equal("key_hash", keyHash),
			updateBuilder.Equal("window_start", current),
		)
		query, args := updateBuilder.Build()
		result, err := d.ExecSQL(ctx, tx, query, args...)
		if err != nil {
			return errs.Wrap(err, "unable to charge rate limit counter")
		}
		charged, err := result.RowsAffected()
		if err != nil {
			return errs.Wrap(err, "unable to get rows affected when charging rate limit counter")
		}
		if charged == 0 {
			return errNoRateLimitCounter
		}

		curr, prev, err := d.GetRateLimitCounts(ctx, tx, keyHash, current, previous)
		if err != nil {
			return err
		}
		if !admit(curr-1, prev) {
			return errRateLimitRefused
		}
		return nil
	})
	if errors.Is(err, errRateLimitRefused) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// createRateLimitCounter inserts a window's row at zero hits, on no transaction. A row already
// there is what a lost race on the key means, and is no error.
func (d *Database) createRateLimitCounter(ctx context.Context, keyHash string, windowStart, expiresAt time.Time) error {
	insertBuilder := d.Flavor.NewInsertBuilder()
	insertBuilder.InsertInto("rate_limit_counters")
	insertBuilder.Cols("key_hash", "window_start", "hits", "expires_at")
	insertBuilder.Values(keyHash, windowStart, 0, expiresAt)

	query, args := insertBuilder.Build()
	_, err := d.ExecSQL(ctx, nil, query, args...)
	if err != nil && !errors.Is(err, data.ErrUniqueViolation) {
		return errs.Wrap(err, "unable to create rate limit counter")
	}
	return nil
}

// RefundRateLimitHit takes one hit back from the window it was charged in. The hits > 0 term keeps
// a count from going below zero, and a row that is gone, swept or never written, is nothing to
// refund.
func (d *Database) RefundRateLimitHit(ctx context.Context, tx *sql.Tx, keyHash string, windowStart time.Time) error {

	if keyHash == "" {
		return errs.New("can't refund a rate limit hit with an empty key hash")
	}

	updateBuilder := d.Flavor.NewUpdateBuilder()
	updateBuilder.Update("rate_limit_counters")
	updateBuilder.Set(updateBuilder.Decr("hits"))
	updateBuilder.Where(
		updateBuilder.Equal("key_hash", keyHash),
		updateBuilder.Equal("window_start", windowStart.UTC()),
		updateBuilder.GreaterThan("hits", 0),
	)
	query, args := updateBuilder.Build()
	if _, err := d.ExecSQL(ctx, tx, query, args...); err != nil {
		return errs.Wrap(err, "unable to refund rate limit counter")
	}
	return nil
}

// GetRateLimitCounts reports keyHash's hits in the current and the previous window.
//
// Both rows are read by one range over the key's windows. The two windows are adjacent, so the
// range holds nothing else, and a row is told apart by whether it began before the current window
// rather than by comparing the instant read back with the one asked for.
//
// The digest each row carries is compared with the one asked for in Go, for the reason
// GetAuthorizeRequestByHandleHash states: SQL Server pads for `=` under every collation.
func (d *Database) GetRateLimitCounts(ctx context.Context, tx *sql.Tx, keyHash string,
	current, previous time.Time) (int, int, error) {

	if keyHash == "" {
		return 0, 0, errs.New("can't read rate limit counts with an empty key hash")
	}

	selectBuilder := d.Flavor.NewSelectBuilder()
	selectBuilder.Select("key_hash", "window_start", "hits").From("rate_limit_counters")
	selectBuilder.Where(
		selectBuilder.Equal("key_hash", keyHash),
		selectBuilder.GreaterEqualThan("window_start", previous.UTC()),
		selectBuilder.LessEqualThan("window_start", current.UTC()),
	)

	query, args := selectBuilder.Build()
	rows, err := d.QuerySQL(ctx, tx, query, args...)
	if err != nil {
		return 0, 0, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var curr, prev int
	for rows.Next() {
		var counter record.RateLimitCounter
		if err := rows.Scan(&counter.KeyHash, &counter.WindowStart, &counter.Hits); err != nil {
			return 0, 0, errs.Wrap(err, "unable to scan rate limit counter")
		}
		if engineFoldedTheMatch(counter.KeyHash, keyHash) {
			continue
		}
		if counter.WindowStart.Before(current) {
			prev = counter.Hits
		} else {
			curr = counter.Hits
		}
	}
	if err := rows.Err(); err != nil {
		return 0, 0, errs.Wrap(err, "unable to read query results")
	}

	return curr, prev, nil
}

// DeleteExpiredRateLimitCounters reaps on expires_at alone: a row is no use once both windows
// that read it are over. An unauthenticated caller creates rows, so the sweep is what bounds the
// table.
func (d *Database) DeleteExpiredRateLimitCounters(ctx context.Context, tx *sql.Tx, now time.Time) error {

	deleteBuilder := d.Flavor.NewDeleteBuilder()
	deleteBuilder.DeleteFrom("rate_limit_counters")
	deleteBuilder.Where(deleteBuilder.LessThan("expires_at", now.UTC()))

	query, args := deleteBuilder.Build()
	if _, err := d.ExecSQL(ctx, tx, query, args...); err != nil {
		return errs.Wrap(err, "unable to delete expired rate limit counters")
	}
	return nil
}
