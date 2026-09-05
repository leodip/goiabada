package datatests

import (
	"sync"
	"testing"
	"time"
)

// A CONCURRENCY TEST THAT CANNOT SEE THE OTHER PARTY BLOCK MEASURES NOTHING.
//
// Every test in this package that claims a lock order works does so by holding one transaction
// open, sending a second one at the same rows, and requiring that neither is aborted. That claim
// is only worth anything if the second transaction genuinely reached the lock and waited. Sleeping
// for a fixed interval and then asserting on the outcome does not establish that: a goroutine the
// scheduler has not run yet satisfies a sleep exactly as well as a goroutine stuck on a row lock,
// so the whole file passes with the ordering under test reverted. That was this package's state
// until #139's final review said so, and it is the failure section 4 of the project's testing
// reference describes, a test that transfers confidence it has not earned.
//
// This harness replaces the sleep with three checks, in order:
//
//  1. THE PARTY SIGNALS. The body calls reached() on the line before the statement expected to
//     block, so a goroutine that never ran, or that failed before getting there, is caught rather
//     than counted as blocked.
//  2. THE ENGINE AGREES. On PostgreSQL, MySQL and SQL Server the server publishes its own lock
//     waits, and the harness polls until the count exceeds what it was before the party started.
//     That is the positive proof: not "it has not finished" but "the server says somebody is
//     waiting for a lock". Counting against a baseline rather than against zero keeps it honest
//     on a server with other work on it.
//  3. IT HAS NOT FINISHED. Checked at the moment the foreground releases what it holds. This one
//     is engine-independent, and it is the check that still fails if the introspection above ever
//     starts answering yes for the wrong reason.
//
// SQLite gets 1 and 3 and a settle window in place of 2, because it publishes no lock-wait view
// at all: a blocked writer is inside the driver's busy-retry loop, which nothing outside the
// process can observe. It is also the engine where this matters least, because the authserver
// builds one data.Database and sqlitedb calls SetMaxOpenConns(1), so a SQLite deployment runs the
// whole process on one connection and the transactions these tests interleave can never overlap
// there at all. The second handle is concurrency SQLite does not have in production (#139).

const (
	// lockWaitCeiling is longer than any engine's own lock timeout here (SQLite's busy_timeout is
	// 5s, InnoDB's lock wait 50s), so a party that reaches this has not been refused by the
	// engine, it is genuinely stuck. Failing beats hanging the tier on a lock nobody will release.
	lockWaitCeiling = 90 * time.Second

	// blockedCeiling is how long a party is given to reach the lock and be seen holding still by
	// the server. It only has to exceed one BeginTransaction and one statement, so it is generous
	// by orders of magnitude; overshooting costs nothing, because the poll below returns the
	// moment the engine reports the wait rather than when this elapses.
	blockedCeiling = 30 * time.Second

	// pollEvery paces the introspection query. Small enough that confirming a wait costs
	// single-digit milliseconds, large enough that the query is not itself the load on the server.
	pollEvery = 5 * time.Millisecond

	// sqliteSettle is what stands in for the engine's answer on the one engine that has none. It
	// is the fixed sleep this harness replaced, kept only where nothing better exists and paired
	// with checks 1 and 3 above rather than standing alone as it used to.
	sqliteSettle = 300 * time.Millisecond
)

// blockedParty is a backgrounded transaction the test needs to catch waiting on a lock the
// foreground transaction is holding.
type blockedParty[T any] struct {
	what     string
	done     chan T
	reached  chan struct{}
	baseline int
}

// goBlocked runs body in a goroutine and returns the handle to wait on.
//
// body is handed a reached function and MUST call it on the last line before the statement
// expected to block, after any setup of its own. Calling it earlier weakens check 1 to "the
// goroutine started"; calling it later, past the blocking statement, means it is never called at
// all while the party is blocked and requireBlocked fails on the ceiling.
func goBlocked[T any](t *testing.T, what string, body func(reached func()) T) *blockedParty[T] {
	t.Helper()

	p := &blockedParty[T]{
		what:    what,
		done:    make(chan T, 1),
		reached: make(chan struct{}),

		// Taken BEFORE the party starts, so the poll below asks whether THIS party is waiting
		// rather than whether anything on the server is. The data tier shares its engine with
		// whatever else the container is running.
		baseline: lockWaiters(t),
	}

	reached := sync.OnceFunc(func() { close(p.reached) })
	go func() { p.done <- body(reached) }()
	return p
}

// requireBlocked returns only once the party is genuinely waiting for a lock, and fails the test
// rather than returning if it is not. Call it before releasing whatever the foreground holds.
func (p *blockedParty[T]) requireBlocked(t *testing.T) {
	t.Helper()

	select {
	case <-p.reached:
	case out := <-p.done:
		p.done <- out
		t.Fatalf("%s returned before it reached the statement that was supposed to block: "+
			"the two transactions never overlapped, so nothing here was measured", p.what)
	case <-time.After(blockedCeiling):
		t.Fatalf("%s never reached the statement that was supposed to block", p.what)
	}

	if _, engineAnswers := lockWaitersQuery(); !engineAnswers {
		// SQLite. Settle, then fall back to the engine-independent half.
		time.Sleep(sqliteSettle)
		p.requireStillWaiting(t)
		return
	}

	deadline := time.Now().Add(blockedCeiling)
	for {
		if lockWaiters(t) > p.baseline {
			return
		}
		select {
		case out := <-p.done:
			p.done <- out
			t.Fatalf("%s finished without the engine ever reporting it waiting for a lock: "+
				"the two transactions never overlapped, so nothing here was measured", p.what)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s reached its statement but the engine never reported it waiting for a "+
				"lock within %s", p.what, blockedCeiling)
		}
		time.Sleep(pollEvery)
	}
}

// requireStillWaiting fails if the party has already returned. Cheap, engine-independent, and the
// one check that survives if the introspection above ever answers yes for the wrong reason.
func (p *blockedParty[T]) requireStillWaiting(t *testing.T) {
	t.Helper()
	select {
	case out := <-p.done:
		p.done <- out
		t.Fatalf("%s returned while the other party still held the row it wanted: the two never "+
			"overlapped, so nothing here was measured", p.what)
	default:
	}
}

// await collects the party's outcome. A deadlock arrives as an error inside T and is the caller's
// to assert on; a live hang arrives as the ceiling here, because failing beats hanging the tier.
func (p *blockedParty[T]) await(t *testing.T) T {
	t.Helper()
	select {
	case out := <-p.done:
		return out
	case <-time.After(lockWaitCeiling):
		t.Fatalf("%s never returned: it is still waiting on a lock that nothing is going to release",
			p.what)
		var zero T
		return zero
	}
}

// lockWaitersQuery is the statement that counts how many sessions this engine currently has
// waiting for a lock, and whether the engine offers one at all.
//
// Each is the server's own accounting rather than anything this package maintains, and each is
// readable by the user the data tier runs as (root on MySQL, postgres on PostgreSQL, sa on SQL
// Server, the last of which needs VIEW SERVER STATE and has it).
func lockWaitersQuery() (string, bool) {
	switch dbType() {
	case "postgres":
		// A row-lock wait shows here as an ungranted transactionid lock; a table-level wait as an
		// ungranted relation lock. Either is what this counts.
		return "SELECT count(*) FROM pg_locks WHERE NOT granted", true
	case "mysql":
		// InnoDB publishes each blocked request against the lock blocking it. Populated directly
		// from the storage engine, so no instrument has to be enabled for it.
		return "SELECT count(*) FROM performance_schema.data_lock_waits", true
	case "mssql":
		// request_status is GRANT, CONVERT or WAIT; WAIT is a request queued behind an
		// incompatible lock, which is exactly the state a blocked party is in.
		return "SELECT count(*) FROM sys.dm_tran_locks WHERE request_status = 'WAIT'", true
	}
	// SQLite, and the empty GOIABADA_DB_TYPE the tier falls back to. See the header.
	return "", false
}

// lockWaiters asks the engine how many sessions are waiting for a lock right now.
//
// It runs on the pool behind the package's shared handle, which opens a further connection for
// it: every engine that answers this leaves its pool unbounded, and only sqlitedb caps it at one,
// which is the engine that never gets here.
func lockWaiters(t *testing.T) int {
	t.Helper()

	query, engineAnswers := lockWaitersQuery()
	if !engineAnswers {
		return 0
	}

	var waiting int
	if err := rawSQLHandle(t).QueryRow(query).Scan(&waiting); err != nil {
		// Loudly, rather than by degrading to a sleep. A harness that quietly stops checking is
		// the defect this file exists to remove, so a permission or a view that is not there has
		// to be visible as a failure and fixed, not absorbed.
		t.Fatalf("counting this engine's lock waiters with %q: %v", query, err)
	}
	return waiting
}
