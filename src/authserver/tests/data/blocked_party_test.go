package datatests

import (
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/data/mssqldb"
	"github.com/leodip/goiabada/core/data/mysqldb"
	"github.com/leodip/goiabada/core/data/postgresdb"
	"github.com/leodip/goiabada/core/data/sqlitedb"
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
//  2. THE ENGINE AGREES, AND NAMES THE BLOCKER. On PostgreSQL, MySQL and SQL Server the server
//     publishes who is waiting on whom, and the harness polls until it reports somebody waiting
//     BEHIND THE FOREGROUND TRANSACTION the test holds open. That is the positive proof: not "it
//     has not finished", and not "somebody somewhere is waiting", but "the server says a session
//     is queued behind the connection this test is holding locks on". The second review round
//     showed why the blocker has to be named: a server-wide count of waiters, taken against a
//     baseline, rose when an unrelated transaction blocked on an unrelated row, and a party whose
//     acquisition had been removed then passed while it was still asleep before its first
//     statement. The data tier shares its engine with whatever else the container is running,
//     so anonymous contention is the normal case rather than a corner.
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

// blocker names the foreground transaction's connection in the engine's own terms, so the poll
// below can ask "is anyone waiting behind THIS" rather than "is anyone waiting".
type blocker struct {
	// known is false on SQLite, which has no view to ask.
	known bool
	// id is the backend pid on PostgreSQL, the InnoDB transaction id on MySQL and the session
	// id (@@SPID) on SQL Server.
	id int64
}

// blockedParty is a backgrounded transaction the test needs to catch waiting on a lock the
// foreground transaction is holding.
type blockedParty[T any] struct {
	what    string
	done    chan T
	reached chan struct{}
	behind  blocker
}

// goBlocked runs body in a goroutine and returns the handle to wait on.
//
// behind is the foreground transaction the party is expected to queue behind. Its connection is
// identified BEFORE the party starts, on the transaction itself, so the identity is the
// connection actually holding the locks and not another one from the same pool.
//
// body is handed a reached function and MUST call it on the last line before the statement
// expected to block, after any setup of its own. Calling it earlier weakens check 1 to "the
// goroutine started"; calling it later, past the blocking statement, means it is never called at
// all while the party is blocked and requireBlocked fails on the ceiling.
func goBlocked[T any](t *testing.T, what string, behind *sql.Tx, body func(reached func()) T) *blockedParty[T] {
	t.Helper()

	p := &blockedParty[T]{
		what:    what,
		done:    make(chan T, 1),
		reached: make(chan struct{}),
		behind:  identify(t, behind),
	}

	reached := sync.OnceFunc(func() { close(p.reached) })
	go func() { p.done <- body(reached) }()
	return p
}

// requireBlocked returns only once the party is genuinely waiting for a lock the foreground
// holds, and fails the test rather than returning if it is not. Call it before releasing
// whatever the foreground holds.
func (p *blockedParty[T]) requireBlocked(t *testing.T) {
	t.Helper()
	if err := p.awaitBlocked(); err != nil {
		t.Fatal(err)
	}
}

// awaitBlocked is requireBlocked's decision as a value, so the harness itself can be tested for
// the answer it gives when the party is NOT blocked, which a t.Fatalf cannot be asked about.
func (p *blockedParty[T]) awaitBlocked() error {
	select {
	case <-p.reached:
	case out := <-p.done:
		p.done <- out
		return fmt.Errorf("%s returned before it reached the statement that was supposed to block: "+
			"the two transactions never overlapped, so nothing here was measured", p.what)
	case <-time.After(blockedCeiling):
		return fmt.Errorf("%s never reached the statement that was supposed to block", p.what)
	}

	if !p.behind.known {
		// SQLite. Settle, then fall back to the engine-independent half.
		time.Sleep(sqliteSettle)
		return p.stillWaiting()
	}

	deadline := time.Now().Add(blockedCeiling)
	for {
		n, err := waitersBehind(p.behind)
		if err != nil {
			return err
		}
		if n > 0 {
			return nil
		}
		select {
		case out := <-p.done:
			p.done <- out
			return fmt.Errorf("%s finished without the engine ever reporting it waiting behind the "+
				"foreground transaction: the two never overlapped, so nothing here was measured", p.what)
		default:
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s reached its statement but the engine never reported it waiting "+
				"behind the foreground transaction within %s", p.what, blockedCeiling)
		}
		time.Sleep(pollEvery)
	}
}

// requireStillWaiting fails if the party has already returned. Cheap, engine-independent, and the
// one check that survives if the introspection above ever answers yes for the wrong reason.
func (p *blockedParty[T]) requireStillWaiting(t *testing.T) {
	t.Helper()
	if err := p.stillWaiting(); err != nil {
		t.Fatal(err)
	}
}

func (p *blockedParty[T]) stillWaiting() error {
	select {
	case out := <-p.done:
		p.done <- out
		return fmt.Errorf("%s returned while the other party still held the row it wanted: the two never "+
			"overlapped, so nothing here was measured", p.what)
	default:
		return nil
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

// identify asks the engine, ON THE GIVEN TRANSACTION, which connection that transaction is on.
// Run on the transaction rather than on the pool so the answer is the connection holding the
// locks and not a neighbour from the same pool.
//
// Each id is the one the engine's own wait view reports blockers by: pg_blocking_pids() returns
// backend pids and sys.dm_exec_requests carries session ids. MySQL is matched by InnoDB
// TRANSACTION id and deliberately not by thread id, although data_lock_waits carries both. A row
// a transaction has deleted or updated is locked implicitly, with no lock record of its own,
// and the lock record is created by the FIRST WAITER on the holder's behalf; measured on MySQL
// 8, that record carries the waiter's own thread id as BLOCKING_THREAD_ID while its
// BLOCKING_ENGINE_TRANSACTION_ID is the holder's. Every "the termination goes first" case in
// this package is exactly that shape, a party queuing on a row the foreground deleted, and a
// thread-id match found none of them. The id is read off the locks the transaction already holds
// in performance_schema.data_locks, which the engine populates directly, rather than from
// information_schema.innodb_trx, which serves a cache refreshed at most every 100ms and so
// omits a transaction that wrote a moment ago. A transaction holds locks only once it has
// written, so identify a transaction after its first write; every call site does.
func identify(t *testing.T, tx *sql.Tx) blocker {
	t.Helper()

	var query string
	switch dbType() {
	case "postgres":
		query = "SELECT pg_backend_pid()"
	case "mysql":
		query = "SELECT ENGINE_TRANSACTION_ID FROM performance_schema.data_locks WHERE THREAD_ID = " +
			"(SELECT THREAD_ID FROM performance_schema.threads WHERE PROCESSLIST_ID = CONNECTION_ID()) LIMIT 1"
	case "mssql":
		query = "SELECT @@SPID"
	default:
		// SQLite, and the empty GOIABADA_DB_TYPE the tier falls back to. See the header.
		return blocker{}
	}

	var id int64
	if err := tx.QueryRow(query).Scan(&id); err != nil {
		// Loudly, rather than by degrading to a sleep. A harness that quietly stops checking is
		// the defect this file exists to remove, so a permission or a view that is not there has
		// to be visible as a failure and fixed, not absorbed. On MySQL, no row here means the
		// transaction has not written yet: identify it after its first statement.
		t.Fatalf("identifying the foreground transaction with %q: %v", query, err)
	}
	return blocker{known: true, id: id}
}

// rawHandle is rawSQLHandle without a testing.T, for the poll below, which reports through an
// error rather than failing the test itself.
func rawHandle() *sql.DB {
	switch d := database.(type) {
	case *sqlitedb.SQLiteDatabase:
		return d.DB
	case *mysqldb.MySQLDatabase:
		return d.DB
	case *postgresdb.PostgresDatabase:
		return d.DB
	case *mssqldb.MsSQLDatabase:
		return d.DB
	}
	return nil
}

// waitersBehind asks the engine how many sessions are waiting for a lock held by the named
// connection, right now.
//
// It runs on the pool behind the package's shared handle, which opens a further connection for
// it: every engine that answers this leaves its pool unbounded, and only sqlitedb caps it at one,
// which is the engine that never gets here. Each view is the server's own accounting rather than
// anything this package maintains, and each is readable by the user the data tier runs as (root
// on MySQL, postgres on PostgreSQL, sa on SQL Server, the last of which needs VIEW SERVER STATE
// and has it).
func waitersBehind(b blocker) (int, error) {
	if !b.known {
		return 0, errors.New("waitersBehind asked on an engine with no lock-wait view")
	}

	var query string
	switch dbType() {
	case "postgres":
		// pg_blocking_pids(pid) lists the backends holding what pid is waiting for. A row-lock
		// wait and a table-level wait both appear.
		query = "SELECT count(*) FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))"
	case "mysql":
		// InnoDB publishes each blocked request against the lock blocking it. Populated
		// directly from the storage engine, so no instrument has to be enabled for it. Matched
		// by transaction id, not thread id: see identify.
		query = "SELECT count(*) FROM performance_schema.data_lock_waits WHERE BLOCKING_ENGINE_TRANSACTION_ID = ?"
	case "mssql":
		// blocking_session_id is set on a request queued behind an incompatible lock held by
		// that session, which is exactly the state a blocked party is in.
		query = "SELECT count(*) FROM sys.dm_exec_requests WHERE blocking_session_id = @p1"
	}

	var waiting int
	if err := rawHandle().QueryRow(query, b.id).Scan(&waiting); err != nil {
		return 0, fmt.Errorf("counting the sessions waiting behind connection %d with %q: %w", b.id, query, err)
	}
	return waiting, nil
}
