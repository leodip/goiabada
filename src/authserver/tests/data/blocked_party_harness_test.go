package datatests

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// THE HARNESS IS TESTED FOR THE ANSWER IT GIVES WHEN THE PARTY IS NOT BLOCKED.
//
// #139's second review round replaced the harness's original check 2, a server-wide count of
// lock waiters taken against a baseline, with the one in blocked_party_test.go, which names the
// foreground connection and counts only the sessions queued behind it. The reproduction that
// forced the change is the first case below: an unrelated transaction blocked on an unrelated
// row raised the server-wide count, and a party whose acquisition had been removed, and which
// was still asleep before its first statement, was reported as blocked. The foreground then
// committed, and the party ran its statements afterwards against rows nothing held. A test
// built on that answer passes with the ordering it exists to pin reverted.
//
// These cases need two rows held by two transactions of this package's own, so they do not run
// on SQLite: its pool has one connection, so a second transaction on it cannot open while the
// first is held, and the harness there is checks 1 and 3 with a settle window, which has no
// blocker to name.

// unrelatedContention holds a second user's row on a second foreground transaction and sends a
// third connection at it, so the engine has a genuine lock waiter that is queued behind
// SOMEBODY ELSE. It returns a function that releases both.
func unrelatedContention(t *testing.T) (release func()) {
	t.Helper()

	// The second handle first, before anything is held: see secondDatabase for why.
	other := secondDatabase(t)

	bystander := createTestUser(t)
	holder, err := database.BeginTransaction()
	require.NoError(t, err, "opening the unrelated holder's transaction")
	require.NoError(t, database.AcquireUserRow(holder, bystander.Id), "the unrelated holder takes its row")

	waiterDone := make(chan error, 1)
	go func() {
		tx, err := other.BeginTransaction()
		if err != nil {
			waiterDone <- err
			return
		}
		defer func() { _ = other.RollbackTransaction(tx) }()
		waiterDone <- other.AcquireUserRow(tx, bystander.Id)
	}()

	// Wait until the engine actually reports the unrelated waiter, so the contention is real
	// by the time the tested party is judged rather than merely scheduled.
	behind := identify(t, holder)
	deadline := time.Now().Add(blockedCeiling)
	for {
		n, err := waitersBehind(behind)
		require.NoError(t, err)
		if n > 0 {
			break
		}
		require.False(t, time.Now().After(deadline), "the unrelated waiter never showed up in the engine's view")
		time.Sleep(pollEvery)
	}

	return func() {
		_ = database.RollbackTransaction(holder)
		select {
		case <-waiterDone:
		case <-time.After(lockWaitCeiling):
			t.Fatal("the unrelated waiter never returned after its holder released")
		}
	}
}

func TestBlockedParty_UnrelatedContentionIsNotThisParty(t *testing.T) {
	if dbType() == "sqlite" || dbType() == "" {
		t.Skip("SQLite's pool has one connection, so a second held transaction cannot open; the harness there names no blocker")
	}

	secondDatabase(t) // before anything is held: see secondDatabase for why

	user := createTestUser(t)
	tx, err := database.BeginTransaction()
	require.NoError(t, err, "opening the foreground transaction")
	defer func() { _ = database.RollbackTransaction(tx) }()
	require.NoError(t, database.AcquireUserRow(tx, user.Id), "the foreground takes its row")

	release := unrelatedContention(t)
	defer release()

	// The tested party: signals, then sleeps past any plausible poll, then does nothing that
	// could block. This is the shape of a party whose acquisition has been removed and which
	// the scheduler has not run yet. A harness counting anonymous waiters says "blocked" here,
	// because the unrelated waiter is in the count.
	party := goBlocked(t, "a party that never touches the held row", tx, func(reached func()) error {
		reached()
		time.Sleep(600 * time.Millisecond)
		return nil
	})

	err = party.awaitBlocked()
	require.Error(t, err, "a party that never waited behind the foreground must not be reported as blocked")
	assert.Contains(t, err.Error(), "finished without the engine ever reporting it waiting behind the foreground transaction",
		"the failure must be the absence of a wait behind THIS transaction, not a ceiling or a missing signal")
}

func TestBlockedParty_AWaitBehindTheForegroundIsReported(t *testing.T) {
	if dbType() == "sqlite" || dbType() == "" {
		t.Skip("SQLite's pool has one connection, so a second held transaction cannot open; the harness there names no blocker")
	}

	other := secondDatabase(t)
	user := createTestUser(t)
	tx, err := database.BeginTransaction()
	require.NoError(t, err, "opening the foreground transaction")
	defer func() { _ = database.RollbackTransaction(tx) }()
	require.NoError(t, database.AcquireUserRow(tx, user.Id), "the foreground takes its row")

	// The same unrelated contention, so this case differs from the one above only in whether
	// the tested party genuinely queues behind the foreground.
	release := unrelatedContention(t)
	defer release()

	party := goBlocked(t, "a party that wants the held row", tx, func(reached func()) error {
		otherTx, err := other.BeginTransaction()
		if err != nil {
			reached()
			return err
		}
		defer func() { _ = other.RollbackTransaction(otherTx) }()
		reached()
		return other.AcquireUserRow(otherTx, user.Id)
	})

	require.NoError(t, party.awaitBlocked(), "a party queued behind the foreground must be reported as blocked")
	party.requireStillWaiting(t)
	require.NoError(t, database.RollbackTransaction(tx), "releasing the foreground")
	require.NoError(t, party.await(t), "the party proceeds once the foreground releases")
}

// TestBlockedParty_IdentityIsTheTransactionsOwnConnection pins that identify() answers on the
// transaction rather than on the pool: two transactions from the same pool are on two
// connections, and the harness must name the one holding the locks. Each writes first, because
// on MySQL a transaction has no id until it has run an InnoDB statement.
func TestBlockedParty_IdentityIsTheTransactionsOwnConnection(t *testing.T) {
	if dbType() == "sqlite" || dbType() == "" {
		t.Skip("SQLite's pool has one connection, so two transactions on it cannot be open at once")
	}

	first, err := database.BeginTransaction()
	require.NoError(t, err)
	defer func() { _ = database.RollbackTransaction(first) }()
	require.NoError(t, database.AcquireUserRow(first, createTestUser(t).Id))
	second, err := database.BeginTransaction()
	require.NoError(t, err)
	defer func() { _ = database.RollbackTransaction(second) }()
	require.NoError(t, database.AcquireUserRow(second, createTestUser(t).Id))

	a := identify(t, first)
	b := identify(t, second)
	require.True(t, a.known)
	require.True(t, b.known)
	assert.NotEqual(t, a.id, b.id, "two open transactions from one pool are on two connections, and each must be named as its own")
}
