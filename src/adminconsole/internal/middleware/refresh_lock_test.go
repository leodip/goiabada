package middleware

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The serialization #621 rests on: one holder at a time per session, sessions independent of
// each other, no entry outliving its last waiter, so a long-lived console keeps no one entry per
// sign-in, and a wait that ends at its deadline holding nothing.

// lockInBackground asks for the session's lock on its own goroutine and reports, on the channel
// it returns, the release once the lock is held.
func lockInBackground(t *testing.T, locks *sessionRefreshLocks, sessionID string) <-chan func() {
	t.Helper()
	acquired := make(chan func(), 1)
	go func() {
		release, err := locks.Lock(context.Background(), sessionID)
		if err != nil {
			t.Errorf("an unbounded wait failed: %v", err)
			return
		}
		acquired <- release
	}()
	return acquired
}

// queuedSignal sets the locks' queued hook and returns the channel it reports each queued
// request on.
func queuedSignal(locks *sessionRefreshLocks) <-chan string {
	queued := make(chan string, 8)
	locks.queued = func(sessionID string) { queued <- sessionID }
	return queued
}

func awaitQueued(t *testing.T, queued <-chan string) {
	t.Helper()
	select {
	case <-queued:
	case <-time.After(5 * time.Second):
		t.Fatal("no request queued on the lock")
	}
}

func awaitAcquired(t *testing.T, acquired <-chan func()) func() {
	t.Helper()
	select {
	case release := <-acquired:
		return release
	case <-time.After(5 * time.Second):
		t.Fatal("the lock was never acquired")
		return nil
	}
}

func assertNotAcquired(t *testing.T, acquired <-chan func(), why string) {
	t.Helper()
	select {
	case <-acquired:
		t.Fatal(why)
	case <-time.After(50 * time.Millisecond):
	}
}

func assertNoEntries(t *testing.T, locks *sessionRefreshLocks) {
	t.Helper()
	locks.mu.Lock()
	defer locks.mu.Unlock()
	assert.Empty(t, locks.locks, "the last one to leave removes the entry")
}

func TestSessionRefreshLocks_ExcludesASecondHolderOfOneSession(t *testing.T) {
	locks := newSessionRefreshLocks()
	queued := queuedSignal(locks)

	release, err := locks.Lock(context.Background(), "the-session")
	require.NoError(t, err)
	acquired := lockInBackground(t, locks, "the-session")
	awaitQueued(t, queued)
	assertNotAcquired(t, acquired, "a second holder entered while the first held the lock")

	release()
	awaitAcquired(t, acquired)()

	// The waiter was counted with the holder, so the entry it leaves behind is removed when
	// the waiter, not the first holder, is the last to leave.
	assertNoEntries(t, locks)
}

// A third request arriving once the holder has released, while the waiter it handed the lock to
// still holds it, waits too: the entry the waiter holds is still the session's, because it was
// counted with the holder and was not removed when the holder left.
func TestSessionRefreshLocks_AThirdArrivalWaitsForTheWaiterThatTookTheLock(t *testing.T) {
	locks := newSessionRefreshLocks()
	queued := queuedSignal(locks)

	holder, err := locks.Lock(context.Background(), "the-session")
	require.NoError(t, err)
	waiterAcquired := lockInBackground(t, locks, "the-session")
	awaitQueued(t, queued)

	holder()
	waiter := awaitAcquired(t, waiterAcquired)

	thirdAcquired := lockInBackground(t, locks, "the-session")
	awaitQueued(t, queued)
	assertNotAcquired(t, thirdAcquired, "a third request held the lock beside the waiter")

	waiter()
	awaitAcquired(t, thirdAcquired)()
	assertNoEntries(t, locks)
}

func TestSessionRefreshLocks_DifferentSessionsDoNotWaitForEachOther(t *testing.T) {
	locks := newSessionRefreshLocks()
	locks.queued = func(sessionID string) { t.Errorf("%s waited for another session's lock", sessionID) }

	release, err := locks.Lock(context.Background(), "the-first-session")
	require.NoError(t, err)
	defer release()

	awaitAcquired(t, lockInBackground(t, locks, "the-second-session"))()
}

func TestSessionRefreshLocks_LeavesNoEntryOnceTheLastHolderReleases(t *testing.T) {
	locks := newSessionRefreshLocks()

	// Two generations, held one after the other: the second acquire must be a fresh entry
	// counting one holder, not the first's with a stale count.
	for i := 0; i < 2; i++ {
		release, err := locks.Lock(context.Background(), "the-session")
		require.NoError(t, err)
		locks.mu.Lock()
		if assert.Len(t, locks.locks, 1, "one entry while it is held") {
			assert.Equal(t, 1, locks.locks["the-session"].waiters, "counting the holder alone")
		}
		locks.mu.Unlock()
		release()
	}

	assertNoEntries(t, locks)
}

// A wait ends at its context's deadline holding nothing and uncounted, so the holder's release
// still removes the entry, and the next request takes the lock at once.
func TestSessionRefreshLocks_AWaitEndsAtItsDeadline(t *testing.T) {
	locks := newSessionRefreshLocks()

	holder, err := locks.Lock(context.Background(), "the-session")
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	release, err := locks.Lock(ctx, "the-session")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Nil(t, release, "holding nothing")
	assert.Less(t, time.Since(started), 5*time.Second, "the wait ended at its deadline")

	locks.mu.Lock()
	assert.Equal(t, 1, locks.locks["the-session"].waiters, "the request that gave up is no longer counted")
	locks.mu.Unlock()

	holder()
	assertNoEntries(t, locks)

	next, err := locks.Lock(context.Background(), "the-session")
	require.NoError(t, err, "the slot the timed-out wait never took is free")
	next()
}
