package middleware

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// The serialization #621 rests on: one holder at a time per session, sessions independent of
// each other, and no entry outliving its last waiter, so a long-lived console keeps no one
// entry per sign-in.

func TestSessionRefreshLocks_ExcludesASecondHolderOfOneSession(t *testing.T) {
	locks := newSessionRefreshLocks()

	release := locks.Lock("the-session")
	acquired := make(chan struct{})
	go func() {
		waited := locks.Lock("the-session")
		waited()
		close(acquired)
	}()

	select {
	case <-acquired:
		t.Fatal("a second holder entered while the first held the lock")
	case <-time.After(50 * time.Millisecond):
	}

	release()
	select {
	case <-acquired:
	case <-time.After(5 * time.Second):
		t.Fatal("the second holder never entered once the lock was released")
	}

	// The waiter was counted with the holder, so the entry it leaves behind is removed when
	// the waiter, not the first holder, is the last to leave.
	locks.mu.Lock()
	assert.Empty(t, locks.locks, "the last one to leave removes the entry")
	locks.mu.Unlock()
}

func TestSessionRefreshLocks_DifferentSessionsDoNotWaitForEachOther(t *testing.T) {
	locks := newSessionRefreshLocks()

	release := locks.Lock("the-first-session")
	defer release()

	acquired := make(chan struct{})
	go func() {
		defer locks.Lock("the-second-session")()
		close(acquired)
	}()

	select {
	case <-acquired:
	case <-time.After(5 * time.Second):
		t.Fatal("a second session waited for the first's lock")
	}
}

func TestSessionRefreshLocks_LeavesNoEntryOnceTheLastHolderReleases(t *testing.T) {
	locks := newSessionRefreshLocks()

	// Two generations, held one after the other: the second acquire must be a fresh entry
	// counting one holder, not the first's with a stale count.
	for i := 0; i < 2; i++ {
		release := locks.Lock("the-session")
		locks.mu.Lock()
		if assert.Len(t, locks.locks, 1, "one entry while it is held") {
			assert.Equal(t, 1, locks.locks["the-session"].waiters, "counting the holder alone")
		}
		locks.mu.Unlock()
		release()
	}

	locks.mu.Lock()
	assert.Empty(t, locks.locks, "the last one to leave removes the entry")
	locks.mu.Unlock()
}
