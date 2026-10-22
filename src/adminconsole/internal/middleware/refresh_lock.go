package middleware

import (
	"context"
	"sync"

	"github.com/leodip/goiabada/core/errs"
)

// sessionRefreshLocks serializes the console's refresh grant per browser session (#621).
//
// The auth server rotates refresh tokens strictly (#128, RFC 9700 section 4.14.2): the first
// presentation of a refresh token claims it, and a second is refused, or reads the whole family
// revoked as a replay. The console's session store is last-writer-wins (#579), so of two requests
// that both find the token due, the loser would be signed out and its clear would save over the
// token set the winner had just stored — two tabs in the last thirty seconds of the access token
// were enough. Keyed by the session identifier, the lock admits one refresh at a time per
// session in this console, and the request that waited re-reads the session before sending
// anything, so it carries the answer the winner stored rather than presenting the same refresh
// token twice. What it does not cover is two replicas of the console: no process can speak for
// another, and the re-read a refused grant makes only narrows that remainder. The High
// availability page runs two console replicas and tells the operator so, with session affinity
// as the remedy.
//
// An entry is handed out under mu and counted, so it lives exactly while requests hold or wait
// for it, and the last one to leave removes it: a long-lived console keeps no one entry per
// sign-in.
type sessionRefreshLocks struct {
	mu    sync.Mutex
	locks map[string]*sessionRefreshLock

	// queued, when set, is called by a request that found the session's lock held, as it starts
	// to wait for it. A test hook: it is how a test knows a second request is waiting rather than
	// hoping the scheduler put it there.
	queued func(sessionID string)
}

// sessionRefreshLock is one session's slot, a one-slot channel so a wait for it can end at a
// deadline. waiters counts the requests mu has handed the entry to, holders and waiters alike,
// so the last to leave is the one that removes it from the map.
type sessionRefreshLock struct {
	slot    chan struct{}
	waiters int
}

func newSessionRefreshLocks() *sessionRefreshLocks {
	return &sessionRefreshLocks{locks: map[string]*sessionRefreshLock{}}
}

// Lock acquires the session's lock, on a fresh entry when this is the first request to ask for
// it, and returns what releases it. A wait that ctx ends first returns ctx's error, holding
// nothing.
func (l *sessionRefreshLocks) Lock(ctx context.Context, sessionID string) (func(), error) {
	l.mu.Lock()
	entry, ok := l.locks[sessionID]
	if !ok {
		entry = &sessionRefreshLock{slot: make(chan struct{}, 1)}
		l.locks[sessionID] = entry
	}
	entry.waiters++
	l.mu.Unlock()

	select {
	case entry.slot <- struct{}{}:
	default:
		if l.queued != nil {
			l.queued(sessionID)
		}
		select {
		case entry.slot <- struct{}{}:
		case <-ctx.Done():
			l.leave(sessionID, entry)
			return nil, errs.Wrap(ctx.Err(), "unable to acquire the session's refresh lock")
		}
	}

	return func() {
		<-entry.slot
		l.leave(sessionID, entry)
	}, nil
}

// leave uncounts one request from entry, removing the entry once the last has left.
func (l *sessionRefreshLocks) leave(sessionID string, entry *sessionRefreshLock) {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry.waiters--
	if entry.waiters == 0 {
		delete(l.locks, sessionID)
	}
}
