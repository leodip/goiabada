package ratelimit

import (
	"strings"
	"time"
)

// Store keeps the per-key counts of a limiter's current and previous window. The
// window boundaries are computed by the Limiter and handed in, so a Store needs no
// clock of its own.
//
// Errors exist so that a store which can fail has a way to say so. The in-process
// store this package ships never returns one, and it is the only implementation in
// production; a Limiter treats any error as a refusal, so a store that cannot answer
// makes the limiter fail closed rather than admit the request (#276).
//
// A Store is called under the mutex of the Limiter or Gate that owns it, and needs
// no locking of its own.
type Store interface {
	// Get reports the hits recorded for key in the current and the previous window.
	// It never evicts.
	Get(key string, current, previous time.Time) (curr, prev int, err error)
	// Add records one hit for key in the current window, evicting anything older
	// than the previous window first.
	Add(key string, current time.Time) error
}

// memStore is the in-process store: one map of counts for the current window and one
// for the previous, swapped when a write arrives in a later window. Memory is bounded
// by the keys written in the last two windows, and eviction happens on write, so there
// is no goroutine and no timer to own. That is the bound httprate gave before this
// package replaced it, and the reason the replacement can be a drop-in (#276).
//
// A limiter that stops receiving writes holds its last two windows of keys until the
// next write, which is bounded and is what the deployment already had.
//
// memStore holds no lock of its own: every access goes through the Limiter or Gate
// that owns it, which serialises callers with its mutex.
type memStore struct {
	// window is needed to tell one roll from two: a write two or more windows on
	// must clear both maps rather than promote a stale current to previous.
	window time.Duration
	// The counts are behind pointers so that a hit on a key already present can be
	// incremented without assigning to the map. Go's map assignment overwrites the
	// stored key with the caller's string ("so it can be garbage collected", says the
	// runtime), so `m[key]++` would put the caller's uncloned string back into the map
	// on every hit after the first and undo the clone add makes. See add.
	curr, prev   map[string]*int
	latestWindow time.Time
}

func newMemStore(window time.Duration) *memStore {
	return &memStore{
		window: window,
		curr:   make(map[string]*int),
		prev:   make(map[string]*int),
	}
}

// Get implements Store. It never returns an error.
func (s *memStore) Get(key string, current, previous time.Time) (int, int, error) {
	curr, prev := s.get(key, current, previous)
	return curr, prev, nil
}

// Add implements Store. It never returns an error.
func (s *memStore) Add(key string, current time.Time) error {
	s.add(key, current)
	return nil
}

// get reads without evicting. When the store's latest write is older than the window
// being asked about, the counts it holds belong to earlier windows and read as zero.
func (s *memStore) get(key string, current, previous time.Time) (int, int) {
	switch {
	case s.latestWindow.Equal(current):
		return count(s.curr, key), count(s.prev, key)
	case s.latestWindow.Equal(previous):
		return 0, count(s.curr, key)
	default:
		return 0, 0
	}
}

func count(m map[string]*int, key string) int {
	if n, ok := m[key]; ok {
		return *n
	}
	return 0
}

// add evicts, then records one hit for key in the current window.
//
// A key not already present is inserted as a copy. A map entry keeps the whole backing
// array of the string it holds alive, and a rate-limit key is often a substring of a
// parsed request body -- the account key comes from the submitted form, whose backing
// array also holds the submitted password -- so storing the caller's string would keep
// that password in the heap for as long as the entry lives. httprate never retained the
// caller's string because it hashed the key to a uint64; this package stores exact keys
// so that no two clients can share a bucket by collision, and the copy at this one
// boundary is what that costs (#276). Removing it reintroduces the retention for every
// caller, not just the ones that pass a substring today. The counts are held behind
// pointers for the same reason: incrementing through the pointer is the only way to
// raise a count without assigning to the map, and an assignment would store the
// caller's string over the clone.
func (s *memStore) add(key string, current time.Time) {
	switch {
	case s.latestWindow.Equal(current):
		// Same window as the last write: nothing to evict.
	case current.Equal(s.latestWindow.Add(s.window)):
		// One roll: the current window's counts become the previous window's.
		s.prev, s.curr = s.curr, make(map[string]*int)
	default:
		// Two or more windows on (or the first write ever): nothing held is recent
		// enough to count. Fresh maps rather than clear(), so a flood of keys does
		// not leave its backing capacity allocated for the life of the process.
		s.prev, s.curr = make(map[string]*int), make(map[string]*int)
	}
	s.latestWindow = current

	if n, ok := s.curr[key]; ok {
		*n++
		return
	}
	n := 1
	s.curr[strings.Clone(key)] = &n
}
