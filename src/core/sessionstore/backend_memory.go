package sessionstore

import (
	"context"
	"sync"
	"time"
)

// MemoryBackend keeps browser sessions in a map. No binary constructs it: it exists so a
// test that needs a real store rather than a mock can have one without a database.
//
// Three test files drive the session store for real, because what they are checking is a
// round trip through it and a mock cannot show one: the link marker tests in the auth
// server, the account activation tests beside them, and the auth helper's clear-reaches-
// the-browser tests in core. All three live outside this package, so the unexported fake
// the store's own tests use is out of reach, and this is the same thing with a name they
// can say (#266).
//
// It injects no failures on purpose. The error paths belong to the store's own tests,
// where the fake can be made to fail in one specific way per case, and to the data tier,
// where the real engines fail for real reasons. A shared double that can also be made to
// fail invites a caller to test the store through it instead.
type MemoryBackend struct {
	mu   sync.Mutex
	rows map[string]*Record

	// lifetime is how far ahead of now a written row's deadline sits. One value for both
	// phases: nothing reachable from this backend distinguishes them, and a test that
	// cares about which phase applies belongs at ExpiresAt, which owns that rule.
	lifetime time.Duration
}

// NewMemoryBackend returns an empty in-memory backend whose sessions expire an hour from
// each write.
func NewMemoryBackend() *MemoryBackend {
	return &MemoryBackend{
		rows:     map[string]*Record{},
		lifetime: time.Hour,
	}
}

func (b *MemoryBackend) Load(_ context.Context, id string) (*Record, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	record, ok := b.rows[id]
	if !ok {
		return nil, ErrNotFound
	}

	// A copy, so a caller holding the result cannot edit the stored row through it. The
	// database backend hands back a copy for free by reading columns; this one has to
	// mean it.
	copied := *record
	return &copied, nil
}

func (b *MemoryBackend) Create(_ context.Context, id string, data []byte, _ bool) (time.Time, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now().UTC()
	expiresAt := now.Add(b.lifetime)
	b.rows[id] = &Record{Data: data, LastAccessed: now, ExpiresAt: expiresAt}
	return expiresAt, nil
}

// Update never inserts, which is the one behaviour of the real backends this double must
// reproduce: a session that is gone stays gone, because whatever removed it was most
// likely rotating the identifier.
func (b *MemoryBackend) Update(_ context.Context, id string, data []byte, _ bool) (time.Time, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	record, ok := b.rows[id]
	if !ok {
		return time.Time{}, ErrNotFound
	}

	now := time.Now().UTC()
	record.Data = data
	record.ExpiresAt = now.Add(b.lifetime)
	return record.ExpiresAt, nil
}

func (b *MemoryBackend) Touch(_ context.Context, id string, _ bool) (time.Time, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	record, ok := b.rows[id]
	if !ok {
		return time.Time{}, ErrNotFound
	}

	now := time.Now().UTC()
	record.LastAccessed = now
	record.ExpiresAt = now.Add(b.lifetime)
	return record.ExpiresAt, nil
}

// Delete is silent about a session that is not there, matching the endpoint's 204 and the
// database backend's unconditional delete: removing something already gone is the outcome
// the caller asked for.
func (b *MemoryBackend) Delete(_ context.Context, id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	delete(b.rows, id)
	return nil
}
