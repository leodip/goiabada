// Package sessiontest holds the in-memory session backend the two servers'
// tests drive, and nothing else. It is a separate package from sessionstore
// because a test double declared beside the store is compiled into both
// production binaries, which is a thing neither of them can use and neither
// should carry (#385).
package sessiontest

import (
	"context"
	"sync"
	"time"

	"github.com/leodip/goiabada/core/sessionstore"
)

var _ sessionstore.Backend = (*MemoryBackend)(nil)

// MemoryBackend keeps browser sessions in a map. No binary constructs it: it exists so a
// test that needs a real store rather than a mock can have one without a database.
//
// A test reaches for it when a mock cannot show what it is checking: a round trip through
// the store, a flash that survives one, which is a stored shape rather than a returned
// value and so cannot be observed through a double that hands back what it was given
// (#269), or simply a store that works rather than a second implementation of Get and
// Save. Those tests live outside sessionstore, so the unexported fake the store's own
// tests use is out of reach, and this is the same thing with a name they can say (#266).
//
// It keeps the one rule of the real backends a caller can observe through the store: a
// row whose ExpiresAt is not after now is no such session, which is the engines'
// expires_at > now (#431). Without it a test over this backend would pass where a real
// deployment signs the browser out.
//
// It injects no failures on purpose. The error paths belong to the store's own tests,
// where the fake can be made to fail in one specific way per case, and to the data tier,
// where the real engines fail for real reasons. A shared double that can also be made to
// fail invites a caller to test the store through it instead; a test that needs one
// failure wraps this backend in a small type of its own that fails that operation.
type MemoryBackend struct {
	mu   sync.Mutex
	rows map[string]*sessionstore.Record

	// lifetime is how far ahead of now a written row's deadline sits. One value for both
	// phases: nothing reachable from this backend distinguishes them, and a test that
	// cares about which phase applies belongs at ExpiresAt, which owns that rule.
	lifetime time.Duration

	// now is the clock, replaceable by this package's own tests.
	now func() time.Time
}

// NewMemoryBackend returns an empty in-memory backend whose sessions expire an hour from
// each write.
func NewMemoryBackend() *MemoryBackend {
	return &MemoryBackend{
		rows:     map[string]*sessionstore.Record{},
		lifetime: time.Hour,
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// live returns the row id names if it has not expired. The caller holds the lock.
func (b *MemoryBackend) live(id string, now time.Time) (*sessionstore.Record, bool) {
	record, ok := b.rows[id]
	if !ok || !record.ExpiresAt.After(now) {
		return nil, false
	}
	return record, true
}

func (b *MemoryBackend) Load(_ context.Context, id string) (*sessionstore.Record, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	record, ok := b.live(id, b.now())
	if !ok {
		return nil, sessionstore.ErrNotFound
	}

	// A copy, so a caller holding the result cannot edit the stored row through it. The
	// database backend hands back a copy for free by reading columns; this one has to
	// mean it, down to the bytes: a struct copy alone would still share Data's array.
	copied := *record
	copied.Data = append([]byte(nil), record.Data...)
	return &copied, nil
}

func (b *MemoryBackend) Create(_ context.Context, id string, data []byte, _ bool) (time.Time, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	expiresAt := now.Add(b.lifetime)
	b.rows[id] = &sessionstore.Record{Data: data, LastAccessed: now, ExpiresAt: expiresAt}
	return expiresAt, nil
}

// Update never inserts, which is the one behaviour of the real backends this double must
// reproduce: a session that is gone stays gone, because whatever removed it was most
// likely rotating the identifier. An expired session is gone.
func (b *MemoryBackend) Update(_ context.Context, id string, data []byte, _ bool) (time.Time, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	record, ok := b.live(id, now)
	if !ok {
		return time.Time{}, sessionstore.ErrNotFound
	}

	record.Data = data
	record.ExpiresAt = now.Add(b.lifetime)
	return record.ExpiresAt, nil
}

func (b *MemoryBackend) Touch(_ context.Context, id string, _ bool) (time.Time, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	record, ok := b.live(id, now)
	if !ok {
		return time.Time{}, sessionstore.ErrNotFound
	}

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
