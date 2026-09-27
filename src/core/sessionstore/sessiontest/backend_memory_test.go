package sessiontest

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/sessionstore"
)

// clockedBackend is a MemoryBackend whose clock the test moves. The row it returns the id of
// was created at start, so it expires at start plus the backend's hour.
func clockedBackend(t *testing.T) (b *MemoryBackend, id string, expiresAt time.Time, at func(time.Time)) {
	t.Helper()

	start := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	current := start
	b = NewMemoryBackend()
	b.now = func() time.Time { return current }

	id = "the-session"
	expiresAt, err := b.Create(context.Background(), id, []byte("contents"), true)
	require.NoError(t, err)
	require.Equal(t, start.Add(time.Hour), expiresAt)

	return b, id, expiresAt, func(now time.Time) { current = now }
}

// The engines read, update and touch only where expires_at > now, so a row is absent from
// the instant it expires, and present one nanosecond before (#431).
func TestMemoryBackend_LoadTreatsAnExpiredRowAsAbsent(t *testing.T) {
	cases := []struct {
		name  string
		shift time.Duration
		found bool
	}{
		{"one nanosecond before ExpiresAt", -time.Nanosecond, true},
		{"at exactly ExpiresAt", 0, false},
		{"one nanosecond past ExpiresAt", time.Nanosecond, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, id, expiresAt, at := clockedBackend(t)
			at(expiresAt.Add(c.shift))

			record, err := b.Load(context.Background(), id)

			if c.found {
				require.NoError(t, err)
				assert.Equal(t, []byte("contents"), record.Data)
				return
			}
			assert.ErrorIs(t, err, sessionstore.ErrNotFound)
			assert.Nil(t, record)
		})
	}
}

func TestMemoryBackend_UpdatePastExpiryAnswersNotFoundAndWritesNothing(t *testing.T) {
	b, id, expiresAt, at := clockedBackend(t)

	at(expiresAt.Add(time.Nanosecond))
	_, err := b.Update(context.Background(), id, []byte("replaced"), true)
	assert.ErrorIs(t, err, sessionstore.ErrNotFound)

	// Back inside the window, the row still holds what it held: the refused update neither
	// replaced the contents nor moved the deadline.
	at(expiresAt.Add(-time.Nanosecond))
	record, err := b.Load(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, []byte("contents"), record.Data)
	assert.Equal(t, expiresAt, record.ExpiresAt)
}

func TestMemoryBackend_UpdateBeforeExpiryReplacesAndExtends(t *testing.T) {
	b, id, expiresAt, at := clockedBackend(t)

	now := expiresAt.Add(-time.Minute)
	at(now)
	newExpiry, err := b.Update(context.Background(), id, []byte("replaced"), true)
	require.NoError(t, err)
	assert.Equal(t, now.Add(time.Hour), newExpiry)

	record, err := b.Load(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, []byte("replaced"), record.Data)
}

func TestMemoryBackend_TouchPastExpiryAnswersNotFound(t *testing.T) {
	b, id, expiresAt, at := clockedBackend(t)

	at(expiresAt)
	_, err := b.Touch(context.Background(), id, true)
	assert.ErrorIs(t, err, sessionstore.ErrNotFound)

	// Nor did the refused touch revive it.
	at(expiresAt.Add(-time.Nanosecond))
	record, err := b.Load(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, expiresAt, record.ExpiresAt)
}

func TestMemoryBackend_TouchBeforeExpiryMovesBothTimestamps(t *testing.T) {
	b, id, expiresAt, at := clockedBackend(t)

	now := expiresAt.Add(-time.Minute)
	at(now)
	newExpiry, err := b.Touch(context.Background(), id, true)
	require.NoError(t, err)
	assert.Equal(t, now.Add(time.Hour), newExpiry)

	record, err := b.Load(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, now, record.LastAccessed)
	assert.Equal(t, newExpiry, record.ExpiresAt)
}

// Deleting what is gone is the outcome asked for, expired or never there.
func TestMemoryBackend_DeleteOfAnExpiredOrAbsentRowAnswersNil(t *testing.T) {
	b, id, expiresAt, at := clockedBackend(t)
	at(expiresAt.Add(time.Nanosecond))

	assert.NoError(t, b.Delete(context.Background(), id), "expired")
	assert.NoError(t, b.Delete(context.Background(), "never-there"), "absent")
}

// A session that is gone stays gone: the request that removed it was most likely rotating the
// identifier, and re-creating the row would undo that rotation.
func TestMemoryBackend_UpdateNeverInserts(t *testing.T) {
	b := NewMemoryBackend()

	_, err := b.Update(context.Background(), "never-there", []byte("contents"), true)
	assert.ErrorIs(t, err, sessionstore.ErrNotFound)

	_, err = b.Load(context.Background(), "never-there")
	assert.ErrorIs(t, err, sessionstore.ErrNotFound, "the refused update created nothing")
}

func TestMemoryBackend_LoadReturnsACopy(t *testing.T) {
	b, id, _, _ := clockedBackend(t)

	record, err := b.Load(context.Background(), id)
	require.NoError(t, err)
	record.Data[0] = 'X'
	record.ExpiresAt = time.Time{}

	again, err := b.Load(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, []byte("contents"), again.Data, "the stored contents are not the caller's to edit")
	assert.False(t, again.ExpiresAt.IsZero())
}
