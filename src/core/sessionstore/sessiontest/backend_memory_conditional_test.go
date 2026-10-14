package sessiontest

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/sessionstore"
)

// The conditional pair carries the stored contents a read returned, and takes effect only while
// the row still holds exactly those (#579).

func TestMemoryBackend_UpdateIfUnchangedWritesWhileTheContentsAreTheOnesRead(t *testing.T) {
	b, id, expiresAt, at := clockedBackend(t)

	now := expiresAt.Add(-time.Minute)
	at(now)
	newExpiry, err := b.UpdateIfUnchanged(context.Background(), id, []byte("contents"), []byte("replaced"), true)
	require.NoError(t, err)
	assert.Equal(t, now.Add(time.Hour), newExpiry)

	record, err := b.Load(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, []byte("replaced"), record.Data)
	assert.Equal(t, newExpiry, record.ExpiresAt)
}

func TestMemoryBackend_UpdateIfUnchangedAfterAnotherWriteWritesNothing(t *testing.T) {
	b, id, expiresAt, _ := clockedBackend(t)
	_, err := b.Update(context.Background(), id, []byte("another request's"), true)
	require.NoError(t, err)

	_, err = b.UpdateIfUnchanged(context.Background(), id, []byte("contents"), []byte("replaced"), true)
	require.ErrorIs(t, err, sessionstore.ErrChanged)

	record, err := b.Load(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, []byte("another request's"), record.Data)
	assert.Equal(t, expiresAt, record.ExpiresAt, "the refused write did not move the deadline")
}

// A touch moves the timestamps and not the contents, so it never makes a conditional write lose.
func TestMemoryBackend_UpdateIfUnchangedAfterATouchStillWrites(t *testing.T) {
	b, id, expiresAt, at := clockedBackend(t)
	at(expiresAt.Add(-30 * time.Minute))
	_, err := b.Touch(context.Background(), id, true)
	require.NoError(t, err)

	_, err = b.UpdateIfUnchanged(context.Background(), id, []byte("contents"), []byte("replaced"), true)
	require.NoError(t, err)

	record, err := b.Load(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, []byte("replaced"), record.Data)
}

func TestMemoryBackend_UpdateIfUnchangedOfAGoneRowAnswersChangedAndInsertsNothing(t *testing.T) {
	t.Run("never there", func(t *testing.T) {
		b := NewMemoryBackend()

		_, err := b.UpdateIfUnchanged(context.Background(), "never-there", []byte("contents"), []byte("replaced"), true)
		require.ErrorIs(t, err, sessionstore.ErrChanged)

		_, err = b.Load(context.Background(), "never-there")
		assert.ErrorIs(t, err, sessionstore.ErrNotFound, "the refused write created nothing")
	})

	t.Run("expired", func(t *testing.T) {
		b, id, expiresAt, at := clockedBackend(t)

		at(expiresAt)
		_, err := b.UpdateIfUnchanged(context.Background(), id, []byte("contents"), []byte("replaced"), true)
		require.ErrorIs(t, err, sessionstore.ErrChanged)

		at(expiresAt.Add(-time.Nanosecond))
		record, err := b.Load(context.Background(), id)
		require.NoError(t, err)
		assert.Equal(t, []byte("contents"), record.Data, "the refused write did not revive the row")
		assert.Equal(t, expiresAt, record.ExpiresAt)
	})
}

func TestMemoryBackend_DeleteIfUnchangedRemovesTheRowItWasGiven(t *testing.T) {
	b, id, _, _ := clockedBackend(t)

	require.NoError(t, b.DeleteIfUnchanged(context.Background(), id, []byte("contents")))

	_, err := b.Load(context.Background(), id)
	assert.ErrorIs(t, err, sessionstore.ErrNotFound)
}

func TestMemoryBackend_DeleteIfUnchangedAfterAnotherWriteKeepsTheRow(t *testing.T) {
	b, id, _, _ := clockedBackend(t)
	_, err := b.Update(context.Background(), id, []byte("another request's"), true)
	require.NoError(t, err)

	err = b.DeleteIfUnchanged(context.Background(), id, []byte("contents"))
	require.ErrorIs(t, err, sessionstore.ErrChanged)

	record, err := b.Load(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, []byte("another request's"), record.Data)
}

// Unlike Delete, the conditional one says when the row it read is not there to remove: the
// caller's rotation turns on whether it removed what it read.
func TestMemoryBackend_DeleteIfUnchangedOfAGoneRowAnswersChanged(t *testing.T) {
	t.Run("never there", func(t *testing.T) {
		b := NewMemoryBackend()
		require.ErrorIs(t, b.DeleteIfUnchanged(context.Background(), "never-there", []byte("contents")), sessionstore.ErrChanged)
	})

	t.Run("expired", func(t *testing.T) {
		b, id, expiresAt, at := clockedBackend(t)
		at(expiresAt)
		require.ErrorIs(t, b.DeleteIfUnchanged(context.Background(), id, []byte("contents")), sessionstore.ErrChanged)
	})
}
