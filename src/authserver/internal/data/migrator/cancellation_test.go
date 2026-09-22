package migrator

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The migrator's half of #386.
//
// Until this stage withConn opened a context.Background() of its own, so every driver call this
// package made was uncancellable however the operation had been started: an operator who
// interrupted `goiabada-authserver migrate` and a start that gave up both waited for the engine
// regardless. The context is now the caller's, and these cases are what say so -- a parameter
// threaded down and then dropped would compile, pass every other case here, and leave the runner
// exactly as uninterruptible as it was.
//
// Each entry point is covered separately because they take two different routes to the
// connection: Version and Plan go through withConn, Up, Migrate and Force through run, which adds
// the cross-process lock. Both must refuse.

// cancelledContext returns a context that is already over, which database/sql answers before the
// driver is touched at all.
func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestVersion_RefusesAnAlreadyCancelledContext(t *testing.T) {
	db := openTestDB(t)
	m := newTestMigrator(t, db, threeVersions())

	_, _, err := m.Version(cancelledContext())

	require.Error(t, err, "a version read must not be issued on behalf of a caller that is already gone")
	assert.ErrorIs(t, err, context.Canceled, "and the reason must be matchable, not a sentence")
}

func TestUp_RefusesAnAlreadyCancelledContextAndMigratesNothing(t *testing.T) {
	db := openTestDB(t)
	m := newTestMigrator(t, db, threeVersions())

	err := m.Up(cancelledContext())

	require.Error(t, err, "a migration must not be started on behalf of a caller that is already gone")
	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, recorded(t, db), "nothing was recorded, because nothing ran")
}

func TestMigrate_RefusesAnAlreadyCancelledContext(t *testing.T) {
	db := openTestDB(t)
	m := newTestMigrator(t, db, threeVersions())
	require.NoError(t, m.Up(context.Background()), "the database is at head before the refusal")

	err := m.Migrate(cancelledContext(), 1)

	require.Error(t, err, "a step down must not be started on behalf of a caller that is already gone")
	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, []RecordedVersion{{Version: 5}}, recorded(t, db),
		"the refused step moved nothing, so the database is still where Up left it")
}
