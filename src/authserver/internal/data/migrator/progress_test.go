package migrator

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The runner's half of #390 decision 7. A starting process writes three records a hung one never
// would: that it is waiting for the migration lock, that it is migrating, and that it has
// migrated. The runner writes none of them; it reports to the process through Progress, and the
// process, which owns the startup records, writes them. These cases hold what the runner reports
// and when. The records themselves are datafactory's, and the real engines' locks are the data
// tier's.

// progressEvent is one report, flattened so a test can compare the whole sequence at once.
//
// Exported fields, because the cases only ever read them through assert.Equal's reflection.
type progressEvent struct {
	Kind    string
	From    int
	To      int
	Count   int
	TookSet bool
}

// recordingProgress keeps every report in order, and runs onMigrating at the moment the runner
// says it is about to migrate, so a case can look at the database at exactly that point.
type recordingProgress struct {
	events      []progressEvent
	onMigrating func()
}

func (p *recordingProgress) WaitingForLock() {
	p.events = append(p.events, progressEvent{Kind: "waiting"})
}

func (p *recordingProgress) Migrating(from, to, pending int) {
	if p.onMigrating != nil {
		p.onMigrating()
	}
	p.events = append(p.events, progressEvent{Kind: "migrating", From: from, To: to, Count: pending})
}

func (p *recordingProgress) Migrated(from, to, applied int, took time.Duration) {
	p.events = append(p.events, progressEvent{Kind: "migrated", From: from, To: to, Count: applied, TookSet: took > 0})
}

func TestUpToHead_ReportsTheMigrationAroundTheFilesItRuns(t *testing.T) {
	t.Run("a never-migrated database reports the whole chain before its first file and after its last", func(t *testing.T) {
		db := openTestDB(t)
		m := newTestMigrator(t, db, threeVersions())

		// The runner holds the pool's one connection while it reports, so the look at the
		// database goes through a second pool on the same file.
		observer := secondPool(t, db)
		var atMigrating []RecordedVersion
		var t1AtMigrating bool
		progress := &recordingProgress{onMigrating: func() {
			atMigrating = recorded(t, observer)
			t1AtMigrating = tableExists(t, observer, "t1")
		}}

		migrated, err := m.UpToHead(context.Background(), "v1.6.0", progress, nil)

		require.NoError(t, err)
		assert.True(t, migrated)
		// threeVersions carries 1, 2 and 5: three files from nothing to 5.
		assert.Equal(t, []progressEvent{
			{Kind: "migrating", From: NilVersion, To: 5, Count: 3},
			{Kind: "migrated", From: NilVersion, To: 5, Count: 3, TookSet: true},
		}, progress.events)
		assert.Empty(t, atMigrating, "migrating is reported before the runner writes its first marker")
		assert.False(t, t1AtMigrating, "and before the first file runs")
	})

	t.Run("a database part of the way reports from where it is", func(t *testing.T) {
		db := openTestDB(t)
		m := newTestMigrator(t, db, threeVersions())
		require.NoError(t, m.Migrate(context.Background(), 1))

		progress := &recordingProgress{}
		_, err := m.UpToHead(context.Background(), "v1.6.0", progress, nil)

		require.NoError(t, err)
		assert.Equal(t, []progressEvent{
			{Kind: "migrating", From: 1, To: 5, Count: 2},
			{Kind: "migrated", From: 1, To: 5, Count: 2, TookSet: true},
		}, progress.events)
	})

	t.Run("a database at head reports nothing, which leaves the start to say so", func(t *testing.T) {
		db := openTestDB(t)
		m := newTestMigrator(t, db, threeVersions())
		require.NoError(t, m.Up(context.Background()))

		progress := &recordingProgress{}
		migrated, err := m.UpToHead(context.Background(), "v1.6.0", progress, nil)

		require.NoError(t, err)
		assert.False(t, migrated)
		assert.Empty(t, progress.events)
	})

	t.Run("a file that fails reports no migrated", func(t *testing.T) {
		db := openTestDB(t)
		m := newTestMigrator(t, db, set(map[string]string{
			"000001_ok.up.sql":     "CREATE TABLE t1 (id INTEGER);",
			"000002_broken.up.sql": "THIS IS NOT SQL;",
		}))

		progress := &recordingProgress{}
		_, err := m.UpToHead(context.Background(), "v1.6.0", progress, nil)

		require.Error(t, err)
		assert.Equal(t, []progressEvent{{Kind: "migrating", From: NilVersion, To: 2, Count: 2}}, progress.events,
			"the schema did not reach head, so nothing may say it was migrated")
	})

	t.Run("SQLite never reports a wait: its lock is a mutex in this process", func(t *testing.T) {
		db := openTestDB(t)
		m := newTestMigrator(t, db, threeVersions())

		progress := &recordingProgress{}
		_, err := m.UpToHead(context.Background(), "v1.6.0", progress, nil)

		require.NoError(t, err)
		for _, e := range progress.events {
			assert.NotEqual(t, "waiting", e.Kind)
		}
	})

	t.Run("no progress at all is allowed", func(t *testing.T) {
		db := openTestDB(t)
		m := newTestMigrator(t, db, threeVersions())

		migrated, err := m.UpToHead(context.Background(), "v1.6.0", nil, nil)

		require.NoError(t, err)
		assert.True(t, migrated)
	})
}

// TestUpToHead_ReportsAWaitOnlyWhenTheLockIsHeld is the try-first rule: the runner asks for the
// lock without waiting, and only when another session holds it does it report the wait and then
// wait. The engine's statements are replaced here because the question is what the runner does
// with their answers; whether each engine's try statement answers truthfully against a held lock
// is the data tier's TestMigrationLock_AStartQueuedBehindTheLock... cases, on the real engines.
func TestUpToHead_ReportsAWaitOnlyWhenTheLockIsHeld(t *testing.T) {
	type calls struct{ Try, Lock, Unlock int }

	engine := func(c *calls, free bool, waitBegan *[]progressEvent, progress *recordingProgress) Engine {
		eng := SQLite()
		eng.tryLock = func(context.Context, *sql.Conn) (bool, error) {
			c.Try++
			return free, nil
		}
		eng.lock = func(context.Context, *sql.Conn) error {
			c.Lock++
			// What had been reported when the wait began.
			*waitBegan = append([]progressEvent(nil), progress.events...)
			return nil
		}
		eng.unlock = func(context.Context, *sql.Conn) error {
			c.Unlock++
			return nil
		}
		return eng
	}

	t.Run("held: the wait is reported once, before the runner waits", func(t *testing.T) {
		var c calls
		var waitBegan []progressEvent
		progress := &recordingProgress{}
		db := openTestDB(t)
		m, err := New(db, threeVersions(), "migrations", engine(&c, false, &waitBegan, progress))
		require.NoError(t, err)

		_, err = m.UpToHead(context.Background(), "v1.6.0", progress, nil)

		require.NoError(t, err)
		assert.Equal(t, calls{Try: 1, Lock: 1, Unlock: 1}, c, "one try, then one wait, then one release")
		assert.Equal(t, []progressEvent{{Kind: "waiting"}}, waitBegan, "the wait was reported before it began")
		require.NotEmpty(t, progress.events)
		assert.Equal(t, "waiting", progress.events[0].Kind)
		waits := 0
		for _, e := range progress.events {
			if e.Kind == "waiting" {
				waits++
			}
		}
		assert.Equal(t, 1, waits, "a start writes the wait record once")
	})

	t.Run("free: the try takes it, so there is no wait to report and no second lock", func(t *testing.T) {
		var c calls
		var waitBegan []progressEvent
		progress := &recordingProgress{}
		db := openTestDB(t)
		m, err := New(db, threeVersions(), "migrations", engine(&c, true, &waitBegan, progress))
		require.NoError(t, err)

		_, err = m.UpToHead(context.Background(), "v1.6.0", progress, nil)

		require.NoError(t, err)
		// A second lock statement after a successful try would take the lock twice. MySQL's
		// GET_LOCK and PostgreSQL's advisory locks both count, so the one release would leave it
		// held against every other migrator for the life of the session.
		assert.Equal(t, calls{Try: 1, Lock: 0, Unlock: 1}, c)
		for _, e := range progress.events {
			assert.NotEqual(t, "waiting", e.Kind)
		}
	})

	t.Run("held, then at head: the wait is reported and nothing else, which the start follows with its own record", func(t *testing.T) {
		var c calls
		var waitBegan []progressEvent
		progress := &recordingProgress{}
		db := openTestDB(t)
		m, err := New(db, threeVersions(), "migrations", engine(&c, false, &waitBegan, progress))
		require.NoError(t, err)
		require.NoError(t, m.Up(context.Background()))
		progress.events = nil

		migrated, err := m.UpToHead(context.Background(), "v1.6.0", progress, nil)

		require.NoError(t, err)
		assert.False(t, migrated)
		assert.Equal(t, []progressEvent{{Kind: "waiting"}}, progress.events)
	})
}

// secondPool opens another pool on the SQLite file db is open on.
func secondPool(t *testing.T, db *sql.DB) *sql.DB {
	t.Helper()
	var file string
	require.NoError(t, db.QueryRow("SELECT file FROM pragma_database_list WHERE name = 'main'").Scan(&file))
	require.NotEmpty(t, file, "the test database is a file")
	other, err := sql.Open("sqlite", file)
	require.NoError(t, err)
	t.Cleanup(func() { _ = other.Close() })
	return other
}
