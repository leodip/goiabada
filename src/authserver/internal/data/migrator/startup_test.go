package migrator

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUpToHead is the startup rule, one row per answer a starting process can be given. It is the
// only place the rule is tested: the four engine methods it replaced had no test reaching their
// no-change or refusal arms (#438).
func TestUpToHead(t *testing.T) {
	const release = "v1.6.0"
	const prefix = "unable to migrate the database: "

	t.Run("a pending chain runs and says so", func(t *testing.T) {
		db := openTestDB(t)
		m := newTestMigrator(t, db, threeVersions())

		migrated, err := m.UpToHead(context.Background(), release, nil, nil)

		require.NoError(t, err)
		assert.True(t, migrated, "migrations ran, so the caller must not write that nothing needed to")
		assert.Equal(t, []RecordedVersion{{Version: 5, Dirty: false}}, recorded(t, db), "the chain reached head")
		assertPoolReturned(t, db)
	})

	t.Run("at head nothing runs and that is not a failure", func(t *testing.T) {
		db := openTestDB(t)
		m := newTestMigrator(t, db, threeVersions())
		_, err := m.UpToHead(context.Background(), release, nil, nil)
		require.NoError(t, err)

		migrated, err := m.UpToHead(context.Background(), release, nil, nil)

		require.NoError(t, err, "ErrNoChange is the ordinary restart, and must never stop one")
		assert.False(t, migrated, "nothing ran, which is what the caller's startup record reports")
		assertPoolReturned(t, db)
	})

	t.Run("a database ahead of the binary is refused with the explanation", func(t *testing.T) {
		db := openTestDB(t)
		_, err := db.Exec("INSERT INTO schema_migrations (version, dirty) VALUES (9, 0)")
		require.NoError(t, err)
		m := newTestMigrator(t, db, threeVersions())

		migrated, err := m.UpToHead(context.Background(), release, nil, nil)

		require.Error(t, err)
		assert.False(t, migrated)
		msg := err.Error()
		assert.Truef(t, strings.HasPrefix(msg, prefix),
			"the operator's text is the one the four engine wrappers wrote: %s", msg)
		assert.Containsf(t, strings.ToLower(msg), "newer release", "StartupRefusal's diagnosis reaches the operator: %s", msg)
		assert.Containsf(t, msg, release, "the release passed in is the one named: %s", msg)
		var unknown UnknownVersionError
		require.ErrorAs(t, err, &unknown, "the typed error survives the explanation and the wrap")
		assert.Equal(t, 9, unknown.Version)
		assert.False(t, tableExists(t, db, "t1"), "nothing ran")
	})

	t.Run("a dirty database is refused with the runner's own message", func(t *testing.T) {
		db := openTestDB(t)
		_, err := db.Exec("INSERT INTO schema_migrations (version, dirty) VALUES (2, 1)")
		require.NoError(t, err)
		m := newTestMigrator(t, db, threeVersions())

		migrated, err := m.UpToHead(context.Background(), release, nil, nil)

		require.Error(t, err)
		assert.False(t, migrated)
		assert.Truef(t, strings.HasPrefix(err.Error(), prefix), "got %s", err.Error())
		var dirty DirtyError
		require.ErrorAs(t, err, &dirty, "StartupRefusal passes DirtyError through, and the wrap keeps it reachable")
		assert.Equal(t, 2, dirty.Version)
	})

	// The identity guard. At head the operation answers the bare sentinel, and a failed unlock is
	// joined onto it, so errors.Is would find ErrNoChange and report a clean start while the lock
	// stays held. Replacing IsNoChange with errors.Is must fail this row.
	t.Run("at head with a failed unlock is an error, never a clean start", func(t *testing.T) {
		unlockErr := errors.New("the lock did not come back")
		eng := SQLite()
		eng.lock = func(context.Context, *sql.Conn) error { return nil }
		eng.unlock = func(context.Context, *sql.Conn) error { return unlockErr }
		db := openTestDB(t)
		m, err := New(db, threeVersions(), "migrations", eng)
		require.NoError(t, err)
		_, err = m.UpToHead(context.Background(), release, nil, nil)
		require.ErrorIs(t, err, unlockErr, "the chain runs and the unlock fails")

		migrated, err := m.UpToHead(context.Background(), release, nil, nil)

		require.Error(t, err, "a lock that did not come back must stop the start, not be read as nothing to do")
		require.ErrorIs(t, err, unlockErr, "the failure that blocks every other migrator is what is reported")
		assert.False(t, migrated)
		assert.Truef(t, strings.HasPrefix(err.Error(), prefix), "got %s", err.Error())
	})
}

// TestUpToHead_BeforeMigrating is the check a starting process makes before its schema moves, which
// the email case pre-flight is: under the migration lock, on the runner's own connection, with the
// clean version the runner read there, and only when there is something to migrate (#542 decision
// 2). It ran before the lock until several replicas starting at once on an empty database showed
// that a check there reads a schema another process is part way through.
func TestUpToHead_BeforeMigrating(t *testing.T) {
	const release = "v1.6.0"

	// lockedEngine is SQLite's engine with a session lock that records whether it is held, which
	// SQLite's own in-process mutex gives no way to observe.
	lockedEngine := func(held *bool) Engine {
		eng := SQLite()
		eng.lock = func(context.Context, *sql.Conn) error { *held = true; return nil }
		eng.unlock = func(context.Context, *sql.Conn) error { *held = false; return nil }
		return eng
	}

	t.Run("it runs under the lock, on the lock's connection, before any file", func(t *testing.T) {
		db := openTestDB(t)
		var held bool
		m, err := New(db, threeVersions(), "migrations", lockedEngine(&held))
		require.NoError(t, err)

		calls := 0
		check := func(ctx context.Context, conn *sql.Conn, recorded, target int) error {
			calls++
			assert.True(t, held, "the check runs while the migration lock is held")
			assert.Equal(t, NilVersion, recorded, "a database never migrated is NilVersion")
			assert.Equal(t, 5, target, "the target is head")
			// The pool has one connection and the runner holds it, so this read can only go
			// through conn; a check reading through the pool would wait here for ever.
			var tables int
			require.NoError(t, conn.QueryRowContext(ctx,
				"SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 't1'").Scan(&tables))
			assert.Zero(t, tables, "no migration file has run yet")
			return nil
		}

		migrated, err := m.UpToHead(context.Background(), release, nil, check)

		require.NoError(t, err)
		assert.True(t, migrated)
		assert.Equal(t, 1, calls)
		assert.False(t, held, "the lock is given back")
		assert.Equal(t, []RecordedVersion{{Version: 5, Dirty: false}}, recorded(t, db))
		assertPoolReturned(t, db)
	})

	t.Run("a database part way up is checked from the version it is at", func(t *testing.T) {
		db := openTestDB(t)
		m := newTestMigrator(t, db, threeVersions())
		require.NoError(t, m.Migrate(context.Background(), 2))

		var got [2]int
		_, err := m.UpToHead(context.Background(), release, nil,
			func(_ context.Context, _ *sql.Conn, recorded, target int) error {
				got = [2]int{recorded, target}
				return nil
			})

		require.NoError(t, err)
		assert.Equal(t, [2]int{2, 5}, got)
	})

	t.Run("a refusal stops the start with nothing written", func(t *testing.T) {
		db := openTestDB(t)
		var held bool
		m, err := New(db, threeVersions(), "migrations", lockedEngine(&held))
		require.NoError(t, err)
		refused := errors.New("the stored addresses cannot be migrated")

		migrated, err := m.UpToHead(context.Background(), release, nil,
			func(context.Context, *sql.Conn, int, int) error { return refused })

		require.ErrorIs(t, err, refused, "the check's refusal is the start's answer")
		assert.False(t, migrated)
		assert.Empty(t, recorded(t, db), "not migrated and not dirty: the version table is as it was")
		assert.False(t, tableExists(t, db, "t1"), "no file ran")
		assert.False(t, held, "the lock is given back after a refusal too")
		assertPoolReturned(t, db)
	})

	t.Run("a database at head is not checked", func(t *testing.T) {
		db := openTestDB(t)
		m := newTestMigrator(t, db, threeVersions())
		_, err := m.UpToHead(context.Background(), release, nil, nil)
		require.NoError(t, err)

		migrated, err := m.UpToHead(context.Background(), release, nil,
			func(context.Context, *sql.Conn, int, int) error {
				t.Error("nothing is about to be migrated, so there is nothing to check")
				return nil
			})

		require.NoError(t, err)
		assert.False(t, migrated)
	})

	t.Run("a dirty database is refused before the check reads it", func(t *testing.T) {
		db := openTestDB(t)
		_, err := db.Exec("INSERT INTO schema_migrations (version, dirty) VALUES (2, 1)")
		require.NoError(t, err)
		m := newTestMigrator(t, db, threeVersions())

		_, err = m.UpToHead(context.Background(), release, nil,
			func(context.Context, *sql.Conn, int, int) error {
				t.Error("a dirty version is a schema part way through a file, which the check must never read")
				return nil
			})

		var dirty DirtyError
		require.ErrorAs(t, err, &dirty)
	})
}

// TestStartupRefusal_DatabaseAheadOfTheBinaryNamesEveryFactAnOperatorNeeds is decision 7's
// second refusal, and it is asserted as facts rather than as a sentence: the wording is the
// run's to change, and a test comparing the whole string would be a copy of it that fails
// whenever a comma moves.
//
// The situation it explains is an upgrade rolled back without the schema being stepped down. A
// replica of the newer release migrated the database to 000044, an older binary is started
// against it, and its own migration set stops at 000041. Nothing about that is corruption, and
// the operator's way out is either to put the newer release back or to step the schema down
// with it first, so the message has to say which.
func TestStartupRefusal_DatabaseAheadOfTheBinaryNamesEveryFactAnOperatorNeeds(t *testing.T) {
	err := StartupRefusal(UnknownVersionError{
		Version: 44,
		Engine:  "postgres",
		Head:    41,
		Below:   41,
		Above:   NilVersion,
	}, "v1.6.0")
	require.Error(t, err)
	msg := err.Error()

	assert.Containsf(t, msg, "000044", "the version the database records: %s", msg)
	assert.Containsf(t, msg, "000041", "the highest version this binary carries: %s", msg)
	assert.Containsf(t, msg, "v1.6.0", "the Goiabada version this binary is: %s", msg)
	assert.Containsf(t, msg, "postgres", "the engine whose set was searched, since the four differ: %s", msg)
	assert.Containsf(t, strings.ToLower(msg), "newer release",
		"the diagnosis, which is what stops an operator treating this as corruption: %s", msg)
	assert.Containsf(t, msg, "migrate to 000041",
		"the remedy, as a command the operator can run rather than a description of one: %s", msg)

	// Wrapped rather than replaced, so a caller that wants the numbers can still reach them.
	var unknown UnknownVersionError
	require.ErrorAs(t, err, &unknown, "the typed error survives the explanation")
	assert.Equal(t, 44, unknown.Version)
}

// TestStartupRefusal_LeavesEverythingElseExactlyAsItWas is the other half, and the one that
// matters for the dirty case: DirtyError composes its own message where the direction of the
// interrupted step is known, and an explanation layered on top of it here would either
// duplicate that or contradict it.
func TestStartupRefusal_LeavesEverythingElseExactlyAsItWas(t *testing.T) {
	require.NoError(t, StartupRefusal(nil, "v1.6.0"), "nil is not a refusal")

	dirty := DirtyError{Version: 40, Applied: 40, Below: 39, Above: 41, Carried: true}
	assert.Equal(t, error(dirty), StartupRefusal(dirty, "v1.6.0"),
		"DirtyError already carries decision 7's dirty message, composed where the direction is known")

	assert.Equal(t, ErrNoChange, StartupRefusal(ErrNoChange, "v1.6.0"),
		"ErrNoChange is not a failure at all and must stay testable with errors.Is")

	other := errors.New("dial tcp 127.0.0.1:5432: connection refused")
	assert.Equal(t, other, StartupRefusal(other, "v1.6.0"),
		"a driver error says what it says")
}
