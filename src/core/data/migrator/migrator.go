// Package migrator applies a set of embedded .up.sql / .down.sql files to a database and records
// how far it got in a schema_migrations table.
//
// It replaces github.com/golang-migrate/migrate/v4, whose bookkeeping it reproduces deliberately
// and exactly: the same table, the same single row rewritten in one transaction per step, the
// same dirty marker written before a file runs and cleared after it, the same per-engine decision
// about whether a file runs inside a transaction, and the same cross-process lock resources. A
// database migrated by the previous release and then opened by this one sees no difference: no
// step is re-run and none is skipped (#268).
//
// What it does differently is narrow and deliberate. Every read of the version table is
// fail-closed, where the library's SQLite driver answered "never migrated" on any read error and
// so re-ran the chain from the first migration against a populated database. And it takes a
// connection out of the pool for the duration of one operation and gives it back, where the
// library pinned one connection per pool for the life of the process; there is nothing here for a
// caller to close.
package migrator

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io/fs"
)

// Migrator applies one engine's migration set to one database.
type Migrator struct {
	db  *sql.DB
	src *source
	eng Engine
}

// New parses the migration files eagerly, so a malformed set is a construction failure rather
// than a surprise half way up the chain. It touches the database not at all.
func New(db *sql.DB, files fs.FS, dir string, eng Engine) (*Migrator, error) {
	if db == nil {
		return nil, errors.New("migrator: no database")
	}
	src, err := newSource(files, dir)
	if err != nil {
		return nil, err
	}
	return &Migrator{db: db, src: src, eng: eng}, nil
}

// Head is the highest version this binary carries for this engine, which is the version Up
// migrates to and the version a release expects a database to be at.
func (m *Migrator) Head() int { return m.src.head() }

// Engine names the engine this migrator was built for.
func (m *Migrator) Engine() string { return m.eng.name }

// Version answers the version recorded in schema_migrations and whether it is dirty. A database
// with no row answers ErrNilVersion, which is what a caller distinguishing "never migrated" from
// "at version 0" tests for.
func (m *Migrator) Version() (version int, dirty bool, err error) {
	err = m.withConn(func(ctx context.Context, conn *sql.Conn) error {
		v, d, err := m.readVersion(ctx, conn)
		if err != nil {
			return err
		}
		if v == NilVersion && !d {
			return ErrNilVersion
		}
		version, dirty = v, d
		return nil
	})
	if err != nil {
		return NilVersion, false, err
	}
	return version, dirty, nil
}

// Up migrates to the highest version this binary carries. It answers ErrNoChange when there is
// nothing to do.
//
// It checks the version the database records against the migration set and refuses one it does
// not carry. That is what stops an older binary migrating a database a newer release already
// migrated: the recorded version is simply not among its files, and running its own chain from
// there would apply migrations that have already been applied.
func (m *Migrator) Up() error {
	return m.run(func(ctx context.Context, conn *sql.Conn) error {
		current, err := m.currentVersion(ctx, conn)
		if err != nil {
			return err
		}
		steps, err := m.stepsFrom(current, m.src.head())
		if err != nil {
			return err
		}
		return m.apply(ctx, conn, steps)
	})
}

// Migrate steps the schema to target in whichever direction that is, one migration at a time.
// Pass NilVersion to step all the way down to an unmigrated database. It answers ErrNoChange when
// the database is already there.
func (m *Migrator) Migrate(target int) error {
	return m.run(func(ctx context.Context, conn *sql.Conn) error {
		current, err := m.currentVersion(ctx, conn)
		if err != nil {
			return err
		}
		if err := m.checkCarried(target); err != nil {
			return err
		}
		steps, err := m.stepsFrom(current, target)
		if err != nil {
			return err
		}
		return m.apply(ctx, conn, steps)
	})
}

// Force records a version and clears the dirty flag without running anything. It is the manual
// repair after an interrupted migration, and the tests use it to place a database at a version so
// one migration can be exercised on its own.
func (m *Migrator) Force(version int) error {
	return m.run(func(ctx context.Context, conn *sql.Conn) error {
		return m.setVersion(ctx, conn, version, false)
	})
}

// Plan answers the versions whose migration files a Migrate(target) would run, in the order it
// would run them, and runs nothing. Going up those are the .up.sql files being applied; going
// down they are the .down.sql files being rolled back, so the list reads highest first. It is
// what an operator is shown before a step down, and it answers the same refusals Migrate would.
func (m *Migrator) Plan(target int) ([]int, error) {
	var versions []int
	err := m.withConn(func(ctx context.Context, conn *sql.Conn) error {
		current, err := m.currentVersion(ctx, conn)
		if err != nil {
			return err
		}
		if err := m.checkCarried(target); err != nil {
			return err
		}
		steps, err := m.stepsFrom(current, target)
		if err != nil {
			return err
		}
		versions = make([]int, 0, len(steps))
		for _, s := range steps {
			versions = append(versions, s.apply)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return versions, nil
}

// ---------------------------------------------------------------------------
// The connection, and the lock on it
// ---------------------------------------------------------------------------

// withConn takes one connection from the pool, runs fn on it, and gives it back before returning.
// Every version read, every bookkeeping write and every migration file in one operation goes
// through that single connection, which is what makes a session-scoped lock cover them.
func (m *Migrator) withConn(fn func(ctx context.Context, conn *sql.Conn) error) (err error) {
	ctx := context.Background()
	conn, err := m.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("unable to take a connection for the migration: %w", err)
	}
	defer func() {
		// ErrConnDone is what Close answers for a connection already disposed of by run's
		// deferred unlock, which is a deliberate outcome rather than a failure.
		if cerr := conn.Close(); cerr != nil && !errors.Is(cerr, sql.ErrConnDone) {
			err = errors.Join(err, cerr)
		}
	}()
	return fn(ctx, conn)
}

// run is withConn plus the cross-process migration lock, taken before the work and released after
// it whatever happened.
//
// A failed unlock is never swallowed. It joins the operation's error when there is one and
// becomes the operation's error when there is not, because a lock that did not come back is one
// every other migrator on this database waits on, on two of the three engines indefinitely, and
// an operation reported as successful is the one nobody investigates.
//
// And the session that failed to unlock does not go back to the pool. It is handed
// driver.ErrBadConn so database/sql discards it, rather than lending the next borrower a
// connection that holds a migration lock for the rest of the process's life. Returning it is
// exactly the leak this package exists to end, in the one case where it is invisible.
func (m *Migrator) run(fn func(ctx context.Context, conn *sql.Conn) error) error {
	return m.withConn(func(ctx context.Context, conn *sql.Conn) (err error) {
		if m.eng.lock == nil {
			// SQLite: no session-scoped lock statement exists, so the exclusion is in-process.
			sqliteMigrationMu.Lock()
			defer sqliteMigrationMu.Unlock()
		} else {
			if lockErr := m.eng.lock(ctx, conn); lockErr != nil {
				return lockErr
			}
			defer func() {
				if unlockErr := m.eng.unlock(ctx, conn); unlockErr != nil {
					err = errors.Join(err, unlockErr)
					_ = conn.Raw(func(any) error { return driver.ErrBadConn })
				}
			}()
		}
		return fn(ctx, conn)
	})
}

// ---------------------------------------------------------------------------
// The version table
// ---------------------------------------------------------------------------

// readVersion reads schema_migrations fail-closed (decision 5): every driver error is returned,
// an empty table is NilVersion, and more than one row is refused naming every row. The runner's
// own writes cannot produce two rows, so a second one is a hand edit or corruption, and choosing
// one of them is how a database gets migrated from a version it is not at.
func (m *Migrator) readVersion(ctx context.Context, conn *sql.Conn) (int, bool, error) {
	rows, err := conn.QueryContext(ctx, "SELECT version, dirty FROM "+migrationsTable)
	if err != nil {
		return NilVersion, false, fmt.Errorf("unable to read %s: %w", migrationsTable, err)
	}
	defer func() { _ = rows.Close() }()

	var recorded []RecordedVersion
	for rows.Next() {
		var r RecordedVersion
		if err := rows.Scan(&r.Version, &r.Dirty); err != nil {
			return NilVersion, false, fmt.Errorf("unable to read a %s row: %w", migrationsTable, err)
		}
		recorded = append(recorded, r)
	}
	if err := rows.Err(); err != nil {
		return NilVersion, false, fmt.Errorf("unable to read %s: %w", migrationsTable, err)
	}

	switch len(recorded) {
	case 0:
		return NilVersion, false, nil
	case 1:
		return recorded[0].Version, recorded[0].Dirty, nil
	default:
		return NilVersion, false, ErrMultipleVersions{Rows: recorded}
	}
}

// currentVersion is the version an operation starts from, with the two refusals every operation
// owes: a dirty database, and a recorded version this binary carries no migration for.
func (m *Migrator) currentVersion(ctx context.Context, conn *sql.Conn) (int, error) {
	current, dirty, err := m.readVersion(ctx, conn)
	if err != nil {
		return NilVersion, err
	}
	if dirty {
		// The row records the version reached and nothing about direction, so which file was
		// running is not knowable from here; ErrDirty says so rather than guessing.
		return NilVersion, ErrDirty{
			Version: current,
			Applied: AppliedUnknown,
			Below:   m.src.prev(current),
			Above:   m.src.next(current),
			// Whether the endpoints below and above mean anything at all. A marker this binary
			// carries no file for came from a newer release, whose set may carry versions between
			// it and the nearest one here (#268).
			Carried: current == NilVersion || m.src.exists(current),
		}
	}
	if current != NilVersion {
		if err := m.checkCarried(current); err != nil {
			return NilVersion, err
		}
	}
	return current, nil
}

// checkCarried refuses a version this binary has no file for, in either direction. A version with
// only a down file counts as carried, which is what golang-migrate's versionExists accepted and
// what lets a database sit at a version whose up file a later release removed.
func (m *Migrator) checkCarried(v int) error {
	if v == NilVersion || m.src.exists(v) {
		return nil
	}
	below, above := m.src.neighbours(v)
	return ErrUnknownVersion{
		Version: v,
		Engine:  m.eng.name,
		Head:    m.src.head(),
		Below:   below,
		Above:   above,
	}
}

// setVersion rewrites the one row of schema_migrations, in a transaction, exactly as
// golang-migrate's drivers did.
//
// The transaction is the point: DELETE and INSERT standing alone would leave an empty table if
// the insert failed, and an empty table reads as "never migrated", which re-runs the whole chain
// against a populated database.
//
// The nil version is written when it is dirty, and only then. That is golang-migrate's own
// workaround for its issue 330: a down step off the first migration marks NilVersion, and without
// the row an interruption there would look like a clean, unmigrated database.
func (m *Migrator) setVersion(ctx context.Context, conn *sql.Conn, version int, dirty bool) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("unable to start the %s transaction: %w", migrationsTable, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if _, err := tx.ExecContext(ctx, "DELETE FROM "+migrationsTable); err != nil {
		return fmt.Errorf("unable to clear %s: %w", migrationsTable, err)
	}

	if version >= 0 || (version == NilVersion && dirty) {
		insert := fmt.Sprintf("INSERT INTO %s (version, dirty) VALUES (%s, %s)",
			migrationsTable, m.eng.placeholder(1), m.eng.placeholder(2))
		if _, err := tx.ExecContext(ctx, insert, version, dirty); err != nil {
			return fmt.Errorf("unable to record version %s in %s: %w", formatVersion(version), migrationsTable, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("unable to commit the %s transaction: %w", migrationsTable, err)
	}
	committed = true
	return nil
}

// ---------------------------------------------------------------------------
// Stepping
// ---------------------------------------------------------------------------

// step is one migration file and the marker written around it. On an up step the two are the same
// version; on a down step the file is the version being removed and the marker is the version
// being returned to.
type step struct {
	apply  int
	up     bool
	marker int
}

// stepsFrom builds the ordered steps between two versions, or ErrNoChange when there are none. It
// walks the versions this engine actually carries rather than counting, because the four sets
// have different gaps: PostgreSQL has no 000002, three engines have no 000015, and 000036 to
// 000043 are each on one or two engines.
func (m *Migrator) stepsFrom(current, target int) ([]step, error) {
	if current == target {
		return nil, ErrNoChange
	}

	var steps []step
	if current < target {
		if current == NilVersion {
			first := m.src.first()
			if first == NilVersion {
				return nil, errors.New("this binary carries no migrations for this engine")
			}
			steps = append(steps, step{apply: first, up: true, marker: first})
			current = first
		}
		for current < target {
			next := m.src.next(current)
			if next == NilVersion {
				return nil, fmt.Errorf("this binary carries no migration above %s", formatVersion(current))
			}
			steps = append(steps, step{apply: next, up: true, marker: next})
			current = next
		}
		return steps, nil
	}

	for current > target && current != NilVersion {
		prev := m.src.prev(current)
		steps = append(steps, step{apply: current, up: false, marker: prev})
		if prev == NilVersion {
			// The floor: the first migration has just been rolled back and the database is
			// unmigrated again.
			break
		}
		current = prev
	}
	return steps, nil
}

// apply runs the steps in order, writing the dirty marker before each file and clearing it after,
// which is what makes an interruption visible as the version it stopped on.
func (m *Migrator) apply(ctx context.Context, conn *sql.Conn, steps []step) error {
	for _, s := range steps {
		if err := m.setVersion(ctx, conn, s.marker, true); err != nil {
			return err
		}

		body, name, present, err := m.readFile(s)
		if err != nil {
			return err
		}
		if present {
			if err := m.runFile(ctx, conn, body); err != nil {
				return fmt.Errorf("migration %s failed: %w; %w", name, err,
					// Below is the source's own predecessor of the marker, never marker minus
					// one: the sets have gaps, and beneath the first migration there is no
					// version at all rather than 000000.
					ErrDirty{Version: s.marker, Applied: s.apply, Below: m.src.prev(s.marker),
						Above: NilVersion, Carried: true})
			}
		}
		// A version with no file in the direction being travelled runs nothing and still moves
		// the marker, which golang-migrate did too and which the four migration sets rely on.

		if err := m.setVersion(ctx, conn, s.marker, false); err != nil {
			return err
		}
	}
	return nil
}

func (m *Migrator) readFile(s step) ([]byte, string, bool, error) {
	if s.up {
		return m.src.readUp(s.apply)
	}
	return m.src.readDown(s.apply)
}

// runFile hands the whole file to one Exec, with no arguments and no statement splitting, which
// is what golang-migrate did on every engine. MySQL needs multiStatements=true in its DSN for
// that to work and already has it.
//
// The transaction wrap is SQLite's alone. The other three engines run the file bare, and their
// migrations are written around that: SQL Server's 000040 opens its own BEGIN TRANSACTION with
// SET XACT_ABORT ON, which an outer transaction would break.
func (m *Migrator) runFile(ctx context.Context, conn *sql.Conn, body []byte) error {
	if !m.eng.txWrap {
		_, err := conn.ExecContext(ctx, string(body))
		return err
	}

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, string(body)); err != nil {
		if rerr := tx.Rollback(); rerr != nil && !errors.Is(rerr, sql.ErrTxDone) {
			return errors.Join(err, rerr)
		}
		return err
	}
	return tx.Commit()
}
