package migrator

import (
	"context"
	"errors"
	"time"

	"github.com/leodip/goiabada/core/errs"
)

// Progress is what a starting process is told while UpToHead works, so it can say so: a start
// waiting for the migration lock, or running a long migration, otherwise writes nothing and
// cannot be told from a hung one (#390 decision 7). The runner writes no record itself; the
// process starting owns the startup records, as it owns "no need to migrate the database".
//
// Versions are the runner's own, so a database never migrated is NilVersion.
type Progress interface {
	// WaitingForLock is called once, before the wait, when another session holds the migration
	// lock. Never on SQLite, whose lock is a mutex in this process.
	WaitingForLock()
	// Migrating is called before the first migration file runs: the version the schema is at,
	// the version it is going to and how many files that takes.
	Migrating(from, to, pending int)
	// Migrated is called after the last file has run and the schema is at to: how many files ran
	// and how long they took. Never after a stop, which UpToHead answers as StoppedError.
	Migrated(from, to, applied int, took time.Duration)
}

// noProgress is the Progress of every operation nobody is reporting on: Up, Migrate and Force, and
// an UpToHead passed nil.
type noProgress struct{}

func (noProgress) WaitingForLock()                       {}
func (noProgress) Migrating(int, int, int)               {}
func (noProgress) Migrated(int, int, int, time.Duration) {}

// UpToHead is the one way a starting process brings its database to head: Up, with "nothing to
// do" answered as (false, nil) and every failure explained by StartupRefusal. migrated reports
// whether any migration ran, so the caller, which owns the startup record, can say so; nothing
// here logs. progress is told what happens on the way, and may be nil.
//
// ctx is the start's: its end cancels a wait, for a connection or for the migration lock, and
// stops the chain between two files, answered as StoppedError and not wrapped as a refusal, since
// the start was asked to stop and did (#390 decision 9).
//
// Nothing to do is the bare ErrNoChange and nothing else, tested by identity. run joins a failed
// unlock onto what the operation returned, so at head with a lock that did not come back Up
// answers errors.Join(ErrNoChange, unlockErr); errors.Is would read that as a clean start and
// leave the lock held against every other migrator on the database, on PostgreSQL and SQL Server
// for as long as the process lives (#268). It is an error here instead.
//
// The wrap is the text each engine's own Migrate used before this replaced the four of them, so
// what an operator reads when a start is refused did not move (#438).
func (m *Migrator) UpToHead(ctx context.Context, goiabadaVersion string, progress Progress) (migrated bool, err error) {
	if progress == nil {
		progress = noProgress{}
	}
	err = m.up(ctx, progress)
	if IsNoChange(err) {
		return false, nil
	}
	var stopped StoppedError
	if errors.As(err, &stopped) {
		// Not a refusal: the start was asked to stop, and it did so with the schema clean.
		return false, err
	}
	if err != nil {
		return false, errs.Wrap(StartupRefusal(err, goiabadaVersion), "unable to migrate the database")
	}
	return true, nil
}

// StartupRefusal turns the one runner error a starting server has to explain into the sentences
// an operator can act on, and returns everything else exactly as it was.
//
// The error is UnknownVersionError out of Up(): the database records a version this binary carries
// no migration for. Reached at startup that has one cause, and it is not corruption. A newer
// release of Goiabada migrated this database, and this binary is older than it. Running its own
// chain from a version it does not recognise would re-apply migrations that have already been
// applied, so it refuses instead, exactly as golang-migrate's versionExists check did (#268).
//
// The Goiabada version is a parameter rather than read here. buildinfo.Version is injected at
// build time and the runner is a library that has to work under a test binary and a generator
// command too, neither of which is a release; the caller that knows which release it is passes
// it in.
//
// DirtyError already carries its own message, composed where the direction is known (see errors.go),
// and is returned untouched. So is ErrNoChange, which is not a failure at all, and so is every
// driver error, which says what it says.
func StartupRefusal(err error, goiabadaVersion string) error {
	var unknown UnknownVersionError
	if !errors.As(err, &unknown) {
		return err
	}

	return errs.Errorf("this database records schema version %s, which this release of Goiabada does not carry: "+
		"the highest %s migration it has is %s, and it is Goiabada %s. "+
		"A newer release migrated this database. Install that release again, "+
		"or run its `goiabada-authserver migrate to %s` first to step the schema down to what this one expects: %w",
		formatVersion(unknown.Version), unknown.Engine, formatVersion(unknown.Head), goiabadaVersion,
		formatVersion(unknown.Head), err)
}
