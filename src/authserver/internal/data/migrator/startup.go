package migrator

import (
	"context"
	"errors"

	"github.com/leodip/goiabada/core/errs"
)

// UpToHead is the one way a starting process brings its database to head: Up, with "nothing to
// do" answered as (false, nil) and every failure explained by StartupRefusal. migrated reports
// whether any migration ran, so the caller, which owns the startup record, can say so; nothing
// here logs.
//
// Nothing to do is the bare ErrNoChange and nothing else, tested by identity. run joins a failed
// unlock onto what the operation returned, so at head with a lock that did not come back Up
// answers errors.Join(ErrNoChange, unlockErr); errors.Is would read that as a clean start and
// leave the lock held against every other migrator on the database, on PostgreSQL and SQL Server
// for as long as the process lives (#268). It is an error here instead.
//
// The wrap is the text each engine's own Migrate used before this replaced the four of them, so
// what an operator reads when a start is refused did not move (#438).
func (m *Migrator) UpToHead(ctx context.Context, goiabadaVersion string) (migrated bool, err error) {
	err = m.Up(ctx)
	if IsNoChange(err) {
		return false, nil
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
