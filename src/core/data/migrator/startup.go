package migrator

import (
	"errors"

	"github.com/leodip/goiabada/core/errs"
)

// StartupRefusal turns the one runner error a starting server has to explain into the sentences
// an operator can act on, and returns everything else exactly as it was.
//
// The error is ErrUnknownVersion out of Up(): the database records a version this binary carries
// no migration for. Reached at startup that has one cause, and it is not corruption. A newer
// release of Goiabada migrated this database, and this binary is older than it. Running its own
// chain from a version it does not recognise would re-apply migrations that have already been
// applied, so it refuses instead, exactly as golang-migrate's versionExists check did (#268).
//
// The Goiabada version is a parameter rather than read here. constants.Version is injected at
// build time and the runner is a library that has to work under a test binary and a generator
// command too, neither of which is a release; the caller that knows which release it is passes
// it in.
//
// ErrDirty already carries its own message, composed where the direction is known (see errors.go),
// and is returned untouched. So is ErrNoChange, which is not a failure at all, and so is every
// driver error, which says what it says.
func StartupRefusal(err error, goiabadaVersion string) error {
	var unknown ErrUnknownVersion
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
