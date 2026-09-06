package migrator

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

// ErrNoChange is answered when the database is already at the requested version. It keeps the
// name and the role golang-migrate's sentinel had, because callers all over the data tier test
// for it around an Up() that legitimately has nothing to do (#268).
var ErrNoChange = errors.New("no change")

// ErrNilVersion is answered by Version() when schema_migrations holds no row, which is what a
// database that has never been migrated looks like.
var ErrNilVersion = errors.New("no migration has been applied to this database")

// ErrLocked is answered when another process holds the migration lock and this one gave up
// waiting. Only MySQL can produce it: GET_LOCK is the one lock statement with a timeout, ten
// seconds, while PostgreSQL and SQL Server wait indefinitely and SQLite locks in-process only.
var ErrLocked = errors.New("another migration is already running on this database")

// NilVersion is the version of a database with no row in schema_migrations. It is -1 rather than
// 0 because 0 is a number a migration set could legitimately carry, and it is the same value
// golang-migrate wrote into the table for the one case that records a nil version (a down step
// off the first migration, interrupted), so the two releases read each other's rows (#268).
const NilVersion = -1

// AppliedUnknown is ErrDirty.Applied when the direction of the interrupted step is not known.
// schema_migrations records the version reached and nothing about direction, so a marker read
// back from the table could have been left by either an up or a down step; only the step that
// fails in this process knows which it was.
const AppliedUnknown = math.MinInt

// ErrDirty says a migration was interrupted between its two bookkeeping writes, so the schema
// sits between two versions and no automatic recovery is safe.
//
// Version is the marker in schema_migrations. Applied is the version whose file was running,
// which is NOT the marker on a down step: an up step to V runs V.up.sql and marks V, while a down
// step from N to its predecessor runs N.down.sql and marks the predecessor. The two legal end
// states are therefore always "Applied's statements did not apply" and "they did", and which of
// those sits above the marker depends on the direction. Deriving them from the marker alone sends
// an operator recovering a failed down to a version the schema was never at (#268).
type ErrDirty struct {
	// Version is the version recorded in schema_migrations, dirty.
	Version int
	// Applied is the version whose file the interrupted step was running, or AppliedUnknown.
	Applied int
	// Above is the next version the source carries after Version, or NilVersion when there is
	// none. It is read only when Applied is AppliedUnknown, where it names the down step that
	// could have left this marker.
	Above int
}

func (e ErrDirty) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "the database records version %s and is marked dirty, so a migration did not finish. ",
		formatVersion(e.Version))
	b.WriteString("Goiabada will not migrate a dirty database, because it cannot tell how much of that migration applied. ")
	b.WriteString("Inspect the schema by hand, repair it to one of the states below, and record that version in schema_migrations with dirty set to false. ")

	if e.Applied != AppliedUnknown {
		// The direction is known, so there are exactly two candidates. On an up step the marker
		// is the applied version, so "did not apply" is the version below it; on a down step the
		// marker is already below the applied version, so "did not apply" is the applied version
		// itself.
		notApplied := e.Applied
		if e.Version == e.Applied {
			notApplied = e.Version - 1
		}
		fmt.Fprintf(&b, "Migration %s was running: version %s if its statements did not apply, version %s if they did.",
			formatVersion(e.Applied), formatVersion(notApplied), formatVersion(e.Version))
		return b.String()
	}

	// The direction was not recorded, so the marker is consistent with two interrupted steps and
	// the message names both rather than guessing one.
	fmt.Fprintf(&b, "The row does not record a direction, so either migration %s was being applied, ",
		formatVersion(e.Version))
	if e.Above == NilVersion {
		fmt.Fprintf(&b, "leaving version %s if its statements did not apply and version %s if they did, "+
			"or a migration above %s was being rolled back by a newer release, leaving that version if its statements did not apply.",
			formatVersion(e.Version-1), formatVersion(e.Version), formatVersion(e.Version))
		return b.String()
	}
	fmt.Fprintf(&b, "leaving version %s if its statements did not apply, or migration %s was being rolled back, "+
		"leaving version %s if its statements did not apply. Version %s is the end state if either one did apply.",
		formatVersion(e.Version-1), formatVersion(e.Above), formatVersion(e.Above), formatVersion(e.Version))
	return b.String()
}

// ErrUnknownVersion says a version is not among the migration files this binary carries for this
// engine. It arises two ways, and they need different sentences: the DATABASE records a version
// the binary does not know, which means a newer release migrated it, or an operator asked to step
// to one.
//
// The type carries the facts and no wording. The "a newer release migrated this database"
// sentence also needs the Goiabada version, which lives in core/constants, and is composed by the
// caller that has it (decision 7).
type ErrUnknownVersion struct {
	// Version is the version that is not in the source.
	Version int
	// Engine names the engine whose migration set was searched, since the four sets differ: three
	// engines have no 000015, PostgreSQL has no 000002, and 000036 to 000043 are each on one or
	// two engines.
	Engine string
	// Head is the highest version this binary carries for that engine.
	Head int
	// Below and Above are the nearest versions the binary does carry either side of Version, each
	// NilVersion when there is none.
	Below int
	Above int
}

func (e ErrUnknownVersion) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "this binary carries no %s migration numbered %s", e.Engine, formatVersion(e.Version))
	switch {
	case e.Below != NilVersion && e.Above != NilVersion:
		fmt.Fprintf(&b, "; the nearest it carries are %s and %s", formatVersion(e.Below), formatVersion(e.Above))
	case e.Below != NilVersion:
		fmt.Fprintf(&b, "; the nearest it carries below is %s", formatVersion(e.Below))
	case e.Above != NilVersion:
		fmt.Fprintf(&b, "; the nearest it carries above is %s", formatVersion(e.Above))
	}
	fmt.Fprintf(&b, "; the highest it carries is %s", formatVersion(e.Head))
	return b.String()
}

// RecordedVersion is one row of schema_migrations.
type RecordedVersion struct {
	Version int
	Dirty   bool
}

// ErrMultipleVersions says schema_migrations holds more than one row. The runner's own writes
// cannot produce that, since every write deletes the table and inserts one row in a single
// transaction, so a second row is a hand edit or corruption. Reading one of them and carrying on
// is how a database gets migrated from a version it is not at (decision 5).
type ErrMultipleVersions struct {
	Rows []RecordedVersion
}

func (e ErrMultipleVersions) Error() string {
	parts := make([]string, 0, len(e.Rows))
	for _, r := range e.Rows {
		parts = append(parts, fmt.Sprintf("(version %s, dirty %t)", formatVersion(r.Version), r.Dirty))
	}
	return fmt.Sprintf("schema_migrations holds %d rows and Goiabada writes exactly one: %s. "+
		"Something other than Goiabada wrote this table; keep the row that matches the schema and delete the rest before starting again",
		len(e.Rows), strings.Join(parts, ", "))
}

// formatVersion prints a version the way the migration filenames and the documentation name it,
// six digits, so an operator can match it against a file without counting zeros. NilVersion
// prints as words rather than as -1, which is an implementation detail nobody outside this
// package should have to recognise.
func formatVersion(v int) string {
	if v <= NilVersion {
		return "none (never migrated)"
	}
	return fmt.Sprintf("%06d", v)
}
