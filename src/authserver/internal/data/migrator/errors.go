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

// IsNoChange reports whether err is the ErrNoChange sentinel and nothing else, and it is the test
// every caller that treats "nothing to do" as success owes.
//
// errors.Is is the wrong one here, and the difference is not academic. run joins a failed unlock
// onto whatever the operation returned, so an Up() with nothing to do on a database whose
// migration lock did not come back answers errors.Join(ErrNoChange, unlockErr). errors.Is finds
// the sentinel inside that and reports the start as successful, discarding the one error saying
// every other migrator on this database is now blocked, on PostgreSQL and SQL Server for as long
// as the process lives. The runner returns the sentinel bare when it means it, so identity is the
// whole test (#268).
func IsNoChange(err error) bool {
	return err == ErrNoChange
}

// ErrNilVersion is answered by Version() when schema_migrations holds no row, which is what a
// database that has never been migrated looks like.
var ErrNilVersion = errors.New("no migration has been applied to this database")

// IsNilVersion reports whether err is the ErrNilVersion sentinel and nothing else. Identity for
// the same reason IsNoChange uses it: withConn joins a failed connection close onto whatever the
// read returned, and errors.Is would report an unmigrated database while dropping the failure
// that says the read could not be completed cleanly (#268).
func IsNilVersion(err error) bool {
	return err == ErrNilVersion
}

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
// an operator recovering a failed down to a version the schema was never at, and deriving the
// lower one by subtracting sends them to a version no engine's set carries (#268).
type ErrDirty struct {
	// Version is the version recorded in schema_migrations, dirty.
	Version int
	// Applied is the version whose file the interrupted step was running, or AppliedUnknown.
	Applied int
	// Below is the highest version the SOURCE carries beneath Version, or NilVersion when there
	// is none. It is carried rather than derived because Version minus one is not a version: the
	// four migration sets have gaps (PostgreSQL has no 000002, three engines have no 000015,
	// 000036 to 000043 are each on one or two engines), so an up to 000005 interrupted on a
	// database last at 000002 would name 000004, which this binary carries no file for and
	// refuses on the next start. Beneath the first migration there is nothing, which is the
	// unmigrated database rather than version 000000.
	Below int
	// Above is the next version the source carries after Version, or NilVersion when there is
	// none. It is read only when Applied is AppliedUnknown, where it names the down step that
	// could have left this marker.
	Above int
	// Carried says this binary has a migration numbered Version for this engine, which is what
	// makes Below and Above endpoints rather than guesses. When it is false a NEWER release wrote
	// the marker, and Below is merely the nearest version this binary happens to know: a set
	// carrying 1, 2, 4, 5 that dies at 5 leaves a marker an older binary carrying 1, 2 reads as
	// preceded by 000002, when 000004 applied and committed. Recording 000002 clean would then
	// re-run 000003 and 000004 against a schema that already has them on the next upgrade, so the
	// message must not name it (#268).
	//
	// A nil marker sets it true: only a rolled-back first migration writes that row, and every
	// engine's first migration is one every release carries.
	Carried bool
}

func (e ErrDirty) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "the database records version %s and is marked dirty, so a migration did not finish. ",
		formatVersion(e.Version))
	b.WriteString("Goiabada will not migrate a dirty database, because it cannot tell how much of that migration applied. ")
	b.WriteString("Inspect the schema by hand, repair it to one of the states below, and record that state in schema_migrations: ")
	b.WriteString("one row carrying that version with dirty set to false, or no row at all where the state is that the database was never migrated. ")

	if e.Applied != AppliedUnknown {
		// The direction is known, so there are exactly two candidates. On an up step the marker
		// is the applied version, so "did not apply" is the version the source carries below it,
		// which is Below rather than the marker minus one; on a down step the marker is already
		// below the applied version, so "did not apply" is the applied version itself.
		notApplied := e.Applied
		if e.Version == e.Applied {
			notApplied = e.Below
		}
		fmt.Fprintf(&b, "Migration %s was running: version %s if its statements did not apply, version %s if they did.",
			formatVersion(e.Applied), formatVersion(notApplied), formatVersion(e.Version))
		return b.String()
	}

	// A nil marker is the one case the direction does not have to be guessed at. An up step
	// always marks the version it applies, which is never nil, so only a rolled-back first
	// migration can have written this row.
	if e.Version == NilVersion {
		fmt.Fprintf(&b, "The row records no version, which only an interrupted rollback of migration %s can leave: "+
			"version %s if its statements did not apply, or never migrated, with the row deleted, if they did.",
			formatVersion(e.Above), formatVersion(e.Above))
		return b.String()
	}

	// A version this binary has no file for was written by a newer release, so the versions its
	// step sat between are in that release's migration set and not in this one. Naming the
	// nearest version this binary does carry would be arithmetic on someone else's set.
	if !e.Carried {
		fmt.Fprintf(&b, "This binary carries no migration %s, so a newer release migrated this database "+
			"and only that release knows which versions the interrupted step sat between. "+
			"Run its binary against this database to be told, and recover there before installing this one.",
			formatVersion(e.Version))
		return b.String()
	}

	// Otherwise the direction was not recorded, so the marker is consistent with two interrupted
	// steps and the message names both rather than guessing one.
	fmt.Fprintf(&b, "The row does not record a direction, so either migration %s was being applied, ",
		formatVersion(e.Version))
	if e.Above == NilVersion {
		fmt.Fprintf(&b, "leaving version %s if its statements did not apply and version %s if they did, "+
			"or a migration above %s was being rolled back by a newer release, leaving that version if its statements did not apply.",
			formatVersion(e.Below), formatVersion(e.Version), formatVersion(e.Version))
		return b.String()
	}
	fmt.Fprintf(&b, "leaving version %s if its statements did not apply, or migration %s was being rolled back, "+
		"leaving version %s if its statements did not apply. Version %s is the end state if either one did apply.",
		formatVersion(e.Below), formatVersion(e.Above), formatVersion(e.Above), formatVersion(e.Version))
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
