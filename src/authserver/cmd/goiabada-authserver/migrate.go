package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/data/migrator"
)

// rollbackFloor is the lowest schema version `migrate to` will step down to: the version this
// release of Goiabada ships with.
//
// Rolling further back would put the schema where an older release expects it while leaving that
// release unable to read the data. Goiabada v1.6.0 moved every TOTP secret into an encrypted
// column and blanked the plaintext one, and moved the data-encryption key out of the database into
// the environment; neither is a SQL migration, so no .down.sql reverses either, and no release
// before v1.6.0 can read what a later one wrote whatever the schema says. Rollback is therefore
// supported between releases from this one onwards, and the floor is what enforces it.
//
// It moves only when a later release introduces another one-way data change, and that release says
// so in its notes. The runner itself is unrestricted, so the tests can step anywhere (#268).
const rollbackFloor = 44

// migrateUsage is printed for every malformed invocation, and is the only place the two
// subcommands are spelled out.
const migrateUsage = `usage:
  goiabada-authserver migrate version      show the schema version this binary expects and the one the database records
  goiabada-authserver migrate to <version> step the schema to <version>, up or down (for example: to 44, or to 000044)

Connection details come from the usual GOIABADA_DB_* environment variables.`

// Exit codes. They are kept apart so a deployment script can tell a mistake in the invocation from
// a refusal by the database, which need different responses: one is fixed by retyping the command,
// the other by looking at the schema.
const (
	migrateExitOK    = 0
	migrateExitError = 1
	migrateExitUsage = 2
)

// migrateCommand opens the configured database WITHOUT migrating it and hands its migrator to
// runMigrate. It is the only caller of data.OpenDatabase: data.NewDatabase brings the schema to
// head on the way out, which would make a step down impossible and a `migrate version` on a
// database behind this binary a lie, since the read would happen after the migration it was meant
// to report on.
func migrateCommand(args []string) int {
	database, err := data.OpenDatabase(config.GetDatabase(), false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to open the database: %+v\n", err)
		return migrateExitError
	}

	provider, ok := database.(data.MigratorProvider)
	if !ok {
		// Every engine type implements NewMigrator, so this is a new engine that forgot to.
		fmt.Fprintf(os.Stderr, "this database engine cannot be migrated by hand: %T has no NewMigrator\n", database)
		return migrateExitError
	}

	m, err := provider.NewMigrator()
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to prepare the migration runner: %+v\n", err)
		return migrateExitError
	}

	return runMigrate(args, m, rollbackFloor, os.Stdout)
}

// runMigrate is the whole of the `migrate` subcommand: the arguments that followed the word
// "migrate", a migrator over the configured engine's embedded set, the lowest version it may step
// down to, and somewhere to print. It returns the process exit code.
//
// It takes the floor as a parameter rather than reading rollbackFloor so that a test can place a
// database above the floor and step it down. On a release where the floor is the head, which is
// this one, no downward step is reachable through the constant at all, and the direction the
// command exists for would go untested.
func runMigrate(args []string, m *migrator.Migrator, floor int, out io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(out, migrateUsage)
		return migrateExitUsage
	}

	switch args[0] {
	case "version":
		if len(args) != 1 {
			fmt.Fprintf(out, "migrate version takes no arguments\n\n%s\n", migrateUsage)
			return migrateExitUsage
		}
		return migrateVersion(m, out)
	case "to":
		if len(args) != 2 {
			fmt.Fprintf(out, "migrate to takes exactly one version\n\n%s\n", migrateUsage)
			return migrateExitUsage
		}
		target, err := parseTargetVersion(args[1])
		if err != nil {
			fmt.Fprintf(out, "%s\n\n%s\n", err, migrateUsage)
			return migrateExitUsage
		}
		return migrateTo(m, target, floor, out)
	default:
		fmt.Fprintf(out, "unknown migrate subcommand %q\n\n%s\n", args[0], migrateUsage)
		return migrateExitUsage
	}
}

// parseTargetVersion accepts the version in every form the operator will have it in front of them:
// bare, as `migrate version` prints it and as a release note states it, or six digits, as the
// migration filenames spell it. Both name the same number.
func parseTargetVersion(arg string) (int, error) {
	trimmed := strings.TrimSpace(arg)
	if trimmed == "" {
		return 0, errors.New("no version given")
	}
	// Base 10 explicitly: ParseInt with base 0 would read 000041 as octal and answer 33.
	v, err := strconv.ParseInt(trimmed, 10, 32)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("%q is not a schema version; give it as a number, for example 44 or 000044", arg)
	}
	return int(v), nil
}

// migrateVersion reports both halves of the question an operator has before a rollback: what this
// binary carries and what the database is actually at. It reads and never writes, so it answers on
// a dirty database too, where it is the first thing to run.
func migrateVersion(m *migrator.Migrator, out io.Writer) int {
	fmt.Fprintf(out, "engine: %s\n", m.Engine())
	fmt.Fprintf(out, "this binary expects schema version %06d\n", m.Head())

	version, dirty, err := m.Version()
	switch {
	case errors.Is(err, migrator.ErrNilVersion):
		fmt.Fprintln(out, "the database records no version: it has never been migrated")
	case err != nil:
		fmt.Fprintf(out, "unable to read the database's schema version: %s\n", err)
		return migrateExitError
	case dirty:
		fmt.Fprintf(out, "the database records schema version %06d, DIRTY: a migration did not finish\n", version)
	default:
		fmt.Fprintf(out, "the database records schema version %06d\n", version)
	}
	return migrateExitOK
}

// migrateTo steps the schema to target, in whichever direction that is.
//
// The refusals it composes itself are the two the runner cannot know about: the rollback floor,
// which is this release's promise rather than a property of the migration set, and a target above
// the head, which the runner reports as an unknown version without saying that being above the
// head is what makes it unknown. Everything else is printed as the runner phrased it, because
// ErrDirty and ErrUnknownVersion already carry the facts an operator needs (decision 7 of #268).
func migrateTo(m *migrator.Migrator, target int, floor int, out io.Writer) int {
	if target < floor {
		// Neutral about direction on purpose: the floor refuses any target below it, and a
		// database still at an old version can ask for one on the way UP as easily as down.
		fmt.Fprintf(out, "refusing to migrate to %06d: rollback is supported between releases from "+
			"Goiabada %s onwards, whose schema version is %06d, and no lower target is safe because "+
			"earlier releases changed data in ways no migration reverses. Start this server normally "+
			"to migrate up instead.\n",
			target, constants.Version, floor)
		return migrateExitError
	}
	if target > m.Head() {
		fmt.Fprintf(out, "refusing to step the schema up to %06d: this binary carries no migration "+
			"above %06d. A newer release of Goiabada carries it.\n", target, m.Head())
		return migrateExitError
	}

	// Plan runs nothing and answers every refusal Migrate would, so a dirty database or an
	// unknown version is reported before anything is written rather than half way up the chain.
	plan, err := m.Plan(target)
	if errors.Is(err, migrator.ErrNoChange) {
		fmt.Fprintf(out, "the database is already at schema version %06d; nothing to do\n", target)
		return migrateExitOK
	}
	if err != nil {
		fmt.Fprintf(out, "%s\n", err)
		return migrateExitError
	}

	current, _, versionErr := m.Version()
	if errors.Is(versionErr, migrator.ErrNilVersion) {
		fmt.Fprintln(out, "current schema version: none (never migrated)")
	} else if versionErr == nil {
		fmt.Fprintf(out, "current schema version: %06d\n", current)
	}
	fmt.Fprintf(out, "target schema version: %06d\n", target)
	fmt.Fprintf(out, "migrations to run, in order: %s\n", formatPlan(plan))

	if err := m.Migrate(target); err != nil {
		if errors.Is(err, migrator.ErrNoChange) {
			fmt.Fprintf(out, "the database is already at schema version %06d; nothing to do\n", target)
			return migrateExitOK
		}
		fmt.Fprintf(out, "migration failed: %s\n", err)
		return migrateExitError
	}

	fmt.Fprintf(out, "done: the database is now at schema version %06d\n", target)
	return migrateExitOK
}

// formatPlan prints the versions in the order they will run, which reads highest first on the way
// down: those are the .down.sql files being rolled back, and an operator comparing the list against
// a release note needs to see the direction rather than infer it.
func formatPlan(plan []int) string {
	if len(plan) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(plan))
	for _, v := range plan {
		parts = append(parts, fmt.Sprintf("%06d", v))
	}
	return strings.Join(parts, ", ")
}
