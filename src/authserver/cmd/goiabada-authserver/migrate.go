package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/datafactory"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
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

Connection details come from the GOIABADA_DB_* environment variables or the --db-* flags
(--db-type, --db-username, --db-password, --db-host, --db-port, --db-name, --db-dsn, --db-create),
given before or after migrate. A flag after migrate overrides the same flag before it. Every other
flag goes before migrate.`

// Exit codes. They are kept apart so a deployment script can tell a mistake in the invocation from
// a refusal by the database, which need different responses: one is fixed by retyping the command,
// the other by looking at the schema. migrateExitUsage also answers a malformed command line before
// any subcommand is chosen, from dispatch in main.go, for the same reason (#424).
const (
	migrateExitOK    = 0
	migrateExitError = 1
	migrateExitUsage = 2
)

// migrateCommand parses the arguments after `migrate`, opens the database they and base describe
// WITHOUT migrating it, and hands its migrator to runMigrate. base is the loaded database
// configuration: the environment, then the --db-* flags given before `migrate`.
//
// It is the only caller of datafactory.OpenDatabase: datafactory.NewDatabase brings the schema to
// head on the way out, which would make a step down impossible and a `migrate version` on a
// database behind this binary a lie, since the read would happen after the migration it was meant
// to report on.
func migrateCommand(args []string, base config.DatabaseConfig, stdout, stderr io.Writer) int {
	inv, err := parseMigrateArgs(args, base)
	if err != nil {
		outf(stderr, "%v\n\n%s\n", err, migrateUsage)
		return migrateExitUsage
	}
	if inv.help {
		outf(stdout, "%s\n", migrateUsage)
		return migrateExitOK
	}

	// The subcommand owns this root: it is a one-shot process with no request above it, and
	// nothing else is waiting on the migration it runs. It exists so that every driver call
	// below takes a context rather than opening one where it lands (#386).
	ctx := context.Background()

	database, err := datafactory.OpenDatabase(&inv.database, false)
	if err != nil {
		outf(stderr, "unable to open the database: %+v\n", err)
		return migrateExitError
	}

	provider, ok := database.(datafactory.MigratorProvider)
	if !ok {
		// Every engine type implements NewMigrator, so this is a new engine that forgot to.
		outf(stderr, "this database engine cannot be migrated by hand: %T has no NewMigrator\n", database)
		return migrateExitError
	}

	m, err := provider.NewMigrator(ctx)
	if err != nil {
		outf(stderr, "unable to prepare the migration runner: %+v\n", err)
		return migrateExitError
	}

	return runMigrate(ctx, inv.positional, database, m, rollbackFloor, stdout)
}

// migrateInvocation is what parseMigrateArgs made of the arguments after `migrate`.
type migrateInvocation struct {
	positional []string              // the subcommand and its operand, for runMigrate
	database   config.DatabaseConfig // base, with every --db-* flag given after `migrate` applied
	help       bool                  // -h or --help was given
}

// parseMigrateArgs reads the arguments after `migrate`: the --db-* flags anywhere among them, and
// the positional arguments runMigrate takes, in order. A flag overrides the same flag in db, which
// is a copy, so the loaded configuration is untouched; given twice, the last one wins.
//
// The scan is written here rather than left to FlagSet.Parse, and only the value parse is the flag
// package's. Parse stops at the first positional argument, so it cannot take flags interleaved
// with `to <n>`, and its errors are unexported text: telling an undefined flag from a malformed
// value, which need different advice, would mean matching that text. Walking the tokens with the
// flag package's own grammar and resolving each name through Lookup classifies every refusal
// before any error exists (#424). The grammar followed is flag's: one or two dashes, `name=value`,
// a non-boolean flag taking the next argument whatever it is, a boolean one never, `--` ending the
// flags, and a lone `-` positional.
func parseMigrateArgs(args []string, db config.DatabaseConfig) (migrateInvocation, error) {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	config.RegisterDatabaseFlags(fs, &db)

	var inv migrateInvocation
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			inv.positional = append(inv.positional, args[i+1:]...)
			break
		}
		if len(arg) < 2 || arg[0] != '-' {
			inv.positional = append(inv.positional, arg)
			continue
		}

		name := strings.TrimPrefix(arg[1:], "-")
		value, hasValue := "", false
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name, value, hasValue = name[:eq], name[eq+1:], true
		}

		if !hasValue && (name == "h" || name == "help") {
			inv.help = true
			continue
		}

		f := fs.Lookup(name)
		if name == "" || f == nil {
			typed := arg
			if name != "" {
				typed = arg[:strings.IndexByte(arg+"=", '=')]
			}
			return migrateInvocation{}, errs.Errorf("%s is not a flag migrate accepts: only the "+
				"--db-* flags can follow migrate, so give any other flag before it", typed)
		}

		if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
			if !hasValue {
				value = "true"
			}
		} else if !hasValue {
			if i+1 == len(args) {
				return migrateInvocation{}, errs.Errorf("--%s needs a value: give it as --%s=<value>",
					name, name)
			}
			i++
			//nolint:gosec // G602: i+1 == len(args) returned above, so i is in range here
			value = args[i]
		}

		if err := fs.Set(name, value); err != nil {
			return migrateInvocation{}, errs.Wrapf(err, "invalid value %q for --%s", value, name)
		}
	}

	inv.database = db
	return inv, nil
}

// runMigrate is the whole of the `migrate` subcommand: the arguments that followed the word
// "migrate", the opened database, a migrator over the configured engine's embedded set, the
// lowest version it may step down to, and somewhere to print. It returns the process exit code.
//
// The database is the whole data.Database rather than a port, which is what every other consumer
// now takes (#386). This command calls no method on it: it hands it to
// datafactory.CheckEmailCaseBeforeMigrating, which is composition and keeps the wide interface,
// and type-asserts it to datafactory.MigratorProvider. A port would have nothing in it.
//
// The database is here for the pre-flight migrateTo runs before an upward step (#351). The
// migrator alone cannot answer it: the check reads the users table through the engine's own SQL,
// and this command is the only path to a migrator that does not come through datafactory.NewDatabase,
// where the startup half of the same check lives.
//
// It takes the floor as a parameter rather than reading rollbackFloor so that a test can place a
// database above the floor and step it down. On a release where the floor is the head, which is
// this one, no downward step is reachable through the constant at all, and the direction the
// command exists for would go untested.
func runMigrate(ctx context.Context, args []string, database data.Database, m *migrator.Migrator, floor int, out io.Writer) int {
	if len(args) == 0 {
		outf(out, "%s\n", migrateUsage)
		return migrateExitUsage
	}

	switch args[0] {
	case "version":
		if len(args) != 1 {
			outf(out, "migrate version takes no arguments\n\n%s\n", migrateUsage)
			return migrateExitUsage
		}
		return migrateVersion(ctx, m, out)
	case "to":
		if len(args) != 2 {
			outf(out, "migrate to takes exactly one version\n\n%s\n", migrateUsage)
			return migrateExitUsage
		}
		target, err := parseTargetVersion(args[1])
		if err != nil {
			outf(out, "%s\n\n%s\n", err, migrateUsage)
			return migrateExitUsage
		}
		return migrateTo(ctx, database, m, target, floor, out)
	default:
		outf(out, "unknown migrate subcommand %q\n\n%s\n", args[0], migrateUsage)
		return migrateExitUsage
	}
}

// parseTargetVersion accepts the version in every form the operator will have it in front of them:
// bare, as `migrate version` prints it and as a release note states it, or six digits, as the
// migration filenames spell it. Both name the same number.
func parseTargetVersion(arg string) (int, error) {
	trimmed := strings.TrimSpace(arg)
	if trimmed == "" {
		return 0, errs.New("no version given")
	}
	// Base 10 explicitly: ParseInt with base 0 would read 000041 as octal and answer 33.
	v, err := strconv.ParseInt(trimmed, 10, 32)
	if err != nil || v < 0 {
		return 0, errs.Errorf("%q is not a schema version; give it as a number, for example 44 or 000044", arg)
	}
	return int(v), nil
}

// migrateVersion reports both halves of the question an operator has before a rollback: what this
// binary carries and what the database is actually at. It reads and never writes, so it answers on
// a dirty database too, where it is the first thing to run.
func migrateVersion(ctx context.Context, m *migrator.Migrator, out io.Writer) int {
	outf(out, "engine: %s\n", m.Engine())
	outf(out, "this binary expects schema version %06d\n", m.Head())

	version, dirty, err := m.Version(ctx)
	switch {
	case migrator.IsNilVersion(err):
		outf(out, "the database records no version: it has never been migrated\n")
	case err != nil:
		outf(out, "unable to read the database's schema version: %s\n", err)
		return migrateExitError
	case dirty:
		outf(out, "the database records schema version %06d, DIRTY: a migration did not finish\n", version)
	default:
		outf(out, "the database records schema version %06d\n", version)
	}
	return migrateExitOK
}

// migrateTo steps the schema to target, in whichever direction that is.
//
// The refusals it composes itself are the three the runner cannot know about: the rollback floor,
// which is this release's promise rather than a property of the migration set, and a target above
// the head, which the runner reports as an unknown version without saying that being above the
// head is what makes it unknown, and the stored email addresses migration 000047 cannot resolve,
// which is a fact about the data rather than about the schema (#351). Everything else is printed
// as the runner phrased it, because ErrDirty and ErrUnknownVersion already carry the facts an
// operator needs (decision 7 of #268).
func migrateTo(ctx context.Context, database data.Database, m *migrator.Migrator, target int, floor int, out io.Writer) int {
	if target < floor {
		// Neutral about direction on purpose: the floor refuses any target below it, and a
		// database still at an old version can ask for one on the way UP as easily as down.
		outf(out, "refusing to migrate to %06d: rollback is supported between releases from "+
			"Goiabada %s onwards, whose schema version is %06d, and no lower target is safe because "+
			"earlier releases changed data in ways no migration reverses. Start this server normally "+
			"to migrate up instead.\n",
			target, constants.Version, floor)
		return migrateExitError
	}
	if target > m.Head() {
		outf(out, "refusing to step the schema up to %06d: this binary carries no migration "+
			"above %06d. A newer release of Goiabada carries it.\n", target, m.Head())
		return migrateExitError
	}

	// Plan runs nothing and answers every refusal Migrate would, so a dirty database or an
	// unknown version is reported before anything is written rather than half way up the chain.
	plan, err := m.Plan(ctx, target)
	// IsNoChange rather than errors.Is, here and below: the runner joins a failed unlock onto
	// whatever the operation returned, so errors.Is would print "nothing to do" and exit 0 on a
	// database whose migration lock is still held (#268).
	if migrator.IsNoChange(err) {
		outf(out, "the database is already at schema version %06d; nothing to do\n", target)
		return migrateExitOK
	}
	if err != nil {
		outf(out, "%s\n", err)
		return migrateExitError
	}

	current, _, versionErr := m.Version(ctx)
	if migrator.IsNilVersion(versionErr) {
		outf(out, "current schema version: none (never migrated)\n")
	} else if versionErr == nil {
		outf(out, "current schema version: %06d\n", current)
	}
	outf(out, "target schema version: %06d\n", target)
	outf(out, "migrations to run, in order: %s\n", formatPlan(plan))

	// The same refusal `goiabada-authserver` performs at startup, run here because this command is
	// the only path to the migrator that does not come through datafactory.NewDatabase: it opens through
	// OpenDatabase precisely so a downward step is possible. Without it, `migrate to 47` on a
	// database holding an email case collision would trip the UNIQUE idx_email half way up the
	// chain and leave the schema dirty, which is the state the check exists to prevent and which
	// this command has no verb to recover from (#351).
	//
	// A version read that failed for any other reason is refused rather than skipped. Version()
	// answers NilVersion on every error, so passing current through would read a broken database
	// as a fresh one and skip the check on exactly the database least worth guessing about. Plan
	// above makes this all but unreachable, since it reads the version too; unreachable is not the
	// same as safe when the consequence is a dirty schema.
	if versionErr != nil && !migrator.IsNilVersion(versionErr) {
		outf(out, "unable to read the database's schema version before checking stored email "+
			"addresses: %s\n", versionErr)
		return migrateExitError
	}

	if err := datafactory.CheckEmailCaseBeforeMigrating(ctx, database, current, target); err != nil {
		outf(out, "%+v\n", err)
		return migrateExitError
	}

	if err := m.Migrate(ctx, target); err != nil {
		if migrator.IsNoChange(err) {
			outf(out, "the database is already at schema version %06d; nothing to do\n", target)
			return migrateExitOK
		}
		outf(out, "migration failed: %s\n", err)
		return migrateExitError
	}

	outf(out, "done: the database is now at schema version %06d\n", target)
	return migrateExitOK
}

// outf writes one line of the command's own output, discarding the error the write returns.
//
// The discard is the point of the function. The destination is the process's stdout or stderr,
// and a command that cannot describe what it did has no second channel to say so on: reporting a
// failed write means writing again, to the thing that just failed. What the command actually
// did is decided by the migrator and reported by the exit code, neither of which depends on
// the description reaching anyone.
//
// It exists rather than a `_, _ =` on each call site above, which is the same discard spelled
// once per line: errcheck flags an unchecked write to an io.Writer. migrateCommand's failures
// reach it too, since #424 gave the command its writers as parameters so a test can read them.
func outf(out io.Writer, format string, a ...any) {
	_, _ = fmt.Fprintf(out, format, a...)
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
