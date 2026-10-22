package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data/datafactory"
	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/recovery"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/errs"
)

// The `recover` subcommand is the one way back into an instance whose last administrator cannot
// sign in (#498). This file reads its arguments, opens the database, checks the schema and
// prints what happened; the recovery itself is internal/recovery's Run, which the data tier runs
// on every engine.

// recoverUsage is printed for every malformed invocation, and is the only place the subcommand's
// flags are spelled out.
const recoverUsage = `usage:
  goiabada-authserver recover --email <address> [flags]

--email names the user to recover by their stored address, and is required. Each action is its
own flag, applied only as asked, and at least one is required:
  --grant-manage         grant the authserver:manage permission
  --password-stdin       set a new password, read from the first line of stdin
  --password <password>  set a new password given on the command line, where the shell's history
                         and the process list see it
  --remove-otp           remove the user's OTP authenticator

A new password is held to the stored password policy, and an empty one is refused.

Whatever is asked, the user's sessions end and their authentication generation advances, so
nothing signed in before the recovery survives it. An unknown or disabled user is refused, and so
is a database whose schema is not the one this binary carries.

Connection details come from the GOIABADA_DB_* environment variables or the --db-* flags
(--db-type, --db-username, --db-password, --db-host, --db-port, --db-name, --db-dsn, --db-create,
the pool's --db-max-open-conns, --db-max-idle-conns, --db-conn-max-lifetime and
--db-conn-max-idle-time, and the connection's --db-tls-mode, --db-tls-ca-file,
--db-tls-client-cert-file, --db-tls-client-key-file and --db-tls-server-name), given before or after recover. A flag after recover overrides the same flag before it. Every other
flag goes before recover.`

// readRecoverCommand reads the arguments after `recover` into the invocation it runs, and the new
// password from stdin when --password-stdin asks for it, or writes the refusal to stderr and
// answers false, for an exit with migrateExitUsage. main calls it before the start's first
// record, so a refusal is the only thing on stderr (#502).
//
// Stdin is read last, after the TLS settings are checked, so a refused setting is reported
// before the command waits for a password typed at a terminal.
func readRecoverCommand(args []string, base config.DatabaseConfig, stdin io.Reader, stderr io.Writer) (recoverInvocation, bool) {
	inv, err := parseRecoverArgs(args, base)
	if err != nil {
		outf(stderr, "%v\n\n%s\n", err, recoverUsage)
		return recoverInvocation{}, false
	}
	if tlsErr := config.CheckDatabaseTLS(&inv.database); tlsErr != nil {
		outf(stderr, "%v\n", tlsErr)
		return recoverInvocation{}, false
	}
	if inv.passwordStdin && !inv.help {
		if inv.password, err = readPasswordLine(stdin); err != nil {
			outf(stderr, "%v\n", err)
			return recoverInvocation{}, false
		}
	}
	return inv, true
}

// readPasswordLine reads the first line of r as the new password, without its line ending. The
// rest of the line is the password, spaces included, since a password may hold them. An empty
// line, or no line at all, is refused: the operator asked for a password to be set, and setting
// none while the other actions commit would leave the forgotten one in place.
func readPasswordLine(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", errs.Wrap(err, "unable to read the new password from stdin")
		}
		return "", errs.New("--password-stdin read nothing: give the new password as the first " +
			"line of stdin")
	}
	if scanner.Text() == "" {
		return "", errs.New("--password-stdin read an empty line: give the new password as the " +
			"first line of stdin")
	}
	return scanner.Text(), nil
}

// runRecoverCommand runs the invocation readRecoverCommand read.
func runRecoverCommand(inv recoverInvocation, stdout, stderr io.Writer) int {
	if inv.help {
		outf(stdout, "%s\n", recoverUsage)
		return migrateExitOK
	}

	// The subcommand owns this root, for the same reason `migrate` does: it is a one-shot
	// process with no request above it, and nothing else is waiting on the writes it runs
	// (#386).
	ctx := context.Background()

	database, err := datafactory.OpenDatabase(ctx, &inv.database, false)
	if err != nil {
		outf(stderr, "unable to open the database: %+v\n", err)
		return migrateExitError
	}
	// Closed when the subcommand ends, which on SQLite checkpoints the WAL the writes left.
	defer func() { _ = database.Close() }()

	m, err := database.NewMigrator(ctx, nil)
	if err != nil {
		outf(stderr, "unable to prepare the migration runner: %+v\n", err)
		return migrateExitError
	}

	// The audit logger is the server's own, reading the switches from the settings the same
	// way the running server does, so a deployment that has turned either target off is
	// obeyed here too.
	return runRecover(ctx, database, m,
		audit.NewLogger(database, middleware.NewAuditSwitches(database)), inv, stdout, stderr)
}

// recoverInvocation is what parseRecoverArgs made of the arguments after `recover`.
type recoverInvocation struct {
	email         string                // the stored address of the user to recover, required
	password      string                // a new password for the user, empty when not asked
	passwordStdin bool                  // read the new password from stdin into password
	grantManage   bool                  // grant authserver:manage
	removeOTP     bool                  // remove the user's OTP authenticator
	database      config.DatabaseConfig // base, with every --db-* flag given after `recover` applied
	help          bool                  // -h or --help was given
}

// parseRecoverArgs reads the arguments after `recover`: the --db-* flags anywhere among them and
// the subcommand's own, and no positional arguments at all. A flag overrides the same flag in db,
// which is a copy, so the loaded configuration is untouched; given twice, the last one wins.
//
// The scan is walkFlagTokens, the one parseMigrateArgs uses, for the reasons that one gives: the
// flag package's Parse stops at the first positional argument and its errors are unexported text,
// which would leave an undefined flag and a malformed value indistinguishable (#424).
//
// Every refusal of how the command was typed is made here, before anything is opened: help is
// answered before the email is required, as `migrate --help` is, and a run with no action, or
// with an empty --password, is refused here rather than after the database is opened.
func parseRecoverArgs(args []string, db config.DatabaseConfig) (recoverInvocation, error) {
	fs := flag.NewFlagSet("recover", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	config.RegisterDatabaseFlags(fs, &db)

	var inv recoverInvocation
	fs.StringVar(&inv.email, "email", "", "the stored address of the user to recover")
	fs.StringVar(&inv.password, "password", "", "a new password for the user")
	fs.BoolVar(&inv.passwordStdin, "password-stdin", false, "read the new password from stdin")
	fs.BoolVar(&inv.grantManage, "grant-manage", false, "grant authserver:manage")
	fs.BoolVar(&inv.removeOTP, "remove-otp", false, "remove the user's OTP authenticator")

	positionals, help, err := walkFlagTokens(fs, "recover",
		"only the --db-* flags and --email, --password, --password-stdin, --grant-manage and "+
			"--remove-otp can follow recover", args)
	if err != nil {
		return recoverInvocation{}, err
	}
	if len(positionals) > 0 {
		return recoverInvocation{}, errs.Errorf("%q is not a flag recover takes as a positional "+
			"argument: the user to recover is named with --email, and every other value comes from "+
			"a flag", positionals[0])
	}

	// The flag package parsed each value; the pool's ranges and the TLS mode are held here as
	// Load holds them (#394 decision 5, #502).
	if err := config.CheckDatabaseFlags(fs, &db); err != nil {
		return recoverInvocation{}, err
	}
	inv.database = db
	if help {
		inv.help = true
		return inv, nil
	}

	if strings.TrimSpace(inv.email) == "" {
		return recoverInvocation{}, errs.New("--email is required: it names the user to recover " +
			"by their stored address")
	}

	// A --password given empty is refused rather than read as "no password asked": an unset
	// variable expands to nothing, and the recovery would commit its other actions and leave the
	// forgotten password in place while it reported success.
	passwordGiven := false
	fs.Visit(func(f *flag.Flag) { passwordGiven = passwordGiven || f.Name == "password" })
	if passwordGiven && inv.passwordStdin {
		return recoverInvocation{}, errs.New("--password and --password-stdin both give the new " +
			"password: give one of them")
	}
	if passwordGiven && inv.password == "" {
		return recoverInvocation{}, errs.New("--password is empty: give the new password, or " +
			"leave the flag out to keep the one the user has")
	}

	// One action at least: a recovery that does nothing is a typo wearing the command's
	// authority, and the usage says what the flags are.
	if !inv.grantManage && !passwordGiven && !inv.passwordStdin && !inv.removeOTP {
		return recoverInvocation{}, errs.New("nothing to do: give at least one of " +
			"--grant-manage, --password-stdin, --password or --remove-otp")
	}
	return inv, nil
}

// schemaVersionReader is what runRecover asks of the migrator: the version the database records
// and the one this binary carries.
type schemaVersionReader interface {
	Head() int
	Version(ctx context.Context) (version int, dirty bool, err error)
}

// runRecover is the whole of the `recover` subcommand against the opened database: the invocation,
// the database, its migrator, the audit logger to record what it did, and somewhere to print. It
// answers the process exit code, so a test can run it against a database it seeded, as the
// migrate tests run runMigrate against one.
func runRecover(ctx context.Context, database recovery.Database, m schemaVersionReader,
	auditLogger recovery.AuditLogger, inv recoverInvocation, stdout, stderr io.Writer) int {

	// The schema must be the one this binary's data tier writes, as the server's start requires
	// before it serves: a database a newer release migrated holds columns and rules this binary
	// does not know, and a dirty one a migration that did not finish. The recovery writes
	// credentials and a permission, which is no place to guess.
	if refusal := checkRecoverSchema(ctx, m); refusal != "" {
		outf(stderr, "refusing to recover: %s\n", refusal)
		return migrateExitError
	}

	outcome, err := recovery.Run(ctx, database, auditLogger, recovery.Request{
		Email:       inv.email,
		Password:    inv.password,
		GrantManage: inv.grantManage,
		RemoveOTP:   inv.removeOTP,
	})
	var refusal *recovery.RefusedError
	if errors.As(err, &refusal) {
		outf(stderr, "refusing to recover: %s\n", refusal.Reason)
		return migrateExitError
	}
	if err != nil {
		outf(stderr, "unable to recover the user: %+v\n", err)
		return migrateExitError
	}

	outf(stdout, "recovered %s (user %d)\n", outcome.Email, outcome.UserId)
	if outcome.PasswordSet {
		outf(stdout, "  password set\n")
	}
	if inv.removeOTP {
		if outcome.OTPRemoved {
			outf(stdout, "  otp authenticator removed\n")
		} else {
			outf(stdout, "  no otp authenticator was enrolled, so nothing was removed\n")
		}
	}
	if inv.grantManage {
		if outcome.ManageGranted {
			outf(stdout, "  %s:%s granted\n",
				builtin.AuthServerResourceIdentifier, builtin.ManagePermissionIdentifier)
		} else {
			outf(stdout, "  %s:%s was already held, so nothing was granted\n",
				builtin.AuthServerResourceIdentifier, builtin.ManagePermissionIdentifier)
		}
	}
	outf(stdout, "  sessions ended: %d, refresh tokens revoked: %d, authentication generation %d to %d\n",
		len(outcome.Revocation.TerminatedSessionIdentifiers), len(outcome.Revocation.RevokedRefreshTokenJtis),
		outcome.Revocation.OldGeneration, outcome.Revocation.NewGeneration)
	return migrateExitOK
}

// checkRecoverSchema answers why the recovery must not write to this database, or "" when the
// database records this binary's head, clean.
func checkRecoverSchema(ctx context.Context, m schemaVersionReader) string {
	version, dirty, err := m.Version(ctx)
	switch {
	case migrator.IsNilVersion(err):
		return "the database records no schema version: it has never been migrated, so it holds " +
			"no user to recover"
	case err != nil:
		return "unable to read the database's schema version: " + err.Error()
	case dirty:
		return fmt.Sprintf("the database records schema version %06d, DIRTY: a migration did "+
			"not finish. Repair it with `goiabada-authserver migrate` first", version)
	case version != m.Head():
		return fmt.Sprintf("the database records schema version %06d and this binary carries "+
			"%06d. Run the recover command of the release whose schema the database is at, or start "+
			"this release's auth server once to migrate the database to its schema", version, m.Head())
	}
	return ""
}
