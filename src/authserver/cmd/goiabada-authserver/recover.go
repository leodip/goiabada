package main

import (
	"context"
	"database/sql"
	"flag"
	"io"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/datafactory"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/otpcredential"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/errs"
)

// The `recover` subcommand is the one way back into an instance whose last administrator cannot
// sign in: the OTP device is lost, or the password is forgotten and SMTP is not configured, or
// every holder of authserver:manage has left. Bootstrap seeds only an empty database, and editing
// the users rows by hand bypasses the authentication generation and writes no audit record (#498).
// The command's authority is the database credentials it is run with, which is what makes it
// trustworthy: whoever holds them already controls the instance. It refuses an unknown or
// disabled user rather than creating or enabling one, and through the same writes the Admin API
// uses, in one transaction, so the authentication generation advances, the sessions end and the
// audit trail names the command as the actor.

// recoverUsage is printed for every malformed invocation, and is the only place the subcommand's
// flags are spelled out.
const recoverUsage = `usage:
  goiabada-authserver recover --email <address> [flags]

--email names the user to recover by their stored address, and is required. Each action is its
own flag, applied only as asked:
  --grant-manage         grant the authserver:manage permission
  --password <password>  set a new password, held to the stored password policy
  --remove-otp           remove the user's OTP authenticator

Whatever is asked, the user's sessions end and their authentication generation advances, so
nothing signed in before the recovery survives it. An unknown or disabled user is refused.

Connection details come from the GOIABADA_DB_* environment variables or the --db-* flags
(--db-type, --db-username, --db-password, --db-host, --db-port, --db-name, --db-dsn, --db-create,
the pool's --db-max-open-conns, --db-max-idle-conns, --db-conn-max-lifetime and
--db-conn-max-idle-time, and the connection's --db-tls-mode, --db-tls-ca-file,
--db-tls-client-cert-file, --db-tls-client-key-file and --db-tls-server-name), given before or after recover. A flag after recover overrides the same flag before it. Every other
flag goes before recover.`

// recoverActor is what the command's audit events name as the actor, where the API sites name the
// signed-in user (#498: "recording an audit event that names the command as the actor"). There is
// no signed-in administrator here, and the database credentials the command is gated on are the
// authority it acts with, so the record says who acted by naming the command itself.
const recoverActor = "goiabada-authserver recover"

// readRecoverCommand reads the arguments after `recover` into the invocation it runs, or writes
// the refusal to stderr and answers false, for an exit with migrateExitUsage. main calls it
// before the start's first record, so a refusal is the only thing on stderr (#502).
func readRecoverCommand(args []string, base config.DatabaseConfig, stderr io.Writer) (recoverInvocation, bool) {
	inv, err := parseRecoverArgs(args, base)
	if err != nil {
		outf(stderr, "%v\n\n%s\n", err, recoverUsage)
		return recoverInvocation{}, false
	}
	if err := config.CheckDatabaseTLS(&inv.database); err != nil {
		outf(stderr, "%v\n", err)
		return recoverInvocation{}, false
	}
	return inv, true
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

	// The audit logger is the server's own, reading the switches from the settings the same
	// way the running server does, so a deployment that has turned either target off is
	// obeyed here too.
	return runRecover(ctx, database,
		audit.NewLogger(database, middleware.NewAuditSwitches(database)), inv, stdout, stderr)
}

// recoverInvocation is what parseRecoverArgs made of the arguments after `recover`.
type recoverInvocation struct {
	email       string                // the stored address of the user to recover, required
	password    string                // a new password for the user, empty when not asked
	grantManage bool                  // grant authserver:manage
	removeOTP   bool                  // remove the user's OTP authenticator
	database    config.DatabaseConfig // base, with every --db-* flag given after `recover` applied
	help        bool                  // -h or --help was given
}

// parseRecoverArgs reads the arguments after `recover`: the --db-* flags anywhere among them and
// the subcommand's own, and no positional arguments at all. A flag overrides the same flag in db,
// which is a copy, so the loaded configuration is untouched; given twice, the last one wins.
//
// The scan is walkFlagTokens, the one parseMigrateArgs uses, for the reasons that one gives: the
// flag package's Parse stops at the first positional argument and its errors are unexported text,
// which would leave an undefined flag and a malformed value indistinguishable (#424).
func parseRecoverArgs(args []string, db config.DatabaseConfig) (recoverInvocation, error) {
	fs := flag.NewFlagSet("recover", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	config.RegisterDatabaseFlags(fs, &db)

	var inv recoverInvocation
	fs.StringVar(&inv.email, "email", "", "the stored address of the user to recover")
	fs.StringVar(&inv.password, "password", "", "a new password for the user")
	fs.BoolVar(&inv.grantManage, "grant-manage", false, "grant authserver:manage")
	fs.BoolVar(&inv.removeOTP, "remove-otp", false, "remove the user's OTP authenticator")

	positionals, help, err := walkFlagTokens(fs, "recover",
		"only the --db-* flags and --email, --password, --grant-manage and --remove-otp can "+
			"follow recover", args)
	if err != nil {
		return recoverInvocation{}, err
	}
	if len(positionals) > 0 {
		return recoverInvocation{}, errs.Errorf("%q is not a flag recover takes as a positional "+
			"argument: the user to recover is named with --email, and every other value comes from "+
			"a flag", positionals[0])
	}
	if strings.TrimSpace(inv.email) == "" {
		return recoverInvocation{}, errs.New("--email is required: it names the user to recover " +
			"by their stored address")
	}
	inv.help = help

	// The flag package parsed each value; the pool's ranges and the TLS mode are held here as
	// Load holds them (#394 decision 5, #502).
	if err := config.CheckDatabaseFlags(fs, &db); err != nil {
		return recoverInvocation{}, err
	}

	inv.database = db
	return inv, nil
}

// runRecover is the whole of the `recover` subcommand against the opened database: the invocation,
// the database, the audit logger to record what it did, and somewhere to print. It answers the
// process exit code, so a test can run it against a database it seeded, as the migrate tests run
// runMigrate against one.
//
// The database is the whole data.Database rather than the one-method port `migrate` takes:
// recovery is several writes across the users, user_permissions and user_sessions tables beside
// the revocation sweep, and a port that narrowed them would name the whole interface again
// (#438).
func runRecover(ctx context.Context, database data.Database, auditLogger revocation.AuditLogger,
	inv recoverInvocation, stdout, stderr io.Writer) int {

	// The address is trimmed and lowercased for the same reason the credential paths do it
	// before GetUserByEmail: every write path stores one, and the engine-fold check in that
	// read refuses an address that differs in anything the engine resolved away.
	email := strings.ToLower(strings.TrimSpace(inv.email))

	user, err := database.GetUserByEmail(ctx, nil, email)
	if err != nil {
		outf(stderr, "unable to read the user: %+v\n", err)
		return migrateExitError
	}
	if user == nil {
		outf(stderr, "refusing to recover: no user holds the address %s\n", inv.email)
		return migrateExitError
	}
	if !user.Enabled {
		outf(stderr, "refusing to recover: the user holding %s is disabled; enable the user "+
			"first, in the admin console or through the Admin API\n", inv.email)
		return migrateExitError
	}

	// One action at least: a recovery that does nothing is a typo wearing the command's
	// authority, and the usage says what the flags are.
	if !inv.grantManage && inv.password == "" && !inv.removeOTP {
		outf(stderr, "nothing to do: give at least one of --grant-manage, --password or "+
			"--remove-otp\n\n%s\n", recoverUsage)
		return migrateExitUsage
	}

	// The manage permission's id is read before the transaction, as the Admin API reads the
	// user before its writes: the permission row it names is seeded with the instance and
	// changes with a migration, not with a concurrent request. A user already holding it is
	// the one case the command must not write, so it is read here rather than caught on the
	// primary key inside the transaction.
	var managePermissionId int64
	var manageHeld bool
	if inv.grantManage {
		resource, resourceErr := database.GetResourceByResourceIdentifier(ctx, nil,
			builtin.AuthServerResourceIdentifier)
		if resourceErr != nil {
			outf(stderr, "unable to read the auth server resource: %+v\n", resourceErr)
			return migrateExitError
		}
		if resource == nil {
			outf(stderr, "refusing to recover: the database holds no %s resource, so there is no "+
				"%s permission to grant\n",
				builtin.AuthServerResourceIdentifier, builtin.ManagePermissionIdentifier)
			return migrateExitError
		}
		permissions, permissionErr := database.GetPermissionsByResourceId(ctx, nil, resource.Id)
		if permissionErr != nil {
			outf(stderr, "unable to read the resource's permissions: %+v\n", permissionErr)
			return migrateExitError
		}
		for _, permission := range permissions {
			if permission.PermissionIdentifier == builtin.ManagePermissionIdentifier {
				managePermissionId = permission.Id
				break
			}
		}
		if managePermissionId == 0 {
			outf(stderr, "refusing to recover: the %s resource holds no %s permission\n",
				builtin.AuthServerResourceIdentifier, builtin.ManagePermissionIdentifier)
			return migrateExitError
		}
		grants, grantsErr := database.GetUserPermissionsByUserId(ctx, nil, user.Id)
		if grantsErr != nil {
			outf(stderr, "unable to read the user's permissions: %+v\n", grantsErr)
			return migrateExitError
		}
		for _, grant := range grants {
			if grant.PermissionId == managePermissionId {
				manageHeld = true
				break
			}
		}
	}

	// A password is held to the stored policy, as the Admin API holds one: the database
	// credentials are the command's authority over WHO signs in, not a licence to weaken what
	// a password must look like, and the deployment's rule is the one every form applies
	// (#550 names the rule this follows).
	var passwordHash string
	if inv.password != "" {
		settings, settingsErr := database.GetSettingsById(ctx, nil, 1)
		if settingsErr != nil {
			outf(stderr, "unable to read the settings: %+v\n", settingsErr)
			return migrateExitError
		}
		if settings == nil {
			outf(stderr, "refusing to recover: the database holds no settings row, so there is "+
				"no password policy to hold the new password to\n")
			return migrateExitError
		}
		validationErr := accountvalidation.NewPasswordValidator().
			ValidatePassword(settings.PasswordPolicy, inv.password)
		if validationErr != nil {
			outf(stderr, "the password is refused by the stored password policy: %v\n", validationErr)
			return migrateExitError
		}
		passwordHash, err = passwordhash.Hash(inv.password)
		if err != nil {
			outf(stderr, "unable to hash the password: %+v\n", err)
			return migrateExitError
		}
	}

	// One transaction holds every write the flags asked for and the revocation sweep, which is
	// what the Admin API's password change does through the same helper: the sweep's
	// generation advance is what ends the user's sessions, refresh tokens included, so a
	// recovered user signs in with nothing issued before the recovery still standing (#106,
	// #498). The body is safe to rerun on a deadlock, for the reason RevokeUserAuthStateTx
	// gives: each write is a compare-and-set, an idempotent column write or an insert whose
	// absence was just read, and the booleans are whatever the committing attempt produced
	// (#301).
	var removedOTP, grantedManage bool
	result, err := revocation.RevokeUserAuthStateTx(ctx, database, user.Id, "", func(tx *sql.Tx) error {
		if inv.password != "" {
			if writeErr := database.SetUserPasswordHash(ctx, tx, user.Id, passwordHash); writeErr != nil {
				return writeErr
			}
		}
		if inv.removeOTP {
			var removeErr error
			removedOTP, removeErr = otpcredential.RemoveTx(ctx, database, tx, user)
			if removeErr != nil {
				return removeErr
			}
		}
		if inv.grantManage && !manageHeld {
			grantedManage = true
			return database.CreateUserPermission(ctx, tx, &record.UserPermission{
				UserId:       user.Id,
				PermissionId: managePermissionId,
			})
		}
		return nil
	})
	if err != nil {
		outf(stderr, "unable to recover the user: %+v\n", err)
		return migrateExitError
	}

	// The audit events, after the commit, as every revocation site writes them: a record of a
	// rollback is a false record (#106 decision 5). Each names the command as the actor.
	if inv.password != "" || inv.removeOTP {
		auditLogger.Log(ctx, audit.EventUpdatedUserAuthentication, map[string]interface{}{
			"user_id": user.Id,
			"command": recoverActor,
		})
	}
	if grantedManage {
		auditLogger.Log(ctx, audit.EventAddedUserPermission, map[string]interface{}{
			"user_id": user.Id,
			"command": recoverActor,
		})
	}
	revocation.LogRevokedUserAuthState(ctx, auditLogger, user.Id, revocation.ReasonRecoveryCommand,
		recoverActor, result)

	outf(stdout, "recovered %s (user %d)\n", email, user.Id)
	if inv.password != "" {
		outf(stdout, "  password set\n")
	}
	if inv.removeOTP {
		if removedOTP {
			outf(stdout, "  otp authenticator removed\n")
		} else {
			outf(stdout, "  no otp authenticator was enrolled, so nothing was removed\n")
		}
	}
	if inv.grantManage {
		if grantedManage {
			outf(stdout, "  %s:%s granted\n",
				builtin.AuthServerResourceIdentifier, builtin.ManagePermissionIdentifier)
		} else {
			outf(stdout, "  %s:%s was already held, so nothing was granted\n",
				builtin.AuthServerResourceIdentifier, builtin.ManagePermissionIdentifier)
		}
	}
	outf(stdout, "  sessions ended: %d, refresh tokens revoked: %d, authentication generation %d to %d\n",
		len(result.TerminatedSessionIdentifiers), len(result.RevokedRefreshTokenJtis),
		result.OldGeneration, result.NewGeneration)
	return migrateExitOK
}
