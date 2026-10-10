// Package bootstrap takes an empty database to a deployment's first state. Run decides from the
// configuration which of the three first-run modes applies and, when one seeds, writes every seed
// row in one transaction. It runs once per start, before the server listens.
//
// It is its own package because the seed is not persistence: it generates keys and secrets, hashes
// a password and writes a credentials file, which is why it left internal/data, and the choice of
// mode is not main's either, since it is decidable and testable without a process (#424).
package bootstrap

import (
	"context"
	"errors"
	"log/slog"
	"os"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/core/errs"
)

// Config is what the first run needs from the configuration. main builds it, so this package reads
// no environment and no global of its own.
type Config struct {
	AdminEmail          string
	AdminPassword       string
	AppName             string
	AuthServerBaseURL   string
	AdminConsoleBaseURL string

	// OAuthClientSecret, when set, selects the single-step mode: goiabada-setup generated the
	// credentials, so the seed stores this secret and startup continues.
	OAuthClientSecret string

	// BootstrapEnvOutFile, when set and OAuthClientSecret is not, selects the legacy two-step
	// mode: the seed generates the credentials, writes them here, and the process exits for the
	// operator to copy them across. CI and run-tests.sh start the server this way (#424
	// decision 2).
	BootstrapEnvOutFile string
}

// Outcome is what the process does after Run.
type Outcome int

const (
	// Refused: the database is empty and neither mode is configured, so the process exits 1. It
	// is the zero value, so an Outcome read beside an ignored error stops the process rather
	// than serving an empty database.
	Refused Outcome = iota
	// Continue: the database was seeded already, or has just been seeded in single-step mode, so
	// startup continues.
	Continue
	// Exit: the two-step bootstrap has written its file, so the process exits 0.
	Exit
)

// runDatabase is Run's port: the emptiness check that chooses whether to seed, and the seed's own.
type runDatabase interface {
	seedDatabase
	IsEmpty(ctx context.Context) (bool, error)
}

// runner carries what Run takes plus the two things its tests replace: the RSA key size, which
// costs about 300ms a key at 4096 bits, and the rename that publishes the bootstrap file, so a
// failure after the commit can be forced. Both are unexported and have no setter, so no production
// caller can change either, as with the rotator's key size.
type runner struct {
	db          runDatabase
	dataCipher  *encryption.DataCipher
	cfg         Config
	keySizeBits int
	rename      func(oldPath, newPath string) error
}

func newRunner(db runDatabase, dataCipher *encryption.DataCipher, cfg Config) *runner {
	return &runner{
		db:          db,
		dataCipher:  dataCipher,
		cfg:         cfg,
		keySizeBits: 4096,
		rename:      os.Rename,
	}
}

// Run seeds an empty database in the mode the configuration selects and answers what the process
// does next. A database already seeded is left alone, and so is one another instance seeds while
// this one is seeding it (seededByAnother). An error means the process exits 1. Every
// error but one means nothing the seed wrote was committed, so the next start, with the cause
// fixed, seeds from the beginning. The exception is a bootstrap file that could not be moved into
// place after the commit: the database is seeded, a restart regenerates nothing, and the error
// names the staged file holding the only copy of the credentials, which the operator moves.
//
// ctx is the start's, and its end is a shutdown signal: it cancels the emptiness check, keeps a
// seed that has not begun from beginning, and leaves one under way to commit (#390 decision 9). A
// start stopped before its seed is answered with an error matching context.Canceled, which is how
// main tells the stop from a failure.
func Run(ctx context.Context, db runDatabase, dataCipher *encryption.DataCipher, cfg Config) (Outcome, error) {
	return newRunner(db, dataCipher, cfg).run(ctx)
}

func (r *runner) run(ctx context.Context) (Outcome, error) {
	isEmpty, err := r.db.IsEmpty(ctx)
	if err != nil {
		return Refused, errs.Wrap(err, "unable to check whether the database is empty")
	}
	if !isEmpty {
		slog.InfoContext(ctx, "database already initialized, proceeding with normal startup")
		return Continue, nil
	}

	// A start asked to stop does not begin the seed, and a seed that has begun commits whatever
	// the stop: it is one transaction, and a seed cut short would only leave the next start to
	// seed again (#390 decision 9).
	if stopErr := ctx.Err(); stopErr != nil {
		return Refused, errs.Wrap(stopErr, "the start was stopped before seeding the database")
	}
	ctx = context.WithoutCancel(ctx)

	slog.InfoContext(ctx, "database is empty, performing initial bootstrap")

	switch {
	case r.cfg.OAuthClientSecret != "":
		slog.InfoContext(ctx, "using single-step setup mode, because an oauth client secret is configured")
		if err := r.seed(ctx, ""); err != nil {
			if r.seededByAnother(ctx, err) {
				return Continue, nil
			}
			return Refused, errs.Wrap(err, "unable to seed the database")
		}
		return Continue, nil

	case r.cfg.BootstrapEnvOutFile != "":
		slog.InfoContext(ctx, "using legacy two-step bootstrap mode")
		if err := r.seed(ctx, r.cfg.BootstrapEnvOutFile); err != nil {
			if r.seededByAnother(ctx, err) {
				return Continue, nil
			}
			return Refused, errs.Wrap(err, "unable to seed the database")
		}
		logBootstrapComplete(ctx, r.cfg.BootstrapEnvOutFile)
		return Exit, nil

	default:
		logInitialSetupRequired(ctx)
		return Refused, nil
	}
}

// seededByAnother answers whether a seed that failed lost the database to another instance seeding
// it at the same time, and if so says so: several replicas starting at once on an empty database
// all find it empty and all seed (#542 decision 2). The engine's unique keys let one commit; every
// other seed's first insert loses on one of them, and its transaction rolls back whole, leaving
// nothing of its own. Such a start then carries on as a start arriving a moment later would, finding
// the database seeded, where it used to exit 1 with a duplicate key and be restarted to find just
// that.
//
// Only a lost unique key counts, and only when the database now reads as seeded: IsEmpty reads the
// settings row, which the winner's transaction writes last, so a database that reads as seeded holds
// all 18 rows. A unique violation on a database that still reads as empty is a fault, not a race,
// and so is a re-check that fails; both are refused with the seed's own error.
//
// A two-step start that lost carries on rather than exiting: it wrote no bootstrap file, its staged
// copy was removed with its rollback, and the credentials are the winner's, in the file the winner
// published.
func (r *runner) seededByAnother(ctx context.Context, seedErr error) bool {
	if !errors.Is(seedErr, data.ErrUniqueViolation) {
		return false
	}
	isEmpty, err := r.db.IsEmpty(ctx)
	if err != nil || isEmpty {
		return false
	}
	slog.InfoContext(ctx, "another instance seeded the database while this one was seeding it, proceeding with normal startup")
	return true
}

// bootstrapCredentialVars are the five values a deployment has to carry over from
// the bootstrap file, three for the admin console and two for the auth server.
//
// One list rather than one per record. Two of this package's records name these
// variables, and before this they were two hand-typed lists in two banners: a
// credential added to the bootstrap file and to one of them would leave an
// operator following the other one short, with a startup failure naming a variable
// they had never been told to set (#320).
var bootstrapCredentialVars = []string{
	"GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET",
	"GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY",
	"GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY",
	"GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY",
	"GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY",
}

// logBootstrapComplete reports the end of the legacy two-step bootstrap.
//
// One record where a 22-line banner used to be. The prose it replaced walked
// through the docker-compose.yml edit twice, once per service; what an operator
// needs from it is the file and the names, and those are the two attributes (#320
// decision 6).
func logBootstrapComplete(ctx context.Context, bootstrapFile string) {
	slog.InfoContext(ctx, "bootstrap complete, so the auth server is exiting: copy every credential from the bootstrap file into the two services' configuration, then restart them",
		"bootstrap_file", bootstrapFile,
		"required", bootstrapCredentialVars)
}

// logInitialSetupRequired reports an empty database with neither bootstrap mode
// configured, which is the one startup failure an operator hits before they have
// any credentials at all.
func logInitialSetupRequired(ctx context.Context) {
	slog.ErrorContext(ctx, "initial setup is required, because the database is empty and neither bootstrap mode is configured",
		"options", []string{
			"run goiabada-setup, which writes a ready-to-use docker-compose.yml carrying every credential",
			"or set GOIABADA_AUTHSERVER_BOOTSTRAP_ENV_OUTFILE, and GOIABADA_ADMIN_PASSWORD to the first administrator's password of at least 15 characters, and restart, then copy the credentials out of the file it writes",
		})
}

// LogCredentialsNotConfigured reports session keys that are missing or malformed on a
// database that is already seeded, in a deployment that configures the legacy two-step
// bootstrap's file. main calls it after Run, where the session keys are validated, for a
// refusal of the current pair alone: a previous pair's is a rotation mistake, and a deployment
// with no bootstrap file has nothing to copy from, so each gets a record of its own there. It
// is here so the variables it names come from the same list as the bootstrap-complete record's.
//
// bootstrap_file is read from the configuration. The banner this replaced printed
// "./bootstrap/bootstrap.env", which was the path the sample compose files used
// rather than this deployment's, so an operator who mounted the file
// somewhere else was sent to look at a path that did not exist (#320).
func LogCredentialsNotConfigured(ctx context.Context, err error, bootstrapFile string) {
	slog.ErrorContext(ctx, "bootstrap credentials are not configured, so the auth server cannot start: copy every credential from the bootstrap file into the two services' configuration, then restart them",
		"error", err,
		"bootstrap_file", bootstrapFile,
		"required", bootstrapCredentialVars)
}
