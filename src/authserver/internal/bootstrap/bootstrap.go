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
	"log/slog"
	"os"

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
	// operator to copy them across. The shipped compose files, CI and run-tests.sh all start the
	// server this way (#424 decision 2).
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
	cfg         Config
	keySizeBits int
	rename      func(oldPath, newPath string) error
}

func newRunner(db runDatabase, cfg Config) *runner {
	return &runner{
		db:          db,
		cfg:         cfg,
		keySizeBits: 4096,
		rename:      os.Rename,
	}
}

// Run seeds an empty database in the mode the configuration selects and answers what the process
// does next. A database already seeded is left alone. An error means the process exits 1: nothing
// the seed wrote was committed, so the next start, with the cause fixed, seeds from the beginning.
func Run(ctx context.Context, db runDatabase, cfg Config) (Outcome, error) {
	return newRunner(db, cfg).run(ctx)
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

	slog.InfoContext(ctx, "database is empty, performing initial bootstrap")

	switch {
	case r.cfg.OAuthClientSecret != "":
		slog.InfoContext(ctx, "using single-step setup mode, because an oauth client secret is configured")
		if err := r.seed(ctx, ""); err != nil {
			return Refused, errs.Wrap(err, "unable to seed the database")
		}
		return Continue, nil

	case r.cfg.BootstrapEnvOutFile != "":
		slog.InfoContext(ctx, "using legacy two-step bootstrap mode")
		if err := r.seed(ctx, r.cfg.BootstrapEnvOutFile); err != nil {
			return Refused, errs.Wrap(err, "unable to seed the database")
		}
		logBootstrapComplete(ctx, r.cfg.BootstrapEnvOutFile)
		return Exit, nil

	default:
		logInitialSetupRequired(ctx)
		return Refused, nil
	}
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
			"or set GOIABADA_AUTHSERVER_BOOTSTRAP_ENV_OUTFILE and restart, then copy the credentials out of the file it writes",
		})
}

// LogCredentialsNotConfigured reports session keys that are missing or malformed on a
// database that is already seeded. main calls it after Run, where the session keys are
// validated; it is here so the variables it names come from the same list as the
// bootstrap-complete record's.
//
// bootstrap_file is read from the configuration. The banner this replaced printed
// "./bootstrap/bootstrap.env", which is the path the shipped compose files happen
// to use rather than this deployment's, so an operator who mounted the file
// somewhere else was sent to look at a path that did not exist (#320).
func LogCredentialsNotConfigured(ctx context.Context, err error, bootstrapFile string) {
	slog.ErrorContext(ctx, "bootstrap credentials are not configured, so the auth server cannot start: copy every credential from the bootstrap file into the two services' configuration, then restart them",
		"error", err,
		"bootstrap_file", bootstrapFile,
		"required", bootstrapCredentialVars)
}
