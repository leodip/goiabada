package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// The `reencrypt` subcommand is the step of a data key rotation that moves every stored secret to
// the current key while the auth servers go on serving (#492 decisions 3, 5 and 8). This file reads
// its arguments and keys, opens the database, checks the schema and prints what happened; the
// sweep itself is the data layer's ReencryptStoredSecrets, which the data tier runs on every
// engine.

// reencryptUsage is printed for every malformed invocation, and is the only place the subcommand's
// flags are spelled out.
const reencryptUsage = `usage:
  goiabada-authserver reencrypt [--db-* flags]

reencrypt moves every stored secret to the data key in GOIABADA_AES_ENCRYPTION_KEY: each value
still sealed under GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS is sealed again under the current key, one
value at a time, while the auth servers go on serving. Run it once every auth server runs with the
new key as GOIABADA_AES_ENCRYPTION_KEY and the old one as GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS, and
remove the previous key only after it exits 0. With no previous key set, it re-encrypts nothing and
checks that every stored secret opens under the current key.

It prints how many stored secrets it re-encrypted and how many were already under the current key,
and names on stderr, by table, column and row id, each value neither key opens, which it leaves as
it is. A run that re-encrypted anything records a reencrypted_stored_secrets audit event. It exits 0
when every stored secret is under the current key, 1 when any is not or the run failed, and 2 for a
malformed invocation. A stop signal ends it between values; run it again to carry on. A database
whose schema is not the one this binary carries is refused.

Connection details come from the GOIABADA_DB_* environment variables or the --db-* flags
(--db-type, --db-username, --db-password, --db-host, --db-port, --db-name, --db-dsn, --db-create,
the pool's --db-max-open-conns, --db-max-idle-conns, --db-conn-max-lifetime and
--db-conn-max-idle-time, and the connection's --db-tls-mode, --db-tls-ca-file,
--db-tls-client-cert-file, --db-tls-client-key-file and --db-tls-server-name), given before or
after reencrypt. A flag after reencrypt overrides the same flag before it. Every other flag goes
before reencrypt.

On MySQL, PostgreSQL and SQL Server, reencrypt reads --db-create and GOIABADA_DB_CREATE as false,
so a database that does not exist is refused as missing. SQLite follows its DSN, which creates a
missing file unless it is a file: URI with mode=rw.`

// reencryptActor names the command as the actor of the event it records, under the key recover's
// records use, `command`.
const reencryptActor = "goiabada-authserver reencrypt"

// reencryptStopAnswers are the lines the command answers stop signals with as they arrive: no
// further value is re-encrypted. Each value's write is a transaction of its own, so a stop leaves
// no value half written: the write in flight is counted when it commits, and rolled back when the
// stop ends its statement, a wait for a row lock included.
var reencryptStopAnswers = stopAnswers{
	first:   "stopping: no further stored secret will be re-encrypted",
	further: "still stopping: a further Ctrl-C changes nothing",
}

// reencryptInvocation is what parseReencryptArgs made of the arguments after `reencrypt`.
type reencryptInvocation struct {
	database config.DatabaseConfig // base, with every --db-* flag given after `reencrypt` applied
	help     bool                  // -h or --help was given
}

// parseReencryptArgs reads the arguments after `reencrypt`: the --db-* flags anywhere among them
// and no positional argument at all. A flag overrides the same flag in db, which is a copy, so the
// loaded configuration is untouched. The scan is walkFlagTokens, the one migrate and recover use.
func parseReencryptArgs(args []string, db config.DatabaseConfig) (reencryptInvocation, error) {
	fs := flag.NewFlagSet("reencrypt", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	config.RegisterDatabaseFlags(fs, &db)

	positionals, help, err := walkFlagTokens(fs, "reencrypt",
		"only the --db-* flags can follow reencrypt, so give any other flag before it", args)
	if err != nil {
		return reencryptInvocation{}, err
	}
	if len(positionals) > 0 {
		return reencryptInvocation{}, errs.Errorf("%q is not an argument reencrypt takes: it takes "+
			"only the --db-* flags", positionals[0])
	}
	// The pool's ranges and the TLS mode are held here as Load holds them (#394 decision 5, #502).
	if err := config.CheckDatabaseFlags(fs, &db); err != nil {
		return reencryptInvocation{}, err
	}
	return reencryptInvocation{database: db, help: help}, nil
}

// readReencryptCommand reads the arguments after `reencrypt` into the invocation it runs, or writes
// the refusal to stderr and answers false, for an exit with migrateExitUsage. main calls it before
// the start's first record, so a refusal is the only thing on stderr, as migrate's and recover's
// are (#502).
func readReencryptCommand(args []string, base config.DatabaseConfig, stderr io.Writer) (reencryptInvocation, bool) {
	inv, err := parseReencryptArgs(args, base)
	if err != nil {
		outf(stderr, "%v\n\n%s\n", err, reencryptUsage)
		return reencryptInvocation{}, false
	}
	if tlsErr := config.CheckDatabaseTLS(&inv.database); tlsErr != nil {
		outf(stderr, "%v\n", tlsErr)
		return reencryptInvocation{}, false
	}
	return inv, true
}

// reencryptDataKeys are the data keys the command re-encrypts with, the current one and the
// previous one when it is set, or why the configured keys give none.
type reencryptDataKeys struct {
	current, previous []byte
	err               error
}

// readReencryptDataKeys reads the data keys from the two variables the server reads, held to the
// rules a start holds them to: a current key that is missing, malformed or the published sample
// key is refused, and the sample key stays usable as the previous key.
func readReencryptDataKeys(cfg *config.Config) reencryptDataKeys {
	current, previous, err := cfg.DataKeys()
	return reencryptDataKeys{current: current, previous: previous, err: err}
}

// runReencryptCommand runs the invocation readReencryptCommand read, opening the database through
// open, with the data keys read from the configuration.
func runReencryptCommand(inv reencryptInvocation, open recoverDatabaseOpener, keys reencryptDataKeys,
	stdout, stderr io.Writer) int {
	if inv.help {
		outf(stdout, "%s\n", reencryptUsage)
		return migrateExitOK
	}
	// The keys are refused before the database is opened, as a start refuses them: nothing is read
	// or written under a key the server would not run with.
	if keys.err != nil {
		outf(stderr, "refusing to re-encrypt: %v\n", keys.err)
		return migrateExitError
	}

	// The command owns the stop signals, so Ctrl-C or a pod's SIGTERM ends it between values: the
	// value being written is a transaction of its own, which commits or does not, and the next does
	// not start.
	// The sweep can be run again from wherever it stopped (#492 decision 4). The signals are
	// migrate's, and so is SIGPIPE's handling, since the acknowledgement is written while the run
	// goes on.
	ctx, stopAnsweringSignals := answerSignalsWith(context.Background(), stdout, reencryptStopAnswers)
	defer stopAnsweringSignals()

	// A re-encryption never creates a server database, for recover's reason: a new database holds
	// no secret, so a mistyped name would leave an empty database behind a refusal saying only that
	// it was never migrated. SQLite reads no such setting: its DSN decides.
	if dialect, dialectErr := data.ParseDialect(inv.database.Type); dialectErr == nil && dialect != data.SQLite {
		slog.InfoContext(ctx, "reencrypt never creates a server database, so it must already exist",
			"setting", "GOIABADA_DB_CREATE", "configured", inv.database.Create)
	}
	inv.database.Create = false
	database, err := open(ctx, &inv.database, false)
	if err != nil {
		if stoppedBySignal(ctx, err) {
			outf(stdout, "stopped by a signal before any stored secret was re-encrypted\n")
			return migrateExitError
		}
		outf(stderr, "unable to open the database: %+v\n", err)
		return migrateExitError
	}
	// Closed when the subcommand ends, which on SQLite checkpoints the WAL the writes left.
	defer func() { _ = database.Close() }()

	m, err := database.NewMigrator(ctx, nil)
	if err != nil {
		if stoppedBySignal(ctx, err) {
			outf(stdout, "stopped by a signal before any stored secret was re-encrypted\n")
			return migrateExitError
		}
		outf(stderr, "unable to prepare the migration runner: %+v\n", err)
		return migrateExitError
	}

	// The audit logger is the server's own, as recover's is, so the audit switches are obeyed.
	return runReencrypt(ctx, database, m,
		audit.NewLogger(database, middleware.NewAuditSwitches(database), middleware.ActingUser{}),
		keys, stdout, stderr)
}

// reencryptDatabase is what runReencrypt asks of the database: the sweep.
type reencryptDatabase interface {
	ReencryptStoredSecrets(ctx context.Context, currentKey, previousKey []byte,
		unreadable func(record.StoredSecret)) (record.Reencryption, error)
}

// reencryptAuditLogger records the event a run that re-encrypted something writes.
type reencryptAuditLogger interface {
	Log(ctx context.Context, auditEvent string, details map[string]interface{})
}

// runReencrypt is the whole of the `reencrypt` subcommand against the opened database: the
// database, its migrator, the audit logger, the data keys and somewhere to print. It answers the
// process exit code, so a test can run it against a database it seeded.
//
// Every value is either re-encrypted, found already under the current key, or reported on stderr
// as unreadable, by table, column and row id, never by its content; the run goes past an
// unreadable value and exits 1 for it (#492 decision 5). A run that re-encrypted at least one value
// records one reencrypted_stored_secrets event as it returns, after a stop or a failure too, since
// the values it wrote stay written (decision 8).
func runReencrypt(ctx context.Context, database reencryptDatabase, m schemaVersionReader,
	auditLogger reencryptAuditLogger, keys reencryptDataKeys, stdout, stderr io.Writer) int {

	// The schema must be the one this binary's data tier reads and writes, as the server's start
	// requires before it serves: the sweep writes into every table holding a secret.
	if refusal := checkCommandSchema(ctx, m, reencryptSchemaWords); refusal != "" {
		outf(stderr, "refusing to re-encrypt: %s\n", refusal)
		return migrateExitError
	}

	// Each unreadable value is named as the sweep reaches it, so a run over a database no key opens
	// prints as it goes and holds no list of every row.
	report, err := database.ReencryptStoredSecrets(ctx, keys.current, keys.previous, func(value record.StoredSecret) {
		outf(stderr, "unreadable: %s.%s, row %d: neither data key opens it, so it was left as it is\n",
			value.Table, value.Column, value.ID)
	})
	if report.Reencrypted > 0 {
		auditLogger.Log(ctx, audit.EventReencryptedStoredSecrets, map[string]interface{}{
			"command":     reencryptActor,
			"reencrypted": report.Reencrypted,
			"unreadable":  report.Unreadable,
		})
	}

	switch {
	case err != nil && stoppedBySignal(ctx, err):
		outf(stdout, "stopped by a signal: stored secrets re-encrypted so far: %d, already under the "+
			"current data key: %d; run the same command again to carry on\n",
			report.Reencrypted, report.AlreadyCurrent)
		return migrateExitError
	case err != nil:
		outf(stderr, "unable to re-encrypt the stored secrets: %v\n", err)
		outf(stderr, "stored secrets re-encrypted before the failure: %d, already under the current "+
			"data key: %d; run the same command again to carry on\n", report.Reencrypted, report.AlreadyCurrent)
		return migrateExitError
	}

	// A previous key absent, or equal to the current one, takes no part: the run was a check.
	if len(keys.previous) == 0 || bytes.Equal(keys.previous, keys.current) {
		outf(stdout, "no previous data key is set, so nothing was re-encrypted; stored secrets under "+
			"the current data key: %d\n", report.AlreadyCurrent)
	} else {
		outf(stdout, "stored secrets re-encrypted to the current data key: %d, already under it: %d\n",
			report.Reencrypted, report.AlreadyCurrent)
	}

	if n := report.Unreadable; n > 0 {
		subject := fmt.Sprintf("%d stored secrets open under neither data key and were left as they are. "+
			"If they were sealed under an older key", n)
		if n == 1 {
			subject = "1 stored secret opens under neither data key and was left as it is. If it was " +
				"sealed under an older key"
		}
		outf(stderr, "%s, set that key as GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS and run reencrypt again\n", subject)
		return migrateExitError
	}
	return migrateExitOK
}

// reencryptSchemaWords is how a schema refusal speaks of the reencrypt command.
var reencryptSchemaWords = schemaWords{
	neverMigrated: "so it holds no stored secret",
	again:         "run reencrypt again",
	newerRelease:  "Run the reencrypt command of that release",
}
