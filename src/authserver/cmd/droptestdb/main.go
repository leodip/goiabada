// Command droptestdb drops the database the test tier about to run will use, so the tier starts
// from an empty one. The auth server, or the data tier's TestMain, then recreates it and replays
// every migration, and the integration server seeds it, exactly as on CI, whose database servers
// are fresh service containers on every job.
//
//	cd src/authserver && go run ./cmd/droptestdb
//
// run-tests.sh runs it after configuring each mysql, postgres or mssql run, and it reads the same
// GOIABADA_DB_* variables the server and both tiers read. Before it, goiabada_data and
// goiabada_integration were created once and reused by every local run, so whatever a run left
// behind was the next run's starting state: rows a test leaked, which is why
// fixture_email_lint_test.go exists, and a migration applied and then abandoned, which the next
// run's migrator skipped. SQLite has no server to drop from; run-tests.sh removes its file.
//
// It refuses every name but those two, because the variables it reads are the same ones that
// reach the dev container's own database, goiabada (#433).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data/mssqldb"
	"github.com/leodip/goiabada/authserver/internal/data/mysqldb"
	"github.com/leodip/goiabada/authserver/internal/data/postgresdb"
	"github.com/leodip/goiabada/core/errs"
)

// disposableDatabases are the only databases this command drops: the two run-tests.sh names.
var disposableDatabases = map[string]bool{
	"goiabada_data":        true,
	"goiabada_integration": true,
}

// dropByEngine is the one database call per engine, a variable so a test can stand in for the
// servers.
var dropByEngine = map[string]func(ctx context.Context, cfg *config.DatabaseConfig) error{
	"mysql": func(ctx context.Context, cfg *config.DatabaseConfig) error {
		return mysqldb.DropDatabase(ctx, &mysqldb.DatabaseConfig{
			Type: cfg.Type, Username: cfg.Username, Password: cfg.Password,
			Host: cfg.Host, Port: cfg.Port, Name: cfg.Name,
		})
	},
	"postgres": func(ctx context.Context, cfg *config.DatabaseConfig) error {
		return postgresdb.DropDatabase(ctx, &postgresdb.DatabaseConfig{
			Type: cfg.Type, Username: cfg.Username, Password: cfg.Password,
			Host: cfg.Host, Port: cfg.Port, Name: cfg.Name,
		})
	},
	"mssql": func(ctx context.Context, cfg *config.DatabaseConfig) error {
		return mssqldb.DropDatabase(ctx, &mssqldb.DatabaseConfig{
			Type: cfg.Type, Username: cfg.Username, Password: cfg.Password,
			Host: cfg.Host, Port: cfg.Port, Name: cfg.Name,
		})
	},
}

func main() {
	// A malformed variable is refused as the server refuses it, with exit 2: the command reads
	// the server's own configuration, so it answers to the same rule (#434).
	cfg, err := config.Load(flag.CommandLine, os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "droptestdb: %v\n", err)
		os.Exit(2)
	}

	// The command owns this root: nothing above it is waiting, and a stuck server fails the
	// tier's own timeout.
	if err := run(context.Background(), &cfg.Database); err != nil {
		fmt.Fprintf(os.Stderr, "droptestdb: %v\n", err)
		os.Exit(1)
	}
}

// run refuses a name outside disposableDatabases and an engine with no server before it reaches
// any database, then drops the one cfg names.
func run(ctx context.Context, cfg *config.DatabaseConfig) error {
	if !disposableDatabases[cfg.Name] {
		return errs.Errorf("refusing to drop %q: only goiabada_data and goiabada_integration are disposable", cfg.Name)
	}
	drop, ok := dropByEngine[cfg.Type]
	if !ok {
		return errs.Errorf("refusing to drop a %q database: only mysql, postgres and mssql have a server to drop it from", cfg.Type)
	}
	if err := drop(ctx, cfg); err != nil {
		return errs.Wrapf(err, "unable to drop %s on %s", cfg.Name, cfg.Type)
	}
	fmt.Printf("droptestdb: dropped %s on %s\n", cfg.Name, cfg.Type)
	return nil
}
