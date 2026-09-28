package datatests

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/datafactory"
	"github.com/leodip/goiabada/authserver/internal/encryption"
)

var database data.Database

// appConfig is this tier's configuration, loaded from the environment in TestMain as the server's
// main loads it; no package-level configuration is left to read (#434).
var appConfig *config.Config

// dataKey and previousDataKey are the data keys appConfig.DataKeys answered, which the database is
// opened with and the re-encryption fixtures hand to their own handles.
var dataKey, previousDataKey []byte

// dataCipher is the cipher under the configured data key, the key the database is opened with, built
// once in TestMain and used by every test that seals or opens a stored secret (#434).
var dataCipher *encryption.DataCipher

// timestampTick separates two writes so their timestamps are guaranteed to
// differ: update tests assert UpdatedAt is strictly after CreatedAt, and the
// audit-log tests need distinct created_at values for a DESC sort to be
// well defined.
//
// Both timestamps are assigned in Go, not by the database, and every engine's
// datetime column keeps at least microsecond precision (sqlite DATETIME, mysql
// datetime(6), postgres timestamp(6), mssql DATETIME2(6)), so a couple of
// milliseconds is three orders of magnitude more separation than required. These
// waits used to be 100ms each, which cost about two seconds per engine across the
// suite for no added certainty.
const timestampTick = 2 * time.Millisecond

func TestMain(m *testing.M) {
	slog.Info("running TestMain")

	var loadErr error
	appConfig, loadErr = config.Load(flag.NewFlagSet("datatests", flag.ContinueOnError), nil)
	if loadErr != nil {
		slog.Error("unable to load the configuration", "error", loadErr)
		os.Exit(1)
	}
	var keysErr error
	dataKey, previousDataKey, keysErr = appConfig.DataKeys()
	if keysErr != nil {
		slog.Error("unable to decode the data keys", "error", keysErr)
		os.Exit(1)
	}

	// The data cipher, under the same key the database is opened with below, for every test that
	// seals or opens a stored secret.
	var cipherErr error
	dataCipher, cipherErr = encryption.NewDataCipher(dataKey)
	if cipherErr != nil {
		slog.Error("unable to initialize the data cipher", "error", cipherErr)
		os.Exit(1)
	}

	// Log database configuration
	dbType := appConfig.Database.Type
	slog.Info(fmt.Sprintf("running data tests for %s", dbType))

	switch dbType {
	case "mysql", "postgres":
		slog.Info("config.DBUsername=" + appConfig.Database.Username)
		slog.Info("config.DBHost=" + appConfig.Database.Host)
		slog.Info("config.DBPort=" + fmt.Sprintf("%d", appConfig.Database.Port))
		slog.Info("config.DBName=" + appConfig.Database.Name)
	case "sqlite":
		slog.Info("config.DBDSN=" + appConfig.Database.DSN)
	}

	// Initialize database
	var err error
	database, err = datafactory.NewDatabase(context.Background(), &appConfig.Database,
		dataKey, previousDataKey, false)
	if err != nil {
		slog.Error("failed to initialize database", "error", err)
		os.Exit(1)
	}

	// Run tests
	code := m.Run()

	// Fixtures built once for the whole package rather than per test cannot register their
	// teardown on a *testing.T, because the T that happened to build one has finished long before
	// the last test using it. The RCSI fixture is the only one, and dropping its database here is
	// what keeps a SQL Server run from leaving one behind on every invocation (#139 stage 8).
	runPackageTeardown()

	os.Exit(code)
}

// packageTeardown holds the cleanups of fixtures that outlive any single test. Append through
// deferPackageTeardown; runPackageTeardown calls them in reverse, the way t.Cleanup would.
var packageTeardown []func()

func deferPackageTeardown(f func()) {
	packageTeardown = append(packageTeardown, f)
}

func runPackageTeardown() {
	for i := len(packageTeardown) - 1; i >= 0; i-- {
		packageTeardown[i]()
	}
}
