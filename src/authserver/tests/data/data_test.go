package datatests

import (
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
)

var database data.Database

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

	config.Init()

	// The data cipher must be initialized before opening the database (its
	// re-encryption migration) and before any test encrypts secrets.
	if err := encryption.InitDataCipher(config.GetAESEncryptionKey()); err != nil {
		slog.Error("failed to init data cipher: " + err.Error())
		os.Exit(1)
	}

	// Log database configuration
	dbType := config.GetDatabase().Type
	slog.Info(fmt.Sprintf("running data tests for %s", dbType))

	switch dbType {
	case "mysql", "postgres":
		slog.Info("config.DBUsername=" + config.GetDatabase().Username)
		slog.Info("config.DBPassword=" + config.GetDatabase().Password)
		slog.Info("config.DBHost=" + config.GetDatabase().Host)
		slog.Info("config.DBPort=" + fmt.Sprintf("%d", config.GetDatabase().Port))
		slog.Info("config.DBName=" + config.GetDatabase().Name)
	case "sqlite":
		slog.Info("config.DBDSN=" + config.GetDatabase().DSN)
	}

	// Initialize database
	var err error
	database, err = data.NewDatabase(config.GetDatabase(), false)
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
