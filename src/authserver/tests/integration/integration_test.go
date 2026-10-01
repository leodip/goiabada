package integration

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/datafactory"
	"github.com/leodip/goiabada/authserver/internal/encryption"
)

var database data.Database

// appConfig is the configuration the server under test was started with, loaded from the same
// environment in TestMain; no package-level configuration is left to read (#434).
var appConfig *config.Config

// dataCipher is the cipher under the configured data key, the one the server under test holds, built
// once in TestMain and used by every test that seals or opens a stored secret (#434).
var dataCipher *encryption.DataCipher

func TestMain(m *testing.M) {
	slog.Info("running TestMain")

	var loadErr error
	appConfig, loadErr = config.Load(flag.NewFlagSet("integration", flag.ContinueOnError), nil)
	if loadErr != nil {
		slog.Error("unable to load the configuration", "error", loadErr)
		os.Exit(1)
	}
	dataKey, previousDataKey, keysErr := appConfig.DataKeys()
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

	dialect, dialectErr := data.ParseDialect(appConfig.Database.Type)
	if dialectErr != nil {
		slog.Error("unable to parse the database type", "error", dialectErr)
		os.Exit(1)
	}
	switch dialect {
	case data.MySQL:
		slog.Info("config.DBUsername=" + appConfig.Database.Username)
		slog.Info("config.DBHost=" + appConfig.Database.Host)
		slog.Info("config.DBPort=" + fmt.Sprintf("%d", appConfig.Database.Port))
		slog.Info("config.DBName=" + appConfig.Database.Name)
	case data.SQLite:
		slog.Info("config.DBDSN=" + appConfig.Database.DSN)
	}

	var err error
	database, err = datafactory.NewDatabase(context.Background(), &appConfig.Database,
		dataKey, previousDataKey, false)
	if err != nil {
		panic(err)
	}

	// configure mailpit
	settings, err := database.GetSettingsById(context.Background(), nil, 1)
	if err != nil {
		slog.Error(fmt.Sprintf("%+v", err))
		os.Exit(1)
	}
	settings.SMTPHost = "mailpit"
	settings.SMTPPort = 1025
	settings.SMTPFromName = "Goiabada"
	settings.SMTPFromEmail = "noreply@goiabada.dev"

	err = database.UpdateSettings(context.Background(), nil, settings)
	if err != nil {
		slog.Error(fmt.Sprintf("%+v", err))
		os.Exit(1)
	}

	// Every test that changes the settings row puts it back (see restoreSettings), and this holds
	// the tier to that: a run that ends with the row different from how it began fails, naming each
	// field, whatever the tests themselves reported.
	atStart, err := database.GetSettingsById(context.Background(), nil, 1)
	if err != nil {
		slog.Error(fmt.Sprintf("%+v", err))
		os.Exit(1)
	}

	// Run the tests
	code := m.Run()

	atEnd, err := database.GetSettingsById(context.Background(), nil, 1)
	if err != nil {
		slog.Error(fmt.Sprintf("%+v", err))
		os.Exit(1)
	}
	if changes := settingsChanges(atStart, atEnd); len(changes) > 0 {
		fmt.Fprintln(os.Stderr, "FAIL: the run left the settings row changed; a test that changes it "+
			"must call restoreSettings or changeSettings first:")
		for _, change := range changes {
			fmt.Fprintln(os.Stderr, "    "+change)
		}
		if code == 0 {
			code = 1
		}
	}

	if code != 0 {
		os.Exit(code)
	}
}
