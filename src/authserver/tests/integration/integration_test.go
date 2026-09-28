package integration

import (
	"context"
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

// dataCipher is the cipher under the configured data key, the one the server under test holds, built
// once in TestMain and used by every test that seals or opens a stored secret (#434).
var dataCipher *encryption.DataCipher

func TestMain(m *testing.M) {
	slog.Info("running TestMain")

	config.Init()

	// The data cipher, under the same key the database is opened with below, for every test that
	// seals or opens a stored secret.
	var cipherErr error
	dataCipher, cipherErr = encryption.NewDataCipher(config.GetAESEncryptionKey())
	if cipherErr != nil {
		slog.Error("unable to initialize the data cipher", "error", cipherErr)
		os.Exit(1)
	}

	if config.GetDatabase().Type == "mysql" {
		slog.Info("config.DBUsername=" + config.GetDatabase().Username)
		slog.Info("config.DBHost=" + config.GetDatabase().Host)
		slog.Info("config.DBPort=" + fmt.Sprintf("%d", config.GetDatabase().Port))
		slog.Info("config.DBName=" + config.GetDatabase().Name)
	} else if config.GetDatabase().Type == "sqlite" {
		slog.Info("config.DBDSN=" + config.GetDatabase().DSN)
	}

	var err error
	database, err = datafactory.NewDatabase(context.Background(), config.GetDatabase(),
		config.GetAESEncryptionKey(), config.GetAESEncryptionKeyPrevious(), false)
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
