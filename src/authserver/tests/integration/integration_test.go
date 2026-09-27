package integrationtests

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

func TestMain(m *testing.M) {
	slog.Info("running TestMain")

	config.Init()

	// The data cipher must be initialized before opening the database (its
	// re-encryption migration) and before any test helper encrypts secrets.
	if err := encryption.InitDataCipher(config.GetAESEncryptionKey()); err != nil {
		slog.Error("unable to initialize the data cipher", "error", err)
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

	// Run the tests
	code := m.Run()

	if code != 0 {
		os.Exit(code)
	}
}
