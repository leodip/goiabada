package integrationtests

import (
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/i18n"
)

var database data.Database

func TestMain(m *testing.M) {
	slog.Info("running TestMain")

	config.Init()

	// The running server answers a refused request from the message catalog, and
	// TestCsrf_MiddlewareIsRegistered asserts the entry rather than repeating the
	// sentence. Without a bundle in this process i18n.T echoes the key, and that
	// assertion would compare a message against a key name.
	if _, err := i18n.LoadBundle(); err != nil {
		slog.Error("failed to load the message bundle: " + err.Error())
		os.Exit(1)
	}

	// The data cipher must be initialized before opening the database (its
	// re-encryption migration) and before any test helper encrypts secrets.
	if err := encryption.InitDataCipher(config.GetAESEncryptionKey()); err != nil {
		slog.Error("failed to init data cipher: " + err.Error())
		os.Exit(1)
	}

	if config.GetDatabase().Type == "mysql" {
		slog.Info("config.DBUsername=" + config.GetDatabase().Username)
		slog.Info("config.DBPassword=" + config.GetDatabase().Password)
		slog.Info("config.DBHost=" + config.GetDatabase().Host)
		slog.Info("config.DBPort=" + fmt.Sprintf("%d", config.GetDatabase().Port))
		slog.Info("config.DBName=" + config.GetDatabase().Name)
	} else if config.GetDatabase().Type == "sqlite" {
		slog.Info("config.DBDSN=" + config.GetDatabase().DSN)
	}

	var err error
	database, err = data.NewDatabase(config.GetDatabase(), false)
	if err != nil {
		panic(err)
	}

	// configure mailpit
	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		slog.Error(fmt.Sprintf("%+v", err))
		os.Exit(1)
	}
	settings.SMTPHost = "mailpit"
	settings.SMTPPort = 1025
	settings.SMTPFromName = "Goiabada"
	settings.SMTPFromEmail = "noreply@goiabada.dev"

	err = database.UpdateSettings(nil, settings)
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
