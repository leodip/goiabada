package integrationtests

import (
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data"
)

func TestMain(m *testing.M) {
	slog.Info("running TestMain")

	config.Init()

	if config.DBType == "mysql" {
		slog.Info("config.DBUsername=" + config.DBUsername)
		slog.Info("config.DBPassword=" + config.DBPassword)
		slog.Info("config.DBHost=" + config.DBHost)
		slog.Info("config.DBPort=" + fmt.Sprintf("%d", config.DBPort))
		slog.Info("config.DBName=" + config.DBName)
	} else if config.DBType == "sqlite" {
		slog.Info("config.DBDSN=" + config.DBDSN)
	}

	var err error
	database, err = data.NewDatabase()
	if err != nil {
		panic(err)
	}

	err = seedTestData(database)
	if err != nil {
		slog.Error(fmt.Sprintf("%+v", err))
		os.Exit(1)
	}

	// configure mailhog
	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		slog.Error(fmt.Sprintf("%+v", err))
		os.Exit(1)
	}
	settings.SMTPHost = "mailhog"
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
