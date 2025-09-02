package integrationtests

import (
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/data"
)

var database data.Database

func TestMain(m *testing.M) {
	slog.Info("running TestMain")

	config.Init("AuthServer")

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
