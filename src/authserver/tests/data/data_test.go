package datatests

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
	database, err = data.NewDatabase()
	if err != nil {
		slog.Error("failed to initialize database", "error", err)
		os.Exit(1)
	}

	// Run tests
	code := m.Run()
	os.Exit(code)
}
