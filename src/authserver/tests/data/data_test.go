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

	// Run tests for MySQL
	runTestsForDatabase("mysql", m)

	// Run tests for SQLite
	runTestsForDatabase("sqlite", m)

	os.Exit(0)
}

func runTestsForDatabase(dbType string, m *testing.M) {
	slog.Info(fmt.Sprintf("running data tests for %s", dbType))

	config.GetDatabase().Type = dbType
	slog.Info("config.DBType=" + dbType)

	if dbType == "mysql" {
		slog.Info("config.DBUsername=" + config.GetDatabase().Username)
		slog.Info("config.DBPassword=" + config.GetDatabase().Password)
		slog.Info("config.DBHost=" + config.GetDatabase().Host)
		slog.Info("config.DBPort=" + fmt.Sprintf("%d", config.GetDatabase().Port))
		slog.Info("config.DBName=" + config.GetDatabase().Name)
	} else if dbType == "sqlite" {
		slog.Info("config.DBDSN=" + config.GetDatabase().DSN)
	}

	var err error
	database, err = data.NewDatabase()
	if err != nil {
		panic(err)
	}

	// Run the tests
	code := m.Run()

	if code != 0 {
		os.Exit(code)
	}
}
