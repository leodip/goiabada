package datatests

import (
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data"
)

var database data.Database

func TestMain(m *testing.M) {
	slog.Info("running TestMain")

	config.Init()

	// Run tests for MySQL
	runTestsForDatabase("mysql", m)

	// Run tests for SQLite
	runTestsForDatabase("sqlite", m)

	os.Exit(0)
}

func runTestsForDatabase(dbType string, m *testing.M) {
	slog.Info(fmt.Sprintf("running tests for %s", dbType))

	config.DBType = dbType
	slog.Info("config.DBType=" + dbType)

	if dbType == "mysql" {
		slog.Info("config.DBUsername=" + config.DBUsername)
		slog.Info("config.DBPassword=" + config.DBPassword)
		slog.Info("config.DBHost=" + config.DBHost)
		slog.Info("config.DBPort=" + fmt.Sprintf("%d", config.DBPort))
		slog.Info("config.DBName=" + config.DBName)
	} else if dbType == "sqlite" {
		slog.Info("config.DBDSN=" + config.DBDSN)
	}

	var err error
	database, err = data.NewDatabase()
	if err != nil {
		panic(err)
	}

	isEmpty, err := database.IsEmpty()
	if err != nil {
		slog.Error(fmt.Sprintf("%+v", err))
		os.Exit(1)
	}

	if isEmpty {
		slog.Info("database is empty, seeding")
		err = database.Seed()
		if err != nil {
			slog.Error(fmt.Sprintf("%+v", err))
			os.Exit(1)
		}
	} else {
		slog.Info("database does not need seeding")
	}

	// Run the tests
	code := m.Run()

	if code != 0 {
		os.Exit(code)
	}
}