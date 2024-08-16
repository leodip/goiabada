package datatests

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data"
)

var testDB *sql.DB
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
	slog.Info("dbType=" + dbType)

	if dbType == "mysql" {
		config.DBUsername = "root"
		config.DBPassword = "abc123"
		config.DBHost = "mysql-server"
		config.DBPort = 3306
		config.DBName = "goiabada_test"

		slog.Info("config.DBUsername=" + config.DBUsername)
		slog.Info("config.DBPassword=" + config.DBPassword)
		slog.Info("config.DBHost=" + config.DBHost)
		slog.Info("config.DBPort=" + fmt.Sprintf("%d", config.DBPort))
		slog.Info("config.DBName=" + config.DBName)
	} else if dbType == "sqlite" {
		config.DBDSN = ":memory:"
		slog.Info("config.DBDSN=" + config.DBDSN)
	}

	var err error
	database, err = data.NewDatabase()
	if err != nil {
		panic(err)
	}

	// Run the tests
	code := m.Run()

	// Close the database connection
	if testDB != nil {
		testDB.Close()
	}

	if code != 0 {
		os.Exit(code)
	}
}
