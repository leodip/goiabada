package data

import (
	"fmt"
	slogGorm "github.com/orandin/slog-gorm"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"log/slog"
)

func NewSqliteDatabase() (*Database, error) {
	// connection string without the database name
	dsn := viper.GetString("DB.DSN")
	if dsn == "" {
		dsn = "file::memory:?cache=shared" // Default to in-memory database
	}

	slog.Info(fmt.Sprintf("using sqlite database: %v", dsn))

	gormTraceAll := viper.GetBool("Logger.Gorm.TraceAll")
	slog.Info(fmt.Sprintf("gorm trace all: %v", gormTraceAll))

	var gormLogger logger.Interface
	if gormTraceAll {
		gormLogger = slogGorm.New(slogGorm.WithLogger(slog.Default()), slogGorm.WithTraceAll())
	} else {
		gormLogger = slogGorm.New(slogGorm.WithLogger(slog.Default()))
	}

	gormDB, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger:                                   gormLogger,
		DisableForeignKeyConstraintWhenMigrating: false,
		SkipDefaultTransaction:                   true,
	})
	if err != nil {
		return nil, errors.Wrap(err, "unable to open database")
	}

	var database = &Database{
		DB: gormDB,
	}

	err = database.migrate()
	if err != nil {
		return nil, err
	}

	err = database.seed()
	if err != nil {
		return nil, err
	}

	return database, nil

}

/*
export GOIABADA_ADMIN_EMAIL="admin@example.com"
export GOIABADA_ADMIN_PASSWORD="changeme"
export GOIABADA_APPNAME="Goiabada"
export GOIABADA_HOST=
export GOIABADA_PORT="8080"
export GOIABADA_TEMPLATEDIR="./web/template"
export GOIABADA_STATICDIR="./web/static"
export GOIABADA_ISBEHINDAREVERSEPROXY="false"
export GOIABADA_DB_TYPE="sqlite"
export GOIABADA_DB_HOST="localhost"
export GOIABADA_DB_PORT="3306"
export GOIABADA_DB_DBNAME="goiabada"
export GOIABADA_DB_USERNAME="root"
export GOIABADA_DB_PASSWORD="Passw0rd"
export GOIABADA_ISSUER="http://localhost:8080"
export GOIABADA_BASEURL="http://localhost:8080"
export GOIABADA_CERTFILE=
export GOIABADA_KEYFILE=
export GOIABADA_LOGGER_GORM_TRACEALL="false"
export GOIABADA_LOGGER_ROUTER_HTTPREQUESTS_ENABLED="true"
export GOIABADA_AUDITING_CONSOLELOG_ENABLED="true"
*/
