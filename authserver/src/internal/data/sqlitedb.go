package data

import (
	"fmt"
	"log/slog"

	"github.com/glebarez/sqlite"
	slogGorm "github.com/orandin/slog-gorm"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func NewSqliteDatabase() (*Database, error) {
	// connection string without the database name
	dsn := viper.GetString("DB.DSN")
	slog.Warn(fmt.Sprintf("dsn: %v", dsn))
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
