package datav2

import (
	"database/sql"
	"errors"
	"log/slog"

	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/spf13/viper"
)

type Database interface {
	IsGoiabadaSchemaCreated() (bool, error)
	Migrate() error
	CreateClientWithAssociations(tx *sql.Tx, client *entitiesv2.Client, associations []enums.ClientAssociations) (*entitiesv2.Client, error)
	CreateClient(tx *sql.Tx, client *entitiesv2.Client) (*entitiesv2.Client, error)
	CreateClientRedirectURI(tx *sql.Tx, clientId int64, redirectURI *entitiesv2.RedirectURI) (*entitiesv2.RedirectURI, error)
}

func NewDatabase() (Database, error) {

	var database Database

	if dbType := viper.GetString("DB.Type"); dbType == "mysql" {
		var err error
		database, err = NewMySQLDatabase()
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("unsupported database type: " + dbType)
	}

	schemaCreated, err := database.IsGoiabadaSchemaCreated()
	if err != nil {
		return nil, err
	}

	if !schemaCreated {
		slog.Info("database schema is not created, will run migrations")

		err = database.Migrate()
		if err != nil {
			return nil, err
		}

		slog.Info("seed initial data")
		err = seed(database)
		if err != nil {
			return nil, err
		}

	} else {
		slog.Info("database schema already created")
	}

	return database, nil
}
