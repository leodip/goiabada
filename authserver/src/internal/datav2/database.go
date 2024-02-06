package datav2

import (
	"database/sql"
	"errors"
	"log/slog"

	"github.com/leodip/goiabada/internal/datav2/mysqldb"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/spf13/viper"
)

type Database interface {
	BeginTransaction() (*sql.Tx, error)
	CommitTransaction(tx *sql.Tx) error
	RollbackTransaction(tx *sql.Tx) error
	IsGoiabadaSchemaCreated() (bool, error)
	Migrate() error

	CreateClient(tx *sql.Tx, client *entitiesv2.Client) (*entitiesv2.Client, error)
	CreateClientRedirectURI(tx *sql.Tx, clientId int64, redirectURI *entitiesv2.RedirectURI) (*entitiesv2.RedirectURI, error)
	GetClientById(tx *sql.Tx, clientId int64) (*entitiesv2.Client, error)
	GetClientByClientIdentifier(tx *sql.Tx, clientIdentifier string) (*entitiesv2.Client, error)

	CreateResource(tx *sql.Tx, resource *entitiesv2.Resource) (*entitiesv2.Resource, error)
	GetResourceById(tx *sql.Tx, resourceId int64) (*entitiesv2.Resource, error)

	CreatePermission(tx *sql.Tx, permission *entitiesv2.Permission) (*entitiesv2.Permission, error)
	GetPermissionById(tx *sql.Tx, permissionId int64) (*entitiesv2.Permission, error)

	CreateUser(tx *sql.Tx, user *entitiesv2.User) (*entitiesv2.User, error)
	GetUserById(tx *sql.Tx, userId int64) (*entitiesv2.User, error)
	GetUserByUsername(tx *sql.Tx, username string) (*entitiesv2.User, error)
	GetUserBySubject(tx *sql.Tx, subject string) (*entitiesv2.User, error)
	GetUserByEmail(tx *sql.Tx, email string) (*entitiesv2.User, error)

	CreateUsersPermission(tx *sql.Tx, usersPermissions *entitiesv2.UsersPermissions) (*entitiesv2.UsersPermissions, error)
	GetUsersPermissionsById(tx *sql.Tx, usersPermissionsId int64) (*entitiesv2.UsersPermissions, error)

	CreateKeyPair(tx *sql.Tx, keyPair *entitiesv2.KeyPair) (*entitiesv2.KeyPair, error)
	GetKeyPairById(tx *sql.Tx, keyPairId int64) (*entitiesv2.KeyPair, error)

	CreateSettings(tx *sql.Tx, settings *entitiesv2.Settings) (*entitiesv2.Settings, error)
	GetSettingsById(tx *sql.Tx, settingsId int64) (*entitiesv2.Settings, error)
}

func NewDatabase() (Database, error) {

	var database Database

	if dbType := viper.GetString("DB.Type"); dbType == "mysql" {
		var err error
		database, err = mysqldb.NewMySQLDatabase()
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
