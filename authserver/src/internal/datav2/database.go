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

	CreateClient(tx *sql.Tx, client *entitiesv2.Client) error
	UpdateClient(tx *sql.Tx, client *entitiesv2.Client) error
	GetClientById(tx *sql.Tx, clientId int64) (*entitiesv2.Client, error)
	GetClientByClientIdentifier(tx *sql.Tx, clientIdentifier string) (*entitiesv2.Client, error)
	GetAllClients(tx *sql.Tx) ([]*entitiesv2.Client, error)
	DeleteClient(tx *sql.Tx, clientId int64) error

	CreateUser(tx *sql.Tx, user *entitiesv2.User) error
	UpdateUser(tx *sql.Tx, user *entitiesv2.User) error
	GetUserById(tx *sql.Tx, userId int64) (*entitiesv2.User, error)
	GetUserByUsername(tx *sql.Tx, username string) (*entitiesv2.User, error)
	GetUserBySubject(tx *sql.Tx, subject string) (*entitiesv2.User, error)
	GetUserByEmail(tx *sql.Tx, email string) (*entitiesv2.User, error)
	DeleteUser(tx *sql.Tx, userId int64) error

	CreateCode(tx *sql.Tx, code *entitiesv2.Code) error
	UpdateCode(tx *sql.Tx, code *entitiesv2.Code) error
	GetCodeById(tx *sql.Tx, codeId int64) (*entitiesv2.Code, error)
	DeleteCode(tx *sql.Tx, codeId int64) error

	CreateResource(tx *sql.Tx, resource *entitiesv2.Resource) error
	UpdateResource(tx *sql.Tx, resource *entitiesv2.Resource) error
	GetResourceById(tx *sql.Tx, resourceId int64) (*entitiesv2.Resource, error)
	GetResourceByResourceIdentifier(tx *sql.Tx, resourceIdentifier string) (*entitiesv2.Resource, error)
	DeleteResource(tx *sql.Tx, resourceId int64) error

	CreatePermission(tx *sql.Tx, permission *entitiesv2.Permission) error
	UpdatePermission(tx *sql.Tx, permission *entitiesv2.Permission) error
	GetPermissionById(tx *sql.Tx, permissionId int64) (*entitiesv2.Permission, error)
	GetPermissionByPermissionIdentifier(tx *sql.Tx, permissionIdentifier string) (*entitiesv2.Permission, error)
	DeletePermission(tx *sql.Tx, permissionId int64) error

	CreateKeyPair(tx *sql.Tx, keyPair *entitiesv2.KeyPair) error
	UpdateKeyPair(tx *sql.Tx, keyPair *entitiesv2.KeyPair) error
	GetKeyPairById(tx *sql.Tx, keyPairId int64) (*entitiesv2.KeyPair, error)
	DeleteKeyPair(tx *sql.Tx, keyPairId int64) error

	CreateRedirectURI(tx *sql.Tx, redirectURI *entitiesv2.RedirectURI) error
	GetRedirectURIById(tx *sql.Tx, redirectURIId int64) (*entitiesv2.RedirectURI, error)
	DeleteRedirectURI(tx *sql.Tx, redirectURIId int64) error

	CreateSettings(tx *sql.Tx, settings *entitiesv2.Settings) error
	UpdateSettings(tx *sql.Tx, settings *entitiesv2.Settings) error
	GetSettingsById(tx *sql.Tx, settingsId int64) (*entitiesv2.Settings, error)

	CreateUserPermission(tx *sql.Tx, userPermission *entitiesv2.UserPermission) error
	UpdateUserPermission(tx *sql.Tx, userPermission *entitiesv2.UserPermission) error
	GetUserPermissionById(tx *sql.Tx, userPermissionId int64) (*entitiesv2.UserPermission, error)
	DeleteUserPermission(tx *sql.Tx, userPermissionId int64) error

	CreateGroup(tx *sql.Tx, group *entitiesv2.Group) error
	UpdateGroup(tx *sql.Tx, group *entitiesv2.Group) error
	GetGroupById(tx *sql.Tx, groupId int64) (*entitiesv2.Group, error)
	GetGroupByGroupIdentifier(tx *sql.Tx, groupIdentifier string) (*entitiesv2.Group, error)
	GetAllGroups(tx *sql.Tx) ([]*entitiesv2.Group, error)
	GetGroupMembersPaginated(tx *sql.Tx, groupId uint, page int, pageSize int) ([]entitiesv2.User, int, error)
	DeleteGroup(tx *sql.Tx, groupId int64) error

	CreateUserAttribute(tx *sql.Tx, userAttribute *entitiesv2.UserAttribute) error
	UpdateUserAttribute(tx *sql.Tx, userAttribute *entitiesv2.UserAttribute) error
	GetUserAttributeById(tx *sql.Tx, userAttributeId int64) (*entitiesv2.UserAttribute, error)
	DeleteUserAttribute(tx *sql.Tx, userAttributeId int64) error

	CreateClientPermission(tx *sql.Tx, clientPermission *entitiesv2.ClientPermission) error
	UpdateClientPermission(tx *sql.Tx, clientPermission *entitiesv2.ClientPermission) error
	GetClientPermissionById(tx *sql.Tx, clientPermissionId int64) (*entitiesv2.ClientPermission, error)
	DeleteClientPermission(tx *sql.Tx, clientPermissionId int64) error

	CreateUserSession(tx *sql.Tx, userSession *entitiesv2.UserSession) error
	UpdateUserSession(tx *sql.Tx, userSession *entitiesv2.UserSession) error
	GetUserSessionById(tx *sql.Tx, userSessionId int64) (*entitiesv2.UserSession, error)
	GetUserSessionBySessionIdentifier(tx *sql.Tx, sessionIdentifier string) (*entitiesv2.UserSession, error)
	GetUserSessionsByClientIdPaginated(tx *sql.Tx, clientId uint, page int, pageSize int) ([]entitiesv2.UserSession, int, error)
	DeleteUserSession(tx *sql.Tx, userSessionId int64) error

	CreateUserConsent(tx *sql.Tx, userConsent *entitiesv2.UserConsent) error
	UpdateUserConsent(tx *sql.Tx, userConsent *entitiesv2.UserConsent) error
	GetUserConsentById(tx *sql.Tx, userConsentId int64) (*entitiesv2.UserConsent, error)
	GetConsentByUserIdAndClientId(tx *sql.Tx, userId int64, clientId int64) (*entitiesv2.UserConsent, error)
	GetConsentsByUserId(tx *sql.Tx, userId int64) ([]entitiesv2.UserConsent, error)
	DeleteUserConsent(tx *sql.Tx, userConsentId int64) error

	CreatePreRegistration(tx *sql.Tx, preRegistration *entitiesv2.PreRegistration) error
	UpdatePreRegistration(tx *sql.Tx, preRegistration *entitiesv2.PreRegistration) error
	GetPreRegistrationById(tx *sql.Tx, preRegistrationId int64) (*entitiesv2.PreRegistration, error)
	GetPreRegistrationByEmail(tx *sql.Tx, email string) (*entitiesv2.PreRegistration, error)
	DeletePreRegistration(tx *sql.Tx, preRegistrationId int64) error
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
