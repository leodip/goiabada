package data

import (
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/data/mssqldb"
	"github.com/leodip/goiabada/core/data/mysqldb"
	"github.com/leodip/goiabada/core/data/postgresdb"
	"github.com/leodip/goiabada/core/data/sqlitedb"
	"github.com/leodip/goiabada/core/models"
)

type Database interface {
	BeginTransaction() (*sql.Tx, error)
	CommitTransaction(tx *sql.Tx) error
	RollbackTransaction(tx *sql.Tx) error
	Migrate() error
	IsEmpty() (bool, error)

	CreateClient(tx *sql.Tx, client *models.Client) error
	UpdateClient(tx *sql.Tx, client *models.Client) error
	GetClientById(tx *sql.Tx, clientId int64) (*models.Client, error)
	GetClientsByIds(tx *sql.Tx, clientIds []int64) ([]models.Client, error)
	GetClientByClientIdentifier(tx *sql.Tx, clientIdentifier string) (*models.Client, error)
	GetAllClients(tx *sql.Tx) ([]models.Client, error)
	DeleteClient(tx *sql.Tx, clientId int64) error
	ClientLoadRedirectURIs(tx *sql.Tx, client *models.Client) error
	ClientLoadWebOrigins(tx *sql.Tx, client *models.Client) error
	ClientLoadPermissions(tx *sql.Tx, client *models.Client) error

	CreateUser(tx *sql.Tx, user *models.User) error
	UpdateUser(tx *sql.Tx, user *models.User) error
	GetUserById(tx *sql.Tx, userId int64) (*models.User, error)
	GetUsersByIds(tx *sql.Tx, userIds []int64) (map[int64]models.User, error)
	GetUserByUsername(tx *sql.Tx, username string) (*models.User, error)
	GetUserBySubject(tx *sql.Tx, subject string) (*models.User, error)
	GetUserByEmail(tx *sql.Tx, email string) (*models.User, error)
	GetLastUserWithOTPState(tx *sql.Tx, otpEnabledState bool) (*models.User, error)
	SearchUsersPaginated(tx *sql.Tx, query string, page int, pageSize int) ([]models.User, int, error)
	DeleteUser(tx *sql.Tx, userId int64) error
	UserLoadGroups(tx *sql.Tx, user *models.User) error
	UsersLoadGroups(tx *sql.Tx, users []models.User) error
	UserLoadPermissions(tx *sql.Tx, user *models.User) error
	UsersLoadPermissions(tx *sql.Tx, users []models.User) error
	UserLoadAttributes(tx *sql.Tx, user *models.User) error

	CreateCode(tx *sql.Tx, code *models.Code) error
	UpdateCode(tx *sql.Tx, code *models.Code) error
	GetCodeById(tx *sql.Tx, codeId int64) (*models.Code, error)
	GetCodeByCodeHash(tx *sql.Tx, codeHash string, used bool) (*models.Code, error)
	DeleteCode(tx *sql.Tx, codeId int64) error
	CodeLoadClient(tx *sql.Tx, code *models.Code) error
	CodeLoadUser(tx *sql.Tx, code *models.Code) error
	DeleteUsedCodesWithoutRefreshTokens(tx *sql.Tx) error

	CreateResource(tx *sql.Tx, resource *models.Resource) error
	UpdateResource(tx *sql.Tx, resource *models.Resource) error
	GetResourceById(tx *sql.Tx, resourceId int64) (*models.Resource, error)
	GetResourcesByIds(tx *sql.Tx, resourceIds []int64) ([]models.Resource, error)
	GetResourceByResourceIdentifier(tx *sql.Tx, resourceIdentifier string) (*models.Resource, error)
	GetAllResources(tx *sql.Tx) ([]models.Resource, error)
	DeleteResource(tx *sql.Tx, resourceId int64) error

	CreatePermission(tx *sql.Tx, permission *models.Permission) error
	UpdatePermission(tx *sql.Tx, permission *models.Permission) error
	GetPermissionById(tx *sql.Tx, permissionId int64) (*models.Permission, error)
	GetPermissionsByIds(tx *sql.Tx, permissionIds []int64) ([]models.Permission, error)
	GetPermissionsByResourceId(tx *sql.Tx, resourceId int64) ([]models.Permission, error)
	DeletePermission(tx *sql.Tx, permissionId int64) error
	PermissionsLoadResources(tx *sql.Tx, permissions []models.Permission) error

	CreateKeyPair(tx *sql.Tx, keyPair *models.KeyPair) error
	UpdateKeyPair(tx *sql.Tx, keyPair *models.KeyPair) error
	GetKeyPairById(tx *sql.Tx, keyPairId int64) (*models.KeyPair, error)
	GetAllSigningKeys(tx *sql.Tx) ([]models.KeyPair, error)
	GetCurrentSigningKey(tx *sql.Tx) (*models.KeyPair, error)
	DeleteKeyPair(tx *sql.Tx, keyPairId int64) error

	CreateRedirectURI(tx *sql.Tx, redirectURI *models.RedirectURI) error
	GetRedirectURIById(tx *sql.Tx, redirectURIId int64) (*models.RedirectURI, error)
	GetRedirectURIsByClientId(tx *sql.Tx, clientId int64) ([]models.RedirectURI, error)
	DeleteRedirectURI(tx *sql.Tx, redirectURIId int64) error

	CreateWebOrigin(tx *sql.Tx, webOrigin *models.WebOrigin) error
	GetWebOriginById(tx *sql.Tx, webOriginId int64) (*models.WebOrigin, error)
	GetAllWebOrigins(tx *sql.Tx) ([]models.WebOrigin, error)
	GetWebOriginsByClientId(tx *sql.Tx, clientId int64) ([]models.WebOrigin, error)
	DeleteWebOrigin(tx *sql.Tx, webOriginId int64) error

	CreateSettings(tx *sql.Tx, settings *models.Settings) error
	UpdateSettings(tx *sql.Tx, settings *models.Settings) error
	GetSettingsById(tx *sql.Tx, settingsId int64) (*models.Settings, error)

	CreateUserPermission(tx *sql.Tx, userPermission *models.UserPermission) error
	UpdateUserPermission(tx *sql.Tx, userPermission *models.UserPermission) error
	GetUserPermissionById(tx *sql.Tx, userPermissionId int64) (*models.UserPermission, error)
	GetUsersByPermissionIdPaginated(tx *sql.Tx, permissionId int64, page int, pageSize int) ([]models.User, int, error)
	GetUserPermissionByUserIdAndPermissionId(tx *sql.Tx, userId, permissionId int64) (*models.UserPermission, error)
	GetUserPermissionsByUserId(tx *sql.Tx, userId int64) ([]models.UserPermission, error)
	GetUserPermissionsByUserIds(tx *sql.Tx, userIds []int64) ([]models.UserPermission, error)
	DeleteUserPermission(tx *sql.Tx, userPermissionId int64) error

	CreateGroup(tx *sql.Tx, group *models.Group) error
	UpdateGroup(tx *sql.Tx, group *models.Group) error
	GetGroupById(tx *sql.Tx, groupId int64) (*models.Group, error)
	GetGroupByGroupIdentifier(tx *sql.Tx, groupIdentifier string) (*models.Group, error)
	GetGroupsByIds(tx *sql.Tx, groupIds []int64) ([]models.Group, error)
	GetAllGroups(tx *sql.Tx) ([]models.Group, error)
	GetAllGroupsPaginated(tx *sql.Tx, page int, pageSize int) ([]models.Group, int, error)
	GetGroupMembersPaginated(tx *sql.Tx, groupId int64, page int, pageSize int) ([]models.User, int, error)
	CountGroupMembers(tx *sql.Tx, groupId int64) (int, error)
	DeleteGroup(tx *sql.Tx, groupId int64) error
	GroupsLoadAttributes(tx *sql.Tx, groups []models.Group) error
	GroupsLoadPermissions(tx *sql.Tx, groups []models.Group) error
	GroupLoadPermissions(tx *sql.Tx, group *models.Group) error

	CreateUserAttribute(tx *sql.Tx, userAttribute *models.UserAttribute) error
	UpdateUserAttribute(tx *sql.Tx, userAttribute *models.UserAttribute) error
	GetUserAttributeById(tx *sql.Tx, userAttributeId int64) (*models.UserAttribute, error)
	GetUserAttributesByUserId(tx *sql.Tx, userId int64) ([]models.UserAttribute, error)
	DeleteUserAttribute(tx *sql.Tx, userAttributeId int64) error

	CreateClientPermission(tx *sql.Tx, clientPermission *models.ClientPermission) error
	UpdateClientPermission(tx *sql.Tx, clientPermission *models.ClientPermission) error
	GetClientPermissionById(tx *sql.Tx, clientPermissionId int64) (*models.ClientPermission, error)
	GetClientPermissionByClientIdAndPermissionId(tx *sql.Tx, clientId, permissionId int64) (*models.ClientPermission, error)
	GetClientPermissionsByClientId(tx *sql.Tx, clientId int64) ([]models.ClientPermission, error)
	DeleteClientPermission(tx *sql.Tx, clientPermissionId int64) error

	CreateUserSession(tx *sql.Tx, userSession *models.UserSession) error
	UpdateUserSession(tx *sql.Tx, userSession *models.UserSession) error
	GetUserSessionById(tx *sql.Tx, userSessionId int64) (*models.UserSession, error)
	GetUserSessionBySessionIdentifier(tx *sql.Tx, sessionIdentifier string) (*models.UserSession, error)
	GetUserSessionsByClientIdPaginated(tx *sql.Tx, clientId int64, page int, pageSize int) ([]models.UserSession, int, error)
	GetUserSessionsByUserId(tx *sql.Tx, userId int64) ([]models.UserSession, error)
	DeleteUserSession(tx *sql.Tx, userSessionId int64) error
	UserSessionLoadUser(tx *sql.Tx, userSession *models.UserSession) error
	UserSessionsLoadUsers(tx *sql.Tx, userSessions []models.UserSession) error
	UserSessionLoadClients(tx *sql.Tx, userSession *models.UserSession) error
	UserSessionsLoadClients(tx *sql.Tx, userSessions []models.UserSession) error
	DeleteIdleSessions(tx *sql.Tx, idleTimeout time.Duration) error
	DeleteExpiredSessions(tx *sql.Tx, maxLifetime time.Duration) error

	CreateUserConsent(tx *sql.Tx, userConsent *models.UserConsent) error
	UpdateUserConsent(tx *sql.Tx, userConsent *models.UserConsent) error
	GetUserConsentById(tx *sql.Tx, userConsentId int64) (*models.UserConsent, error)
	GetConsentByUserIdAndClientId(tx *sql.Tx, userId int64, clientId int64) (*models.UserConsent, error)
	GetConsentsByUserId(tx *sql.Tx, userId int64) ([]models.UserConsent, error)
	DeleteUserConsent(tx *sql.Tx, userConsentId int64) error
	DeleteAllUserConsent(tx *sql.Tx) error
	UserConsentsLoadClients(tx *sql.Tx, userConsents []models.UserConsent) error

	CreatePreRegistration(tx *sql.Tx, preRegistration *models.PreRegistration) error
	UpdatePreRegistration(tx *sql.Tx, preRegistration *models.PreRegistration) error
	GetPreRegistrationById(tx *sql.Tx, preRegistrationId int64) (*models.PreRegistration, error)
	GetPreRegistrationByEmail(tx *sql.Tx, email string) (*models.PreRegistration, error)
	DeletePreRegistration(tx *sql.Tx, preRegistrationId int64) error

	CreateUserGroup(tx *sql.Tx, userGroup *models.UserGroup) error
	UpdateUserGroup(tx *sql.Tx, userGroup *models.UserGroup) error
	GetUserGroupById(tx *sql.Tx, userGroupId int64) (*models.UserGroup, error)
	GetUserGroupByUserIdAndGroupId(tx *sql.Tx, userId, groupId int64) (*models.UserGroup, error)
	GetUserGroupsByUserId(tx *sql.Tx, userId int64) ([]models.UserGroup, error)
	GetUserGroupsByUserIds(tx *sql.Tx, userIds []int64) ([]models.UserGroup, error)
	DeleteUserGroup(tx *sql.Tx, userGroupId int64) error

	CreateGroupAttribute(tx *sql.Tx, groupAttribute *models.GroupAttribute) error
	UpdateGroupAttribute(tx *sql.Tx, groupAttribute *models.GroupAttribute) error
	GetGroupAttributeById(tx *sql.Tx, groupAttributeId int64) (*models.GroupAttribute, error)
	GetGroupAttributesByGroupId(tx *sql.Tx, groupId int64) ([]models.GroupAttribute, error)
	GetGroupAttributesByGroupIds(tx *sql.Tx, groupIds []int64) ([]models.GroupAttribute, error)
	DeleteGroupAttribute(tx *sql.Tx, groupAttributeId int64) error

	CreateGroupPermission(tx *sql.Tx, groupPermission *models.GroupPermission) error
	UpdateGroupPermission(tx *sql.Tx, groupPermission *models.GroupPermission) error
	GetGroupPermissionById(tx *sql.Tx, groupPermissionId int64) (*models.GroupPermission, error)
	GetGroupPermissionByGroupIdAndPermissionId(tx *sql.Tx, groupId, permissionId int64) (*models.GroupPermission, error)
	GetGroupPermissionsByGroupIds(tx *sql.Tx, groupIds []int64) ([]models.GroupPermission, error)
	GetGroupPermissionsByGroupId(tx *sql.Tx, groupId int64) ([]models.GroupPermission, error)
	DeleteGroupPermission(tx *sql.Tx, groupPermissionId int64) error

	CreateRefreshToken(tx *sql.Tx, refreshToken *models.RefreshToken) error
	UpdateRefreshToken(tx *sql.Tx, refreshToken *models.RefreshToken) error
	GetRefreshTokenById(tx *sql.Tx, refreshTokenId int64) (*models.RefreshToken, error)
	GetRefreshTokenByJti(tx *sql.Tx, jti string) (*models.RefreshToken, error)
	DeleteRefreshToken(tx *sql.Tx, refreshTokenId int64) error
	RefreshTokenLoadCode(tx *sql.Tx, refreshToken *models.RefreshToken) error
	DeleteExpiredOrRevokedRefreshTokens(tx *sql.Tx) error

	CreateUserSessionClient(tx *sql.Tx, userSessionClient *models.UserSessionClient) error
	UpdateUserSessionClient(tx *sql.Tx, userSessionClient *models.UserSessionClient) error
	GetUserSessionClientById(tx *sql.Tx, userSessionClientId int64) (*models.UserSessionClient, error)
	GetUserSessionsClientByIds(tx *sql.Tx, userSessionClientIds []int64) ([]models.UserSessionClient, error)
	GetUserSessionClientsByUserSessionId(tx *sql.Tx, userSessionId int64) ([]models.UserSessionClient, error)
	GetUserSessionClientsByUserSessionIds(tx *sql.Tx, userSessionIds []int64) ([]models.UserSessionClient, error)
	DeleteUserSessionClient(tx *sql.Tx, userSessionClientId int64) error
	UserSessionClientsLoadClients(tx *sql.Tx, userSessionClients []models.UserSessionClient) error

	CreateHttpSession(tx *sql.Tx, httpSession *models.HttpSession) error
	UpdateHttpSession(tx *sql.Tx, httpSession *models.HttpSession) error
	GetHttpSessionById(tx *sql.Tx, httpSessionId int64) (*models.HttpSession, error)
	DeleteHttpSession(tx *sql.Tx, httpSessionId int64) error
	DeleteHttpSessionExpired(tx *sql.Tx) error
}

func NewDatabase(dbConfig *config.DatabaseConfig, logSQL bool) (Database, error) {
	var database Database
	var err error

	// Remove leading and trailing single or double quotes from dbType
	dbType := strings.Trim(dbConfig.Type, "\"'")

	slog.Info("db type is " + dbType)

	switch dbType {
	case "mysql":
		slog.Info("creating mysql database")
		mysqlConfig := &mysqldb.DatabaseConfig{
			Type:     dbConfig.Type,
			Username: dbConfig.Username,
			Password: dbConfig.Password,
			Host:     dbConfig.Host,
			Port:     dbConfig.Port,
			Name:     dbConfig.Name,
			DSN:      dbConfig.DSN,
		}
		database, err = mysqldb.NewMySQLDatabase(mysqlConfig, logSQL)
	case "sqlite":
		slog.Info("creating sqlite database")
		sqliteConfig := &sqlitedb.DatabaseConfig{
			Type:     dbConfig.Type,
			Username: dbConfig.Username,
			Password: dbConfig.Password,
			Host:     dbConfig.Host,
			Port:     dbConfig.Port,
			Name:     dbConfig.Name,
			DSN:      dbConfig.DSN,
		}
		database, err = sqlitedb.NewSQLiteDatabase(sqliteConfig, logSQL)
	case "postgres":
		slog.Info("creating postgres database")
		postgresConfig := &postgresdb.DatabaseConfig{
			Type:     dbConfig.Type,
			Username: dbConfig.Username,
			Password: dbConfig.Password,
			Host:     dbConfig.Host,
			Port:     dbConfig.Port,
			Name:     dbConfig.Name,
			DSN:      dbConfig.DSN,
		}
		database, err = postgresdb.NewPostgresDatabase(postgresConfig, logSQL)
	case "mssql":
		slog.Info("creating mssql database")
		mssqlConfig := &mssqldb.DatabaseConfig{
			Type:     dbConfig.Type,
			Username: dbConfig.Username,
			Password: dbConfig.Password,
			Host:     dbConfig.Host,
			Port:     dbConfig.Port,
			Name:     dbConfig.Name,
			DSN:      dbConfig.DSN,
		}
		database, err = mssqldb.NewMsSQLDatabase(mssqlConfig, logSQL)
	default:
		msg := fmt.Sprintf("unsupported database type: %s (string length %d). supported types are: mysql, sqlite, postgres, mssql", dbType, len(dbType))
		return nil, errors.WithStack(errors.New(msg))
	}

	if err != nil {
		return nil, err
	}

	err = database.Migrate()
	if err != nil {
		return nil, err
	}

	return database, nil
}
