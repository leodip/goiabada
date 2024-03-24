package data

import (
	"database/sql"
	"log/slog"

	"github.com/pkg/errors"

	"github.com/leodip/goiabada/internal/data/mysqldb"
	"github.com/leodip/goiabada/internal/data/sqlitedb"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/spf13/viper"
)

type Database interface {
	BeginTransaction() (*sql.Tx, error)
	CommitTransaction(tx *sql.Tx) error
	RollbackTransaction(tx *sql.Tx) error
	Migrate() error

	CreateClient(tx *sql.Tx, client *entities.Client) error
	UpdateClient(tx *sql.Tx, client *entities.Client) error
	GetClientById(tx *sql.Tx, clientId int64) (*entities.Client, error)
	GetClientsByIds(tx *sql.Tx, clientIds []int64) ([]entities.Client, error)
	GetClientByClientIdentifier(tx *sql.Tx, clientIdentifier string) (*entities.Client, error)
	GetAllClients(tx *sql.Tx) ([]*entities.Client, error)
	DeleteClient(tx *sql.Tx, clientId int64) error
	ClientLoadRedirectURIs(tx *sql.Tx, client *entities.Client) error
	ClientLoadWebOrigins(tx *sql.Tx, client *entities.Client) error
	ClientLoadPermissions(tx *sql.Tx, client *entities.Client) error

	CreateUser(tx *sql.Tx, user *entities.User) error
	UpdateUser(tx *sql.Tx, user *entities.User) error
	GetUserById(tx *sql.Tx, userId int64) (*entities.User, error)
	GetUsersByIds(tx *sql.Tx, userIds []int64) (map[int64]entities.User, error)
	GetUserByUsername(tx *sql.Tx, username string) (*entities.User, error)
	GetUserBySubject(tx *sql.Tx, subject string) (*entities.User, error)
	GetUserByEmail(tx *sql.Tx, email string) (*entities.User, error)
	GetLastUserWithOTPState(tx *sql.Tx, otpEnabledState bool) (*entities.User, error)
	SearchUsersPaginated(tx *sql.Tx, query string, page int, pageSize int) ([]entities.User, int, error)
	DeleteUser(tx *sql.Tx, userId int64) error
	UserLoadGroups(tx *sql.Tx, user *entities.User) error
	UsersLoadGroups(tx *sql.Tx, users []entities.User) error
	UserLoadPermissions(tx *sql.Tx, user *entities.User) error
	UsersLoadPermissions(tx *sql.Tx, users []entities.User) error
	UserLoadAttributes(tx *sql.Tx, user *entities.User) error

	CreateCode(tx *sql.Tx, code *entities.Code) error
	UpdateCode(tx *sql.Tx, code *entities.Code) error
	GetCodeById(tx *sql.Tx, codeId int64) (*entities.Code, error)
	GetCodeByCodeHash(tx *sql.Tx, codeHash string, used bool) (*entities.Code, error)
	DeleteCode(tx *sql.Tx, codeId int64) error
	CodeLoadClient(tx *sql.Tx, code *entities.Code) error
	CodeLoadUser(tx *sql.Tx, code *entities.Code) error

	CreateResource(tx *sql.Tx, resource *entities.Resource) error
	UpdateResource(tx *sql.Tx, resource *entities.Resource) error
	GetResourceById(tx *sql.Tx, resourceId int64) (*entities.Resource, error)
	GetResourcesByIds(tx *sql.Tx, resourceIds []int64) ([]entities.Resource, error)
	GetResourceByResourceIdentifier(tx *sql.Tx, resourceIdentifier string) (*entities.Resource, error)
	GetAllResources(tx *sql.Tx) ([]entities.Resource, error)
	DeleteResource(tx *sql.Tx, resourceId int64) error

	CreatePermission(tx *sql.Tx, permission *entities.Permission) error
	UpdatePermission(tx *sql.Tx, permission *entities.Permission) error
	GetPermissionById(tx *sql.Tx, permissionId int64) (*entities.Permission, error)
	GetPermissionsByIds(tx *sql.Tx, permissionIds []int64) ([]entities.Permission, error)
	GetPermissionsByResourceId(tx *sql.Tx, resourceId int64) ([]entities.Permission, error)
	DeletePermission(tx *sql.Tx, permissionId int64) error
	PermissionsLoadResources(tx *sql.Tx, permissions []entities.Permission) error

	CreateKeyPair(tx *sql.Tx, keyPair *entities.KeyPair) error
	UpdateKeyPair(tx *sql.Tx, keyPair *entities.KeyPair) error
	GetKeyPairById(tx *sql.Tx, keyPairId int64) (*entities.KeyPair, error)
	GetAllSigningKeys(tx *sql.Tx) ([]entities.KeyPair, error)
	GetCurrentSigningKey(tx *sql.Tx) (*entities.KeyPair, error)
	DeleteKeyPair(tx *sql.Tx, keyPairId int64) error

	CreateRedirectURI(tx *sql.Tx, redirectURI *entities.RedirectURI) error
	GetRedirectURIById(tx *sql.Tx, redirectURIId int64) (*entities.RedirectURI, error)
	GetRedirectURIsByClientId(tx *sql.Tx, clientId int64) ([]entities.RedirectURI, error)
	DeleteRedirectURI(tx *sql.Tx, redirectURIId int64) error

	CreateWebOrigin(tx *sql.Tx, webOrigin *entities.WebOrigin) error
	GetWebOriginById(tx *sql.Tx, webOriginId int64) (*entities.WebOrigin, error)
	GetAllWebOrigins(tx *sql.Tx) ([]*entities.WebOrigin, error)
	GetWebOriginsByClientId(tx *sql.Tx, clientId int64) ([]entities.WebOrigin, error)
	DeleteWebOrigin(tx *sql.Tx, webOriginId int64) error

	CreateSettings(tx *sql.Tx, settings *entities.Settings) error
	UpdateSettings(tx *sql.Tx, settings *entities.Settings) error
	GetSettingsById(tx *sql.Tx, settingsId int64) (*entities.Settings, error)

	CreateUserPermission(tx *sql.Tx, userPermission *entities.UserPermission) error
	UpdateUserPermission(tx *sql.Tx, userPermission *entities.UserPermission) error
	GetUserPermissionById(tx *sql.Tx, userPermissionId int64) (*entities.UserPermission, error)
	GetUsersByPermissionIdPaginated(tx *sql.Tx, permissionId int64, page int, pageSize int) ([]entities.User, int, error)
	GetUserPermissionByUserIdAndPermissionId(tx *sql.Tx, userId, permissionId int64) (*entities.UserPermission, error)
	GetUserPermissionsByUserId(tx *sql.Tx, userId int64) ([]entities.UserPermission, error)
	GetUserPermissionsByUserIds(tx *sql.Tx, userIds []int64) ([]entities.UserPermission, error)
	DeleteUserPermission(tx *sql.Tx, userPermissionId int64) error

	CreateGroup(tx *sql.Tx, group *entities.Group) error
	UpdateGroup(tx *sql.Tx, group *entities.Group) error
	GetGroupById(tx *sql.Tx, groupId int64) (*entities.Group, error)
	GetGroupByGroupIdentifier(tx *sql.Tx, groupIdentifier string) (*entities.Group, error)
	GetGroupsByIds(tx *sql.Tx, groupIds []int64) ([]entities.Group, error)
	GetAllGroups(tx *sql.Tx) ([]*entities.Group, error)
	GetAllGroupsPaginated(tx *sql.Tx, page int, pageSize int) ([]entities.Group, int, error)
	GetGroupMembersPaginated(tx *sql.Tx, groupId int64, page int, pageSize int) ([]entities.User, int, error)
	CountGroupMembers(tx *sql.Tx, groupId int64) (int, error)
	DeleteGroup(tx *sql.Tx, groupId int64) error
	GroupsLoadAttributes(tx *sql.Tx, groups []entities.Group) error
	GroupsLoadPermissions(tx *sql.Tx, groups []entities.Group) error
	GroupLoadPermissions(tx *sql.Tx, group *entities.Group) error

	CreateUserAttribute(tx *sql.Tx, userAttribute *entities.UserAttribute) error
	UpdateUserAttribute(tx *sql.Tx, userAttribute *entities.UserAttribute) error
	GetUserAttributeById(tx *sql.Tx, userAttributeId int64) (*entities.UserAttribute, error)
	GetUserAttributesByUserId(tx *sql.Tx, userId int64) ([]entities.UserAttribute, error)
	DeleteUserAttribute(tx *sql.Tx, userAttributeId int64) error

	CreateClientPermission(tx *sql.Tx, clientPermission *entities.ClientPermission) error
	UpdateClientPermission(tx *sql.Tx, clientPermission *entities.ClientPermission) error
	GetClientPermissionById(tx *sql.Tx, clientPermissionId int64) (*entities.ClientPermission, error)
	GetClientPermissionByClientIdAndPermissionId(tx *sql.Tx, clientId, permissionId int64) (*entities.ClientPermission, error)
	GetClientPermissionsByClientId(tx *sql.Tx, clientId int64) ([]entities.ClientPermission, error)
	DeleteClientPermission(tx *sql.Tx, clientPermissionId int64) error

	CreateUserSession(tx *sql.Tx, userSession *entities.UserSession) error
	UpdateUserSession(tx *sql.Tx, userSession *entities.UserSession) error
	GetUserSessionById(tx *sql.Tx, userSessionId int64) (*entities.UserSession, error)
	GetUserSessionBySessionIdentifier(tx *sql.Tx, sessionIdentifier string) (*entities.UserSession, error)
	GetUserSessionsByClientIdPaginated(tx *sql.Tx, clientId int64, page int, pageSize int) ([]entities.UserSession, int, error)
	GetUserSessionsByUserId(tx *sql.Tx, userId int64) ([]entities.UserSession, error)
	DeleteUserSession(tx *sql.Tx, userSessionId int64) error
	UserSessionLoadUser(tx *sql.Tx, userSession *entities.UserSession) error
	UserSessionsLoadUsers(tx *sql.Tx, userSessions []entities.UserSession) error
	UserSessionLoadClients(tx *sql.Tx, userSession *entities.UserSession) error
	UserSessionsLoadClients(tx *sql.Tx, userSessions []entities.UserSession) error

	CreateUserConsent(tx *sql.Tx, userConsent *entities.UserConsent) error
	UpdateUserConsent(tx *sql.Tx, userConsent *entities.UserConsent) error
	GetUserConsentById(tx *sql.Tx, userConsentId int64) (*entities.UserConsent, error)
	GetConsentByUserIdAndClientId(tx *sql.Tx, userId int64, clientId int64) (*entities.UserConsent, error)
	GetConsentsByUserId(tx *sql.Tx, userId int64) ([]entities.UserConsent, error)
	DeleteUserConsent(tx *sql.Tx, userConsentId int64) error
	DeleteAllUserConsent(tx *sql.Tx) error
	UserConsentsLoadClients(tx *sql.Tx, userConsents []entities.UserConsent) error

	CreatePreRegistration(tx *sql.Tx, preRegistration *entities.PreRegistration) error
	UpdatePreRegistration(tx *sql.Tx, preRegistration *entities.PreRegistration) error
	GetPreRegistrationById(tx *sql.Tx, preRegistrationId int64) (*entities.PreRegistration, error)
	GetPreRegistrationByEmail(tx *sql.Tx, email string) (*entities.PreRegistration, error)
	DeletePreRegistration(tx *sql.Tx, preRegistrationId int64) error

	CreateUserGroup(tx *sql.Tx, userGroup *entities.UserGroup) error
	UpdateUserGroup(tx *sql.Tx, userGroup *entities.UserGroup) error
	GetUserGroupById(tx *sql.Tx, userGroupId int64) (*entities.UserGroup, error)
	GetUserGroupByUserIdAndGroupId(tx *sql.Tx, userId, groupId int64) (*entities.UserGroup, error)
	GetUserGroupsByUserId(tx *sql.Tx, userId int64) ([]entities.UserGroup, error)
	GetUserGroupsByUserIds(tx *sql.Tx, userIds []int64) ([]entities.UserGroup, error)
	DeleteUserGroup(tx *sql.Tx, userGroupId int64) error

	CreateGroupAttribute(tx *sql.Tx, groupAttribute *entities.GroupAttribute) error
	UpdateGroupAttribute(tx *sql.Tx, groupAttribute *entities.GroupAttribute) error
	GetGroupAttributeById(tx *sql.Tx, groupAttributeId int64) (*entities.GroupAttribute, error)
	GetGroupAttributesByGroupId(tx *sql.Tx, groupId int64) ([]entities.GroupAttribute, error)
	GetGroupAttributesByGroupIds(tx *sql.Tx, groupIds []int64) ([]entities.GroupAttribute, error)
	DeleteGroupAttribute(tx *sql.Tx, groupAttributeId int64) error

	CreateGroupPermission(tx *sql.Tx, groupPermission *entities.GroupPermission) error
	UpdateGroupPermission(tx *sql.Tx, groupPermission *entities.GroupPermission) error
	GetGroupPermissionById(tx *sql.Tx, groupPermissionId int64) (*entities.GroupPermission, error)
	GetGroupPermissionByGroupIdAndPermissionId(tx *sql.Tx, groupId, permissionId int64) (*entities.GroupPermission, error)
	GetGroupPermissionsByGroupIds(tx *sql.Tx, groupIds []int64) ([]entities.GroupPermission, error)
	GetGroupPermissionsByGroupId(tx *sql.Tx, groupId int64) ([]entities.GroupPermission, error)
	DeleteGroupPermission(tx *sql.Tx, groupPermissionId int64) error

	CreateRefreshToken(tx *sql.Tx, refreshToken *entities.RefreshToken) error
	UpdateRefreshToken(tx *sql.Tx, refreshToken *entities.RefreshToken) error
	GetRefreshTokenById(tx *sql.Tx, refreshTokenId int64) (*entities.RefreshToken, error)
	GetRefreshTokenByJti(tx *sql.Tx, jti string) (*entities.RefreshToken, error)
	DeleteRefreshToken(tx *sql.Tx, refreshTokenId int64) error
	RefreshTokenLoadCode(tx *sql.Tx, refreshToken *entities.RefreshToken) error

	CreateUserSessionClient(tx *sql.Tx, userSessionClient *entities.UserSessionClient) error
	UpdateUserSessionClient(tx *sql.Tx, userSessionClient *entities.UserSessionClient) error
	GetUserSessionClientById(tx *sql.Tx, userSessionClientId int64) (*entities.UserSessionClient, error)
	GetUserSessionsClientByIds(tx *sql.Tx, userSessionClientIds []int64) ([]entities.UserSessionClient, error)
	GetUserSessionClientsByUserSessionId(tx *sql.Tx, userSessionId int64) ([]entities.UserSessionClient, error)
	GetUserSessionClientsByUserSessionIds(tx *sql.Tx, userSessionIds []int64) ([]entities.UserSessionClient, error)
	DeleteUserSessionClient(tx *sql.Tx, userSessionClientId int64) error
	UserSessionClientsLoadClients(tx *sql.Tx, userSessionClients []entities.UserSessionClient) error

	CreateHttpSession(tx *sql.Tx, httpSession *entities.HttpSession) error
	UpdateHttpSession(tx *sql.Tx, httpSession *entities.HttpSession) error
	GetHttpSessionById(tx *sql.Tx, httpSessionId int64) (*entities.HttpSession, error)
	DeleteHttpSession(tx *sql.Tx, httpSessionId int64) error
	DeleteHttpSessionExpired(tx *sql.Tx) error
}

func NewDatabase() (Database, error) {

	var database Database
	var err error

	if dbType := viper.GetString("DB.Type"); dbType == "mysql" {
		database, err = mysqldb.NewMySQLDatabase()
		if err != nil {
			return nil, err
		}
	} else if dbType == "sqlite" {
		database, err = sqlitedb.NewSQLiteDatabase()
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.WithStack(errors.New("unsupported database type: " + dbType))
	}

	err = database.Migrate()
	if err != nil {
		return nil, err
	}

	dbEmpty, err := isDatabaseEmpty(database)
	if err != nil {
		return nil, err
	}

	if dbEmpty {
		slog.Info("seed initial data")
		err = seed(database)
		if err != nil {
			return nil, err
		}

	} else {
		slog.Info("database does not need seeding")
	}

	return database, nil
}

func isDatabaseEmpty(database Database) (bool, error) {
	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		return false, errors.Wrap(err, "unable to check if database is empty")
	}
	return settings == nil, nil
}
