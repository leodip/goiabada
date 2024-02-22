package datav2

import (
	"database/sql"
	"log/slog"

	"github.com/pkg/errors"

	"github.com/leodip/goiabada/internal/datav2/mysqldb"
	"github.com/leodip/goiabada/internal/datav2/sqlitedb"
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
	GetClientsByIds(tx *sql.Tx, clientIds []int64) ([]entitiesv2.Client, error)
	GetClientByClientIdentifier(tx *sql.Tx, clientIdentifier string) (*entitiesv2.Client, error)
	GetAllClients(tx *sql.Tx) ([]*entitiesv2.Client, error)
	DeleteClient(tx *sql.Tx, clientId int64) error
	ClientLoadRedirectURIs(tx *sql.Tx, client *entitiesv2.Client) error
	ClientLoadWebOrigins(tx *sql.Tx, client *entitiesv2.Client) error
	ClientLoadPermissions(tx *sql.Tx, client *entitiesv2.Client) error

	CreateUser(tx *sql.Tx, user *entitiesv2.User) error
	UpdateUser(tx *sql.Tx, user *entitiesv2.User) error
	GetUserById(tx *sql.Tx, userId int64) (*entitiesv2.User, error)
	GetUsersByIds(tx *sql.Tx, userIds []int64) (map[int64]entitiesv2.User, error)
	GetUserByUsername(tx *sql.Tx, username string) (*entitiesv2.User, error)
	GetUserBySubject(tx *sql.Tx, subject string) (*entitiesv2.User, error)
	GetUserByEmail(tx *sql.Tx, email string) (*entitiesv2.User, error)
	GetLastUserWithOTPState(tx *sql.Tx, otpEnabledState bool) (*entitiesv2.User, error)
	SearchUsersPaginated(tx *sql.Tx, query string, page int, pageSize int) ([]entitiesv2.User, int, error)
	DeleteUser(tx *sql.Tx, userId int64) error
	UserLoadGroups(tx *sql.Tx, user *entitiesv2.User) error
	UsersLoadGroups(tx *sql.Tx, users []entitiesv2.User) error
	UserLoadPermissions(tx *sql.Tx, user *entitiesv2.User) error
	UsersLoadPermissions(tx *sql.Tx, users []entitiesv2.User) error
	UserLoadAttributes(tx *sql.Tx, user *entitiesv2.User) error

	CreateCode(tx *sql.Tx, code *entitiesv2.Code) error
	UpdateCode(tx *sql.Tx, code *entitiesv2.Code) error
	GetCodeById(tx *sql.Tx, codeId int64) (*entitiesv2.Code, error)
	GetCodeByCodeHash(tx *sql.Tx, codeHash string, used bool) (*entitiesv2.Code, error)
	DeleteCode(tx *sql.Tx, codeId int64) error
	CodeLoadClient(tx *sql.Tx, code *entitiesv2.Code) error
	CodeLoadUser(tx *sql.Tx, code *entitiesv2.Code) error

	CreateResource(tx *sql.Tx, resource *entitiesv2.Resource) error
	UpdateResource(tx *sql.Tx, resource *entitiesv2.Resource) error
	GetResourceById(tx *sql.Tx, resourceId int64) (*entitiesv2.Resource, error)
	GetResourcesByIds(tx *sql.Tx, resourceIds []int64) ([]entitiesv2.Resource, error)
	GetResourceByResourceIdentifier(tx *sql.Tx, resourceIdentifier string) (*entitiesv2.Resource, error)
	GetAllResources(tx *sql.Tx) ([]entitiesv2.Resource, error)
	DeleteResource(tx *sql.Tx, resourceId int64) error

	CreatePermission(tx *sql.Tx, permission *entitiesv2.Permission) error
	UpdatePermission(tx *sql.Tx, permission *entitiesv2.Permission) error
	GetPermissionById(tx *sql.Tx, permissionId int64) (*entitiesv2.Permission, error)
	GetPermissionsByIds(tx *sql.Tx, permissionIds []int64) ([]entitiesv2.Permission, error)
	GetPermissionByPermissionIdentifier(tx *sql.Tx, permissionIdentifier string) (*entitiesv2.Permission, error)
	GetPermissionsByResourceId(tx *sql.Tx, resourceId int64) ([]entitiesv2.Permission, error)
	DeletePermission(tx *sql.Tx, permissionId int64) error
	PermissionsLoadResources(tx *sql.Tx, permissions []entitiesv2.Permission) error

	CreateKeyPair(tx *sql.Tx, keyPair *entitiesv2.KeyPair) error
	UpdateKeyPair(tx *sql.Tx, keyPair *entitiesv2.KeyPair) error
	GetKeyPairById(tx *sql.Tx, keyPairId int64) (*entitiesv2.KeyPair, error)
	GetAllSigningKeys(tx *sql.Tx) ([]entitiesv2.KeyPair, error)
	GetCurrentSigningKey(tx *sql.Tx) (*entitiesv2.KeyPair, error)
	DeleteKeyPair(tx *sql.Tx, keyPairId int64) error

	CreateRedirectURI(tx *sql.Tx, redirectURI *entitiesv2.RedirectURI) error
	GetRedirectURIById(tx *sql.Tx, redirectURIId int64) (*entitiesv2.RedirectURI, error)
	GetRedirectURIsByClientId(tx *sql.Tx, clientId int64) ([]entitiesv2.RedirectURI, error)
	DeleteRedirectURI(tx *sql.Tx, redirectURIId int64) error

	CreateWebOrigin(tx *sql.Tx, webOrigin *entitiesv2.WebOrigin) error
	GetWebOriginById(tx *sql.Tx, webOriginId int64) (*entitiesv2.WebOrigin, error)
	GetAllWebOrigins(tx *sql.Tx) ([]*entitiesv2.WebOrigin, error)
	GetWebOriginsByClientId(tx *sql.Tx, clientId int64) ([]entitiesv2.WebOrigin, error)
	DeleteWebOrigin(tx *sql.Tx, webOriginId int64) error

	CreateSettings(tx *sql.Tx, settings *entitiesv2.Settings) error
	UpdateSettings(tx *sql.Tx, settings *entitiesv2.Settings) error
	GetSettingsById(tx *sql.Tx, settingsId int64) (*entitiesv2.Settings, error)

	CreateUserPermission(tx *sql.Tx, userPermission *entitiesv2.UserPermission) error
	UpdateUserPermission(tx *sql.Tx, userPermission *entitiesv2.UserPermission) error
	GetUserPermissionById(tx *sql.Tx, userPermissionId int64) (*entitiesv2.UserPermission, error)
	GetUsersByPermissionIdPaginated(tx *sql.Tx, permissionId int64, page int, pageSize int) ([]entitiesv2.User, int, error)
	GetUserPermissionByUserIdAndPermissionId(tx *sql.Tx, userId, permissionId int64) (*entitiesv2.UserPermission, error)
	GetUserPermissionsByUserId(tx *sql.Tx, userId int64) ([]entitiesv2.UserPermission, error)
	GetUserPermissionsByUserIds(tx *sql.Tx, userIds []int64) ([]entitiesv2.UserPermission, error)
	DeleteUserPermission(tx *sql.Tx, userPermissionId int64) error

	CreateGroup(tx *sql.Tx, group *entitiesv2.Group) error
	UpdateGroup(tx *sql.Tx, group *entitiesv2.Group) error
	GetGroupById(tx *sql.Tx, groupId int64) (*entitiesv2.Group, error)
	GetGroupByGroupIdentifier(tx *sql.Tx, groupIdentifier string) (*entitiesv2.Group, error)
	GetGroupsByIds(tx *sql.Tx, groupIds []int64) ([]entitiesv2.Group, error)
	GetAllGroups(tx *sql.Tx) ([]*entitiesv2.Group, error)
	GetAllGroupsPaginated(tx *sql.Tx, page int, pageSize int) ([]entitiesv2.Group, int, error)
	GetGroupMembersPaginated(tx *sql.Tx, groupId int64, page int, pageSize int) ([]entitiesv2.User, int, error)
	CountGroupMembers(tx *sql.Tx, groupId int64) (int, error)
	DeleteGroup(tx *sql.Tx, groupId int64) error
	GroupsLoadAttributes(tx *sql.Tx, groups []entitiesv2.Group) error
	GroupsLoadPermissions(tx *sql.Tx, groups []entitiesv2.Group) error
	GroupLoadPermissions(tx *sql.Tx, group *entitiesv2.Group) error

	CreateUserAttribute(tx *sql.Tx, userAttribute *entitiesv2.UserAttribute) error
	UpdateUserAttribute(tx *sql.Tx, userAttribute *entitiesv2.UserAttribute) error
	GetUserAttributeById(tx *sql.Tx, userAttributeId int64) (*entitiesv2.UserAttribute, error)
	GetUserAttributesByUserId(tx *sql.Tx, userId int64) ([]entitiesv2.UserAttribute, error)
	DeleteUserAttribute(tx *sql.Tx, userAttributeId int64) error

	CreateClientPermission(tx *sql.Tx, clientPermission *entitiesv2.ClientPermission) error
	UpdateClientPermission(tx *sql.Tx, clientPermission *entitiesv2.ClientPermission) error
	GetClientPermissionById(tx *sql.Tx, clientPermissionId int64) (*entitiesv2.ClientPermission, error)
	GetClientPermissionByClientIdAndPermissionId(tx *sql.Tx, clientId, permissionId int64) (*entitiesv2.ClientPermission, error)
	GetClientPermissionsByClientId(tx *sql.Tx, clientId int64) ([]entitiesv2.ClientPermission, error)
	DeleteClientPermission(tx *sql.Tx, clientPermissionId int64) error

	CreateUserSession(tx *sql.Tx, userSession *entitiesv2.UserSession) error
	UpdateUserSession(tx *sql.Tx, userSession *entitiesv2.UserSession) error
	GetUserSessionById(tx *sql.Tx, userSessionId int64) (*entitiesv2.UserSession, error)
	GetUserSessionBySessionIdentifier(tx *sql.Tx, sessionIdentifier string) (*entitiesv2.UserSession, error)
	GetUserSessionsByClientIdPaginated(tx *sql.Tx, clientId int64, page int, pageSize int) ([]entitiesv2.UserSession, int, error)
	GetUserSessionsByUserId(tx *sql.Tx, userId int64) ([]entitiesv2.UserSession, error)
	DeleteUserSession(tx *sql.Tx, userSessionId int64) error
	UserSessionLoadUser(tx *sql.Tx, userSession *entitiesv2.UserSession) error
	UserSessionsLoadUsers(tx *sql.Tx, userSessions []entitiesv2.UserSession) error
	UserSessionLoadClients(tx *sql.Tx, userSession *entitiesv2.UserSession) error
	UserSessionsLoadClients(tx *sql.Tx, userSessions []entitiesv2.UserSession) error

	CreateUserConsent(tx *sql.Tx, userConsent *entitiesv2.UserConsent) error
	UpdateUserConsent(tx *sql.Tx, userConsent *entitiesv2.UserConsent) error
	GetUserConsentById(tx *sql.Tx, userConsentId int64) (*entitiesv2.UserConsent, error)
	GetConsentByUserIdAndClientId(tx *sql.Tx, userId int64, clientId int64) (*entitiesv2.UserConsent, error)
	GetConsentsByUserId(tx *sql.Tx, userId int64) ([]entitiesv2.UserConsent, error)
	DeleteUserConsent(tx *sql.Tx, userConsentId int64) error
	DeleteAllUserConsent(tx *sql.Tx) error
	UserConsentsLoadClients(tx *sql.Tx, userConsents []entitiesv2.UserConsent) error

	CreatePreRegistration(tx *sql.Tx, preRegistration *entitiesv2.PreRegistration) error
	UpdatePreRegistration(tx *sql.Tx, preRegistration *entitiesv2.PreRegistration) error
	GetPreRegistrationById(tx *sql.Tx, preRegistrationId int64) (*entitiesv2.PreRegistration, error)
	GetPreRegistrationByEmail(tx *sql.Tx, email string) (*entitiesv2.PreRegistration, error)
	DeletePreRegistration(tx *sql.Tx, preRegistrationId int64) error

	CreateUserGroup(tx *sql.Tx, userGroup *entitiesv2.UserGroup) error
	UpdateUserGroup(tx *sql.Tx, userGroup *entitiesv2.UserGroup) error
	GetUserGroupById(tx *sql.Tx, userGroupId int64) (*entitiesv2.UserGroup, error)
	GetUserGroupByUserIdAndGroupId(tx *sql.Tx, userId, groupId int64) (*entitiesv2.UserGroup, error)
	GetUserGroupsByUserId(tx *sql.Tx, userId int64) ([]entitiesv2.UserGroup, error)
	GetUserGroupsByUserIds(tx *sql.Tx, userIds []int64) ([]entitiesv2.UserGroup, error)
	DeleteUserGroup(tx *sql.Tx, userGroupId int64) error

	CreateGroupAttribute(tx *sql.Tx, groupAttribute *entitiesv2.GroupAttribute) error
	UpdateGroupAttribute(tx *sql.Tx, groupAttribute *entitiesv2.GroupAttribute) error
	GetGroupAttributeById(tx *sql.Tx, groupAttributeId int64) (*entitiesv2.GroupAttribute, error)
	GetGroupAttributesByGroupId(tx *sql.Tx, groupId int64) ([]entitiesv2.GroupAttribute, error)
	GetGroupAttributesByGroupIds(tx *sql.Tx, groupIds []int64) ([]entitiesv2.GroupAttribute, error)
	DeleteGroupAttribute(tx *sql.Tx, groupAttributeId int64) error

	CreateGroupPermission(tx *sql.Tx, groupPermission *entitiesv2.GroupPermission) error
	UpdateGroupPermission(tx *sql.Tx, groupPermission *entitiesv2.GroupPermission) error
	GetGroupPermissionById(tx *sql.Tx, groupPermissionId int64) (*entitiesv2.GroupPermission, error)
	GetGroupPermissionByGroupIdAndPermissionId(tx *sql.Tx, groupId, permissionId int64) (*entitiesv2.GroupPermission, error)
	GetGroupPermissionsByGroupIds(tx *sql.Tx, groupIds []int64) ([]entitiesv2.GroupPermission, error)
	GetGroupPermissionsByGroupId(tx *sql.Tx, groupId int64) ([]entitiesv2.GroupPermission, error)
	DeleteGroupPermission(tx *sql.Tx, groupPermissionId int64) error

	CreateRefreshToken(tx *sql.Tx, refreshToken *entitiesv2.RefreshToken) error
	UpdateRefreshToken(tx *sql.Tx, refreshToken *entitiesv2.RefreshToken) error
	GetRefreshTokenById(tx *sql.Tx, refreshTokenId int64) (*entitiesv2.RefreshToken, error)
	GetRefreshTokenByJti(tx *sql.Tx, jti string) (*entitiesv2.RefreshToken, error)
	DeleteRefreshToken(tx *sql.Tx, refreshTokenId int64) error
	RefreshTokenLoadCode(tx *sql.Tx, refreshToken *entitiesv2.RefreshToken) error

	CreateUserSessionClient(tx *sql.Tx, userSessionClient *entitiesv2.UserSessionClient) error
	UpdateUserSessionClient(tx *sql.Tx, userSessionClient *entitiesv2.UserSessionClient) error
	GetUserSessionClientById(tx *sql.Tx, userSessionClientId int64) (*entitiesv2.UserSessionClient, error)
	GetUserSessionsClientByIds(tx *sql.Tx, userSessionClientIds []int64) ([]entitiesv2.UserSessionClient, error)
	GetUserSessionClientsByUserSessionId(tx *sql.Tx, userSessionId int64) ([]entitiesv2.UserSessionClient, error)
	GetUserSessionClientsByUserSessionIds(tx *sql.Tx, userSessionIds []int64) ([]entitiesv2.UserSessionClient, error)
	DeleteUserSessionClient(tx *sql.Tx, userSessionClientId int64) error
	UserSessionClientsLoadClients(tx *sql.Tx, userSessionClients []entitiesv2.UserSessionClient) error

	CreateHttpSession(tx *sql.Tx, httpSession *entitiesv2.HttpSession) error
	UpdateHttpSession(tx *sql.Tx, httpSession *entitiesv2.HttpSession) error
	GetHttpSessionById(tx *sql.Tx, httpSessionId int64) (*entitiesv2.HttpSession, error)
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
