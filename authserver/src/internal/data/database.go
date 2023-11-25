package data

import (
	"database/sql"
	"fmt"
	"strings"

	"log/slog"

	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"

	slogGorm "github.com/orandin/slog-gorm"
)

type Database struct {
	DB *gorm.DB
}

func NewDatabase() (*Database, error) {

	// connection string without the database name
	dsn := fmt.Sprintf("%v:%v@tcp(%v:%v)/?charset=utf8mb4&parseTime=True&loc=UTC",
		viper.GetString("DB.Username"),
		viper.GetString("DB.Password"),
		viper.GetString("DB.Host"),
		viper.GetInt("DB.Port"))

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, errors.Wrap(err, "unable to open database")
	}

	// create the database it does not exist
	createDatabaseCommand := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %v CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;", viper.GetString("DB.DbName"))
	_, err = db.Exec(createDatabaseCommand)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create database")
	}

	// connection string with database name
	dsn = fmt.Sprintf("%v:%v@tcp(%v:%v)/%v?charset=utf8mb4&parseTime=True&loc=UTC",
		viper.GetString("DB.Username"),
		viper.GetString("DB.Password"),
		viper.GetString("DB.Host"),
		viper.GetInt("DB.Port"),
		viper.GetString("DB.DbName"))

	logMsg := strings.ReplaceAll(dsn, viper.GetString("DB.Password"), "******")
	slog.Info(fmt.Sprintf("using database: %v", logMsg))

	gormTraceAll := viper.GetBool("Logger.Gorm.TraceAll")
	slog.Info(fmt.Sprintf("gorm trace all: %v", gormTraceAll))

	var gormLogger logger.Interface
	if gormTraceAll {
		gormLogger = slogGorm.New(slogGorm.WithLogger(slog.Default()), slogGorm.WithTraceAll())
	} else {
		gormLogger = slogGorm.New(slogGorm.WithLogger(slog.Default()))
	}

	gormDB, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
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

func (d *Database) migrate() error {
	err := d.DB.AutoMigrate(
		&entities.Client{},
		&entities.Permission{},
		&entities.User{},
		&entities.UserConsent{},
		&entities.UserSession{},
		&entities.UserSessionClient{},
		&entities.RedirectURI{},
		&entities.WebOrigin{},
		&entities.Code{},
		&entities.KeyPair{},
		&entities.Settings{},
		&entities.PreRegistration{},
		&entities.Resource{},
		&entities.Group{},
		&entities.GroupAttribute{},
		&entities.UserAttribute{},
		&entities.RefreshToken{},
	)

	if err != nil {
		return errors.Wrap(err, "unable to migrate entities")
	}
	return err
}

func (d *Database) isDbEmpty() bool {
	if err := d.DB.First(&entities.Settings{}).Error; errors.Is(err, gorm.ErrRecordNotFound) {
		return true
	}
	return false
}

func (d *Database) GetClientByClientIdentifier(clientIdentifier string) (*entities.Client, error) {
	var client entities.Client

	result := d.DB.
		Preload("RedirectURIs").
		Preload("WebOrigins").
		Preload("Permissions").
		Preload("Permissions.Resource").
		Where("client_identifier = ?", clientIdentifier).First(&client)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch client from database")
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return &client, nil
}

func (d *Database) GetUserByUsername(username string) (*entities.User, error) {
	var user entities.User

	result := d.DB.
		Preload(clause.Associations).
		Where("username = ?", username).First(&user)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch user from database")
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return &user, nil
}

func (d *Database) GetUserById(id uint) (*entities.User, error) {
	var user entities.User

	result := d.DB.
		Preload(clause.Associations).
		Preload("Permissions.Resource").
		Preload("Groups.Permissions").
		Where("id = ?", id).First(&user)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch user from database")
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return &user, nil
}

func (d *Database) GetUserBySubject(subject string) (*entities.User, error) {
	var user entities.User

	result := d.DB.
		Preload(clause.Associations).
		Preload("Groups.Attributes").
		Where("subject = ?", subject).First(&user)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch user from database")
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return &user, nil
}

func (d *Database) GetUserByEmail(email string) (*entities.User, error) {
	var user entities.User

	result := d.DB.
		Preload(clause.Associations).
		Where("email = ?", email).First(&user)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch user from database")
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return &user, nil
}

func (d *Database) SaveCode(code *entities.Code) (*entities.Code, error) {
	result := d.DB.Save(code)

	if result.Error != nil {
		return nil, errors.Wrap(result.Error, "unable to save code in database")
	}

	return code, nil
}

func (d *Database) GetCodeByCodeHash(codeHash string, used bool) (*entities.Code, error) {
	var c entities.Code

	result := d.DB.
		Preload("Client").
		Preload("Client.RedirectURIs").
		Preload("Client.WebOrigins").
		Preload("User").
		Preload("User.Permissions").
		Preload("User.Attributes").
		Preload("User.Groups").
		Preload("User.Groups.Permissions").
		Preload("User.Groups.Attributes").
		Where("code_hash = ? and used = ?", codeHash, used).First(&c)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch code from database")
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return &c, nil
}

func (d *Database) GetAllSigningKeys() ([]entities.KeyPair, error) {
	var keys []entities.KeyPair

	result := d.DB.Find(&keys)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch keys from database")
	}

	if result.RowsAffected == 0 {
		return []entities.KeyPair{}, nil
	}

	return keys, nil
}

func (d *Database) GetCurrentSigningKey() (*entities.KeyPair, error) {
	var c entities.KeyPair

	result := d.DB.
		Where("state = ?", enums.KeyStateCurrent.String()).
		First(&c)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch keypair from database")
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return &c, nil
}

func (d *Database) SaveKeyPair(keyPair *entities.KeyPair) (*entities.KeyPair, error) {

	result := d.DB.Save(keyPair)

	if result.Error != nil {
		return nil, errors.Wrap(result.Error, "unable to save key pair in database")
	}

	return keyPair, nil
}

func (d *Database) DeleteKeyPair(keyPairId uint) error {
	result := d.DB.Unscoped().Delete(&entities.KeyPair{}, keyPairId)

	if result.Error != nil {
		return errors.Wrap(result.Error, "unable to delete keypair from database")
	}

	return nil
}

func (d *Database) GetSettings() (*entities.Settings, error) {
	var settings entities.Settings

	var result = d.DB.First(&settings)
	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch settings from database")
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return &settings, nil
}

func (d *Database) GetAllResources() ([]entities.Resource, error) {
	var resources []entities.Resource

	result := d.DB.Find(&resources)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch resources from database")
	}

	if result.RowsAffected == 0 {
		return []entities.Resource{}, nil
	}

	return resources, nil
}

func (d *Database) GetResourceById(id uint) (*entities.Resource, error) {
	var res entities.Resource

	result := d.DB.
		Where("id = ?", id).First(&res)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch resource from database")
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return &res, nil
}

func (d *Database) GetResourceByResourceIdentifier(resourceIdentifier string) (*entities.Resource, error) {
	var res entities.Resource

	result := d.DB.
		Where("resource_identifier = ?", resourceIdentifier).First(&res)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch resource from database")
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return &res, nil
}

func (d *Database) GetPermissionsByResourceId(resourceId uint) ([]entities.Permission, error) {
	var permissions []entities.Permission

	result := d.DB.
		Preload(clause.Associations).
		Where("resource_id = ?", resourceId).
		Find(&permissions)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch resource permissions from database")
	}

	if result.RowsAffected == 0 {
		return []entities.Permission{}, nil
	}

	return permissions, nil
}

func (d *Database) GetUserSessionBySessionIdentifier(sessionIdentifier string) (*entities.UserSession, error) {
	var userSession entities.UserSession

	result := d.DB.
		Preload(clause.Associations).
		Preload("Clients.Client").
		Where("session_identifier = ?", sessionIdentifier).First(&userSession)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch user session from database")
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return &userSession, nil
}

func (d *Database) GetUserSessionsByUserId(userId uint) ([]entities.UserSession, error) {
	var userSessions []entities.UserSession

	result := d.DB.
		Preload(clause.Associations).
		Preload("Clients.Client").
		Where("user_id = ?", userId).Find(&userSessions)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch user sessions from database")
	}

	if result.RowsAffected == 0 {
		return []entities.UserSession{}, nil
	}
	return userSessions, nil
}

func (d *Database) UpdateUserSession(userSession *entities.UserSession) (*entities.UserSession, error) {

	result := d.DB.Session(&gorm.Session{FullSaveAssociations: true}).Updates(&userSession)

	if result.Error != nil {
		return nil, errors.Wrap(result.Error, "unable to update user session in database")
	}

	return userSession, nil
}

func (d *Database) CreateUserSession(userSession *entities.UserSession) (*entities.UserSession, error) {

	result := d.DB.Create(userSession)

	if result.Error != nil {
		return nil, errors.Wrap(result.Error, "unable to create user session in database")
	}

	return userSession, nil
}

func (d *Database) GetConsentByUserIdAndClientId(userId uint, clientId uint) (*entities.UserConsent, error) {
	var consent *entities.UserConsent

	result := d.DB.
		Preload("Client").
		Preload("User").
		Where("user_id = ? and client_id = ?", userId, clientId).First(&consent)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch user consent from database")
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return consent, nil
}

func (d *Database) GetConsentsByUserId(userId uint) ([]entities.UserConsent, error) {
	var consents []entities.UserConsent

	result := d.DB.
		Preload("Client").
		Where("user_id = ?", userId).Find(&consents)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch user consents from database")
	}

	if result.RowsAffected == 0 {
		return []entities.UserConsent{}, nil
	}
	return consents, nil
}

func (d *Database) DeleteUserConsent(consentId uint) error {
	result := d.DB.Unscoped().Delete(&entities.UserConsent{}, consentId)

	if result.Error != nil {
		return errors.Wrap(result.Error, "unable to delete user consent from database")
	}

	return nil
}

func (d *Database) DeleteUserSession(userSessionId uint) error {

	err := d.DB.Transaction(func(tx *gorm.DB) error {

		// delete user session clients
		result := tx.Exec("DELETE FROM user_session_clients WHERE user_session_id = ?", userSessionId)
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to delete user session clients from database")
		}

		// delete user session
		result = tx.Unscoped().Delete(&entities.UserSession{}, userSessionId)
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to delete user session from database")
		}

		return nil
	})

	if err != nil {
		return err
	}

	return nil
}

func (d *Database) SaveUserConsent(userConsent *entities.UserConsent) (*entities.UserConsent, error) {

	result := d.DB.Save(userConsent)

	if result.Error != nil {
		return nil, errors.Wrap(result.Error, "unable to save user consent in database")
	}

	return userConsent, nil
}

func (d *Database) SavePreRegistration(preRegistration *entities.PreRegistration) (*entities.PreRegistration, error) {
	result := d.DB.Save(preRegistration)

	if result.Error != nil {
		return nil, errors.Wrap(result.Error, "unable to save pre registration in database")
	}

	return preRegistration, nil
}

func (d *Database) GetPreRegistrationByEmail(email string) (*entities.PreRegistration, error) {
	var preRegistration entities.PreRegistration

	result := d.DB.
		Preload(clause.Associations).
		Where("email = ?", email).First(&preRegistration)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch pre registration from database")
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return &preRegistration, nil
}

func (d *Database) SaveUser(user *entities.User) (*entities.User, error) {

	result := d.DB.Save(user)

	if result.Error != nil {
		return nil, errors.Wrap(result.Error, "unable to save user in database")
	}

	return user, nil
}

func (d *Database) DeletePreRegistration(preRegistrationId uint) error {
	result := d.DB.Unscoped().Delete(&entities.PreRegistration{}, preRegistrationId)

	if result.Error != nil {
		return errors.Wrap(result.Error, "unable to delete pre registration from database")
	}

	return nil
}

func (d *Database) GetClients() ([]entities.Client, error) {
	var clients []entities.Client

	result := d.DB.Find(&clients)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch clients from database")
	}

	if result.RowsAffected == 0 {
		return []entities.Client{}, nil
	}

	return clients, nil
}

func (d *Database) GetClientById(id uint) (*entities.Client, error) {
	var client entities.Client

	result := d.DB.
		Preload(clause.Associations).
		Preload("Permissions.Resource").
		Where("id = ?", id).First(&client)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch client from database")
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return &client, nil
}

func (d *Database) SaveRedirectURI(redirectURI *entities.RedirectURI) (*entities.RedirectURI, error) {
	result := d.DB.Save(redirectURI)

	if result.Error != nil {
		return nil, errors.Wrap(result.Error, "unable to save redirect uri in database")
	}

	return redirectURI, nil
}

func (d *Database) DeleteRedirectURI(redirectURIId uint) error {
	result := d.DB.Unscoped().Delete(&entities.RedirectURI{}, redirectURIId)

	if result.Error != nil {
		return errors.Wrap(result.Error, "unable to delete redirect uri from database")
	}

	return nil
}

func (d *Database) GetPermissionById(id uint) (*entities.Permission, error) {
	var permission entities.Permission

	result := d.DB.
		Preload(clause.Associations).
		Where("id = ?", id).First(&permission)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch permission from database")
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return &permission, nil
}

func (d *Database) DeleteClientPermission(clientId uint, permissionId uint) error {

	client, err := d.GetClientById(clientId)
	if err != nil {
		return err
	}

	permission, err := d.GetPermissionById(permissionId)
	if err != nil {
		return err
	}

	err = d.DB.Model(&client).Association("Permissions").Delete(permission)

	if err != nil {
		return errors.Wrap(err, "unable to delete client permission from database")
	}

	return nil
}

func (d *Database) AddClientPermission(clientId uint, permissionId uint) error {

	client, err := d.GetClientById(clientId)
	if err != nil {
		return err
	}

	permission, err := d.GetPermissionById(permissionId)
	if err != nil {
		return err
	}

	err = d.DB.Model(&client).Association("Permissions").Append(permission)

	if err != nil {
		return errors.Wrap(err, "unable to append client permission in database")
	}

	return nil
}

func (d *Database) DeleteClient(clientId uint) error {

	err := d.DB.Transaction(func(tx *gorm.DB) error {
		// delete codes
		result := tx.Unscoped().Where("client_id = ?", clientId).Delete(&entities.Code{})
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to delete codes from database (to delete a client)")
		}

		// delete web origins
		result = tx.Unscoped().Where("client_id = ?", clientId).Delete(&entities.WebOrigin{})
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to delete web origins from database (to delete a client)")
		}

		// delete redirect uris
		result = tx.Unscoped().Where("client_id = ?", clientId).Delete(&entities.RedirectURI{})
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to delete redirect uris from database (to delete a client)")
		}

		// delete user session clients
		result = tx.Unscoped().Where("client_id = ?", clientId).Delete(&entities.UserSessionClient{})
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to delete user session clients from database (to delete a client)")
		}

		// delete user consents
		result = tx.Unscoped().Where("client_id = ?", clientId).Delete(&entities.UserConsent{})
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to delete user consents from database (to delete a client)")
		}

		// delete permissions assigned to client
		result = tx.Exec("DELETE FROM clients_permissions WHERE client_id = ?", clientId)
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to delete client permissions from database (to delete a client)")
		}

		// delete client
		result = tx.Unscoped().Delete(&entities.Client{}, clientId)
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to delete client from database")
		}
		return nil
	})

	if err != nil {
		return err
	}

	return nil
}

func (d *Database) SaveClient(client *entities.Client) (*entities.Client, error) {
	result := d.DB.Save(client)

	if result.Error != nil {
		return nil, errors.Wrap(result.Error, "unable to save client in database")
	}

	return client, nil
}

func (d *Database) GetPermissionByPermissionIdentifier(permissionIdentifier string) (*entities.Permission, error) {
	var permission entities.Permission

	result := d.DB.
		Preload(clause.Associations).
		Where("permission_identifier = ?", permissionIdentifier).First(&permission)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch permission from database")
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return &permission, nil
}

func (d *Database) SavePermission(permission *entities.Permission) (*entities.Permission, error) {
	result := d.DB.Save(permission)

	if result.Error != nil {
		return nil, errors.Wrap(result.Error, "unable to save permission in database")
	}

	return permission, nil
}

func (d *Database) DeletePermission(permissionId uint) error {

	err := d.DB.Transaction(func(tx *gorm.DB) error {
		// delete groups_permissions
		result := tx.Exec("DELETE FROM groups_permissions WHERE permission_id = ?", permissionId)
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to delete group permissions from database")
		}

		// delete users_permissions
		result = tx.Exec("DELETE FROM users_permissions WHERE permission_id = ?", permissionId)
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to delete user permissions from database")
		}

		// delete clients_permissions
		result = tx.Exec("DELETE FROM clients_permissions WHERE permission_id = ?", permissionId)
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to delete client permissions from database")
		}

		// delete permission
		result = tx.Unscoped().Delete(&entities.Permission{}, permissionId)
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to delete permission from database")
		}

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

func (d *Database) DeleteResource(resourceId uint) error {

	permissions, err := d.GetPermissionsByResourceId(resourceId)
	if err != nil {
		return err
	}

	err = d.DB.Transaction(func(tx *gorm.DB) error {

		for _, permission := range permissions {
			err = d.DeletePermission(permission.Id)
			if err != nil {
				return err
			}
		}

		result := tx.Unscoped().Delete(&entities.Resource{}, resourceId)
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to delete resource from database")
		}
		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

func (d *Database) GetAllGroups() ([]entities.Group, error) {
	var groups []entities.Group

	result := d.DB.Find(&groups)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch groups from database")
	}

	if result.RowsAffected == 0 {
		return []entities.Group{}, nil
	}

	return groups, nil
}

func (d *Database) GetGroupById(id uint) (*entities.Group, error) {
	var group entities.Group

	result := d.DB.
		Preload("Permissions").
		Where("id = ?", id).First(&group)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch group from database")
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return &group, nil
}

func (d *Database) GetGroupByGroupIdentifier(groupIdentifier string) (*entities.Group, error) {
	var group entities.Group

	result := d.DB.
		Where("group_identifier = ?", groupIdentifier).First(&group)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch group from database")
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return &group, nil
}

func (d *Database) GetGroupMembersPaginated(groupId uint, page int, pageSize int) ([]entities.User, int, error) {
	var users []entities.User

	result := d.DB.Raw("SELECT users.* FROM users_groups "+
		"INNER JOIN users ON users_groups.user_id = users.id "+
		"WHERE users_groups.group_id = ? "+
		"ORDER BY users.given_name ASC "+
		"LIMIT ?, ?", groupId, (page-1)*pageSize, pageSize).Scan(&users)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, 0, errors.Wrap(result.Error, "unable to fetch users from database")
	}

	if result.RowsAffected == 0 {
		return []entities.User{}, 0, nil
	}

	var total int64
	d.DB.Raw("SELECT COUNT(*) FROM users_groups WHERE users_groups.group_id = ?", groupId).Count(&total)

	return users, int(total), nil
}

func (d *Database) GetUserSessionsByClientIdPaginated(clientId uint, page int, pageSize int) ([]entities.UserSession, int, error) {
	var userSessions []entities.UserSession

	result := d.DB.
		Preload(clause.Associations).
		Preload("Clients.Client").
		Joins("JOIN user_session_clients ON user_session_clients.user_session_id = user_sessions.id").
		Where("user_session_clients.client_id = ?", clientId).
		Order("user_sessions.last_accessed DESC").
		Limit(pageSize).
		Offset((page - 1) * pageSize).
		Find(&userSessions)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, 0, errors.Wrap(result.Error, "unable to fetch user sessions from database")
	}

	if result.RowsAffected == 0 {
		return []entities.UserSession{}, 0, nil
	}

	var total int64
	d.DB.Raw("SELECT COUNT(*) FROM user_sessions "+
		"INNER JOIN user_session_clients ON user_session_clients.user_session_id = user_sessions.id "+
		"WHERE user_session_clients.client_id = ? ", clientId).Count(&total)

	return userSessions, int(total), nil
}

func (d *Database) SaveResource(resource *entities.Resource) (*entities.Resource, error) {
	result := d.DB.Save(resource)

	if result.Error != nil {
		return nil, errors.Wrap(result.Error, "unable to save resource in database")
	}

	return resource, nil
}

func (d *Database) AddUserToGroup(user *entities.User, group *entities.Group) error {

	err := d.DB.Model(&user).Association("Groups").Append(group)

	if err != nil {
		return errors.Wrap(err, "unable to append user to group in database")
	}

	return nil
}

func (d *Database) RemoveUserFromGroup(user *entities.User, group *entities.Group) error {

	err := d.DB.Model(&user).Association("Groups").Delete(group)

	if err != nil {
		return errors.Wrap(err, "unable to remove user from group in database")
	}

	return nil
}

func (d *Database) SaveGroup(group *entities.Group) (*entities.Group, error) {
	result := d.DB.Save(group)

	if result.Error != nil {
		return nil, errors.Wrap(result.Error, "unable to save group in database")
	}

	return group, nil
}

func (d *Database) CountGroupMembers(groupId uint) (int, error) {
	var total int64
	d.DB.Raw("SELECT COUNT(*) FROM users_groups WHERE users_groups.group_id = ?", groupId).Count(&total)

	return int(total), nil
}

func (d *Database) DeleteGroup(groupId uint) error {

	err := d.DB.Transaction(func(tx *gorm.DB) error {
		// delete group attributes
		result := tx.Exec("DELETE FROM group_attributes WHERE group_id = ?", groupId)
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to delete group attributes from database")
		}

		// delete group permissions
		result = tx.Exec("DELETE FROM groups_permissions WHERE group_id = ?", groupId)
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to delete group permissions from database")
		}

		// delete users_groups
		result = tx.Exec("DELETE FROM users_groups WHERE group_id = ?", groupId)
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to delete user groups from database")
		}

		// delete group
		result = tx.Unscoped().Delete(&entities.Group{}, groupId)
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to delete group from database")
		}

		return nil
	})

	if err != nil {
		return err
	}

	return nil
}

func (d *Database) GetGroupAttributesByGroupId(groupId uint) ([]entities.GroupAttribute, error) {
	var attributes []entities.GroupAttribute

	result := d.DB.
		Preload(clause.Associations).
		Where("group_id = ?", groupId).Order("`key` ASC").Find(&attributes)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch attributes from database")
	}

	if result.RowsAffected == 0 {
		return []entities.GroupAttribute{}, nil
	}

	return attributes, nil
}

func (d *Database) DeleteGroupAttributeById(groupAttributeId uint) error {

	result := d.DB.Unscoped().Delete(&entities.GroupAttribute{}, groupAttributeId)

	if result.Error != nil {
		return errors.Wrap(result.Error, "unable to delete group attribute from database")
	}

	return nil
}

func (d *Database) SaveGroupAttribute(groupAttribute *entities.GroupAttribute) (*entities.GroupAttribute, error) {
	result := d.DB.Save(groupAttribute)

	if result.Error != nil {
		return nil, errors.Wrap(result.Error, "unable to save group attribute in database")
	}

	return groupAttribute, nil
}

func (d *Database) GetGroupAttributeById(attributeId uint) (*entities.GroupAttribute, error) {
	var attr entities.GroupAttribute

	result := d.DB.
		Preload(clause.Associations).
		Where("id = ?", attributeId).First(&attr)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch group attribute from database")
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return &attr, nil
}

func (d *Database) AddGroupPermission(groupId uint, permissionId uint) error {

	group, err := d.GetGroupById(groupId)
	if err != nil {
		return err
	}

	permission, err := d.GetPermissionById(permissionId)
	if err != nil {
		return err
	}

	err = d.DB.Model(&group).Association("Permissions").Append(permission)

	if err != nil {
		return errors.Wrap(err, "unable to append group permission in database")
	}

	return nil
}

func (d *Database) DeleteGroupPermission(groupId uint, permissionId uint) error {

	group, err := d.GetGroupById(groupId)
	if err != nil {
		return err
	}

	permission, err := d.GetPermissionById(permissionId)
	if err != nil {
		return err
	}

	err = d.DB.Model(&group).Association("Permissions").Delete(permission)

	if err != nil {
		return errors.Wrap(err, "unable to delete group permission from database")
	}

	return nil
}

func (d *Database) SearchUsersPaginated(query string, page int, pageSize int) ([]entities.User, int, error) {
	var users []entities.User

	var result *gorm.DB
	var where string

	query = strings.TrimSpace(query)
	if query == "" {
		// no search filter
		result = d.DB.
			Preload("Groups").
			Preload("Permissions").
			Limit(pageSize).
			Offset((page - 1) * pageSize).
			Find(&users)

	} else {
		// with search filter
		where = "subject LIKE ? OR " +
			"username LIKE ? OR " +
			"given_name LIKE ? OR " +
			"middle_name LIKE ? OR " +
			"family_name LIKE ? OR " +
			"email LIKE ? "
		query = "%" + query + "%"

		result = d.DB.
			Preload("Groups").
			Preload("Permissions").
			Limit(pageSize).
			Offset((page-1)*pageSize).
			Where(where, query, query, query, query, query, query).
			Find(&users)
	}

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, 0, errors.Wrap(result.Error, "unable to fetch users from database")
	}

	if result.RowsAffected == 0 {
		return []entities.User{}, 0, nil
	}

	var total int64
	if query == "" {
		d.DB.Raw("SELECT COUNT(*) FROM users").Count(&total)
	} else {
		d.DB.Raw("SELECT COUNT(*) FROM users WHERE "+where,
			query, query, query, query, query, query).Count(&total)
	}

	return users, int(total), nil
}

func (d *Database) AddUserPermission(userId uint, permissionId uint) error {

	user, err := d.GetUserById(userId)
	if err != nil {
		return err
	}

	permission, err := d.GetPermissionById(permissionId)
	if err != nil {
		return err
	}

	err = d.DB.Model(&user).Association("Permissions").Append(permission)

	if err != nil {
		return errors.Wrap(err, "unable to append user permission in database")
	}

	return nil
}

func (d *Database) DeleteUserPermission(userId uint, permissionId uint) error {

	user, err := d.GetUserById(userId)
	if err != nil {
		return err
	}

	permission, err := d.GetPermissionById(permissionId)
	if err != nil {
		return err
	}

	err = d.DB.Model(&user).Association("Permissions").Delete(permission)

	if err != nil {
		return errors.Wrap(err, "unable to delete user permission from database")
	}

	return nil
}

func (d *Database) GetUserAttributesByUserId(userId uint) ([]entities.UserAttribute, error) {
	var attributes []entities.UserAttribute

	result := d.DB.
		Preload(clause.Associations).
		Where("user_id = ?", userId).Order("`key` ASC").Find(&attributes)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch attributes from database")
	}

	if result.RowsAffected == 0 {
		return []entities.UserAttribute{}, nil
	}

	return attributes, nil
}

func (d *Database) DeleteUserAttributeById(userAttributeId uint) error {

	result := d.DB.Unscoped().Delete(&entities.UserAttribute{}, userAttributeId)

	if result.Error != nil {
		return errors.Wrap(result.Error, "unable to delete user attribute from database")
	}

	return nil
}

func (d *Database) SaveUserAttribute(userAttribute *entities.UserAttribute) (*entities.UserAttribute, error) {
	result := d.DB.Save(userAttribute)

	if result.Error != nil {
		return nil, errors.Wrap(result.Error, "unable to save user attribute in database")
	}

	return userAttribute, nil
}

func (d *Database) GetUserAttributeById(attributeId uint) (*entities.UserAttribute, error) {
	var attr entities.UserAttribute

	result := d.DB.
		Preload(clause.Associations).
		Where("id = ?", attributeId).First(&attr)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch user attribute from database")
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return &attr, nil
}

func (d *Database) DeleteUser(user *entities.User) error {

	err := d.DB.Transaction(func(tx *gorm.DB) error {
		var codes []entities.Code
		result := d.DB.Where("user_id = ?", user.Id).Find(&codes)
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to fetch codes from database (to delete a user)")
		}

		var codeIds []uint
		for _, code := range codes {
			codeIds = append(codeIds, code.Id)
		}

		// delete refresh tokens
		result = tx.Exec("DELETE FROM refresh_tokens WHERE code_id IN (?)", codeIds)
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to delete refresh tokens from database")
		}

		// delete codes
		result = tx.Exec("DELETE FROM codes WHERE user_id = ?", user.Id)
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to delete user codes from database")
		}

		// delete user attributes
		result = tx.Exec("DELETE FROM user_attributes WHERE user_id = ?", user.Id)
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to delete user attributes from database")
		}

		// delete user consents
		result = tx.Exec("DELETE FROM user_consents WHERE user_id = ?", user.Id)
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to delete user consents from database")
		}

		// delete user session clients
		result = tx.Exec("DELETE FROM user_session_clients "+
			"WHERE user_session_id IN (SELECT id FROM user_sessions WHERE user_id = ?)", user.Id)
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to delete user session clients from database")
		}

		// delete user sessions
		result = tx.Exec("DELETE FROM user_sessions WHERE user_id = ?", user.Id)
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to delete user sessions from database")
		}

		// delete user groups
		result = tx.Exec("DELETE FROM users_groups WHERE user_id = ?", user.Id)
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to delete user groups from database")
		}

		// delete user permissions
		result = tx.Exec("DELETE FROM users_permissions WHERE user_id = ?", user.Id)
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to delete user permissions from database")
		}

		// delete user
		result = tx.Unscoped().Delete(user)
		if result.Error != nil {
			return errors.Wrap(result.Error, "unable to delete user from database")
		}

		return nil
	})

	if err != nil {
		return err
	}
	return nil
}

func (d *Database) SaveSettings(settings *entities.Settings) (*entities.Settings, error) {

	result := d.DB.Save(settings)

	if result.Error != nil {
		return nil, errors.Wrap(result.Error, "unable to save settings in database")
	}

	return settings, nil
}

func (d *Database) SaveRefreshToken(refreshToken *entities.RefreshToken) (*entities.RefreshToken, error) {

	result := d.DB.Save(refreshToken)

	if result.Error != nil {
		return nil, errors.Wrap(result.Error, "unable to save refresh token in database")
	}

	return refreshToken, nil
}

func (d *Database) GetRefreshTokenByJti(jti string) (*entities.RefreshToken, error) {
	var refreshToken entities.RefreshToken

	result := d.DB.
		Preload(clause.Associations).
		Preload("Code.User").
		Preload("Code.Client").
		Where("refresh_token_jti = ?", jti).First(&refreshToken)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch refresh token from database")
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return &refreshToken, nil
}

func (d *Database) GetUsersByPermissionIdPaginated(permissionId uint, page int, pageSize int) ([]entities.User, int, error) {
	var users []entities.User

	result := d.DB.Raw("SELECT users.* FROM users "+
		"INNER JOIN users_permissions ON users_permissions.user_id = users.id "+
		"WHERE users_permissions.permission_id = ? "+
		"ORDER BY users.given_name ASC "+
		"LIMIT ?, ?", permissionId, (page-1)*pageSize, pageSize).Scan(&users)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, 0, errors.Wrap(result.Error, "unable to fetch users from database")
	}

	if result.RowsAffected == 0 {
		return []entities.User{}, 0, nil
	}

	var total int64
	d.DB.Raw("SELECT COUNT(*) FROM users_permissions WHERE users_permissions.permission_id = ?", permissionId).Count(&total)

	return users, int(total), nil
}

func (d *Database) GetAllGroupsPaginated(page int, pageSize int) ([]entities.Group, int, error) {
	var groups []entities.Group

	result := d.DB.
		Preload("Permissions").
		Limit(pageSize).
		Offset((page - 1) * pageSize).
		Order("group_identifier ASC").
		Find(&groups)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, 0, errors.Wrap(result.Error, "unable to fetch groups from database")
	}

	if result.RowsAffected == 0 {
		return []entities.Group{}, 0, nil
	}

	var total int64
	result = d.DB.Model(&entities.Group{}).Count(&total)
	if result.Error != nil {
		return nil, 0, errors.Wrap(result.Error, "unable to count groups in database")
	}

	return groups, int(total), nil
}

func (d *Database) SaveWebOrigin(webOrigin *entities.WebOrigin) (*entities.WebOrigin, error) {
	result := d.DB.Save(webOrigin)

	if result.Error != nil {
		return nil, errors.Wrap(result.Error, "unable to save web origin in database")
	}

	return webOrigin, nil
}

func (d *Database) DeleteWebOrigin(webOriginId uint) error {
	result := d.DB.Unscoped().Delete(&entities.WebOrigin{}, webOriginId)

	if result.Error != nil {
		return errors.Wrap(result.Error, "unable to delete web origin from database")
	}

	return nil
}

func (d *Database) GetAllWebOrigins() ([]entities.WebOrigin, error) {
	var webOrigins []entities.WebOrigin

	result := d.DB.Find(&webOrigins)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, errors.Wrap(result.Error, "unable to fetch web origins from database")
	}

	if result.RowsAffected == 0 {
		return []entities.WebOrigin{}, nil
	}

	return webOrigins, nil
}

func (d *Database) DeleteUserSessionClient(userSessionClientId uint) error {

	result := d.DB.Unscoped().Delete(&entities.UserSessionClient{}, userSessionClientId)

	if result.Error != nil {
		return errors.Wrap(result.Error, "unable to delete user session client from database")
	}

	return nil
}
