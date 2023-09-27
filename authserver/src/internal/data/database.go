package data

import (
	"fmt"
	"net/http"

	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Database struct {
	DB *gorm.DB
}

func NewDatabase() (*Database, error) {

	dsn := fmt.Sprintf("%v:%v@tcp(%v:%v)/%v?charset=utf8mb4&parseTime=True&loc=UTC",
		viper.GetString("DB.Username"),
		viper.GetString("DB.Password"),
		viper.GetString("DB.Host"),
		viper.GetInt("DB.Port"),
		viper.GetString("DB.DbName"))

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, customerrors.NewAppError(err, "", "unable to open database", http.StatusInternalServerError)
	}

	var database = &Database{
		DB: db,
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
		&entities.Role{},
		&entities.User{},
		&entities.UserConsent{},
		&entities.UserSession{},
		&entities.RedirectUri{},
		&entities.Code{},
		&entities.KeyPair{},
		&entities.Settings{},
	)
	if err != nil {
		return customerrors.NewAppError(err, "", "unable to migrate entities", http.StatusInternalServerError)
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
		Preload("RedirectUris").
		Preload("Permissions").
		Preload("Permissions.Resource").
		Where("client_identifier = ?", clientIdentifier).First(&client)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, customerrors.NewAppError(result.Error, "", "unable to fetch client from database", http.StatusInternalServerError)
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
		return nil, customerrors.NewAppError(result.Error, "", "unable to fetch user from database", http.StatusInternalServerError)
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
		Where("id = ?", id).First(&user)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, customerrors.NewAppError(result.Error, "", "unable to fetch user from database", http.StatusInternalServerError)
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
		Where("subject = ?", subject).First(&user)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, customerrors.NewAppError(result.Error, "", "unable to fetch user from database", http.StatusInternalServerError)
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
		return nil, customerrors.NewAppError(result.Error, "", "unable to fetch user from database", http.StatusInternalServerError)
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return &user, nil
}

func (d *Database) CreateCode(code *entities.Code) (*entities.Code, error) {
	result := d.DB.Create(code)

	if result.Error != nil {
		return nil, customerrors.NewAppError(result.Error, "", "unable to create code in database", http.StatusInternalServerError)
	}

	return code, nil
}

func (d *Database) GetCode(code string, used bool) (*entities.Code, error) {
	var c entities.Code

	result := d.DB.
		Preload("Client").
		Preload("User").
		Preload("User.Permissions").
		Preload("User.Roles").
		Where("code = ? and used = ?", code, used).First(&c)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, customerrors.NewAppError(result.Error, "", "unable to fetch code from database", http.StatusInternalServerError)
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return &c, nil
}

func (d *Database) GetSigningKey() (*entities.KeyPair, error) {
	var c entities.KeyPair

	result := d.DB.Order("ID desc").First(&c) // most recent

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, customerrors.NewAppError(result.Error, "", "unable to fetch keypair from database", http.StatusInternalServerError)
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return &c, nil
}

func (d *Database) GetSettings() (*entities.Settings, error) {
	var settings entities.Settings

	var result = d.DB.First(&settings)
	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, customerrors.NewAppError(result.Error, "", "unable to fetch settings from database", http.StatusInternalServerError)
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return &settings, nil
}

func (d *Database) GetResourceByResourceIdentifier(resourceIdentifier string) (*entities.Resource, error) {
	var res entities.Resource

	result := d.DB.
		Where("resource_identifier = ?", resourceIdentifier).First(&res)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, customerrors.NewAppError(result.Error, "", "unable to fetch resource from database", http.StatusInternalServerError)
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return &res, nil
}

func (d *Database) GetResourcePermissions(resourceId uint) ([]entities.Permission, error) {
	var permissions []entities.Permission

	result := d.DB.Where("resource_id = ?", resourceId).Find(&permissions)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, customerrors.NewAppError(result.Error, "", "unable to fetch resource permissions from database", http.StatusInternalServerError)
	}

	if result.RowsAffected == 0 {
		return []entities.Permission{}, nil
	}

	return permissions, nil
}

func (d *Database) GetUserSessionBySessionIdentifier(sessionIdentifier string) (*entities.UserSession, error) {
	var userSession entities.UserSession

	result := d.DB.
		Preload("User").
		Where("session_identifier = ?", sessionIdentifier).First(&userSession)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, customerrors.NewAppError(result.Error, "", "unable to fetch user session from database", http.StatusInternalServerError)
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return &userSession, nil
}

func (d *Database) UpdateUserSession(userSession *entities.UserSession) (*entities.UserSession, error) {

	result := d.DB.Save(userSession)

	if result.Error != nil {
		return nil, customerrors.NewAppError(result.Error, "", "unable to update user session in database", http.StatusInternalServerError)
	}

	return userSession, nil
}

func (d *Database) CreateUserSession(userSession *entities.UserSession) (*entities.UserSession, error) {

	result := d.DB.Save(userSession)

	if result.Error != nil {
		return nil, customerrors.NewAppError(result.Error, "", "unable to create user session in database", http.StatusInternalServerError)
	}

	return userSession, nil
}

func (d *Database) UpdateUser(user *entities.User) (*entities.User, error) {

	result := d.DB.Save(user)

	if result.Error != nil {
		return nil, customerrors.NewAppError(result.Error, "", "unable to update user in database", http.StatusInternalServerError)
	}

	return user, nil
}

func (d *Database) GetUserConsent(userID uint, clientID uint) (*entities.UserConsent, error) {
	var consent *entities.UserConsent

	result := d.DB.
		Preload("Client").
		Preload("User").
		Where("user_id = ? and client_id = ?", userID, clientID).First(&consent)

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return nil, customerrors.NewAppError(result.Error, "", "unable to fetch user consent from database", http.StatusInternalServerError)
	}

	if result.RowsAffected == 0 {
		return nil, nil
	}

	return consent, nil
}

func (d *Database) SaveUserConsent(userConsent *entities.UserConsent) (*entities.UserConsent, error) {

	result := d.DB.Save(userConsent)

	if result.Error != nil {
		return nil, customerrors.NewAppError(result.Error, "", "unable to update user consent in database", http.StatusInternalServerError)
	}

	return userConsent, nil
}

func (d *Database) UpdateCode(code *entities.Code) (*entities.Code, error) {

	result := d.DB.Save(code)

	if result.Error != nil {
		return nil, customerrors.NewAppError(result.Error, "", "unable to update code in database", http.StatusInternalServerError)
	}

	return code, nil
}
