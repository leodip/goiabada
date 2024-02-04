package datav2

import (
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/mysql"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/google/uuid"
	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

//go:embed migrations/mysql/*.sql
var mysqlMigrationsFs embed.FS

type MySQLDatabase struct {
	DB *sql.DB
}

func NewMySQLDatabase() (Database, error) {
	dsnWithoutDBname := fmt.Sprintf("%v:%v@tcp(%v:%v)/?charset=utf8mb4&parseTime=True&loc=UTC",
		viper.GetString("DB.Username"),
		viper.GetString("DB.Password"),
		viper.GetString("DB.Host"),
		viper.GetInt("DB.Port"))

	dsnWithDBname := fmt.Sprintf("%v:%v@tcp(%v:%v)/%v?charset=utf8mb4&parseTime=True&loc=UTC&multiStatements=true",
		viper.GetString("DB.Username"),
		viper.GetString("DB.Password"),
		viper.GetString("DB.Host"),
		viper.GetInt("DB.Port"),
		viper.GetString("DB.DbName"))

	logMsg := strings.ReplaceAll(dsnWithDBname, viper.GetString("DB.Password"), "******")
	slog.Info(fmt.Sprintf("using database: %v", logMsg))

	db, err := sql.Open("mysql", dsnWithoutDBname)
	if err != nil {
		return nil, errors.Wrap(err, "unable to open database")
	}

	// create the database if it does not exist
	createDatabaseCommand := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %v CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;", viper.GetString("DB.DbName"))
	_, err = db.Exec(createDatabaseCommand)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create database")
	}

	db, err = sql.Open("mysql", dsnWithDBname)
	if err != nil {
		return nil, errors.Wrap(err, "unable to open database")
	}

	mysqlDb := MySQLDatabase{DB: db}
	return &mysqlDb, nil
}

func (d *MySQLDatabase) BeginTransaction() (*sql.Tx, error) {
	if viper.GetBool("Log.Sql") {
		slog.Info("beginning transaction")
	}

	tx, err := d.DB.Begin()
	if err != nil {
		return nil, errors.Wrap(err, "unable to begin transaction")
	}
	return tx, nil
}

func (d *MySQLDatabase) CommitTransaction(tx *sql.Tx) error {
	if viper.GetBool("Log.Sql") {
		slog.Info("committing transaction")
	}

	err := tx.Commit()
	if err != nil {
		return errors.Wrap(err, "unable to commit transaction")
	}
	return nil
}

func (d *MySQLDatabase) RollbackTransaction(tx *sql.Tx) error {
	if viper.GetBool("Log.Sql") {
		slog.Info("rolling back transaction")
	}

	err := tx.Rollback()
	if err != nil {
		return errors.Wrap(err, "unable to rollback transaction")
	}
	return nil
}

func (d *MySQLDatabase) IsGoiabadaSchemaCreated() (bool, error) {
	var count int
	// check if the users table exists
	err := d.DB.QueryRow("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = ? AND table_name = ?", viper.GetString("DB.DbName"), "users").Scan(&count)
	if err != nil {
		return false, errors.Wrap(err, "unable to query database")
	}
	return count > 0, nil
}

func (d *MySQLDatabase) Migrate() error {
	driver, err := mysql.WithInstance(d.DB, &mysql.Config{
		DatabaseName: viper.GetString("DB.DbName"),
	})
	if err != nil {
		return errors.Wrap(err, "unable to create migration driver")
	}

	iofs, err := iofs.New(mysqlMigrationsFs, "migrations/mysql")
	if err != nil {
		return errors.Wrap(err, "unable to create migration filesystem")
	}

	migrate, err := migrate.NewWithInstance("iofs", iofs, "mysql", driver)

	if err != nil {
		return errors.Wrap(err, "unable to create migration instance")
	}
	migrate.Up()

	return nil
}
func (d *MySQLDatabase) log(sql string, args ...any) {
	if viper.GetBool("Log.Sql") {
		slog.Info(fmt.Sprintf("sql: %v", sql))
		argsStr := ""
		for i, arg := range args {
			argsStr += fmt.Sprintf("[arg %v: %v] ", i, arg)
		}
		slog.Info(fmt.Sprintf("sql args: %v", argsStr))
	}
}

func (d *MySQLDatabase) execSql(tx *sql.Tx, sql string, args ...any) (sql.Result, error) {

	d.log(sql, args...)

	if tx != nil {
		result, err := tx.Exec(sql, args...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to execute SQL")
		}
		return result, nil
	}

	result, err := d.DB.Exec(sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to execute SQL")
	}
	return result, nil
}

func (d *MySQLDatabase) querySql(tx *sql.Tx, sql string, args ...any) (*sql.Rows, error) {
	d.log(sql, args...)

	if tx != nil {
		result, err := tx.Query(sql, args...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to execute SQL")
		}
		return result, nil
	}

	result, err := d.DB.Query(sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to execute SQL")
	}
	return result, nil
}

func (d *MySQLDatabase) CreateClient(tx *sql.Tx, client *entitiesv2.Client) (*entitiesv2.Client, error) {

	insertBuilder := sqlbuilder.MySQL.NewInsertBuilder()
	insertBuilder.InsertInto("clients")
	insertBuilder.Cols(
		"created_at",
		"updated_at",
		"client_identifier",
		"client_secret_encrypted",
		"description",
		"enabled",
		"consent_required",
		"is_public",
		"authorization_code_enabled",
		"client_credentials_enabled",
		"token_expiration_in_seconds",
		"refresh_token_offline_idle_timeout_in_seconds",
		"refresh_token_offline_max_lifetime_in_seconds",
		"include_open_id_connect_claims_in_access_token",
		"default_acr_level",
	)

	now := time.Now().UTC()
	insertBuilder.Values(
		now,
		now,
		client.ClientIdentifier,
		client.ClientSecretEncrypted,
		client.Description,
		client.Enabled,
		client.ConsentRequired,
		client.IsPublic,
		client.AuthorizationCodeEnabled,
		client.ClientCredentialsEnabled,
		client.TokenExpirationInSeconds,
		client.RefreshTokenOfflineIdleTimeoutInSeconds,
		client.RefreshTokenOfflineMaxLifetimeInSeconds,
		client.IncludeOpenIDConnectClaimsInAccessToken,
		client.DefaultAcrLevel,
	)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to insert client")
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, errors.Wrap(err, "unable to get last insert id")
	}

	client, err = d.GetClientById(tx, id)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get client by id")
	}
	return client, nil
}

func (d *MySQLDatabase) CreateClientRedirectURI(tx *sql.Tx, clientId int64, redirectURI *entitiesv2.RedirectURI) (*entitiesv2.RedirectURI, error) {

	insertBuilder := sqlbuilder.MySQL.NewInsertBuilder()
	insertBuilder.InsertInto("redirect_uris")
	insertBuilder.Cols(
		"created_at",
		"uri",
		"client_id",
	)
	insertBuilder.Values(
		time.Now().UTC(),
		redirectURI.URI,
		clientId,
	)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to insert client redirect uri")
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, errors.Wrap(err, "unable to get last insert id")
	}

	redirectURI.Id = id
	return redirectURI, nil
}

func (d *MySQLDatabase) scanClient(rows *sql.Rows) (*entitiesv2.Client, error) {
	var (
		id                                             int64
		created_at                                     time.Time
		updated_at                                     time.Time
		client_identifier                              string
		client_secret_encrypted                        []byte
		description                                    string
		enabled                                        bool
		consent_required                               bool
		is_public                                      bool
		authorization_code_enabled                     bool
		client_credentials_enabled                     bool
		token_expiration_in_seconds                    int
		refresh_token_offline_idle_timeout_in_seconds  int
		refresh_token_offline_max_lifetime_in_seconds  int
		include_open_id_connect_claims_in_access_token string
		default_acr_level                              enums.AcrLevel
	)

	err := rows.Scan(
		&id,
		&created_at,
		&updated_at,
		&client_identifier,
		&client_secret_encrypted,
		&description,
		&enabled,
		&consent_required,
		&is_public,
		&authorization_code_enabled,
		&client_credentials_enabled,
		&token_expiration_in_seconds,
		&refresh_token_offline_idle_timeout_in_seconds,
		&refresh_token_offline_max_lifetime_in_seconds,
		&include_open_id_connect_claims_in_access_token,
		&default_acr_level,
	)
	if err != nil {
		return nil, errors.Wrap(err, "unable to scan client")
	}

	client := &entitiesv2.Client{
		Id:                                      id,
		CreatedAt:                               created_at,
		UpdatedAt:                               updated_at,
		ClientIdentifier:                        client_identifier,
		ClientSecretEncrypted:                   client_secret_encrypted,
		Description:                             description,
		Enabled:                                 enabled,
		ConsentRequired:                         consent_required,
		IsPublic:                                is_public,
		AuthorizationCodeEnabled:                authorization_code_enabled,
		ClientCredentialsEnabled:                client_credentials_enabled,
		TokenExpirationInSeconds:                token_expiration_in_seconds,
		RefreshTokenOfflineIdleTimeoutInSeconds: refresh_token_offline_idle_timeout_in_seconds,
		RefreshTokenOfflineMaxLifetimeInSeconds: refresh_token_offline_max_lifetime_in_seconds,
		IncludeOpenIDConnectClaimsInAccessToken: include_open_id_connect_claims_in_access_token,
		DefaultAcrLevel:                         default_acr_level,
	}

	return client, nil
}

func (d *MySQLDatabase) scanRedirectURI(rows *sql.Rows) (*entitiesv2.RedirectURI, error) {
	var (
		id         int64
		created_at time.Time
		uri        string
		client_id  int64
	)

	err := rows.Scan(
		&id,
		&created_at,
		&uri,
		&client_id,
	)
	if err != nil {
		return nil, errors.Wrap(err, "unable to scan redirect uri")
	}

	redirectURI := &entitiesv2.RedirectURI{
		Id:        id,
		CreatedAt: created_at,
		URI:       uri,
		ClientId:  client_id,
	}

	return redirectURI, nil
}

func (d *MySQLDatabase) GetClientById(tx *sql.Tx, clientId int64) (*entitiesv2.Client, error) {

	selectBuilder := sqlbuilder.MySQL.NewSelectBuilder()
	selectBuilder.
		Select("*").
		From("clients").
		Where(selectBuilder.Equal("id", clientId))

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var client *entitiesv2.Client
	if rows.Next() {
		client, err = d.scanClient(rows)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan row")
		}
	}

	return client, nil
}

func (d *MySQLDatabase) CreateResource(tx *sql.Tx, resource *entitiesv2.Resource) (*entitiesv2.Resource, error) {

	insertBuilder := sqlbuilder.MySQL.NewInsertBuilder()
	insertBuilder.InsertInto("resources")
	insertBuilder.Cols(
		"created_at",
		"updated_at",
		"resource_identifier",
		"description",
	)

	now := time.Now().UTC()
	insertBuilder.Values(
		now,
		now,
		resource.ResourceIdentifier,
		resource.Description,
	)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to insert resource")
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, errors.Wrap(err, "unable to get last insert id")
	}

	resource, err = d.GetResourceById(tx, id)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get resource by id")
	}
	return resource, nil
}

func (d *MySQLDatabase) GetResourceById(tx *sql.Tx, resourceId int64) (*entitiesv2.Resource, error) {

	selectBuilder := sqlbuilder.MySQL.NewSelectBuilder()
	selectBuilder.
		Select("*").
		From("resources").
		Where(selectBuilder.Equal("id", resourceId))

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var resource *entitiesv2.Resource
	if rows.Next() {
		resource, err = d.scanResource(rows)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan row")
		}
	}

	return resource, nil
}

func (d *MySQLDatabase) scanResource(rows *sql.Rows) (*entitiesv2.Resource, error) {
	var (
		id                  int64
		created_at          time.Time
		updated_at          time.Time
		resource_identifier string
		description         string
	)

	err := rows.Scan(
		&id,
		&created_at,
		&updated_at,
		&resource_identifier,
		&description,
	)
	if err != nil {
		return nil, errors.Wrap(err, "unable to scan resource")
	}

	resource := &entitiesv2.Resource{
		Id:                 id,
		CreatedAt:          created_at,
		UpdatedAt:          updated_at,
		ResourceIdentifier: resource_identifier,
		Description:        description,
	}

	return resource, nil
}

func (d *MySQLDatabase) CreatePermission(tx *sql.Tx, permission *entitiesv2.Permission) (*entitiesv2.Permission, error) {

	insertBuilder := sqlbuilder.MySQL.NewInsertBuilder()
	insertBuilder.InsertInto("permissions")
	insertBuilder.Cols(
		"created_at",
		"updated_at",
		"permission_identifier",
		"description",
		"resource_id",
	)

	now := time.Now().UTC()
	insertBuilder.Values(
		now,
		now,
		permission.PermissionIdentifier,
		permission.Description,
		permission.ResourceId,
	)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to insert permission")
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, errors.Wrap(err, "unable to get last insert id")
	}

	permission, err = d.GetPermissionById(tx, id)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get permission by id")
	}
	return permission, nil
}

func (d *MySQLDatabase) GetPermissionById(tx *sql.Tx, permissionId int64) (*entitiesv2.Permission, error) {

	selectBuilder := sqlbuilder.MySQL.NewSelectBuilder()
	selectBuilder.
		Select("*").
		From("permissions").
		Where(selectBuilder.Equal("id", permissionId))

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var permission *entitiesv2.Permission
	if rows.Next() {
		permission, err = d.scanPermission(rows)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan row")
		}
	}

	return permission, nil
}

func (d *MySQLDatabase) scanPermission(rows *sql.Rows) (*entitiesv2.Permission, error) {
	var (
		id                    int64
		created_at            time.Time
		updated_at            time.Time
		permission_identifier string
		description           string
		resource_id           int64
	)

	err := rows.Scan(
		&id,
		&created_at,
		&updated_at,
		&permission_identifier,
		&description,
		&resource_id,
	)
	if err != nil {
		return nil, errors.Wrap(err, "unable to scan permission")
	}

	permission := &entitiesv2.Permission{
		Id:                   id,
		CreatedAt:            created_at,
		UpdatedAt:            updated_at,
		PermissionIdentifier: permission_identifier,
		Description:          description,
		ResourceId:           resource_id,
	}

	return permission, nil
}

func (d *MySQLDatabase) CreateUser(tx *sql.Tx, user *entitiesv2.User) (*entitiesv2.User, error) {

	insertBuilder := sqlbuilder.MySQL.NewInsertBuilder()
	insertBuilder.InsertInto("users")
	insertBuilder.Cols(
		"created_at",
		"updated_at",
		"enabled",
		"subject",
		"username",
		"given_name",
		"middle_name",
		"family_name",
		"nickname",
		"website",
		"gender",
		"email",
		"email_verified",
		"email_verification_code_encrypted",
		"email_verification_code_issued_at",
		"zone_info_country_name",
		"zone_info",
		"locale",
		"birth_date",
		"phone_number",
		"phone_number_verified",
		"phone_number_verification_code_encrypted",
		"phone_number_verification_code_issued_at",
		"address_line1",
		"address_line2",
		"address_locality",
		"address_region",
		"address_postal_code",
		"address_country",
		"password_hash",
		"otp_secret",
		"otp_enabled",
		"forgot_password_code_encrypted",
		"forgot_password_code_issued_at",
	)

	now := time.Now().UTC()
	insertBuilder.Values(
		now,
		now,
		user.Enabled,
		user.Subject,
		user.Username,
		user.GivenName,
		user.MiddleName,
		user.FamilyName,
		user.Nickname,
		user.Website,
		user.Gender,
		user.Email,
		user.EmailVerified,
		user.EmailVerificationCodeEncrypted,
		user.EmailVerificationCodeIssuedAt,
		user.ZoneInfoCountryName,
		user.ZoneInfo,
		user.Locale,
		user.BirthDate,
		user.PhoneNumber,
		user.PhoneNumberVerified,
		user.PhoneNumberVerificationCodeEncrypted,
		user.PhoneNumberVerificationCodeIssuedAt,
		user.AddressLine1,
		user.AddressLine2,
		user.AddressLocality,
		user.AddressRegion,
		user.AddressPostalCode,
		user.AddressCountry,
		user.PasswordHash,
		user.OTPSecret,
		user.OTPEnabled,
		user.ForgotPasswordCodeEncrypted,
		user.ForgotPasswordCodeIssuedAt,
	)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to insert user")
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, errors.Wrap(err, "unable to get last insert id")
	}

	user, err = d.GetUserById(tx, id)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get user by id")
	}
	return user, nil
}

func (d *MySQLDatabase) GetUserById(tx *sql.Tx, userId int64) (*entitiesv2.User, error) {

	selectBuilder := sqlbuilder.MySQL.NewSelectBuilder()
	selectBuilder.
		Select("*").
		From("users").
		Where(selectBuilder.Equal("id", userId))

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var user *entitiesv2.User
	if rows.Next() {
		user, err = d.scanUser(rows)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan row")
		}
	}

	return user, nil
}

func (d *MySQLDatabase) scanUser(rows *sql.Rows) (*entitiesv2.User, error) {
	var (
		id                                       int64
		created_at                               time.Time
		updated_at                               time.Time
		enabled                                  bool
		subject                                  uuid.UUID
		username                                 string
		given_name                               string
		middle_name                              string
		family_name                              string
		nickname                                 string
		website                                  string
		gender                                   string
		email                                    string
		email_verified                           bool
		email_verification_code_encrypted        []byte
		email_verification_code_issued_at        *time.Time
		zone_info_country_name                   string
		zone_info                                string
		locale                                   string
		birth_date                               *time.Time
		phone_number                             string
		phone_number_verified                    bool
		phone_number_verification_code_encrypted []byte
		phone_number_verification_code_issued_at *time.Time
		address_line1                            string
		address_line2                            string
		address_locality                         string
		address_region                           string
		address_postal_code                      string
		address_country                          string
		password_hash                            string
		otp_secret                               string
		otp_enabled                              bool
		forgot_password_code_encrypted           []byte
		forgot_password_code_issued_at           *time.Time
	)

	err := rows.Scan(
		&id,
		&created_at,
		&updated_at,
		&enabled,
		&subject,
		&username,
		&given_name,
		&middle_name,
		&family_name,
		&nickname,
		&website,
		&gender,
		&email,
		&email_verified,
		&email_verification_code_encrypted,
		&email_verification_code_issued_at,
		&zone_info_country_name,
		&zone_info,
		&locale,
		&birth_date,
		&phone_number,
		&phone_number_verified,
		&phone_number_verification_code_encrypted,
		&phone_number_verification_code_issued_at,
		&address_line1,
		&address_line2,
		&address_locality,
		&address_region,
		&address_postal_code,
		&address_country,
		&password_hash,
		&otp_secret,
		&otp_enabled,
		&forgot_password_code_encrypted,
		&forgot_password_code_issued_at,
	)
	if err != nil {
		return nil, errors.Wrap(err, "unable to scan user")
	}

	user := &entitiesv2.User{
		Id:                                   id,
		CreatedAt:                            created_at,
		UpdatedAt:                            updated_at,
		Enabled:                              enabled,
		Subject:                              subject,
		Username:                             username,
		GivenName:                            given_name,
		MiddleName:                           middle_name,
		FamilyName:                           family_name,
		Nickname:                             nickname,
		Website:                              website,
		Gender:                               gender,
		Email:                                email,
		EmailVerified:                        email_verified,
		EmailVerificationCodeEncrypted:       email_verification_code_encrypted,
		EmailVerificationCodeIssuedAt:        email_verification_code_issued_at,
		ZoneInfoCountryName:                  zone_info_country_name,
		ZoneInfo:                             zone_info,
		Locale:                               locale,
		BirthDate:                            birth_date,
		PhoneNumber:                          phone_number,
		PhoneNumberVerified:                  phone_number_verified,
		PhoneNumberVerificationCodeEncrypted: phone_number_verification_code_encrypted,
		PhoneNumberVerificationCodeIssuedAt:  phone_number_verification_code_issued_at,
		AddressLine1:                         address_line1,
		AddressLine2:                         address_line2,
		AddressLocality:                      address_locality,
		AddressRegion:                        address_region,
		AddressPostalCode:                    address_postal_code,
		AddressCountry:                       address_country,
		PasswordHash:                         password_hash,
		OTPSecret:                            otp_secret,
		OTPEnabled:                           otp_enabled,
		ForgotPasswordCodeEncrypted:          forgot_password_code_encrypted,
		ForgotPasswordCodeIssuedAt:           forgot_password_code_issued_at,
	}

	return user, nil
}

func (d *MySQLDatabase) CreateUsersPermission(tx *sql.Tx, usersPermissions *entitiesv2.UsersPermissions) (*entitiesv2.UsersPermissions, error) {

	insertBuilder := sqlbuilder.MySQL.NewInsertBuilder()
	insertBuilder.InsertInto("users_permissions")
	insertBuilder.Cols(
		"created_at",
		"updated_at",
		"user_id",
		"permission_id",
	)
	now := time.Now().UTC()
	insertBuilder.Values(
		now,
		now,
		usersPermissions.UserId,
		usersPermissions.PermissionId,
	)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to insert user permission")
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, errors.Wrap(err, "unable to get last insert id")
	}

	usersPermissions, err = d.GetUsersPermissionsById(tx, id)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get user permission by id")
	}

	return usersPermissions, nil
}

func (d *MySQLDatabase) GetUsersPermissionsById(tx *sql.Tx, usersPermissionsId int64) (*entitiesv2.UsersPermissions, error) {

	selectBuilder := sqlbuilder.MySQL.NewSelectBuilder()
	selectBuilder.
		Select("*").
		From("users_permissions").
		Where(selectBuilder.Equal("id", usersPermissionsId))

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var usersPermissions *entitiesv2.UsersPermissions
	if rows.Next() {
		usersPermissions, err = d.scanUsersPermissions(rows)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan row")
		}
	}

	return usersPermissions, nil
}

func (d *MySQLDatabase) scanUsersPermissions(rows *sql.Rows) (*entitiesv2.UsersPermissions, error) {
	var (
		id            int64
		created_at    time.Time
		updated_at    time.Time
		user_id       int64
		permission_id int64
	)

	err := rows.Scan(
		&id,
		&created_at,
		&updated_at,
		&user_id,
		&permission_id,
	)
	if err != nil {
		return nil, errors.Wrap(err, "unable to scan users permissions")
	}

	usersPermissions := &entitiesv2.UsersPermissions{
		Id:           id,
		CreatedAt:    created_at,
		UpdatedAt:    updated_at,
		UserId:       user_id,
		PermissionId: permission_id,
	}

	return usersPermissions, nil
}
