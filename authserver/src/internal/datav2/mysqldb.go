package datav2

import (
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/mysql"
	"github.com/golang-migrate/migrate/v4/source/iofs"
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

func (d *MySQLDatabase) CreateClientWithAssociations(tx *sql.Tx, client *entitiesv2.Client,
	associations []enums.ClientAssociations) (*entitiesv2.Client, error) {

	var err error
	if tx == nil {
		tx, err = d.DB.Begin()
		if err != nil {
			return nil, errors.Wrap(err, "unable to begin transaction")
		}
	}
	defer tx.Rollback()

	client, err = d.CreateClient(tx, client)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create client")
	}

	if slices.Contains(associations, enums.ClientAssociationsRedirectURIs) {
		for i, redirectURI := range client.RedirectURIs {
			createdRedirectURI, err := d.CreateClientRedirectURI(tx, client.Id, &redirectURI)
			if err != nil {
				return nil, errors.Wrap(err, "unable to create client redirect uri")
			}
			client.RedirectURIs[i] = *createdRedirectURI
		}
	}

	if err = tx.Commit(); err != nil {
		return nil, errors.Wrap(err, "unable to commit transaction")
	}

	client, err = d.GetClientById(nil, client.Id, associations)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get client by id")
	}

	return client, nil
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

	client.Id = id
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

func (d *MySQLDatabase) GetClientById(tx *sql.Tx, clientId int64, associations []enums.ClientAssociations) (*entitiesv2.Client, error) {

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

	if slices.Contains(associations, enums.ClientAssociationsRedirectURIs) {

		selectBuilder = sqlbuilder.MySQL.NewSelectBuilder()
		selectBuilder.
			Select("*").
			From("redirect_uris").
			Where(selectBuilder.Equal("client_id", client.Id))

		sql, args = selectBuilder.Build()
		rows, err = d.querySql(tx, sql, args...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to query database")
		}
		defer rows.Close()

		for rows.Next() {
			redirectURI, err := d.scanRedirectURI(rows)
			if err != nil {
				return nil, errors.Wrap(err, "unable to scan row")
			}
			if client.RedirectURIs == nil {
				client.RedirectURIs = make([]entitiesv2.RedirectURI, 0)
			}
			client.RedirectURIs = append(client.RedirectURIs, *redirectURI)
		}
	}

	return client, nil
}
