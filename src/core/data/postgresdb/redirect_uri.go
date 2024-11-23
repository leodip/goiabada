package postgresdb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *PostgresDatabase) CreateRedirectURI(tx *sql.Tx, redirectURI *models.RedirectURI) error {
	if redirectURI.ClientId == 0 {
		return errors.WithStack(errors.New("client id must be greater than 0"))
	}

	now := time.Now().UTC()

	originalCreatedAt := redirectURI.CreatedAt
	redirectURI.CreatedAt = sql.NullTime{Time: now, Valid: true}

	redirectURIStruct := sqlbuilder.NewStruct(new(models.RedirectURI)).
		For(sqlbuilder.PostgreSQL)

	insertBuilder := redirectURIStruct.WithoutTag("pk").InsertInto("redirect_uris", redirectURI)

	sql, args := insertBuilder.Build()
	sql = sql + " RETURNING id"

	rows, err := d.CommonDB.QuerySql(tx, sql, args...)
	if err != nil {
		redirectURI.CreatedAt = originalCreatedAt
		return errors.Wrap(err, "unable to insert redirectURI")
	}
	defer rows.Close()

	if rows.Next() {
		err = rows.Scan(&redirectURI.Id)
		if err != nil {
			redirectURI.CreatedAt = originalCreatedAt
			return errors.Wrap(err, "unable to scan redirectURI id")
		}
	}

	return nil
}

func (d *PostgresDatabase) GetRedirectURIById(tx *sql.Tx, redirectURIId int64) (*models.RedirectURI, error) {
	return d.CommonDB.GetRedirectURIById(tx, redirectURIId)
}

func (d *PostgresDatabase) GetRedirectURIsByClientId(tx *sql.Tx, clientId int64) ([]models.RedirectURI, error) {
	return d.CommonDB.GetRedirectURIsByClientId(tx, clientId)
}

func (d *PostgresDatabase) DeleteRedirectURI(tx *sql.Tx, redirectURIId int64) error {
	return d.CommonDB.DeleteRedirectURI(tx, redirectURIId)
}
