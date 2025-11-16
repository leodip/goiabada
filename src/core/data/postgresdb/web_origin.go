package postgresdb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *PostgresDatabase) CreateWebOrigin(tx *sql.Tx, webOrigin *models.WebOrigin) error {
	if webOrigin.ClientId == 0 {
		return errors.WithStack(errors.New("client id must be greater than 0"))
	}

	now := time.Now().UTC()

	originalCreatedAt := webOrigin.CreatedAt
	webOrigin.CreatedAt = sql.NullTime{Time: now, Valid: true}

	webOriginStruct := sqlbuilder.NewStruct(new(models.WebOrigin)).
		For(sqlbuilder.PostgreSQL)

	insertBuilder := webOriginStruct.WithoutTag("pk").InsertInto("web_origins", webOrigin)

	sql, args := insertBuilder.Build()
	sql = sql + " RETURNING id"

	rows, err := d.CommonDB.QuerySql(tx, sql, args...)
	if err != nil {
		webOrigin.CreatedAt = originalCreatedAt
		return errors.Wrap(err, "unable to insert webOrigin")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&webOrigin.Id)
		if err != nil {
			webOrigin.CreatedAt = originalCreatedAt
			return errors.Wrap(err, "unable to scan webOrigin id")
		}
	}

	return nil
}

func (d *PostgresDatabase) GetWebOriginById(tx *sql.Tx, webOriginId int64) (*models.WebOrigin, error) {
	return d.CommonDB.GetWebOriginById(tx, webOriginId)
}

func (d *PostgresDatabase) GetWebOriginsByClientId(tx *sql.Tx, clientId int64) ([]models.WebOrigin, error) {
	return d.CommonDB.GetWebOriginsByClientId(tx, clientId)
}

func (d *PostgresDatabase) GetAllWebOrigins(tx *sql.Tx) ([]models.WebOrigin, error) {
	return d.CommonDB.GetAllWebOrigins(tx)
}

func (d *PostgresDatabase) DeleteWebOrigin(tx *sql.Tx, webOriginId int64) error {
	return d.CommonDB.DeleteWebOrigin(tx, webOriginId)
}
