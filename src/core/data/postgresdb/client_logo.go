package postgresdb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *PostgresDatabase) CreateClientLogo(tx *sql.Tx, clientLogo *models.ClientLogo) error {
	if clientLogo.ClientId == 0 {
		return errors.WithStack(errors.New("can't create client logo with client_id 0"))
	}

	now := time.Now().UTC()

	originalCreatedAt := clientLogo.CreatedAt
	originalUpdatedAt := clientLogo.UpdatedAt
	clientLogo.CreatedAt = sql.NullTime{Time: now, Valid: true}
	clientLogo.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	clientLogoStruct := sqlbuilder.NewStruct(new(models.ClientLogo)).
		For(sqlbuilder.PostgreSQL)

	insertBuilder := clientLogoStruct.WithoutTag("pk").InsertInto("client_logos", clientLogo)
	sqlStr, args := insertBuilder.Build()
	sqlStr = sqlStr + " RETURNING id"

	rows, err := d.CommonDB.QuerySql(tx, sqlStr, args...)
	if err != nil {
		clientLogo.CreatedAt = originalCreatedAt
		clientLogo.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert client logo")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&clientLogo.Id)
		if err != nil {
			clientLogo.CreatedAt = originalCreatedAt
			clientLogo.UpdatedAt = originalUpdatedAt
			return errors.Wrap(err, "unable to scan client logo id")
		}
	}

	return nil
}

func (d *PostgresDatabase) UpdateClientLogo(tx *sql.Tx, clientLogo *models.ClientLogo) error {
	return d.CommonDB.UpdateClientLogo(tx, clientLogo)
}

func (d *PostgresDatabase) GetClientLogoByClientId(tx *sql.Tx, clientId int64) (*models.ClientLogo, error) {
	return d.CommonDB.GetClientLogoByClientId(tx, clientId)
}

func (d *PostgresDatabase) DeleteClientLogo(tx *sql.Tx, clientId int64) error {
	return d.CommonDB.DeleteClientLogo(tx, clientId)
}

func (d *PostgresDatabase) ClientHasLogo(tx *sql.Tx, clientId int64) (bool, error) {
	return d.CommonDB.ClientHasLogo(tx, clientId)
}
