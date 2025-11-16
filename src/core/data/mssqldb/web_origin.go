package mssqldb

import (
	"database/sql"
	"strings"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *MsSQLDatabase) CreateWebOrigin(tx *sql.Tx, webOrigin *models.WebOrigin) error {
	if webOrigin.ClientId == 0 {
		return errors.WithStack(errors.New("client id must be greater than 0"))
	}

	now := time.Now().UTC()

	originalCreatedAt := webOrigin.CreatedAt
	webOrigin.CreatedAt = sql.NullTime{Time: now, Valid: true}

	webOriginStruct := sqlbuilder.NewStruct(new(models.WebOrigin)).
		For(sqlbuilder.SQLServer)

	insertBuilder := webOriginStruct.WithoutTag("pk").InsertInto("web_origins", webOrigin)
	sql, args := insertBuilder.Build()

	parts := strings.SplitN(sql, "VALUES", 2)
	if len(parts) != 2 {
		return errors.New("unexpected SQL format from sqlbuilder")
	}
	sql = parts[0] + "OUTPUT INSERTED.id VALUES" + parts[1]

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

func (d *MsSQLDatabase) GetWebOriginById(tx *sql.Tx, webOriginId int64) (*models.WebOrigin, error) {
	return d.CommonDB.GetWebOriginById(tx, webOriginId)
}

func (d *MsSQLDatabase) GetWebOriginsByClientId(tx *sql.Tx, clientId int64) ([]models.WebOrigin, error) {
	return d.CommonDB.GetWebOriginsByClientId(tx, clientId)
}

func (d *MsSQLDatabase) GetAllWebOrigins(tx *sql.Tx) ([]models.WebOrigin, error) {
	return d.CommonDB.GetAllWebOrigins(tx)
}

func (d *MsSQLDatabase) DeleteWebOrigin(tx *sql.Tx, webOriginId int64) error {
	return d.CommonDB.DeleteWebOrigin(tx, webOriginId)
}
