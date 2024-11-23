package mssqldb

import (
	"database/sql"
	"strings"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *MsSQLDatabase) CreateRedirectURI(tx *sql.Tx, redirectURI *models.RedirectURI) error {
	if redirectURI.ClientId == 0 {
		return errors.WithStack(errors.New("client id must be greater than 0"))
	}

	now := time.Now().UTC()

	originalCreatedAt := redirectURI.CreatedAt
	redirectURI.CreatedAt = sql.NullTime{Time: now, Valid: true}

	redirectURIStruct := sqlbuilder.NewStruct(new(models.RedirectURI)).
		For(sqlbuilder.SQLServer)

	insertBuilder := redirectURIStruct.WithoutTag("pk").InsertInto("redirect_uris", redirectURI)
	sql, args := insertBuilder.Build()

	parts := strings.SplitN(sql, "VALUES", 2)
	if len(parts) != 2 {
		return errors.New("unexpected SQL format from sqlbuilder")
	}
	sql = parts[0] + "OUTPUT INSERTED.id VALUES" + parts[1]

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

func (d *MsSQLDatabase) GetRedirectURIById(tx *sql.Tx, redirectURIId int64) (*models.RedirectURI, error) {
	return d.CommonDB.GetRedirectURIById(tx, redirectURIId)
}

func (d *MsSQLDatabase) GetRedirectURIsByClientId(tx *sql.Tx, clientId int64) ([]models.RedirectURI, error) {
	return d.CommonDB.GetRedirectURIsByClientId(tx, clientId)
}

func (d *MsSQLDatabase) DeleteRedirectURI(tx *sql.Tx, redirectURIId int64) error {
	return d.CommonDB.DeleteRedirectURI(tx, redirectURIId)
}
