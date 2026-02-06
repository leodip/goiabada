package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *CommonDatabase) CreateClientLogo(tx *sql.Tx, clientLogo *models.ClientLogo) error {

	if clientLogo.ClientId == 0 {
		return errors.WithStack(errors.New("can't create client logo with client_id 0"))
	}

	now := time.Now().UTC()

	originalCreatedAt := clientLogo.CreatedAt
	originalUpdatedAt := clientLogo.UpdatedAt
	clientLogo.CreatedAt = sql.NullTime{Time: now, Valid: true}
	clientLogo.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	clientLogoStruct := sqlbuilder.NewStruct(new(models.ClientLogo)).
		For(d.Flavor)

	insertBuilder := clientLogoStruct.WithoutTag("pk").InsertInto("client_logos", clientLogo)

	sql, args := insertBuilder.Build()
	result, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		clientLogo.CreatedAt = originalCreatedAt
		clientLogo.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert client logo")
	}

	id, err := result.LastInsertId()
	if err != nil {
		clientLogo.CreatedAt = originalCreatedAt
		clientLogo.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	clientLogo.Id = id
	return nil
}

func (d *CommonDatabase) UpdateClientLogo(tx *sql.Tx, clientLogo *models.ClientLogo) error {

	if clientLogo.Id == 0 {
		return errors.WithStack(errors.New("can't update client logo with id 0"))
	}

	originalUpdatedAt := clientLogo.UpdatedAt
	clientLogo.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	clientLogoStruct := sqlbuilder.NewStruct(new(models.ClientLogo)).
		For(d.Flavor)

	updateBuilder := clientLogoStruct.WithoutTag("pk").WithoutTag("dont-update").Update("client_logos", clientLogo)
	updateBuilder.Where(updateBuilder.Equal("id", clientLogo.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		clientLogo.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update client logo")
	}

	return nil
}

func (d *CommonDatabase) GetClientLogoByClientId(tx *sql.Tx, clientId int64) (*models.ClientLogo, error) {

	clientLogoStruct := sqlbuilder.NewStruct(new(models.ClientLogo)).
		For(d.Flavor)

	selectBuilder := clientLogoStruct.SelectFrom("client_logos")
	selectBuilder.Where(selectBuilder.Equal("client_id", clientId))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var clientLogo models.ClientLogo
	if rows.Next() {
		addr := clientLogoStruct.Addr(&clientLogo)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan client logo")
		}
		return &clientLogo, nil
	}
	return nil, nil
}

func (d *CommonDatabase) DeleteClientLogo(tx *sql.Tx, clientId int64) error {

	clientLogoStruct := sqlbuilder.NewStruct(new(models.ClientLogo)).
		For(d.Flavor)

	deleteBuilder := clientLogoStruct.DeleteFrom("client_logos")
	deleteBuilder.Where(deleteBuilder.Equal("client_id", clientId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete client logo")
	}

	return nil
}

func (d *CommonDatabase) ClientHasLogo(tx *sql.Tx, clientId int64) (bool, error) {

	selectBuilder := d.Flavor.NewSelectBuilder()
	selectBuilder.Select("1").From("client_logos")
	selectBuilder.Where(selectBuilder.Equal("client_id", clientId))
	selectBuilder.Limit(1)

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return false, errors.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	return rows.Next(), nil
}
