package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/pkg/errors"
)

func (d *CommonDatabase) CreateWebOrigin(tx *sql.Tx, webOrigin *entities.WebOrigin) error {

	if webOrigin.ClientId == 0 {
		return errors.WithStack(errors.New("client id must be greater than 0"))
	}

	now := time.Now().UTC()

	originalCreatedAt := webOrigin.CreatedAt
	webOrigin.CreatedAt = sql.NullTime{Time: now, Valid: true}

	webOriginStruct := sqlbuilder.NewStruct(new(entities.WebOrigin)).
		For(d.Flavor)

	insertBuilder := webOriginStruct.WithoutTag("pk").InsertInto("web_origins", webOrigin)

	sql, args := insertBuilder.Build()
	result, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		webOrigin.CreatedAt = originalCreatedAt
		return errors.Wrap(err, "unable to insert webOrigin")
	}

	id, err := result.LastInsertId()
	if err != nil {
		webOrigin.CreatedAt = originalCreatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	webOrigin.Id = id
	return nil
}

func (d *CommonDatabase) getWebOriginCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	webOriginStruct *sqlbuilder.Struct) (*entities.WebOrigin, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var webOrigin entities.WebOrigin
	if rows.Next() {
		addr := webOriginStruct.Addr(&webOrigin)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan webOrigin")
		}
		return &webOrigin, nil
	}
	return nil, nil
}

func (d *CommonDatabase) GetWebOriginById(tx *sql.Tx, webOriginId int64) (*entities.WebOrigin, error) {

	webOriginStruct := sqlbuilder.NewStruct(new(entities.WebOrigin)).
		For(d.Flavor)

	selectBuilder := webOriginStruct.SelectFrom("web_origins")
	selectBuilder.Where(selectBuilder.Equal("id", webOriginId))

	webOrigin, err := d.getWebOriginCommon(tx, selectBuilder, webOriginStruct)
	if err != nil {
		return nil, err
	}

	return webOrigin, nil
}

func (d *CommonDatabase) GetWebOriginsByClientId(tx *sql.Tx, clientId int64) ([]entities.WebOrigin, error) {

	webOriginStruct := sqlbuilder.NewStruct(new(entities.WebOrigin)).
		For(d.Flavor)

	selectBuilder := webOriginStruct.SelectFrom("web_origins")
	selectBuilder.Where(selectBuilder.Equal("client_id", clientId))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var webOrigins []entities.WebOrigin
	for rows.Next() {
		var webOrigin entities.WebOrigin
		addr := webOriginStruct.Addr(&webOrigin)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan webOrigin")
		}
		webOrigins = append(webOrigins, webOrigin)
	}

	return webOrigins, nil
}

func (d *CommonDatabase) GetAllWebOrigins(tx *sql.Tx) ([]*entities.WebOrigin, error) {

	webOriginStruct := sqlbuilder.NewStruct(new(entities.WebOrigin)).
		For(d.Flavor)

	selectBuilder := webOriginStruct.SelectFrom("web_origins")

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var webOrigins []*entities.WebOrigin
	for rows.Next() {
		var webOrigin entities.WebOrigin
		addr := webOriginStruct.Addr(&webOrigin)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan webOrigin")
		}
		webOrigins = append(webOrigins, &webOrigin)
	}

	return webOrigins, nil
}

func (d *CommonDatabase) DeleteWebOrigin(tx *sql.Tx, webOriginId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(entities.WebOrigin)).
		For(d.Flavor)

	deleteBuilder := clientStruct.DeleteFrom("web_origins")
	deleteBuilder.Where(deleteBuilder.Equal("id", webOriginId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete webOrigin")
	}

	return nil
}
