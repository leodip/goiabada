package mysqldb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateWebOrigin(tx *sql.Tx, webOrigin *entitiesv2.WebOrigin) error {

	if webOrigin.ClientId == 0 {
		return errors.New("client id must be greater than 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := webOrigin.CreatedAt
	webOrigin.CreatedAt = sql.NullTime{Time: now, Valid: true}

	webOriginStruct := sqlbuilder.NewStruct(new(entitiesv2.WebOrigin)).
		For(sqlbuilder.MySQL)

	insertBuilder := webOriginStruct.WithoutTag("pk").InsertInto("web_origins", webOrigin)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
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

func (d *MySQLDatabase) getWebOriginCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	webOriginStruct *sqlbuilder.Struct) (*entitiesv2.WebOrigin, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var webOrigin entitiesv2.WebOrigin
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

func (d *MySQLDatabase) GetWebOriginById(tx *sql.Tx, webOriginId int64) (*entitiesv2.WebOrigin, error) {

	webOriginStruct := sqlbuilder.NewStruct(new(entitiesv2.WebOrigin)).
		For(sqlbuilder.MySQL)

	selectBuilder := webOriginStruct.SelectFrom("web_origins")
	selectBuilder.Where(selectBuilder.Equal("id", webOriginId))

	webOrigin, err := d.getWebOriginCommon(tx, selectBuilder, webOriginStruct)
	if err != nil {
		return nil, err
	}

	return webOrigin, nil
}

func (d *MySQLDatabase) GetWebOriginsByClientId(tx *sql.Tx, clientId int64) ([]entitiesv2.WebOrigin, error) {

	webOriginStruct := sqlbuilder.NewStruct(new(entitiesv2.WebOrigin)).
		For(sqlbuilder.MySQL)

	selectBuilder := webOriginStruct.SelectFrom("web_origins")
	selectBuilder.Where(selectBuilder.Equal("client_id", clientId))

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var webOrigins []entitiesv2.WebOrigin
	for rows.Next() {
		var webOrigin entitiesv2.WebOrigin
		addr := webOriginStruct.Addr(&webOrigin)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan webOrigin")
		}
		webOrigins = append(webOrigins, webOrigin)
	}

	return webOrigins, nil
}

func (d *MySQLDatabase) GetAllWebOrigins(tx *sql.Tx) ([]*entitiesv2.WebOrigin, error) {

	webOriginStruct := sqlbuilder.NewStruct(new(entitiesv2.WebOrigin)).
		For(sqlbuilder.MySQL)

	selectBuilder := webOriginStruct.SelectFrom("web_origins")

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var webOrigins []*entitiesv2.WebOrigin
	for rows.Next() {
		var webOrigin entitiesv2.WebOrigin
		addr := webOriginStruct.Addr(&webOrigin)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan webOrigin")
		}
		webOrigins = append(webOrigins, &webOrigin)
	}

	return webOrigins, nil
}

func (d *MySQLDatabase) DeleteWebOrigin(tx *sql.Tx, webOriginId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(entitiesv2.WebOrigin)).
		For(sqlbuilder.MySQL)

	deleteBuilder := clientStruct.DeleteFrom("web_origins")
	deleteBuilder.Where(deleteBuilder.Equal("id", webOriginId))

	sql, args := deleteBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete webOrigin")
	}

	return nil
}
