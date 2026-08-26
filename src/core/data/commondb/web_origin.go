package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *CommonDatabase) CreateWebOrigin(tx *sql.Tx, webOrigin *models.WebOrigin) error {

	if webOrigin.ClientId == 0 {
		return errors.WithStack(errors.New("client id must be greater than 0"))
	}

	now := time.Now().UTC()

	originalCreatedAt := webOrigin.CreatedAt
	webOrigin.CreatedAt = sql.NullTime{Time: now, Valid: true}

	webOriginStruct := sqlbuilder.NewStruct(new(models.WebOrigin)).
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
	webOriginStruct *sqlbuilder.Struct) (*models.WebOrigin, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var webOrigin models.WebOrigin
	if rows.Next() {
		addr := webOriginStruct.Addr(&webOrigin)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan webOrigin")
		}
		return &webOrigin, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "unable to read query results")
	}

	return nil, nil
}

func (d *CommonDatabase) GetWebOriginById(tx *sql.Tx, webOriginId int64) (*models.WebOrigin, error) {

	webOriginStruct := sqlbuilder.NewStruct(new(models.WebOrigin)).
		For(d.Flavor)

	selectBuilder := webOriginStruct.SelectFrom("web_origins")
	selectBuilder.Where(selectBuilder.Equal("id", webOriginId))

	webOrigin, err := d.getWebOriginCommon(tx, selectBuilder, webOriginStruct)
	if err != nil {
		return nil, err
	}

	return webOrigin, nil
}

func (d *CommonDatabase) GetWebOriginsByClientId(tx *sql.Tx, clientId int64) ([]models.WebOrigin, error) {

	webOriginStruct := sqlbuilder.NewStruct(new(models.WebOrigin)).
		For(d.Flavor)

	selectBuilder := webOriginStruct.SelectFrom("web_origins")
	selectBuilder.Where(selectBuilder.Equal("client_id", clientId))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var webOrigins []models.WebOrigin
	for rows.Next() {
		var webOrigin models.WebOrigin
		addr := webOriginStruct.Addr(&webOrigin)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan webOrigin")
		}
		webOrigins = append(webOrigins, webOrigin)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "unable to read query results")
	}

	return webOrigins, nil
}

func (d *CommonDatabase) GetAllWebOrigins(tx *sql.Tx) ([]models.WebOrigin, error) {

	webOriginStruct := sqlbuilder.NewStruct(new(models.WebOrigin)).
		For(d.Flavor)

	selectBuilder := webOriginStruct.SelectFrom("web_origins")

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var webOrigins []models.WebOrigin
	for rows.Next() {
		var webOrigin models.WebOrigin
		addr := webOriginStruct.Addr(&webOrigin)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan webOrigin")
		}
		webOrigins = append(webOrigins, webOrigin)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "unable to read query results")
	}

	return webOrigins, nil
}

// WebOriginExists reports whether any client has registered origin. It answers the CORS
// middleware's only question, which is server-wide rather than per client: a browser's
// preflight carries no client identity, so there is nothing to scope the lookup to (#250).
//
// It exists to replace a full read of web_origins on every CORS-checked request. The unique
// index on (origin, client_id) that migration 000034 adds is origin-leading precisely so this
// count is an index lookup rather than a scan.
//
// The rows.Err() check is not boilerplate. This method gates cross-origin access, so a query
// that failed part way through and reported false would fail closed with no explanation, and
// one that reported true would fail open; either way every mock-backed test above stays green.
func (d *CommonDatabase) WebOriginExists(tx *sql.Tx, origin string) (bool, error) {

	selectBuilder := d.Flavor.NewSelectBuilder()
	selectBuilder.Select("count(*)").From("web_origins")
	selectBuilder.Where(selectBuilder.Equal("origin", origin))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return false, errors.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var count int
	if rows.Next() {
		if err := rows.Scan(&count); err != nil {
			return false, errors.Wrap(err, "unable to scan web origin count")
		}
	}

	if err := rows.Err(); err != nil {
		return false, errors.Wrap(err, "unable to read query results")
	}

	return count > 0, nil
}

func (d *CommonDatabase) DeleteWebOrigin(tx *sql.Tx, webOriginId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(models.WebOrigin)).
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
