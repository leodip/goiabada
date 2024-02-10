package mysqldb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateRedirectURI(tx *sql.Tx, redirectURI *entitiesv2.RedirectURI) error {

	if redirectURI.ClientId == 0 {
		return errors.New("client id must be greater than 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := redirectURI.CreatedAt
	redirectURI.CreatedAt = now

	redirectURIStruct := sqlbuilder.NewStruct(new(entitiesv2.RedirectURI)).
		For(sqlbuilder.MySQL)

	insertBuilder := redirectURIStruct.WithoutTag("pk").InsertInto("redirect_uris", redirectURI)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		redirectURI.CreatedAt = originalCreatedAt
		return errors.Wrap(err, "unable to insert redirectURI")
	}

	id, err := result.LastInsertId()
	if err != nil {
		redirectURI.CreatedAt = originalCreatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	redirectURI.Id = id
	return nil
}

func (d *MySQLDatabase) getRedirectURICommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	redirectURIStruct *sqlbuilder.Struct) (*entitiesv2.RedirectURI, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var redirectURI entitiesv2.RedirectURI
	if rows.Next() {
		addr := redirectURIStruct.Addr(&redirectURI)
		rows.Scan(addr...)
		return &redirectURI, nil
	}
	return nil, nil
}

func (d *MySQLDatabase) GetRedirectURIById(tx *sql.Tx, redirectURIId int64) (*entitiesv2.RedirectURI, error) {

	if redirectURIId <= 0 {
		return nil, errors.New("redirectURI id must be greater than 0")
	}

	redirectURIStruct := sqlbuilder.NewStruct(new(entitiesv2.RedirectURI)).
		For(sqlbuilder.MySQL)

	selectBuilder := redirectURIStruct.SelectFrom("redirect_uris")
	selectBuilder.Where(selectBuilder.Equal("id", redirectURIId))

	redirectURI, err := d.getRedirectURICommon(tx, selectBuilder, redirectURIStruct)
	if err != nil {
		return nil, err
	}

	return redirectURI, nil
}
