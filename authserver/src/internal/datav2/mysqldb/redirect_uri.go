package mysqldb

import (
	"database/sql"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/datav2/commondb"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateClientRedirectURI(tx *sql.Tx, redirectURI *entitiesv2.RedirectURI) (*entitiesv2.RedirectURI, error) {

	insertBuilder := sqlbuilder.MySQL.NewInsertBuilder()
	commondb.SetRedirectURIInsertColsAndValues(insertBuilder, redirectURI, redirectURI.ClientId)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to insert client redirect uri")
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, errors.Wrap(err, "unable to get last insert id")
	}

	redirectURI, err = d.GetRedirectURIById(tx, id)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get redirect uri by id")
	}
	return redirectURI, nil
}

func (d *MySQLDatabase) GetRedirectURIById(tx *sql.Tx, redirectURIId int64) (*entitiesv2.RedirectURI, error) {

	selectBuilder := sqlbuilder.MySQL.NewSelectBuilder()
	selectBuilder.
		Select("*").
		From("redirect_uris").
		Where(selectBuilder.Equal("id", redirectURIId))

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var redirectURI *entitiesv2.RedirectURI
	if rows.Next() {
		redirectURI, err = commondb.ScanRedirectURI(rows)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan row")
		}
	}

	return redirectURI, nil
}
