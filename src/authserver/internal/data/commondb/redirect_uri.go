package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

func (d *CommonDatabase) CreateRedirectURI(ctx context.Context, tx *sql.Tx, redirectURI *models.RedirectURI) error {

	if redirectURI.ClientId == 0 {
		return errs.New("client id must be greater than 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := redirectURI.CreatedAt
	redirectURI.CreatedAt = sql.NullTime{Time: now, Valid: true}

	redirectURIStruct := sqlbuilder.NewStruct(new(models.RedirectURI)).
		For(d.Flavor)

	insertBuilder := redirectURIStruct.WithoutTag("pk").InsertInto("redirect_uris", redirectURI)

	id, err := d.insertReturningId(ctx, tx, insertBuilder, "redirectURI")
	if err != nil {
		redirectURI.CreatedAt = originalCreatedAt
		return err
	}

	redirectURI.Id = id
	return nil
}

func (d *CommonDatabase) getRedirectURICommon(ctx context.Context, tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	redirectURIStruct *sqlbuilder.Struct) (*models.RedirectURI, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(ctx, tx, sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var redirectURI models.RedirectURI
	if rows.Next() {
		addr := redirectURIStruct.Addr(&redirectURI)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan redirectURI")
		}
		return &redirectURI, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return nil, nil
}

func (d *CommonDatabase) GetRedirectURIById(ctx context.Context, tx *sql.Tx, redirectURIId int64) (*models.RedirectURI, error) {

	redirectURIStruct := sqlbuilder.NewStruct(new(models.RedirectURI)).
		For(d.Flavor)

	selectBuilder := redirectURIStruct.SelectFrom("redirect_uris")
	selectBuilder.Where(selectBuilder.Equal("id", redirectURIId))

	redirectURI, err := d.getRedirectURICommon(ctx, tx, selectBuilder, redirectURIStruct)
	if err != nil {
		return nil, err
	}

	return redirectURI, nil
}

func (d *CommonDatabase) GetRedirectURIsByClientId(ctx context.Context, tx *sql.Tx, clientId int64) ([]models.RedirectURI, error) {

	redirectURIStruct := sqlbuilder.NewStruct(new(models.RedirectURI)).
		For(d.Flavor)

	selectBuilder := redirectURIStruct.SelectFrom("redirect_uris")
	selectBuilder.Where(selectBuilder.Equal("client_id", clientId))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(ctx, tx, sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	redirectURIs := []models.RedirectURI{}
	for rows.Next() {
		var redirectURI models.RedirectURI
		addr := redirectURIStruct.Addr(&redirectURI)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan redirectURI")
		}
		redirectURIs = append(redirectURIs, redirectURI)
	}

	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return redirectURIs, nil
}

func (d *CommonDatabase) DeleteRedirectURI(ctx context.Context, tx *sql.Tx, redirectURIId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(models.RedirectURI)).
		For(d.Flavor)

	deleteBuilder := clientStruct.DeleteFrom("redirect_uris")
	deleteBuilder.Where(deleteBuilder.Equal("id", redirectURIId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(ctx, tx, sql, args...)
	if err != nil {
		return errs.Wrap(err, "unable to delete redirectURI")
	}

	return nil
}
