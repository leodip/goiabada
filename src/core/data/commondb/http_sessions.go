package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *CommonDatabase) CreateHttpSession(tx *sql.Tx, httpSession *models.HttpSession) error {

	now := time.Now().UTC()

	originalCreatedAt := httpSession.CreatedAt
	originalUpdatedAt := httpSession.UpdatedAt
	httpSession.CreatedAt = sql.NullTime{Time: now, Valid: true}
	httpSession.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	httpSessionStruct := sqlbuilder.NewStruct(new(models.HttpSession)).
		For(d.Flavor)

	insertBuilder := httpSessionStruct.WithoutTag("pk").InsertInto("http_sessions", httpSession)

	sql, args := insertBuilder.Build()
	result, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		httpSession.CreatedAt = originalCreatedAt
		httpSession.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert httpSession")
	}

	id, err := result.LastInsertId()
	if err != nil {
		httpSession.CreatedAt = originalCreatedAt
		httpSession.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	httpSession.Id = id
	return nil
}

func (d *CommonDatabase) UpdateHttpSession(tx *sql.Tx, httpSession *models.HttpSession) error {

	if httpSession.Id == 0 {
		return errors.WithStack(errors.New("can't update httpSession with id 0"))
	}

	originalUpdatedAt := httpSession.UpdatedAt
	httpSession.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	httpSessionStruct := sqlbuilder.NewStruct(new(models.HttpSession)).
		For(d.Flavor)

	updateBuilder := httpSessionStruct.WithoutTag("pk").WithoutTag("dont-update").Update("http_sessions", httpSession)
	updateBuilder.Where(updateBuilder.Equal("id", httpSession.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		httpSession.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update httpSession")
	}

	return nil
}

func (d *CommonDatabase) getHttpSessionCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	httpSessionStruct *sqlbuilder.Struct) (*models.HttpSession, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var httpSession models.HttpSession
	if rows.Next() {
		addr := httpSessionStruct.Addr(&httpSession)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan httpSession")
		}
		return &httpSession, nil
	}
	return nil, nil
}

func (d *CommonDatabase) GetHttpSessionById(tx *sql.Tx, httpSessionId int64) (*models.HttpSession, error) {

	httpSessionStruct := sqlbuilder.NewStruct(new(models.HttpSession)).
		For(d.Flavor)

	selectBuilder := httpSessionStruct.SelectFrom("http_sessions")
	selectBuilder.Where(selectBuilder.Equal("id", httpSessionId))

	httpSession, err := d.getHttpSessionCommon(tx, selectBuilder, httpSessionStruct)
	if err != nil {
		return nil, err
	}

	return httpSession, nil
}

func (d *CommonDatabase) DeleteHttpSession(tx *sql.Tx, httpSessionId int64) error {

	userConsentStruct := sqlbuilder.NewStruct(new(models.HttpSession)).
		For(d.Flavor)

	deleteBuilder := userConsentStruct.DeleteFrom("http_sessions")
	deleteBuilder.Where(deleteBuilder.Equal("id", httpSessionId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete httpSession")
	}

	return nil
}

func (d *CommonDatabase) DeleteHttpSessionExpired(tx *sql.Tx) error {

	userConsentStruct := sqlbuilder.NewStruct(new(models.HttpSession)).
		For(d.Flavor)

	deleteBuilder := userConsentStruct.DeleteFrom("http_sessions")
	deleteBuilder.Where(deleteBuilder.LessThan("expires_on", time.Now().UTC()))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete expired http sessions")
	}

	return nil
}
