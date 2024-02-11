package mysqldb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateUserSession(tx *sql.Tx, userSession *entitiesv2.UserSession) error {

	if userSession.UserId == 0 {
		return errors.New("user id must be greater than 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := userSession.CreatedAt
	originalUpdatedAt := userSession.UpdatedAt
	userSession.CreatedAt = now
	userSession.UpdatedAt = now

	userSessionStruct := sqlbuilder.NewStruct(new(entitiesv2.UserSession)).
		For(sqlbuilder.MySQL)

	insertBuilder := userSessionStruct.WithoutTag("pk").InsertInto("user_sessions", userSession)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		userSession.CreatedAt = originalCreatedAt
		userSession.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert userSession")
	}

	id, err := result.LastInsertId()
	if err != nil {
		userSession.CreatedAt = originalCreatedAt
		userSession.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	userSession.Id = id
	return nil
}

func (d *MySQLDatabase) UpdateUserSession(tx *sql.Tx, userSession *entitiesv2.UserSession) error {

	if userSession.Id == 0 {
		return errors.New("can't update userSession with id 0")
	}

	originalUpdatedAt := userSession.UpdatedAt
	userSession.UpdatedAt = time.Now().UTC()

	userSessionStruct := sqlbuilder.NewStruct(new(entitiesv2.UserSession)).
		For(sqlbuilder.MySQL)

	updateBuilder := userSessionStruct.WithoutTag("pk").Update("user_sessions", userSession)
	updateBuilder.Where(updateBuilder.Equal("id", userSession.Id))

	sql, args := updateBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		userSession.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update userSession")
	}

	return nil
}

func (d *MySQLDatabase) getUserSessionCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	userSessionStruct *sqlbuilder.Struct) (*entitiesv2.UserSession, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var userSession entitiesv2.UserSession
	if rows.Next() {
		addr := userSessionStruct.Addr(&userSession)
		rows.Scan(addr...)
		return &userSession, nil
	}
	return nil, nil
}

func (d *MySQLDatabase) GetUserSessionById(tx *sql.Tx, userSessionId int64) (*entitiesv2.UserSession, error) {

	if userSessionId <= 0 {
		return nil, errors.New("userSession id must be greater than 0")
	}

	userSessionStruct := sqlbuilder.NewStruct(new(entitiesv2.UserSession)).
		For(sqlbuilder.MySQL)

	selectBuilder := userSessionStruct.SelectFrom("user_sessions")
	selectBuilder.Where(selectBuilder.Equal("id", userSessionId))

	userSession, err := d.getUserSessionCommon(tx, selectBuilder, userSessionStruct)
	if err != nil {
		return nil, err
	}

	return userSession, nil
}

func (d *MySQLDatabase) GetUserSessionBySessionIdentifier(tx *sql.Tx, sessionIdentifier string) (*entitiesv2.UserSession, error) {

	if sessionIdentifier == "" {
		return nil, errors.New("session identifier must not be empty")
	}

	userSessionStruct := sqlbuilder.NewStruct(new(entitiesv2.UserSession)).
		For(sqlbuilder.MySQL)

	selectBuilder := userSessionStruct.SelectFrom("user_sessions")
	selectBuilder.Where(selectBuilder.Equal("session_identifier", sessionIdentifier))

	userSession, err := d.getUserSessionCommon(tx, selectBuilder, userSessionStruct)
	if err != nil {
		return nil, err
	}

	return userSession, nil
}

func (d *MySQLDatabase) DeleteUserSession(tx *sql.Tx, userSessionId int64) error {
	if userSessionId <= 0 {
		return errors.New("userSession id must be greater than 0")
	}

	userSessionStruct := sqlbuilder.NewStruct(new(entitiesv2.UserSession)).
		For(sqlbuilder.MySQL)

	deleteBuilder := userSessionStruct.DeleteFrom("user_sessions")
	deleteBuilder.Where(deleteBuilder.Equal("id", userSessionId))

	sql, args := deleteBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete userSession")
	}

	return nil
}
