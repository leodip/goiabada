package mysqldb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateRefreshToken(tx *sql.Tx, refreshToken *entitiesv2.RefreshToken) error {

	now := time.Now().UTC()

	originalCreatedAt := refreshToken.CreatedAt
	originalUpdatedAt := refreshToken.UpdatedAt
	refreshToken.CreatedAt = sql.NullTime{Time: now, Valid: true}
	refreshToken.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	refreshTokenStruct := sqlbuilder.NewStruct(new(entitiesv2.RefreshToken)).
		For(sqlbuilder.MySQL)

	insertBuilder := refreshTokenStruct.WithoutTag("pk").InsertInto("refresh_tokens", refreshToken)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		refreshToken.CreatedAt = originalCreatedAt
		refreshToken.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert refreshToken")
	}

	id, err := result.LastInsertId()
	if err != nil {
		refreshToken.CreatedAt = originalCreatedAt
		refreshToken.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	refreshToken.Id = id
	return nil
}

func (d *MySQLDatabase) UpdateRefreshToken(tx *sql.Tx, refreshToken *entitiesv2.RefreshToken) error {

	if refreshToken.Id == 0 {
		return errors.New("can't update refreshToken with id 0")
	}

	originalUpdatedAt := refreshToken.UpdatedAt
	refreshToken.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	refreshTokenStruct := sqlbuilder.NewStruct(new(entitiesv2.RefreshToken)).
		For(sqlbuilder.MySQL)

	updateBuilder := refreshTokenStruct.WithoutTag("pk").Update("refresh_tokens", refreshToken)
	updateBuilder.Where(updateBuilder.Equal("id", refreshToken.Id))

	sql, args := updateBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		refreshToken.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update refreshToken")
	}

	return nil
}

func (d *MySQLDatabase) getRefreshTokenCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	refreshTokenStruct *sqlbuilder.Struct) (*entitiesv2.RefreshToken, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var refreshToken entitiesv2.RefreshToken
	if rows.Next() {
		addr := refreshTokenStruct.Addr(&refreshToken)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan refreshToken")
		}
		return &refreshToken, nil
	}
	return nil, nil
}

func (d *MySQLDatabase) GetRefreshTokenById(tx *sql.Tx, refreshTokenId int64) (*entitiesv2.RefreshToken, error) {

	refreshTokenStruct := sqlbuilder.NewStruct(new(entitiesv2.RefreshToken)).
		For(sqlbuilder.MySQL)

	selectBuilder := refreshTokenStruct.SelectFrom("refresh_tokens")
	selectBuilder.Where(selectBuilder.Equal("id", refreshTokenId))

	refreshToken, err := d.getRefreshTokenCommon(tx, selectBuilder, refreshTokenStruct)
	if err != nil {
		return nil, err
	}

	return refreshToken, nil
}

func (d *MySQLDatabase) RefreshTokenLoadCode(tx *sql.Tx, refreshToken *entitiesv2.RefreshToken) error {
	if refreshToken == nil {
		return nil
	}

	code, err := d.GetCodeById(tx, refreshToken.CodeId)
	if err != nil {
		return errors.Wrap(err, "unable to load code")
	}

	if code != nil {
		refreshToken.Code = *code
	}

	return nil
}

func (d *MySQLDatabase) GetRefreshTokenByJti(tx *sql.Tx, jti string) (*entitiesv2.RefreshToken, error) {

	refreshTokenStruct := sqlbuilder.NewStruct(new(entitiesv2.RefreshToken)).
		For(sqlbuilder.MySQL)

	selectBuilder := refreshTokenStruct.SelectFrom("refresh_tokens")
	selectBuilder.Where(selectBuilder.Equal("refresh_token_jti", jti))

	refreshToken, err := d.getRefreshTokenCommon(tx, selectBuilder, refreshTokenStruct)
	if err != nil {
		return nil, err
	}

	return refreshToken, nil
}

func (d *MySQLDatabase) DeleteRefreshToken(tx *sql.Tx, refreshTokenId int64) error {

	userConsentStruct := sqlbuilder.NewStruct(new(entitiesv2.RefreshToken)).
		For(sqlbuilder.MySQL)

	deleteBuilder := userConsentStruct.DeleteFrom("refresh_tokens")
	deleteBuilder.Where(deleteBuilder.Equal("id", refreshTokenId))

	sql, args := deleteBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete refreshToken")
	}

	return nil
}
