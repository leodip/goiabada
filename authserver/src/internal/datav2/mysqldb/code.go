package mysqldb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateCode(tx *sql.Tx, code *entitiesv2.Code) error {

	if code.ClientId == 0 {
		return errors.New("client id must be greater than 0")
	}

	if code.UserId == 0 {
		return errors.New("user id must be greater than 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := code.CreatedAt
	originalUpdatedAt := code.UpdatedAt
	code.CreatedAt = now
	code.UpdatedAt = now

	codeStruct := sqlbuilder.NewStruct(new(entitiesv2.Code)).
		For(sqlbuilder.MySQL)

	insertBuilder := codeStruct.WithoutTag("pk").InsertInto("codes", code)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		code.CreatedAt = originalCreatedAt
		code.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert code")
	}

	id, err := result.LastInsertId()
	if err != nil {
		code.CreatedAt = originalCreatedAt
		code.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	code.Id = id
	return nil
}

func (d *MySQLDatabase) UpdateCode(tx *sql.Tx, code *entitiesv2.Code) error {

	if code.Id == 0 {
		return errors.New("can't update code with id 0")
	}

	originalUpdatedAt := code.UpdatedAt
	code.UpdatedAt = time.Now().UTC()

	codeStruct := sqlbuilder.NewStruct(new(entitiesv2.Code)).
		For(sqlbuilder.MySQL)

	updateBuilder := codeStruct.WithoutTag("pk").Update("codes", code)
	updateBuilder.Where(updateBuilder.Equal("id", code.Id))

	sql, args := updateBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		code.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update code")
	}

	return nil
}

func (d *MySQLDatabase) getCodeCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	codeStruct *sqlbuilder.Struct) (*entitiesv2.Code, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var code entitiesv2.Code
	if rows.Next() {
		addr := codeStruct.Addr(&code)
		rows.Scan(addr...)
		return &code, nil
	}
	return nil, nil
}

func (d *MySQLDatabase) GetCodeById(tx *sql.Tx, codeId int64) (*entitiesv2.Code, error) {

	if codeId <= 0 {
		return nil, errors.New("code id must be greater than 0")
	}

	codeStruct := sqlbuilder.NewStruct(new(entitiesv2.Code)).
		For(sqlbuilder.MySQL)

	selectBuilder := codeStruct.SelectFrom("codes")
	selectBuilder.Where(selectBuilder.Equal("id", codeId))

	code, err := d.getCodeCommon(tx, selectBuilder, codeStruct)
	if err != nil {
		return nil, err
	}

	return code, nil
}
