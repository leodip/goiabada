package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/models"
	"github.com/pkg/errors"
)

func (d *CommonDatabase) CreateCode(tx *sql.Tx, code *models.Code) error {

	if code.ClientId == 0 {
		return errors.WithStack(errors.New("client id must be greater than 0"))
	}

	if code.UserId == 0 {
		return errors.WithStack(errors.New("user id must be greater than 0"))
	}

	now := time.Now().UTC()

	originalCreatedAt := code.CreatedAt
	originalUpdatedAt := code.UpdatedAt
	code.CreatedAt = sql.NullTime{Time: now, Valid: true}
	code.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	codeStruct := sqlbuilder.NewStruct(new(models.Code)).
		For(d.Flavor)

	insertBuilder := codeStruct.WithoutTag("pk").InsertInto("codes", code)

	sql, args := insertBuilder.Build()
	result, err := d.ExecSql(tx, sql, args...)
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

func (d *CommonDatabase) UpdateCode(tx *sql.Tx, code *models.Code) error {

	if code.Id == 0 {
		return errors.WithStack(errors.New("can't update code with id 0"))
	}

	originalUpdatedAt := code.UpdatedAt
	code.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	codeStruct := sqlbuilder.NewStruct(new(models.Code)).
		For(d.Flavor)

	updateBuilder := codeStruct.WithoutTag("pk").Update("codes", code)
	updateBuilder.Where(updateBuilder.Equal("id", code.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		code.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update code")
	}

	return nil
}

func (d *CommonDatabase) getCodeCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	codeStruct *sqlbuilder.Struct) (*models.Code, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var code models.Code
	if rows.Next() {
		addr := codeStruct.Addr(&code)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan code")
		}
		return &code, nil
	}
	return nil, nil
}

func (d *CommonDatabase) GetCodeById(tx *sql.Tx, codeId int64) (*models.Code, error) {

	codeStruct := sqlbuilder.NewStruct(new(models.Code)).
		For(d.Flavor)

	selectBuilder := codeStruct.SelectFrom("codes")
	selectBuilder.Where(selectBuilder.Equal("id", codeId))

	code, err := d.getCodeCommon(tx, selectBuilder, codeStruct)
	if err != nil {
		return nil, err
	}

	return code, nil
}

func (d *CommonDatabase) CodeLoadClient(tx *sql.Tx, code *models.Code) error {

	if code == nil {
		return nil
	}

	client, err := d.GetClientById(tx, code.ClientId)
	if err != nil {
		return errors.Wrap(err, "unable to load client")
	}

	if client != nil {
		code.Client = *client
	}
	return nil
}

func (d *CommonDatabase) CodeLoadUser(tx *sql.Tx, code *models.Code) error {

	if code == nil {
		return nil
	}

	user, err := d.GetUserById(tx, code.UserId)
	if err != nil {
		return errors.Wrap(err, "unable to load user")
	}

	if user != nil {
		code.User = *user
	}
	return nil
}

func (d *CommonDatabase) GetCodeByCodeHash(tx *sql.Tx, codeHash string, used bool) (*models.Code, error) {
	codeStruct := sqlbuilder.NewStruct(new(models.Code)).
		For(d.Flavor)

	selectBuilder := codeStruct.SelectFrom("codes")
	selectBuilder.Where(selectBuilder.Equal("code_hash", codeHash))
	selectBuilder.Where(selectBuilder.Equal("used", used))

	code, err := d.getCodeCommon(tx, selectBuilder, codeStruct)
	if err != nil {
		return nil, err
	}

	return code, nil
}

func (d *CommonDatabase) DeleteCode(tx *sql.Tx, codeId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(models.Code)).
		For(d.Flavor)

	deleteBuilder := clientStruct.DeleteFrom("codes")
	deleteBuilder.Where(deleteBuilder.Equal("id", codeId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete code")
	}

	return nil
}
