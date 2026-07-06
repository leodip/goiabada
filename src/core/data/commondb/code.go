package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
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

	updateBuilder := codeStruct.WithoutTag("pk").WithoutTag("dont-update").Update("codes", code)
	updateBuilder.Where(updateBuilder.Equal("id", code.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		code.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update code")
	}

	return nil
}

// MarkCodeAsUsed atomically transitions a code from unused to used via a
// conditional UPDATE (`WHERE id = ? AND used = false`). It returns true only if
// this call is the one that flipped the flag; a false return means the row was
// already used, i.e. a concurrent request redeemed the same code first. Callers
// treat that as authorization-code reuse. This compare-and-set closes the
// double-spend race that a read-then-unconditional-update leaves open (#77).
func (d *CommonDatabase) MarkCodeAsUsed(tx *sql.Tx, codeId int64) (bool, error) {

	if codeId == 0 {
		return false, errors.WithStack(errors.New("can't mark code with id 0 as used"))
	}

	ub := sqlbuilder.NewUpdateBuilder()
	ub.Update("codes")
	ub.Set(
		ub.Assign("used", true),
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(
		ub.Equal("id", codeId),
		ub.Equal("used", false),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSql(tx, query, args...)
	if err != nil {
		return false, errors.Wrap(err, "unable to mark code as used")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errors.Wrap(err, "unable to get rows affected when marking code as used")
	}

	return rowsAffected == 1, nil
}

func (d *CommonDatabase) getCodeCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	codeStruct *sqlbuilder.Struct) (*models.Code, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

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

// Deletes codes that are marked as used and have no refresh tokens referencing them
func (d *CommonDatabase) DeleteUsedCodesWithoutRefreshTokens(tx *sql.Tx) error {
	deleteBuilder := d.Flavor.NewDeleteBuilder()
	deleteBuilder.DeleteFrom("codes")
	deleteBuilder.Where(
		deleteBuilder.And(
			deleteBuilder.Equal("used", true),
			deleteBuilder.NotIn("id",
				d.Flavor.NewSelectBuilder().Select("code_id").From("refresh_tokens"),
			),
		),
	)

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete used codes without refresh tokens")
	}

	return nil
}
