package postgresdb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

func (d *PostgresDatabase) CreateCode(tx *sql.Tx, code *models.Code) error {
	if code.ClientId == 0 {
		return errs.New("client id must be greater than 0")
	}

	if code.UserId == 0 {
		return errs.New("user id must be greater than 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := code.CreatedAt
	originalUpdatedAt := code.UpdatedAt
	code.CreatedAt = sql.NullTime{Time: now, Valid: true}
	code.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	codeStruct := sqlbuilder.NewStruct(new(models.Code)).
		For(sqlbuilder.PostgreSQL)

	insertBuilder := codeStruct.WithoutTag("pk").InsertInto("codes", code)

	sql, args := insertBuilder.Build()
	sql = sql + " RETURNING id"

	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		code.CreatedAt = originalCreatedAt
		code.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to insert code")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&code.Id)
		if err != nil {
			code.CreatedAt = originalCreatedAt
			code.UpdatedAt = originalUpdatedAt
			return errs.Wrap(err, "unable to scan code id")
		}
	}

	// The driver can defer a constraint violation to the result set rather than
	// returning it from the query, in which case Next() simply reports no row.
	// Without this the insert would look like a success with id 0.
	if err := rows.Err(); err != nil {
		code.CreatedAt = originalCreatedAt
		code.UpdatedAt = originalUpdatedAt
		return d.WrapSQLError(err, "unable to insert code")
	}

	return nil
}
