package mssqldb

import (
	"database/sql"
	"strings"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

func (d *MsSQLDatabase) CreateClient(tx *sql.Tx, client *models.Client) error {
	now := time.Now().UTC()

	originalCreatedAt := client.CreatedAt
	originalUpdatedAt := client.UpdatedAt
	client.CreatedAt = sql.NullTime{Time: now, Valid: true}
	client.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	clientStruct := sqlbuilder.NewStruct(new(models.Client)).
		For(sqlbuilder.SQLServer)

	insertBuilder := clientStruct.WithoutTag("pk").InsertInto("clients", client)
	sql, args := insertBuilder.Build()

	parts := strings.SplitN(sql, "VALUES", 2)
	if len(parts) != 2 {
		return errs.New("unexpected SQL format from sqlbuilder")
	}
	sql = parts[0] + "OUTPUT INSERTED.id VALUES" + parts[1]

	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		client.CreatedAt = originalCreatedAt
		client.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to insert client")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&client.Id)
		if err != nil {
			client.CreatedAt = originalCreatedAt
			client.UpdatedAt = originalUpdatedAt
			return errs.Wrap(err, "unable to scan client id")
		}
	}

	// The driver can defer a constraint violation to the result set rather than
	// returning it from the query, in which case Next() simply reports no row.
	// Without this the insert would look like a success with id 0.
	if err := rows.Err(); err != nil {
		client.CreatedAt = originalCreatedAt
		client.UpdatedAt = originalUpdatedAt
		return d.WrapSQLError(err, "unable to insert client")
	}

	return nil
}
