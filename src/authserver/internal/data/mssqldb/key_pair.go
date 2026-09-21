package mssqldb

import (
	"database/sql"
	"strings"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

func (d *MsSQLDatabase) CreateKeyPair(tx *sql.Tx, keyPair *models.KeyPair) error {
	now := time.Now().UTC()

	originalCreatedAt := keyPair.CreatedAt
	originalUpdatedAt := keyPair.UpdatedAt
	keyPair.CreatedAt = sql.NullTime{Time: now, Valid: true}
	keyPair.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	keyPairStruct := sqlbuilder.NewStruct(new(models.KeyPair)).
		For(sqlbuilder.SQLServer)

	insertBuilder := keyPairStruct.WithoutTag("pk").InsertInto("key_pairs", keyPair)
	sql, args := insertBuilder.Build()

	parts := strings.SplitN(sql, "VALUES", 2)
	if len(parts) != 2 {
		return errs.New("unexpected SQL format from sqlbuilder")
	}
	sql = parts[0] + "OUTPUT INSERTED.id VALUES" + parts[1]

	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		keyPair.CreatedAt = originalCreatedAt
		keyPair.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to insert keyPair")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&keyPair.Id)
		if err != nil {
			keyPair.CreatedAt = originalCreatedAt
			keyPair.UpdatedAt = originalUpdatedAt
			return errs.Wrap(err, "unable to scan keyPair id")
		}
	}

	// The driver can defer a constraint violation to the result set rather than
	// returning it from the query, in which case Next() simply reports no row.
	// Without this the insert would look like a success with id 0.
	if err := rows.Err(); err != nil {
		keyPair.CreatedAt = originalCreatedAt
		keyPair.UpdatedAt = originalUpdatedAt
		return d.WrapSQLError(err, "unable to insert keyPair")
	}

	return nil
}
