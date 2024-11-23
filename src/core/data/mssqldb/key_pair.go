package mssqldb

import (
	"database/sql"
	"strings"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
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
		return errors.New("unexpected SQL format from sqlbuilder")
	}
	sql = parts[0] + "OUTPUT INSERTED.id VALUES" + parts[1]

	rows, err := d.CommonDB.QuerySql(tx, sql, args...)
	if err != nil {
		keyPair.CreatedAt = originalCreatedAt
		keyPair.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert keyPair")
	}
	defer rows.Close()

	if rows.Next() {
		err = rows.Scan(&keyPair.Id)
		if err != nil {
			keyPair.CreatedAt = originalCreatedAt
			keyPair.UpdatedAt = originalUpdatedAt
			return errors.Wrap(err, "unable to scan keyPair id")
		}
	}

	return nil
}

func (d *MsSQLDatabase) UpdateKeyPair(tx *sql.Tx, keyPair *models.KeyPair) error {
	return d.CommonDB.UpdateKeyPair(tx, keyPair)
}

func (d *MsSQLDatabase) GetKeyPairById(tx *sql.Tx, keyPairId int64) (*models.KeyPair, error) {
	return d.CommonDB.GetKeyPairById(tx, keyPairId)
}

func (d *MsSQLDatabase) GetAllSigningKeys(tx *sql.Tx) ([]models.KeyPair, error) {
	return d.CommonDB.GetAllSigningKeys(tx)
}

func (d *MsSQLDatabase) GetCurrentSigningKey(tx *sql.Tx) (*models.KeyPair, error) {
	return d.CommonDB.GetCurrentSigningKey(tx)
}

func (d *MsSQLDatabase) DeleteKeyPair(tx *sql.Tx, keyPairId int64) error {
	return d.CommonDB.DeleteKeyPair(tx, keyPairId)
}
