package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entitiesv2"
)

func (d *SQLiteDatabase) CreateKeyPair(tx *sql.Tx, keyPair *entitiesv2.KeyPair) error {
	return d.CommonDB.CreateKeyPair(tx, keyPair)
}

func (d *SQLiteDatabase) UpdateKeyPair(tx *sql.Tx, keyPair *entitiesv2.KeyPair) error {
	return d.CommonDB.UpdateKeyPair(tx, keyPair)
}

func (d *SQLiteDatabase) GetKeyPairById(tx *sql.Tx, keyPairId int64) (*entitiesv2.KeyPair, error) {
	return d.CommonDB.GetKeyPairById(tx, keyPairId)
}

func (d *SQLiteDatabase) GetAllSigningKeys(tx *sql.Tx) ([]entitiesv2.KeyPair, error) {
	return d.CommonDB.GetAllSigningKeys(tx)
}

func (d *SQLiteDatabase) GetCurrentSigningKey(tx *sql.Tx) (*entitiesv2.KeyPair, error) {
	return d.CommonDB.GetCurrentSigningKey(tx)
}

func (d *SQLiteDatabase) DeleteKeyPair(tx *sql.Tx, keyPairId int64) error {
	return d.CommonDB.DeleteKeyPair(tx, keyPairId)
}
