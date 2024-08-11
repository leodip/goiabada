package mysqldb

import (
	"database/sql"

	"github.com/leodip/goiabada/adminconsole/internal/models"
)

func (d *MySQLDatabase) CreateKeyPair(tx *sql.Tx, keyPair *models.KeyPair) error {
	return d.CommonDB.CreateKeyPair(tx, keyPair)
}

func (d *MySQLDatabase) UpdateKeyPair(tx *sql.Tx, keyPair *models.KeyPair) error {
	return d.CommonDB.UpdateKeyPair(tx, keyPair)
}

func (d *MySQLDatabase) GetKeyPairById(tx *sql.Tx, keyPairId int64) (*models.KeyPair, error) {
	return d.CommonDB.GetKeyPairById(tx, keyPairId)
}

func (d *MySQLDatabase) GetAllSigningKeys(tx *sql.Tx) ([]models.KeyPair, error) {
	return d.CommonDB.GetAllSigningKeys(tx)
}

func (d *MySQLDatabase) GetCurrentSigningKey(tx *sql.Tx) (*models.KeyPair, error) {
	return d.CommonDB.GetCurrentSigningKey(tx)
}

func (d *MySQLDatabase) DeleteKeyPair(tx *sql.Tx, keyPairId int64) error {
	return d.CommonDB.DeleteKeyPair(tx, keyPairId)
}
