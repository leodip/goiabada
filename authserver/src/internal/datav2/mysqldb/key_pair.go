package mysqldb

import (
	"database/sql"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/datav2/commondb"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateKeyPair(tx *sql.Tx, keyPair *entitiesv2.KeyPair) (*entitiesv2.KeyPair, error) {

	insertBuilder := sqlbuilder.MySQL.NewInsertBuilder()
	insertBuilder = commondb.SetKeyPairInsertColsAndValues(insertBuilder, keyPair)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to insert key pair")
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, errors.Wrap(err, "unable to get last insert id")
	}

	keyPair, err = d.GetKeyPairById(tx, id)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get key pair by id")
	}
	return keyPair, nil
}

func (d *MySQLDatabase) GetKeyPairById(tx *sql.Tx, keyPairId int64) (*entitiesv2.KeyPair, error) {

	selectBuilder := sqlbuilder.MySQL.NewSelectBuilder()
	selectBuilder.
		Select("*").
		From("key_pairs").
		Where(selectBuilder.Equal("id", keyPairId))

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var keyPair *entitiesv2.KeyPair
	if rows.Next() {
		keyPair, err = commondb.ScanKeyPair(rows)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan row")
		}
	}

	return keyPair, nil
}
