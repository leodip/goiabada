package mysqldb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateKeyPair(tx *sql.Tx, keyPair *entitiesv2.KeyPair) error {

	now := time.Now().UTC()

	originalCreatedAt := keyPair.CreatedAt
	originalUpdatedAt := keyPair.UpdatedAt
	keyPair.CreatedAt = now
	keyPair.UpdatedAt = now

	keyPairStruct := sqlbuilder.NewStruct(new(entitiesv2.KeyPair)).
		For(sqlbuilder.MySQL)

	insertBuilder := keyPairStruct.WithoutTag("pk").InsertInto("keyPairs", keyPair)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		keyPair.CreatedAt = originalCreatedAt
		keyPair.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert keyPair")
	}

	id, err := result.LastInsertId()
	if err != nil {
		keyPair.CreatedAt = originalCreatedAt
		keyPair.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	keyPair.Id = id
	return nil
}

func (d *MySQLDatabase) UpdateKeyPair(tx *sql.Tx, keyPair *entitiesv2.KeyPair) error {

	if keyPair.Id == 0 {
		return errors.New("can't update keyPair with id 0")
	}

	originalUpdatedAt := keyPair.UpdatedAt
	keyPair.UpdatedAt = time.Now().UTC()

	keyPairStruct := sqlbuilder.NewStruct(new(entitiesv2.KeyPair)).
		For(sqlbuilder.MySQL)

	updateBuilder := keyPairStruct.WithoutTag("pk").Update("keyPairs", keyPair)
	updateBuilder.Where(updateBuilder.Equal("id", keyPair.Id))

	sql, args := updateBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		keyPair.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update keyPair")
	}

	return nil
}

func (d *MySQLDatabase) getKeyPairCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	keyPairStruct *sqlbuilder.Struct) (*entitiesv2.KeyPair, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var keyPair entitiesv2.KeyPair
	if rows.Next() {
		aaa := keyPairStruct.Addr(&keyPair)
		rows.Scan(aaa...)
	}

	return &keyPair, nil
}

func (d *MySQLDatabase) GetKeyPairById(tx *sql.Tx, keyPairId int64) (*entitiesv2.KeyPair, error) {

	if keyPairId <= 0 {
		return nil, errors.New("keyPair id must be greater than 0")
	}

	keyPairStruct := sqlbuilder.NewStruct(new(entitiesv2.KeyPair)).
		For(sqlbuilder.MySQL)

	selectBuilder := keyPairStruct.SelectFrom("keyPairs")
	selectBuilder.Where(selectBuilder.Equal("id", keyPairId))

	keyPair, err := d.getKeyPairCommon(tx, selectBuilder, keyPairStruct)
	if err != nil {
		return nil, err
	}

	return keyPair, nil
}
