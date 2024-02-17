package mysqldb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateKeyPair(tx *sql.Tx, keyPair *entitiesv2.KeyPair) error {

	now := time.Now().UTC()

	originalCreatedAt := keyPair.CreatedAt
	originalUpdatedAt := keyPair.UpdatedAt
	keyPair.CreatedAt = sql.NullTime{Time: now, Valid: true}
	keyPair.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	keyPairStruct := sqlbuilder.NewStruct(new(entitiesv2.KeyPair)).
		For(sqlbuilder.MySQL)

	insertBuilder := keyPairStruct.WithoutTag("pk").InsertInto("key_pairs", keyPair)

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
	keyPair.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	keyPairStruct := sqlbuilder.NewStruct(new(entitiesv2.KeyPair)).
		For(sqlbuilder.MySQL)

	updateBuilder := keyPairStruct.WithoutTag("pk").Update("key_pairs", keyPair)
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
		addr := keyPairStruct.Addr(&keyPair)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan keyPair")
		}
		return &keyPair, nil
	}
	return nil, nil
}

func (d *MySQLDatabase) GetKeyPairById(tx *sql.Tx, keyPairId int64) (*entitiesv2.KeyPair, error) {

	if keyPairId <= 0 {
		return nil, errors.New("keyPair id must be greater than 0")
	}

	keyPairStruct := sqlbuilder.NewStruct(new(entitiesv2.KeyPair)).
		For(sqlbuilder.MySQL)

	selectBuilder := keyPairStruct.SelectFrom("key_pairs")
	selectBuilder.Where(selectBuilder.Equal("id", keyPairId))

	keyPair, err := d.getKeyPairCommon(tx, selectBuilder, keyPairStruct)
	if err != nil {
		return nil, err
	}

	return keyPair, nil
}

func (d *MySQLDatabase) GetAllSigningKeys() ([]entitiesv2.KeyPair, error) {
	keyPairStruct := sqlbuilder.NewStruct(new(entitiesv2.KeyPair)).
		For(sqlbuilder.MySQL)

	selectBuilder := keyPairStruct.SelectFrom("key_pairs")

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(nil, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var keyPairs []entitiesv2.KeyPair
	for rows.Next() {
		var keyPair entitiesv2.KeyPair
		addr := keyPairStruct.Addr(&keyPair)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan keyPair")
		}
		keyPairs = append(keyPairs, keyPair)
	}

	return keyPairs, nil
}

func (d *MySQLDatabase) GetCurrentSigningKey() (*entitiesv2.KeyPair, error) {
	keyPairStruct := sqlbuilder.NewStruct(new(entitiesv2.KeyPair)).
		For(sqlbuilder.MySQL)

	selectBuilder := keyPairStruct.SelectFrom("key_pairs")
	selectBuilder.Where(selectBuilder.Equal("state", enums.KeyStateCurrent.String()))

	keyPair, err := d.getKeyPairCommon(nil, selectBuilder, keyPairStruct)
	if err != nil {
		return nil, err
	}

	return keyPair, nil
}

func (d *MySQLDatabase) DeleteKeyPair(tx *sql.Tx, keyPairId int64) error {
	if keyPairId <= 0 {
		return errors.New("keyPairId id must be greater than 0")
	}

	userConsentStruct := sqlbuilder.NewStruct(new(entitiesv2.KeyPair)).
		For(sqlbuilder.MySQL)

	deleteBuilder := userConsentStruct.DeleteFrom("key_pairs")
	deleteBuilder.Where(deleteBuilder.Equal("id", keyPairId))

	sql, args := deleteBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete keyPair")
	}

	return nil
}
