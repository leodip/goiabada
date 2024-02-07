package mysqldb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateKeyPair(tx *sql.Tx, keypair entitiesv2.KeyPair) (*entitiesv2.KeyPair, error) {

	now := time.Now().UTC()
	keypair.CreatedAt = now
	keypair.UpdatedAt = now

	keypairStruct := sqlbuilder.NewStruct(new(entitiesv2.KeyPair)).
		For(sqlbuilder.MySQL)

	insertBuilder := keypairStruct.WithoutTag("pk").InsertInto("keypairs", keypair)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to insert keypair")
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, errors.Wrap(err, "unable to get last insert id")
	}
	keypair.Id = id

	return &keypair, nil
}

func (d *MySQLDatabase) UpdateKeyPair(tx *sql.Tx, keypair entitiesv2.KeyPair) (*entitiesv2.KeyPair, error) {

	if keypair.Id == 0 {
		return nil, errors.New("can't update keypair with id 0")
	}

	keypair.UpdatedAt = time.Now().UTC()

	keypairStruct := sqlbuilder.NewStruct(new(entitiesv2.KeyPair)).
		For(sqlbuilder.MySQL)

	updateBuilder := keypairStruct.WithoutTag("pk").Update("keypairs", keypair)
	updateBuilder.Where(updateBuilder.Equal("id", keypair.Id))

	sql, args := updateBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to update keypair")
	}

	return &keypair, nil
}

func (d *MySQLDatabase) getKeyPairCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	keypairStruct *sqlbuilder.Struct) (*entitiesv2.KeyPair, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var keypair entitiesv2.KeyPair
	if rows.Next() {
		aaa := keypairStruct.Addr(&keypair)
		rows.Scan(aaa...)
	}

	return &keypair, nil
}

func (d *MySQLDatabase) GetKeyPairById(tx *sql.Tx, keypairId int64) (*entitiesv2.KeyPair, error) {

	if keypairId <= 0 {
		return nil, errors.New("keypair id must be greater than 0")
	}

	keypairStruct := sqlbuilder.NewStruct(new(entitiesv2.KeyPair)).
		For(sqlbuilder.MySQL)

	selectBuilder := keypairStruct.SelectFrom("keypairs")
	selectBuilder.Where(selectBuilder.Equal("id", keypairId))

	keypair, err := d.getKeyPairCommon(tx, selectBuilder, keypairStruct)
	if err != nil {
		return nil, err
	}

	return keypair, nil
}
