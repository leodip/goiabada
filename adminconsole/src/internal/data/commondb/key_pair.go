package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/adminconsole/internal/enums"
	"github.com/leodip/goiabada/adminconsole/internal/models"
	"github.com/pkg/errors"
)

func (d *CommonDatabase) CreateKeyPair(tx *sql.Tx, keyPair *models.KeyPair) error {

	now := time.Now().UTC()

	originalCreatedAt := keyPair.CreatedAt
	originalUpdatedAt := keyPair.UpdatedAt
	keyPair.CreatedAt = sql.NullTime{Time: now, Valid: true}
	keyPair.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	keyPairStruct := sqlbuilder.NewStruct(new(models.KeyPair)).
		For(d.Flavor)

	insertBuilder := keyPairStruct.WithoutTag("pk").InsertInto("key_pairs", keyPair)

	sql, args := insertBuilder.Build()
	result, err := d.ExecSql(tx, sql, args...)
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

func (d *CommonDatabase) UpdateKeyPair(tx *sql.Tx, keyPair *models.KeyPair) error {

	if keyPair.Id == 0 {
		return errors.WithStack(errors.New("can't update keyPair with id 0"))
	}

	originalUpdatedAt := keyPair.UpdatedAt
	keyPair.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	keyPairStruct := sqlbuilder.NewStruct(new(models.KeyPair)).
		For(d.Flavor)

	updateBuilder := keyPairStruct.WithoutTag("pk").Update("key_pairs", keyPair)
	updateBuilder.Where(updateBuilder.Equal("id", keyPair.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		keyPair.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update keyPair")
	}

	return nil
}

func (d *CommonDatabase) getKeyPairCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	keyPairStruct *sqlbuilder.Struct) (*models.KeyPair, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var keyPair models.KeyPair
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

func (d *CommonDatabase) GetKeyPairById(tx *sql.Tx, keyPairId int64) (*models.KeyPair, error) {

	keyPairStruct := sqlbuilder.NewStruct(new(models.KeyPair)).
		For(d.Flavor)

	selectBuilder := keyPairStruct.SelectFrom("key_pairs")
	selectBuilder.Where(selectBuilder.Equal("id", keyPairId))

	keyPair, err := d.getKeyPairCommon(tx, selectBuilder, keyPairStruct)
	if err != nil {
		return nil, err
	}

	return keyPair, nil
}

func (d *CommonDatabase) GetAllSigningKeys(tx *sql.Tx) ([]models.KeyPair, error) {
	keyPairStruct := sqlbuilder.NewStruct(new(models.KeyPair)).
		For(d.Flavor)

	selectBuilder := keyPairStruct.SelectFrom("key_pairs")

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var keyPairs []models.KeyPair
	for rows.Next() {
		var keyPair models.KeyPair
		addr := keyPairStruct.Addr(&keyPair)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan keyPair")
		}
		keyPairs = append(keyPairs, keyPair)
	}

	return keyPairs, nil
}

func (d *CommonDatabase) GetCurrentSigningKey(tx *sql.Tx) (*models.KeyPair, error) {
	keyPairStruct := sqlbuilder.NewStruct(new(models.KeyPair)).
		For(d.Flavor)

	selectBuilder := keyPairStruct.SelectFrom("key_pairs")
	selectBuilder.Where(selectBuilder.Equal("state", enums.KeyStateCurrent.String()))

	keyPair, err := d.getKeyPairCommon(tx, selectBuilder, keyPairStruct)
	if err != nil {
		return nil, err
	}

	return keyPair, nil
}

func (d *CommonDatabase) DeleteKeyPair(tx *sql.Tx, keyPairId int64) error {

	userConsentStruct := sqlbuilder.NewStruct(new(models.KeyPair)).
		For(d.Flavor)

	deleteBuilder := userConsentStruct.DeleteFrom("key_pairs")
	deleteBuilder.Where(deleteBuilder.Equal("id", keyPairId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete keyPair")
	}

	return nil
}
