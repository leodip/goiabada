package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
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

	updateBuilder := keyPairStruct.WithoutTag("pk").WithoutTag("dont-update").Update("key_pairs", keyPair)
	updateBuilder.Where(updateBuilder.Equal("id", keyPair.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		keyPair.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update keyPair")
	}

	return nil
}

// UpdateKeyPairState moves one key from fromState to toState, and reports whether this call
// is the one that made the transition. The state predicate is what makes it a compare-and-set:
// without it two concurrent rotations both write the snapshot they read, and the loser deletes
// the previous key the winner had just demoted, retiring every token that key signed (#251).
func (d *CommonDatabase) UpdateKeyPairState(tx *sql.Tx, keyPairId int64, fromState string,
	toState string) (bool, error) {

	if keyPairId == 0 {
		return false, errors.WithStack(errors.New("can't update the state of a keyPair with id 0"))
	}

	ub := sqlbuilder.NewUpdateBuilder()
	ub.Update("key_pairs")
	ub.Set(
		ub.Assign("state", toState),
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(
		ub.Equal("id", keyPairId),
		ub.Equal("state", fromState),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSql(tx, query, args...)
	if err != nil {
		return false, errors.Wrap(err, "unable to update keyPair state")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errors.Wrap(err, "unable to get rows affected when updating keyPair state")
	}

	return rowsAffected == 1, nil
}

func (d *CommonDatabase) getKeyPairCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	keyPairStruct *sqlbuilder.Struct) (*models.KeyPair, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var keyPair models.KeyPair
	if rows.Next() {
		addr := keyPairStruct.Addr(&keyPair)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan keyPair")
		}
		return &keyPair, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "unable to read query results")
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
	defer func() { _ = rows.Close() }()

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

	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "unable to read query results")
	}

	return keyPairs, nil
}

// GetCurrentSigningKey returns an error when no key is in the current state, departing from
// the (nil, nil) this package returns for a lookup that may legitimately miss. Every caller
// dereferences the result to read key material, so a nil pair is a panic rather than a
// diagnosable failure, and a deployment with no current key cannot validate the bearer token
// needed to repair itself. Returning the error here is what makes all of those sites correct
// at once, including ones added later (#251).
func (d *CommonDatabase) GetCurrentSigningKey(tx *sql.Tx) (*models.KeyPair, error) {
	keyPairStruct := sqlbuilder.NewStruct(new(models.KeyPair)).
		For(d.Flavor)

	selectBuilder := keyPairStruct.SelectFrom("key_pairs")
	selectBuilder.Where(selectBuilder.Equal("state", enums.KeyStateCurrent.String()))

	keyPair, err := d.getKeyPairCommon(tx, selectBuilder, keyPairStruct)
	if err != nil {
		return nil, err
	}

	if keyPair == nil {
		return nil, errors.WithStack(errors.New("no current signing key found"))
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
