package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *CommonDatabase) CreateSettings(tx *sql.Tx, settings *models.Settings) error {

	now := time.Now().UTC()

	originalCreatedAt := settings.CreatedAt
	originalUpdatedAt := settings.UpdatedAt
	settings.CreatedAt = sql.NullTime{Time: now, Valid: true}
	settings.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	settingsStruct := sqlbuilder.NewStruct(new(models.Settings)).
		For(d.Flavor)

	insertBuilder := settingsStruct.WithoutTag("pk").InsertInto("settings", settings)

	sql, args := insertBuilder.Build()
	result, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		settings.CreatedAt = originalCreatedAt
		settings.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert settings")
	}

	id, err := result.LastInsertId()
	if err != nil {
		settings.CreatedAt = originalCreatedAt
		settings.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	settings.Id = id
	return nil
}

func (d *CommonDatabase) UpdateSettings(tx *sql.Tx, settings *models.Settings) error {

	if settings.Id == 0 {
		return errors.WithStack(errors.New("can't update settings with id 0"))
	}

	originalUpdatedAt := settings.UpdatedAt
	settings.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	settingsStruct := sqlbuilder.NewStruct(new(models.Settings)).
		For(d.Flavor)

	updateBuilder := settingsStruct.WithoutTag("pk").WithoutTag("dont-update").Update("settings", settings)
	updateBuilder.Where(updateBuilder.Equal("id", settings.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		settings.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update settings")
	}

	return nil
}

func (d *CommonDatabase) getSettingsCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	settingsStruct *sqlbuilder.Struct) (*models.Settings, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var settings models.Settings
	if rows.Next() {
		addr := settingsStruct.Addr(&settings)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan settings")
		}
		return &settings, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "unable to read query results")
	}

	return nil, nil
}

func (d *CommonDatabase) GetSettingsById(tx *sql.Tx, settingsId int64) (*models.Settings, error) {

	settingsStruct := sqlbuilder.NewStruct(new(models.Settings)).
		For(d.Flavor)

	selectBuilder := settingsStruct.SelectFrom("settings")
	selectBuilder.Where(selectBuilder.Equal("id", settingsId))

	settings, err := d.getSettingsCommon(tx, selectBuilder, settingsStruct)
	if err != nil {
		return nil, err
	}

	return settings, nil
}

// TryClaimCleanupRun atomically claims the next background cleanup run, and
// reports whether this caller won the claim.
//
// The claim is a conditional UPDATE on settings.last_cleanup_at, which makes this
// column serve two purposes at once:
//
//   - Single flight across instances. Every replica polls, but only the one whose
//     UPDATE affects a row proceeds, so the cleanup does not run concurrently on
//     the same tables from several replicas.
//   - A wall-clock schedule. The decision is "has it been long enough since the
//     last run", not "how long has this process been up", so restarts no longer
//     reset the interval.
//
// claimableBefore is the cutoff: the run is claimable when last_cleanup_at is
// null (never run) or older than it. Pass now.Add(-interval).
//
// The claim is taken BEFORE the work runs, so a crash mid-cleanup delays the next
// attempt by one interval rather than letting every instance retry immediately.
func (d *CommonDatabase) TryClaimCleanupRun(tx *sql.Tx, now time.Time, claimableBefore time.Time) (bool, error) {

	ub := sqlbuilder.NewUpdateBuilder()
	ub.Update("settings")
	ub.Set(
		ub.Assign("last_cleanup_at", now),
		ub.Assign("updated_at", now),
	)
	ub.Where(
		ub.Equal("id", 1),
		ub.Or(
			ub.IsNull("last_cleanup_at"),
			ub.LessThan("last_cleanup_at", claimableBefore),
		),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSql(tx, query, args...)
	if err != nil {
		return false, errors.Wrap(err, "unable to claim the cleanup run")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errors.Wrap(err, "unable to get rows affected when claiming the cleanup run")
	}

	return rowsAffected == 1, nil
}
