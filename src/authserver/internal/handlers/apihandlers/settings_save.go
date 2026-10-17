package apihandlers

import (
	"context"
	"database/sql"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// settingsSaveDatabase is what a settings section's save needs: the transaction, the settings row's
// lock, the read under it and the write.
type settingsSaveDatabase interface {
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
	AcquireSettingsRow(ctx context.Context, tx *sql.Tx, settingsId int64) error
	GetSettingsById(ctx context.Context, tx *sql.Tx, settingsId int64) (*record.Settings, error)
	UpdateSettings(ctx context.Context, tx *sql.Tx, settings *record.Settings) error
}

// saveSettingsSection writes one settings section and answers the row as committed. UpdateSettings
// writes every mutable column, so a save written from the row its request started with would carry
// every other section back from that copy and undo a save of another section committed meanwhile
// (#407). This takes the row first, reads it again under that lock, hands it to apply, which sets
// this section's columns and nothing else, and writes it.
//
// The caller has parsed, validated and checked the ceiling before it calls this, so the transaction
// holds the settings row and touches no other table. apply runs again if the engine reruns the body
// as a deadlock victim, on that attempt's own read, so it must set its columns from values it was
// given rather than accumulate anything; a value it records, such as what the section held before,
// is the committed attempt's. The settings on the request's context are left as the request started
// with them, which is what the audit logger reads its switches from.
func saveSettingsSection(ctx context.Context, database settingsSaveDatabase, settingsId int64,
	apply func(stored *record.Settings)) (*record.Settings, error) {

	var saved *record.Settings
	err := database.RunInTransaction(ctx, func(tx *sql.Tx) error {
		saved = nil
		if acquireErr := database.AcquireSettingsRow(ctx, tx, settingsId); acquireErr != nil {
			return errs.Wrap(acquireErr, "unable to acquire the settings row")
		}
		stored, readErr := database.GetSettingsById(ctx, tx, settingsId)
		if readErr != nil {
			return errs.Wrap(readErr, "unable to read the settings row")
		}
		if stored == nil {
			return errs.New("the settings row no longer exists")
		}
		apply(stored)
		if updateErr := database.UpdateSettings(ctx, tx, stored); updateErr != nil {
			return errs.Wrap(updateErr, "unable to save the settings")
		}
		saved = stored
		return nil
	})
	if err != nil {
		return nil, err
	}
	return saved, nil
}
