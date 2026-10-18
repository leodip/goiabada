package datatests

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAcquireSettingsRow covers the contract of the statement that holds the settings row for the
// rest of a transaction (#407). It writes nothing a reader can observe but updated_at, which the
// save that follows it overwrites, so what there is to pin is that, and when it refuses.
func TestAcquireSettingsRow(t *testing.T) {
	settings := createTestSettings(t)

	tx := beginTx(t)
	require.NoError(t, database.AcquireSettingsRow(context.Background(), tx, settings.Id))
	held, err := database.GetSettingsById(context.Background(), tx, settings.Id)
	require.NoError(t, err)
	require.NotNil(t, held, "the row vanished inside the transaction that acquired it")
	assert.Equal(t, settings.AppName, held.AppName, "acquiring the row changed it")
	assert.Equal(t, settings.TokenExpirationInSeconds, held.TokenExpirationInSeconds, "acquiring the row changed it")
	assert.Equal(t, settings.SMTPHost, held.SMTPHost, "acquiring the row changed it")
	require.NoError(t, database.CommitTransaction(context.Background(), tx))

	// A row that is not there is not an error: there is nothing to hold, and the read that follows
	// decides whether it exists, as with AcquireClientRow.
	tx = beginTx(t)
	require.NoError(t, database.AcquireSettingsRow(context.Background(), tx, settings.Id+1_000_000))
	_ = database.RollbackTransaction(context.Background(), tx)

	tx = beginTx(t)
	require.Error(t, database.AcquireSettingsRow(context.Background(), tx, 0), "a settings id of 0")
	_ = database.RollbackTransaction(context.Background(), tx)

	// Without a transaction the statement autocommits and releases the row before the caller can
	// read it, which is the whole of what this buys. Refused rather than silently degraded.
	require.Error(t, database.AcquireSettingsRow(context.Background(), nil, settings.Id),
		"acquiring the row without a transaction")
}

// saveSettingsSectionUnderTheLock is the shape every settings section's save writes in: the row
// taken, read again on the transaction, the section applied onto what was read, and written.
func saveSettingsSectionUnderTheLock(ctx context.Context, tx *sql.Tx, settingsId int64,
	apply func(stored *record.Settings)) error {
	if err := database.AcquireSettingsRow(ctx, tx, settingsId); err != nil {
		return err
	}
	stored, err := database.GetSettingsById(ctx, tx, settingsId)
	if err != nil {
		return err
	}
	apply(stored)
	return database.UpdateSettings(ctx, tx, stored)
}

// A save of one section made under the row's lock keeps a save of another section that committed
// while it waited, so neither is lost (#407). The other save holds the row uncommitted; this one
// must not get past its acquisition until that commits, and must then write onto what it
// committed. Under MVCC (mysql, postgres) a bare re-read would return the row as it stood before
// the other save without waiting, and the write would put the other section back.
//
// On SQLite the pool has one connection, so this save's transaction cannot open until the other
// commits: it waits in a different place, and what it then writes is the same.
func TestAcquireSettingsRow_ASaveUnderTheLockKeepsAConcurrentSaveOfAnotherSection(t *testing.T) {
	settings := createTestSettings(t)

	// The other save, of the token settings, holding the row uncommitted.
	other := beginTx(t)
	require.NoError(t, saveSettingsSectionUnderTheLock(context.Background(), other, settings.Id, func(stored *record.Settings) {
		stored.TokenExpirationInSeconds = settings.TokenExpirationInSeconds + 7
	}))

	// This save, of the general settings, started while the other is in flight.
	done := make(chan error, 1)
	go func() {
		done <- database.RunInTransaction(context.Background(), func(tx *sql.Tx) error {
			return saveSettingsSectionUnderTheLock(context.Background(), tx, settings.Id, func(stored *record.Settings) {
				stored.AppName = "Saved under the lock"
			})
		})
	}()

	select {
	case err := <-done:
		t.Fatalf("the save completed while another save held the row uncommitted (err %v): it must wait for "+
			"that save rather than write onto the row it left behind", err)
	case <-time.After(500 * time.Millisecond):
	}

	require.NoError(t, database.CommitTransaction(context.Background(), other), "committing the other save")

	select {
	case err := <-done:
		require.NoError(t, err, "the save under the lock")
	case <-time.After(30 * time.Second):
		t.Fatal("the save never returned after the other save committed")
	}

	stored, err := database.GetSettingsById(context.Background(), nil, settings.Id)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, "Saved under the lock", stored.AppName, "this save was lost")
	assert.Equal(t, settings.TokenExpirationInSeconds+7, stored.TokenExpirationInSeconds,
		"the other section's save was written back over")
}
