package datatests

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// CreateInitialSettings writes the settings row at id 1 on every engine, inside a transaction and
// never outside one, and leaves each engine's counter able to hand out the next id: SQL Server's
// identity moves past an explicit value by itself, MySQL's AUTO_INCREMENT and SQLite's rowid do,
// and PostgreSQL's sequence is moved by setval (#424 decision 14). On isolated databases, because
// the shared one's settings table already holds rows at 1 and above.

func initialSettings(appName string) *models.Settings {
	return &models.Settings{
		AppName:                appName,
		Issuer:                 "https://localhost:8080",
		PasswordPolicy:         models.PasswordPolicyLow,
		AESEncryptionKeyLegacy: []byte{},
	}
}

func TestCreateInitialSettings_WritesIdOneAndTheCounterMovesPastIt(t *testing.T) {
	h := migratedIsolatedDB(t)
	ctx := context.Background()

	settings := initialSettings("Initial")
	require.NoError(t, h.DB.RunInTransaction(ctx, func(tx *sql.Tx) error {
		return h.DB.CreateInitialSettings(ctx, tx, settings)
	}))
	assert.Equal(t, int64(1), settings.Id)

	stored, err := h.DB.GetSettingsById(ctx, nil, 1)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, "Initial", stored.AppName)
	isEmpty, err := h.DB.IsEmpty(ctx)
	require.NoError(t, err)
	assert.False(t, isEmpty)

	next := initialSettings("Next")
	require.NoError(t, h.DB.CreateSettings(ctx, nil, next),
		"an ordinary insert after the explicit id does not collide with it")
	assert.Greater(t, next.Id, int64(1))
}

// The shape decision 14 exists for: an id drawn inside a rolled-back transaction, which three of
// the four engines do not give back. The explicit insert still lands at 1.
func TestCreateInitialSettings_AfterARolledBackInsertDrewAnId(t *testing.T) {
	h := migratedIsolatedDB(t)
	ctx := context.Background()
	errRollBack := errors.New("roll back")

	err := h.DB.RunInTransaction(ctx, func(tx *sql.Tx) error {
		if err := h.DB.CreateSettings(ctx, tx, initialSettings("Rolled back")); err != nil {
			return err
		}
		return errRollBack
	})
	require.ErrorIs(t, err, errRollBack)

	settings := initialSettings("Initial")
	require.NoError(t, h.DB.RunInTransaction(ctx, func(tx *sql.Tx) error {
		return h.DB.CreateInitialSettings(ctx, tx, settings)
	}))
	assert.Equal(t, int64(1), settings.Id)
	isEmpty, err := h.DB.IsEmpty(ctx)
	require.NoError(t, err)
	assert.False(t, isEmpty, "the row IsEmpty reads is there, whatever the counter did")

	require.NoError(t, h.DB.CreateSettings(ctx, nil, initialSettings("Next")))
}

func TestCreateInitialSettings_RefusesANilTransaction(t *testing.T) {
	h := migratedIsolatedDB(t)
	ctx := context.Background()
	settings := initialSettings("Initial")

	err := h.DB.CreateInitialSettings(ctx, nil, settings)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "inside a transaction")
	assert.Zero(t, settings.Id, "the struct is left as it was given")
	stored, err := h.DB.GetSettingsById(ctx, nil, 1)
	require.NoError(t, err)
	assert.Nil(t, stored)
}

// A failed insert restores the struct, as every Create does, and leaves the engine able to take
// the insert again in a later transaction: on SQL Server the failure falls between IDENTITY_INSERT
// ON and OFF, and the connection's session is reset before it is reused.
func TestCreateInitialSettings_AFailedInsertCanBeRetried(t *testing.T) {
	h := migratedIsolatedDB(t)
	ctx := context.Background()

	require.NoError(t, h.DB.RunInTransaction(ctx, func(tx *sql.Tx) error {
		return h.DB.CreateInitialSettings(ctx, tx, initialSettings("First"))
	}))

	duplicate := initialSettings("Duplicate")
	err := h.DB.RunInTransaction(ctx, func(tx *sql.Tx) error {
		return h.DB.CreateInitialSettings(ctx, tx, duplicate)
	})
	require.Error(t, err, "id 1 is taken")
	assert.Zero(t, duplicate.Id)

	for i := 0; i < 3; i++ {
		require.NoError(t, h.DB.CreateSettings(ctx, nil, initialSettings("Ordinary")),
			"no connection returned to the pool refuses an ordinary insert afterwards")
	}
}
