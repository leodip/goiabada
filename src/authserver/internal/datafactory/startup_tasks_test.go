package datafactory

import (
	"database/sql"
	"errors"
	"testing"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startupKey is a 32-byte data-encryption key. Its value never matters here: every task under
// test is stubbed, and the length is the only thing runStartupDataTasks reads it for.
var startupKey = make([]byte, 32)

// TestRunStartupDataTasks_IsFailClosed pins the boundary every application crosses exactly once,
// at startup, before it serves anything: a data task that fails must stop the process rather
// than let it run on half-converted data.
//
// Serving on data that is half re-encrypted is worse than not serving: half the rows readable
// under the env key and half under the legacy one is a database no single key opens, and a TOTP
// secret the pass did not reach is still in plaintext at rest.
//
// The email lowercase pass was the fourth task here and was this test's headline case until #351
// made it migration 000047. Its fail-closed property did not go away with it: it moved to
// CheckEmailCaseBeforeMigrating, which refuses BEFORE the migration chain rather than
// repairing after it, and is covered in preflight_test.go.
//
// One case per task, each stubbing the tasks before it as succeeding and the task itself as
// failing, and asserting the error comes back out. The final case is the whole sequence
// succeeding, which is what says the failures above are caused by the failure and not by a
// mock nobody set up.
func TestRunStartupDataTasks_IsFailClosed(t *testing.T) {
	boom := errors.New("storage is unavailable")

	// A settings row still holding the legacy 32-byte key, which is what makes the one-shot
	// re-encryption run at all. Absent it the task is skipped, so a case asserting that it
	// fails closed would pass with the call deleted.
	legacySettings := &models.Settings{
		AESEncryptionKeyLegacy: make([]byte, 32),
	}

	tests := []struct {
		name        string
		previousKey []byte
		arrange     func(db *mocks_data.Database)
		wantErr     string
		why         string
	}{
		{
			name: "the settings read",
			arrange: func(db *mocks_data.Database) {
				db.EXPECT().GetSettingsById((*sql.Tx)(nil), int64(1)).Return(nil, boom)
			},
			wantErr: "unable to load settings for encryption migration",
			why:     "an unreadable settings row means the legacy key cannot be ruled out, so continuing could serve on data encrypted under a key nobody is using",
		},
		{
			name: "the one-shot move of the data key out of the database",
			arrange: func(db *mocks_data.Database) {
				db.EXPECT().GetSettingsById((*sql.Tx)(nil), int64(1)).Return(legacySettings, nil)
				db.EXPECT().ReencryptDataToNewKey(legacySettings.AESEncryptionKeyLegacy, startupKey).Return(boom)
			},
			wantErr: "failed to migrate data-at-rest encryption",
			why:     "half the rows would be readable under the env key and half under the legacy one",
		},
		{
			name:        "the env-to-env key rotation",
			previousKey: make([]byte, 32),
			arrange: func(db *mocks_data.Database) {
				db.EXPECT().GetSettingsById((*sql.Tx)(nil), int64(1)).Return(nil, nil)
				db.EXPECT().RotateEncryptionKeyIfNeeded(startupKey, make([]byte, 32)).Return(false, boom)
			},
			wantErr: "AES data key rotation failed",
			why:     "same hazard as above, from the other direction",
		},
		{
			name: "the TOTP secret encryption pass",
			arrange: func(db *mocks_data.Database) {
				db.EXPECT().GetSettingsById((*sql.Tx)(nil), int64(1)).Return(nil, nil)
				db.EXPECT().BackfillEncryptedOTPSecrets(startupKey).Return(0, boom)
			},
			wantErr: "failed to encrypt legacy plaintext OTP secrets",
			why:     "a TOTP secret left in plaintext at rest is the defect #82 closed, and serving would leave it open silently",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := mocks_data.NewDatabase(t)
			tc.arrange(db)

			err := runStartupDataTasks(db, startupKey, tc.previousKey)

			require.Errorf(t, err, "a failure in %s must stop startup: %s", tc.name, tc.why)
			assert.Containsf(t, err.Error(), tc.wantErr,
				"the error must name what failed, because this is the only message an operator gets: %v", err)
		})
	}

	t.Run("and the whole sequence succeeding returns no error", func(t *testing.T) {
		db := mocks_data.NewDatabase(t)
		db.EXPECT().GetSettingsById((*sql.Tx)(nil), int64(1)).Return(nil, nil)
		db.EXPECT().BackfillEncryptedOTPSecrets(startupKey).Return(3, nil)

		assert.NoError(t, runStartupDataTasks(db, startupKey, nil),
			"every task succeeded, so the cases above fail because of the injected error rather than because of an unset mock")
	})
}
