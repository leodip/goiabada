package datafactory

import (
	"errors"
	"testing"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// startupKey is a 32-byte data-encryption key. Its value never matters here: every task under
// test is stubbed, and the length is the only thing runStartupDataTasks reads it for.
var startupKey = make([]byte, 32)

// TestRunStartupDataTasks_IsFailClosed pins the boundary every application crosses exactly once,
// at startup, before it serves anything: a data task that fails must stop the process rather
// than let it run on half-converted data.
//
// Serving on data that is half re-keyed is worse than not serving: half the rows readable under
// the current key and half under the previous one is a database no single key opens.
//
// ONE TASK IS LEFT, and the two that went are why the cases below look thin. The email lowercase
// pass was the fourth and was this test's headline case until #351 made it migration 000047; its
// fail-closed property moved to CheckEmailCaseBeforeMigrating, which refuses BEFORE the migration
// chain rather than repairing after it, and is covered in preflight_test.go. The one-shot move of
// the data key out of the database and the TOTP secret encryption pass (#82) were deleted by #359
// along with the policy decision that an upgrade must pass through 1.6.x (#262).
//
// So the table is the rotation's failure case, plus the sequence succeeding, which is what says
// the failure is caused by the injected error and not by a mock nobody set up. The third case is
// the one guarding what is NOT there.
func TestRunStartupDataTasks_IsFailClosed(t *testing.T) {
	boom := errors.New("storage is unavailable")

	t.Run("the env-to-env key rotation", func(t *testing.T) {
		db := mocks_data.NewDatabase(t)
		db.EXPECT().RotateEncryptionKeyIfNeeded(startupKey, make([]byte, 32)).Return(false, boom)

		err := runStartupDataTasks(db, startupKey, make([]byte, 32))

		require.Error(t, err,
			"a rotation failure must stop startup: half the rows would read under the current key and half under the previous one")
		assert.Contains(t, err.Error(), "AES data key rotation failed",
			"the error must name what failed, because this is the only message an operator gets")
	})

	t.Run("a previous key of the wrong length skips the rotation entirely", func(t *testing.T) {
		db := mocks_data.NewDatabase(t)

		assert.NoError(t, runStartupDataTasks(db, startupKey, []byte("too short")),
			"rotation is acted on only at 32 bytes, so nothing must be called here")
		db.AssertNotCalled(t, "RotateEncryptionKeyIfNeeded", mock.Anything, mock.Anything)
	})

	// The assertion that fails if someone re-adds a settings read. runStartupDataTasks read
	// settings.aes_encryption_key for the 1.5.x conversion alone, and #359 deleted that
	// conversion (#262); the legacy column has no reader left and rotation never wanted one.
	//
	// AssertNotCalled is spelled out rather than left to mockery's unexpected-call panic, because
	// an assertion that is only the absence of a line is not one a reader can see.
	t.Run("and the surviving sequence reads no settings at all", func(t *testing.T) {
		db := mocks_data.NewDatabase(t)
		db.EXPECT().RotateEncryptionKeyIfNeeded(startupKey, make([]byte, 32)).Return(true, nil)

		assert.NoError(t, runStartupDataTasks(db, startupKey, make([]byte, 32)),
			"a successful rotation is a successful startup, so the case above fails because of the injected error")
		db.AssertNotCalled(t, "GetSettingsById", mock.Anything, mock.Anything)
	})
}
