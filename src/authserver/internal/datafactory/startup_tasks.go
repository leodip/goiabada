package datafactory

import (
	"context"
	"log/slog"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/core/errs"
)

// runStartupDataTasks is everything that has to happen to the stored data after the migration
// chain and before either application serves a request. One thing is left: the optional
// env-to-env key rotation. The email lowercase pass went in #351, which made it migration 000047
// and a pre-flight that runs BEFORE the chain rather than after it; the one-shot move of the data
// key out of the database and the TOTP secret encryption pass (#82) went in #359, which deleted
// both 1.5.x conversions and set the policy that an upgrade must pass through 1.6.x (#262).
//
// So this function reads no settings at all. Nothing here is allowed to re-add a settings read:
// the legacy key column is the conversion's, not rotation's, and startup_tasks_test.go asserts
// GetSettingsById is never called.
//
// THE REMAINING TASK IS FAIL-CLOSED, and that is the property this function exists to make
// testable rather than merely true. It returns an error that must stop startup, because it leaves
// the data half-converted when it fails: secrets re-keyed under a key the running process does not
// hold are a set of clients and accounts that silently cannot be used. NewDatabase builds a real
// database out of global configuration, so no test can drive it into that branch; extracted, the
// branch is one mock call away.
//
// The keys are parameters rather than config reads for the same reason. The caller has already
// validated envKey as 32 bytes; previousKey is optional and is acted on only at that length.
func runStartupDataTasks(ctx context.Context, database data.Database, envKey []byte, previousKey []byte) error {

	// Env-to-env key rotation (issue #83): if a previous key is supplied and the
	// data is still encrypted under it, re-encrypt everything to the current key.
	// Idempotent (safe to leave the previous key set across restarts) and
	// fail-closed.
	if len(previousKey) == 32 {
		rotated, err := database.RotateEncryptionKeyIfNeeded(ctx, envKey, previousKey)
		if err != nil {
			return errs.Wrap(err, "AES data key rotation failed")
		}
		if rotated {
			slog.InfoContext(ctx, "rotated data-at-rest encryption to the new GOIABADA_AES_ENCRYPTION_KEY")
		}
	}

	return nil
}
